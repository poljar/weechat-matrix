# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import json
import socket
import ssl
import time

from builtins import bytes
from collections import deque, Mapping, Iterable
from enum import Enum, unique
from functools import wraps
from typing import List, Set, Dict, Tuple, Text, Optional, AnyStr, Deque, Any

from http_parser.pyparser import HttpParser

import weechat

WEECHAT_SCRIPT_NAME        = "matrix"                              # type: unicode
WEECHAT_SCRIPT_DESCRIPTION = "matrix chat plugin"                  # type: unicode
WEECHAT_SCRIPT_AUTHOR      = "Damir Jelić <poljar@termina.org.uk>" # type: unicode
WEECHAT_SCRIPT_VERSION     = "0.1"                                 # type: unicode
WEECHAT_SCRIPT_LICENSE     = "MIT"                                 # type: unicode

SCRIPT_COMMAND  = WEECHAT_SCRIPT_NAME   # type: unicode

MATRIX_API_PATH = "/_matrix/client/r0"  # type: unicode

SERVERS = dict()

# Unicode handling

def encode_to_utf8(data):
    if isinstance(data, unicode):
        return data.encode('utf-8')
    if isinstance(data, bytes):
        return data
    elif isinstance(data, Mapping):
        return type(data)(map(encode_to_utf8, data.iteritems()))
    elif isinstance(data, Iterable):
        return type(data)(map(encode_to_utf8, data))
    else:
        return data


def decode_from_utf8(data):
    if isinstance(data, bytes):
        return data.decode('utf-8')
    if isinstance(data, unicode):
        return data
    elif isinstance(data, Mapping):
        return type(data)(map(decode_from_utf8, data.iteritems()))
    elif isinstance(data, Iterable):
        return type(data)(map(decode_from_utf8, data))
    else:
        return data


def utf8_decode(f):
    """
    Decode all arguments from byte strings to unicode strings. Use this for
    functions called from outside of this script, e.g. callbacks from weechat.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        return f(*decode_from_utf8(args), **decode_from_utf8(kwargs))
    return wrapper


class WeechatWrapper(object):
    def __init__(self, wrapped_class):
        self.wrapped_class = wrapped_class

    # Helper method used to encode/decode method calls.
    def wrap_for_utf8(self, method):
        def hooked(*args, **kwargs):
            result = method(*encode_to_utf8(args), **encode_to_utf8(kwargs))
            # Prevent wrapped_class from becoming unwrapped
            if result == self.wrapped_class:
                return self
            return decode_from_utf8(result)
        return hooked

    # Encode and decode everything sent to/received from weechat. We use the
    # unicode type internally in wee-slack, but has to send utf8 to weechat.
    def __getattr__(self, attr):
        orig_attr = self.wrapped_class.__getattribute__(attr)
        if callable(orig_attr):
            return self.wrap_for_utf8(orig_attr)
        else:
            return decode_from_utf8(orig_attr)

    # Ensure all lines sent to weechat specify a prefix. For lines after the
    # first, we want to disable the prefix, which is done by specifying a space.
    def prnt_date_tags(self, buffer, date, tags, message):
        message = message.replace("\n", "\n \t")
        return self.wrap_for_utf8(self.wrapped_class.prnt_date_tags)(buffer, date, tags, message)


@unique
class MessageType(Enum):
    LOGIN    = 1
    SYNC     = 2
    POST_MSG = 3


@unique
class RequestType(Enum):
    GET    = 1
    POST   = 2
    PUT    = 3
    DELETE = 4


class RequestBuilder:
    # TODO put the user agent somewhere globally
    def __init__(self, host, user_agent='weechat-matrix/0.1'):
        # type: (unicode, unicode) -> None
        self.host = host

        self.host_header = 'Host: {host}'.format(host=host)
        self.user_agent  = 'User-Agent: {agent}'.format(agent=user_agent)

    # TODO we need to handle PUT as well
    def request(self, location, data=None):
        # type: (unicode, Dict[Any, Any]) -> (HttpRequest)

        request_list  = []             # type: List[unicode]
        accept_header = 'Accept: */*'  # type: unicode
        end_separator = '\r\n'         # type: unicode
        payload       = None           # type: unicode

        if data:
            json_data     = json.dumps(data, separators=(',', ':'))

            post          = 'POST {location} HTTP/1.1'.format(location=location)
            type_header   = 'Content-Type: application/x-www-form-urlencoded'
            length_header = 'Content-Length: {length}'.format(length=len(json_data))

            request_list  = [post, self.host_header,
                             self.user_agent, accept_header,
                             length_header, type_header, end_separator]
            payload       = json_data
        else:
            get = 'GET {location} HTTP/1.1'.format(location=location)
            request_list  = [get, self.host_header,
                             self.user_agent, accept_header, end_separator]

        request = '\r\n'.join(request_list)

        return HttpRequest(request, payload)


class HttpResponse:
    def __init__(self, status, headers, body):
        self.status  = status   # type: int
        self.headers = headers  # type: Dict[unicode, unicode]
        self.body    = body     # type: bytes


class HttpRequest:
    def __init__(self, request, payload):
        # type: (unicode, unicode) -> None
        self.request = request
        self.payload = payload


class MatrixMessage:
    def __init__(self, messageType, request, response):
        # type: (MessageType, HttpRequest, HttpResponse) -> None
        self.type     = messageType
        self.request  = request
        self.response = response


class Matrix:
    def __init__(self, settings):
        # type: (Settings) -> None
        self.settings = settings # type: Settings
        self.access_token = ""   # type: unicode
        self.next_batch = ""     # type: unicode
        self.rooms = {}          # type: Dict[unicode, MatrixRoom]


class MatrixRoom:
    def __init__(self, id, join_rule, alias=None):
        # type: (unicode, unicode, unicode) -> None
        self.id        = id         # type: unicode
        self.alias     = alias      # type: unicode
        self.join_rule = join_rule  # type: unicode
        self.users     = []         # type: MatrixUsers


class MatrixServer:
    def __init__(self, name, address, port):
        # type: (str) -> None
        self.name          = name     # type: unicode
        self.address       = address  # type: unicode
        self.port          = port     # type: int

        self.buffers       = dict()  # type: Dict[unicode, weechat.buffer]
        self.server_buffer = None    # type: weechat.buffer
        self.fd_hook       = None
        self.timer_hook    = None

        self.connected  = False                           # type: bool
        self.connecting = False                           # type: bool
        self.reconnectCount = 0                           # type: long
        self.socket = None                                # type: ssl.SSLSocket
        self.ssl_context = ssl.create_default_context()   # type: ssl.SSLContext

        # TODO this belongs into the Matrix class
        self.access_token = None                         # type: unicode
        host_string = ':'.join([self.address,
                                str(self.port)])     # type: unicode
        self.builder    = RequestBuilder(host_string)    # type: RequestBuilder
        self.next_batch = None

        self.httpParser = HttpParser()                   # type: HttpParser
        self.httpBodyBuffer = []                         # type: List[bytes]

        # Queue of messages we need to send off.
        self.sendQueue = deque()  # type: Deque[MatrixMessage]
        # Queue of messages we send off and are waiting a response for
        self.recieveQueue = deque()  # type: Deque[MatrixMessage]
        # Queue for messages we got a response of and need to handle
        # TODO is this needed? will we ever deffer message handling?
        self.MessageQueue = deque()  # type: Deque[MatrixMessage]

        # FIXME Don't set insecure
        self.set_insecure()

    # TODO remove this
    def set_insecure(self):
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE


def wrap_socket(server, fd):
    # type: (MatrixServer, int) -> None
    s = None  # type: socket.socket

    # TODO explain why these type gymnastics are needed
    tempSocket = socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM)

    if type(tempSocket) == socket._socket.socket:
        s = socket._socketobject(_sock=tempSocket)
    else:
        s = tempSocket

    try:
        ssl_socket = server.ssl_context.wrap_socket(s,
            server_hostname=server.address)  # type: ssl.SSLSocket
        return ssl_socket
    # TODO add the other relevant exceptions
    except ssl.SSLError as e:
        server_buffer_prnt(e)
        return None


def handleHttpResponse(message):
    # type: (MatrixMessage) -> None

    status_code = message.response.status

    # TODO handle error responses
    # TODO handle try again response
    if status_code == 200:
        # TODO json.loads can fail
        response = json.loads(message.response.body, encoding='utf-8')
        handleMatrixMessage(message.type, response)
    else:
        server_buffer_prnt("ERROR IN HTTP RESPONSE {status_code}".format(status_code=status_code))
        server_buffer_prnt(message.request.request)
        server_buffer_prnt(message.response.body)

    return

NICK_GROUP_HERE = "0|Here"
NICK_GROUP_AWAY = "1|Away"

def handle_room_info(room_info):
    def create_buffer(roomd_id, alias=None):
        if not alias:
            alias = "#{id}".format(id=room_id)

        buf = W.buffer_new(
            alias,
            "room_input_cb",
            "",
            "room_close_cb",
            ""
        )

        # TODO set the buffer type dynamically
        W.buffer_set(buf, "localvar_set_type", 'channel')
        W.buffer_set(buf, "type", 'formated')
        W.buffer_set(buf, "localvar_set_channel", alias)

        # TODO set the nick dynamically
        W.buffer_set(buf, "localvar_set_nick", 'poljar')

        W.buffer_set(buf, "localvar_set_server", "matrix.org")
        # W.buffer_set(buf, "title", "🔐")

        # TODO put this in a function
        short_name = name=alias.rsplit(":", 1)[0]
        W.buffer_set(buf, "short_name", short_name)

        CLIENT.buffers[room_id] = buf

    def handle_aliases(room_id, event):
        if room_id not in CLIENT.buffers:
            alias = event['content']['aliases'][-1]
            create_buffer(room_id, alias)

    def handle_members(room_id, event):
        if event['membership'] == 'join':
            try:
                buf = CLIENT.buffers[room_id]
            except KeyError:
                event_queue.append(event)
                return

            W.buffer_set(buf, "nicklist", "1")
            W.buffer_set(buf, "nicklist_display_groups", "0")
            # create nicklists for the current channel if they don't exist
            # if they do, use the existing pointer
            # TODO move this into the buffer creation
            here = W.nicklist_search_group(buf, '', NICK_GROUP_HERE)
            nick = event['content']['displayname']
            if not here:
                here = W.nicklist_add_group(
                    buf,
                    '',
                    NICK_GROUP_HERE,
                    "weechat.color.nicklist_group",
                    1
                )

            W.nicklist_add_nick(buf, here, nick, "", "", "", 1)

    def handle_room_state(state_events):
        for event in state_events:
            if event['type'] == 'm.room.aliases':
                handle_aliases(room_id, event)
            elif event['type'] == 'm.room.member':
                handle_members(room_id, event)
            elif event['type'] == 'm.room.message':
                message_queue.append(event)

    def handle_room_timeline(timeline_events):
        for event in timeline_events:
            if event['type'] == 'm.room.aliases':
                handle_aliases(room_id, event)

            elif event['type'] == 'm.room.member':
                handle_members(room_id, event)
            elif event['type'] == 'm.room.message':
                message_queue.append(event)

    def handle_text_message(room_id, event):
        msg = event['content']['body']

        # TODO put this in a function or lambda
        msg_author = event['sender'].rsplit(":", 1)[0][1:]

        data = "{author}\t{msg}".format(author=msg_author, msg=msg)

        event_id = event['event_id']
        event_id = "matrix_id_{id}".format(id=event_id)

        msg_age = event['unsigned']['age']
        t = time.time()
        t = int(t - (msg_age / 1000))
        buf = CLIENT.buffers[room_id]

        # TODO if this is an initial sync tag the messages as backlog
        tag = "nick_{a},{event_id},irc_privmsg,notify_message".format(
                a=msg_author, event_id=event_id)

        W.prnt_date_tags(buf, t, tag, data)

    for room_id, room in room_info['join'].iteritems():
        # TODO do we need these queues or can we just rename the buffer if and
        # when we get an alias dynamically?
        event_queue = deque()
        message_queue = deque()

        handle_room_state(room['state']['events'])
        handle_room_timeline(room['timeline']['events'])

        # The room doesn't have an alias, create it now using the room id
        if room_id not in CLIENT.buffers:
            create_buffer(room_id)

        # TODO we don't need a separate event/message queue here
        while event_queue:
            event = event_queue.popleft()

            if event['type'] == 'm.room.member':
                handle_members(room_id, event)
            else:
                assert("Wrong event type in event queue")

        while message_queue:
            event = message_queue.popleft()

            if event['type'] == 'm.room.message':
                if event['content']['msgtype'] == 'm.text':
                    handle_text_message(room_id, event)
                # TODO handle different content types here
                else:
                    server_buffer_prnt("Handling of content type {type} not implemented".format(type=event['content']['type']))


def handleMatrixMessage(messageType, matrixResponse):
    # type: (MessageType, Dict[Any, Any]) -> None

    if messageType is MessageType.LOGIN:
        CLIENT.access_token = matrixResponse["access_token"]
        message = generate_matrix_request(MessageType.SYNC, CLIENT.builder,
                                          CLIENT.access_token)
        send_or_queue(message)

    elif messageType is messageType.SYNC:
        next_batch = matrixResponse['next_batch']

        # we got the same batch again, nothing to do
        if next_batch == CLIENT.next_batch:
            return

        room_info = matrixResponse['rooms']
        handle_room_info(room_info)

        CLIENT.next_batch = next_batch

    else:
        server_buffer_prnt("Handling of message type {type} not implemented".format(type=messageType))


def generate_matrix_request(type, http_builder, access_token=None, room_id=None, data=None):
    # type: (MessageType, RequestBuilder, unicode, unicode, Dict[Any, Any]) -> MatrixMessage
    # TODO clean this up
    if type == MessageType.LOGIN:
        path = '/_matrix/client/r0/login'
        post_data = {"type": "m.login.password",
                     "user": 'example',
                     "password": 'wordpass'}

        request = CLIENT.builder.request(path, post_data)

        return MatrixMessage(MessageType.LOGIN, request, None)

    elif type == MessageType.SYNC:
        path = '/_matrix/client/r0/sync?access_token={access_token}'.format(access_token=access_token)

        if CLIENT.next_batch:
            path = path + '&since={next_batch}'.format(next_batch=CLIENT.next_batch)

        request = CLIENT.builder.request(path)

        return MatrixMessage(MessageType.SYNC, request, None)

    elif type == MessageType.POST_MSG:
        path = '/_matrix/client/r0/rooms/{room}/send/m.room.message?access_token={access_token}'.format(room=room_id, access_token=access_token)
        request = CLIENT.builder.request(path, data)

        return MatrixMessage(MessageType.POST_MSG, request, None)

    else:
        assert("Incorrect message type")
        return None


def matrix_login(server):
    # type: MatrixServer
    message = generate_matrix_request(MessageType.LOGIN, server.builder)
    send_or_queue(message)


def matrix_initial_sync():
    message = generate_matrix_request(MessageType.SYNC, CLIENT.builder,
                                      CLIENT.access_token)
    send_or_queue(message)


def send_or_queue(message):
    # type: (MatrixServer, MatrixMessage) -> None
    if not send(message):
        CLIENT.sendQueue.append(message)

def send(message):
    # type: (MatrixMessage) -> Bool

    request = message.request.request
    payload = message.request.payload

    try:
        CLIENT.socket.sendall(bytes(request, 'utf-8'))
        if payload:
            CLIENT.socket.sendall(bytes(payload, 'utf-8'))

        CLIENT.recieveQueue.append(message)
        return True

    except socket.error as e:
        disconnect()
        server_buffer_prnt(e)
        return False

@utf8_decode
def recieve_cb(data, fd):
    if not CLIENT.connected:
        server_buffer_prnt("NOT CONNECTED WHILE RECEIVING")
        # can this happen?
        # do reconnection
        pass

    while True:
        try:
            data = CLIENT.socket.recv(4096)
        # TODO add the other relevant exceptions
        except ssl.SSLWantReadError:
            break
        except socket.error as e:
            disconnect()

            # Queue the failed message for resending
            message = CLIENT.recieveQueue.popleft()
            CLIENT.sendQueue.appendleft(message)

            server_buffer_prnt(e)
            return

        if not data:
            server_buffer_prnt("No data while reading")
            disconnect()
            break

        recieved = len(data)  # type: int
        nParsed  = CLIENT.httpParser.execute(data, recieved)

        assert nParsed == recieved

        if CLIENT.httpParser.is_partial_body():
            CLIENT.httpBodyBuffer.append(CLIENT.httpParser.recv_body())

        if CLIENT.httpParser.is_message_complete():
            status = CLIENT.httpParser.get_status_code()
            headers = CLIENT.httpParser.get_headers()
            body = b"".join(CLIENT.httpBodyBuffer)

            message = CLIENT.recieveQueue.popleft()
            message.response = HttpResponse(status, headers, body)

            # Message done, reset the parser state.
            CLIENT.httpParser = HttpParser()
            CLIENT.httpBodyBuffer = []

            handleHttpResponse(message)
            break

    return W.WEECHAT_RC_OK


def disconnect():
    if CLIENT.fd_hook:
        W.unhook(CLIENT.fd_hook)

    # if CLIENT.timer_hook:
    #     W.unhook(CLIENT.timer_hook)

    CLIENT.fd_hook    = None
    CLIENT.timer_hook = None
    CLIENT.socket     = None
    CLIENT.connected  = False

    server_buffer_prnt("Disconnected")


def server_buffer_prnt(string):
    # type: (unicode) -> None
    assert(CLIENT.server_buffer)
    b = CLIENT.server_buffer
    t = int(time.time())
    W.prnt_date_tags(b, t, "", string)


def create_server_buffer(server):
    # type: (MatrixServer) -> None
    server.server_buffer = W.buffer_new(
        server.name,
        "server_buffer_cb",
        "",
        "",
        ""
    )

    # TODO the nick and server name should be dynamic
    W.buffer_set(CLIENT.server_buffer, "localvar_set_type", 'server')
    W.buffer_set(CLIENT.server_buffer, "localvar_set_nick", 'poljar')
    W.buffer_set(CLIENT.server_buffer, "localvar_set_server", server.name)
    W.buffer_set(CLIENT.server_buffer, "localvar_set_channel", server.name)

    # TODO this should go into the matrix config section
    if W.config_string(W.config_get('irc.look.server_buffer')) == 'merge_with_core':
        W.buffer_merge(CLIENT.server_buffer, W.buffer_search_main())


# TODO if we're reconnecting we should retry even if there was an error on the
# socket creation
@utf8_decode
def connect_cb(data, status, gnutls_rc, sock, error, ip_address):
    status_value = int(status)  # type: long
    server = SERVERS[data]
    print(server.name)

    if status_value == W.WEECHAT_HOOK_CONNECT_OK:
        fd = int(sock)  # type: int
        socket = wrap_socket(server, fd)

        if socket:
            server.socket = socket
            fd = server.socket.fileno()
            hook = W.hook_fd(fd, 1, 0, 0, "recieve_cb", server.name)

            server.fd_hook        = hook
            server.connected      = True
            server.connecting     = False
            server.reconnectCount = 0

            server_buffer_prnt("Connected")

            if not server.access_token:
                matrix_login(server)
        else:
            reconnect_cmd(None, None, None)

    elif status_value == W.WEECHAT_HOOK_CONNECT_ADDRESS_NOT_FOUND:
        W.prnt("", '{address} not found'.format(address=ip_address))

    elif status_value == W.WEECHAT_HOOK_CONNECT_IP_ADDRESS_NOT_FOUND:
        W.prnt("", 'IP address not found')

    elif status_value == W.WEECHAT_HOOK_CONNECT_CONNECTION_REFUSED:
        W.prnt("", 'Connection refused')

    elif status_value == W.WEECHAT_HOOK_CONNECT_PROXY_ERROR:
        W.prnt("", 'Proxy fails to establish connection to server')

    elif status_value == W.WEECHAT_HOOK_CONNECT_LOCAL_HOSTNAME_ERROR:
        W.prnt("", 'Unable to set local hostname')

    elif status_value == W.WEECHAT_HOOK_CONNECT_GNUTLS_INIT_ERROR:
        W.prnt("", 'TLS init error')

    elif status_value == W.WEECHAT_HOOK_CONNECT_GNUTLS_HANDSHAKE_ERROR:
        W.prnt("", 'TLS Handshake failed')

    elif status_value == W.WEECHAT_HOOK_CONNECT_MEMORY_ERROR:
        W.prnt("", 'Not enough memory')

    elif status_value == W.WEECHAT_HOOK_CONNECT_TIMEOUT:
        W.prnt("", 'Timeout')

    elif status_value == W.WEECHAT_HOOK_CONNECT_SOCKET_ERROR:
        W.prnt("", 'Unable to create socket')
    else:
        W.prnt("", 'Unexpected error: {status}'.format(status=status_value))

    return W.WEECHAT_RC_OK


def reconnect_cmd(data, buffer, args):
    timeout = CLIENT.reconnectCount * 5 * 1000

    if timeout > 0:
        server_buffer_prnt("Reconnecting in {timeout} seconds.".format(timeout=timeout / 1000))
        W.hook_timer(timeout, 0, 1, "reconnect_cb", "")
    else:
        connect_cmd()

    CLIENT.reconnectCount += 1

    return W.WEECHAT_RC_OK


@utf8_decode
def reconnect_cb(data, remaining):
    connect_cmd()
    return W.WEECHAT_RC_OK


def connect_cmd(server):
    # type: (MatrixServer) -> int
    if not server.server_buffer:
        create_server_buffer(server)

    server.timer_hook = W.hook_timer(
        1 * 1000,
        0,
        0,
        "matrix_timer_cb",
        server.name
    )

    W.hook_connect("", server.address, server.port, 1, 0, "",
                   "connect_cb", server.name)

    CLIENT.connecting = True
    return W.WEECHAT_RC_OK


@utf8_decode
def room_input_cb(data, buffer, input_data):
    room_id = list(CLIENT.buffers.keys())[list(CLIENT.buffers.values()).index(buffer)]
    body = {"msgtype": "m.text", "body": input_data}
    message = generate_matrix_request(MessageType.POST_MSG, CLIENT.builder,
                                      data=body, room_id=room_id,
                                      access_token=CLIENT.access_token)
    send_or_queue(message)
    return W.WEECHAT_RC_OK


@utf8_decode
def room_close_cb(data, buffer):
    W.prnt("", "Buffer '%s' will be closed!" %
           W.buffer_get_string(buffer, "name"))
    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_timer_cb(data, remaining_calls):
    if not CLIENT.connected:
        if not CLIENT.connecting:
            server_buffer_prnt("Reconnecting timeout blaaaa")
            reconnect_cmd(None, None, None)
        return W.WEECHAT_RC_OK

    while CLIENT.sendQueue:
        message = CLIENT.sendQueue.popleft()

        if not send(message):
            # We got an error while sending the last message return the message
            # to the queue and exit the loop
            CLIENT.sendQueue.appendleft(message)
            break

    for message in CLIENT.MessageQueue:
        server_buffer_prnt("Handling message: {message}".format(message=message))

    # TODO don't send this out here, if a SYNC fails for some reason (504 try
    # again!) we'll hammer the server unnecessarily
    if CLIENT.next_batch:
        message = generate_matrix_request(MessageType.SYNC, CLIENT.builder,
                                          CLIENT.access_token)
        CLIENT.sendQueue.append(message)

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_config_reload_cb(data, config_file):
    return W.WEECHAT_RC_OK


def init_matrix_config():
    config_file = W.config_new("matrix", "matrix_config_reload_cb", "")
    # TODO create config sections and config values

    section = W.config_new_section(config_file, "color", 0, 0, "", "", "", "",
        "", "", "", "", "", "")

    # TODO color options

    section = W.config_new_section(config_file, "look", 0, 0, "", "", "", "",
        "", "", "", "", "", "")

    # TODO look options

    section = W.config_new_section(config_file, "network", 0, 0, "", "", "", "",
        "", "", "", "", "", "")

    # TODO network options

    section = W.config_new_section(config_file, "server_default", 0, 0, "", "",
        "", "", "", "", "", "", "", "")

    W.config_new_option(config_file, section, "autoconnect", "boolean",
        "Automatically connect to the matrix server when Weechat is starting",
        "", 0, 0, "off", "off", 0,
        "", "",
        "", "",
        "", "")

    W.config_new_option(config_file, section, "address", "string",
        "Server address to connect to.",
        "", 0, 0, "localhost", "localhost", 1,
        "", "",
        "", "",
        "", "")

    W.config_new_option(config_file, section, "port", "integer",
        "Port of the server to connect to",
        "", 0, 65535, "8448", "8448", 0,
        "", "",
        "", "",
        "", "")

    W.config_new_option(config_file, section, "user", "string",
        "Log in user ",
        "", 0, 0, "example", "example", 1,
        "", "",
        "", "",
        "", "")

    W.config_new_option(config_file, section, "password", "string",
        "Password",
        "", 0, 0, "wordpass", "wordpass", 1,
        "", "",
        "", "",
        "", "")

    # TODO per server section and options

    return config_file


def read_matrix_config():
    # type: None -> Bool
    rc = W.config_read(CONFIG)
    if rc == weechat.WEECHAT_CONFIG_READ_OK:
        return True
    elif rc == weechat.WEECHAT_CONFIG_READ_MEMORY_ERROR:
        return False
    elif rc == weechat.WEECHAT_CONFIG_READ_FILE_NOT_FOUND:
        return True


@utf8_decode
def unload_cb():
    for section in ["network", "look", "color", "server_default"]:
        s = W.config_search_section(CONFIG, section)
        W.config_section_free_options(s)
        W.config_section_free(s)

    W.config_free(CONFIG)

    return W.WEECHAT_RC_OK


def get_boolean(config, section, key):
    s = W.config_search_section(config, section)
    option = W.config_search_option(config, s, key)
    return W.config_boolean(option)


@utf8_decode
def matrix_command_cb(data, buffer, args):
    a = args.split(' ', 1)

    command, args = a[0], a[1:]

    if command == 'connect':
        if not args:
            connect_cmd()
    else:
        print("Unknown command")

    return W.WEECHAT_RC_OK


def create_servers():
    pass


if __name__ == "__main__":
    W = WeechatWrapper(weechat)

    if W.register(WEECHAT_SCRIPT_NAME,
                  WEECHAT_SCRIPT_AUTHOR,
                  WEECHAT_SCRIPT_VERSION,
                  WEECHAT_SCRIPT_LICENSE,
                  WEECHAT_SCRIPT_DESCRIPTION,
                  'unload_cb',
                  ''):

        # TODO if this fails we should abort and unload the script.
        CONFIG = init_matrix_config()
        read_matrix_config()

        create_servers()
        CLIENT = MatrixServer('matrix.org', 'localhost', 8448)

        SERVERS['matrix.org'] = CLIENT

        subcommands = ['connect', 'disconnect']

        W.hook_command(
            # Command name and description
            'matrix', 'Matrix chat protocol',
            # Usage
            '[command] [command options]',
            # Description of arguments
            'Commands:\n' +
            '\n'.join(subcommands) +
            '\nUse /matrix help [command] to find out more\n',
            # Completions
            '|'.join(subcommands),
            # Function name
            'matrix_command_cb', '')

        if (get_boolean(CONFIG, "server_default", "autoconnect")):
            connect_cmd(CLIENT)
