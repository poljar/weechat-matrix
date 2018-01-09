# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import json
import socket
import ssl
import time

# pylint: disable=redefined-builtin
from builtins import bytes

from collections import deque, Mapping, Iterable, namedtuple
from enum import Enum, unique
from functools import wraps

# pylint: disable=unused-import
from typing import (List, Set, Dict, Tuple, Text, Optional, AnyStr, Deque, Any)

from http_parser.pyparser import HttpParser

# pylint: disable=import-error
import weechat

WEECHAT_SCRIPT_NAME        = "matrix"                              # type: unicode
WEECHAT_SCRIPT_DESCRIPTION = "matrix chat plugin"                  # type: unicode
WEECHAT_SCRIPT_AUTHOR      = "Damir Jelić <poljar@termina.org.uk>" # type: unicode
WEECHAT_SCRIPT_VERSION     = "0.1"                                 # type: unicode
WEECHAT_SCRIPT_LICENSE     = "MIT"                                 # type: unicode

MATRIX_API_PATH = "/_matrix/client/r0"  # type: unicode

SERVERS = dict()  # type: Dict[unicode, MatrixServer]
CONFIG  = None    # type: weechat.config

NICK_GROUP_HERE = "0|Here"


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
    return data


def utf8_decode(function):
    """
    Decode all arguments from byte strings to unicode strings. Use this for
    functions called from outside of this script, e.g. callbacks from weechat.
    """
    @wraps(function)
    def wrapper(*args, **kwargs):
        return function(*decode_from_utf8(args), **decode_from_utf8(kwargs))
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
        return decode_from_utf8(orig_attr)

    # Ensure all lines sent to weechat specify a prefix. For lines after the
    # first, we want to disable the prefix, which is done by specifying a space.
    def prnt_date_tags(self, buffer, date, tags, message):
        message = message.replace("\n", "\n \t")
        return self.wrap_for_utf8(self.wrapped_class.prnt_date_tags)(
            buffer,
            date,
            tags,
            message
        )


@unique
class MessageType(Enum):
    LOGIN    = 0
    SYNC     = 1
    POST_MSG = 2


@unique
class RequestType(Enum):
    GET    = 0
    POST   = 1
    PUT    = 2
    DELETE = 3


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

            post          = 'POST {location} HTTP/1.1'.format(
                location=location
            )

            type_header   = 'Content-Type: application/x-www-form-urlencoded'
            length_header = 'Content-Length: {length}'.format(
                length=len(json_data)
            )

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
    def __init__(self):
        # type: () -> None
        self.access_token = ""   # type: unicode
        self.next_batch = ""     # type: unicode
        self.rooms = {}          # type: Dict[unicode, MatrixRoom]


class MatrixRoom:
    def __init__(self, room_id, join_rule, alias=None):
        # type: (unicode, unicode, unicode) -> None
        self.room_id = room_id      # type: unicode
        self.alias   = alias        # type: unicode
        self.join_rule = join_rule  # type: unicode


@utf8_decode
def server_config_change_cb(server_name, option):
    server = SERVERS[server_name]
    option_name = None

    # The function config_option_get_string() is used to get differing
    # properties from a config option, sadly it's only available in the plugin
    # API of weechat.
    # TODO we already have a function to get a key from a value out of a dict
    for name, server_option in server.options.items():
        if server_option == option:
            option_name = name
            break

    if not option_name:
        # TODO print error here, can this happen?
        return 0

    if option_name == "address":
        value = W.config_string(option)
        server.address = value
    elif option_name == "autoconnect":
        value = W.config_boolean(option)
        server.autoconnect = value
    elif option_name == "port":
        value = W.config_integer(option)
        server.port = value
    elif option_name == "username":
        value = W.config_string(option)
        server.user = value
    elif option_name == "password":
        value = W.config_string(option)
        server.password = value
    else:
        pass

    return 1


class MatrixServer:
    # pylint: disable=too-many-instance-attributes
    def __init__(self, name, config_file):
        # type: (unicode, weechat.config) -> None
        self.name            = name     # type: unicode
        self.address         = ""       # type: unicode
        self.port            = 8448     # type: int
        self.options         = dict()   # type: Dict[unicode, weechat.config]

        self.user            = ""       # type: unicode
        self.password        = ""       # type: unicode

        self.buffers         = dict()   # type: Dict[unicode, weechat.buffer]
        self.server_buffer   = None     # type: weechat.buffer
        self.fd_hook         = None     # type: weechat.hook
        self.timer_hook      = None     # type: weechat.hook

        self.autoconnect     = False                         # type: bool
        self.connected       = False                         # type: bool
        self.connecting      = False                         # type: bool
        self.reconnect_count = 0                             # type: int
        self.socket          = None                          # type: ssl.SSLSocket
        self.ssl_context     = ssl.create_default_context()  # type: ssl.SSLContext

        self.access_token    = None                          # type: unicode
        self.next_batch      = None                          # type: unicode

        # TODO this should be made stateless
        host_string = ':'.join([self.address,
                                str(self.port)])         # type: unicode
        self.builder     = RequestBuilder(host_string)   # type: RequestBuilder

        self.http_parser = HttpParser()                  # type: HttpParser
        self.http_buffer = []                            # type: List[bytes]

        # Queue of messages we need to send off.
        self.send_queue = deque()  # type: Deque[MatrixMessage]
        # Queue of messages we send off and are waiting a response for
        self.receive_queue = deque()  # type: Deque[MatrixMessage]
        self.message_queue = deque()  # type: Deque[MatrixMessage]

        self._create_options(config_file)

        # FIXME Don't set insecure
        self._set_insecure()

    # TODO remove this
    def _set_insecure(self):
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

    def _create_options(self, config_file):
        option = namedtuple(
            'Option', [
                'name',
                'type',
                'string_values',
                'min',
                'max',
                'value',
                'description'
            ])

        options = [
            option(
                'autoconnect', 'boolean', '', 0, 0, 'off',
                (
                    "Automatically connect to the matrix server when Weechat "
                    "is starting"
                )
            ),
            option(
                'address', 'string', '', 0, 0, '',
                "Hostname or IP address for the server"
            ),
            option(
                'port', 'integer', '', 0, 65535, '8448',
                "Port for the server"
            ),
            option(
                'username', 'string', '', 0, 0, '',
                "Username to use on server"
            ),
            option(
                'password', 'string', '', 0, 0, '',
                "Password for server"
            ),
        ]

        section = W.config_search_section(config_file, 'server')

        for option in options:
            option_name = "{server}.{option}".format(
                server=self.name, option=option.name)

            self.options[option.name] = W.config_new_option(
                config_file, section, option_name,
                option.type, option.description, option.string_values,
                option.min, option.max, option.value, option.value, 0, "",
                "", "server_config_change_cb", self.name, "", "")


def wrap_socket(server, file_descriptor):
    # type: (MatrixServer, int) -> socket.socket
    sock = None  # type: socket.socket

    temp_socket = socket.fromfd(
        file_descriptor,
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    # TODO explain why these type gymnastics are needed
    # pylint: disable=protected-access
    if isinstance(temp_socket, socket._socket.socket):
        # pylint: disable=no-member
        sock = socket._socketobject(_sock=temp_socket)
    else:
        sock = temp_socket

    try:
        ssl_socket = server.ssl_context.wrap_socket(
            sock,
            server_hostname=server.address)  # type: ssl.SSLSocket

        return ssl_socket
    # TODO add the other relevant exceptions
    except ssl.SSLError as error:
        server_buffer_prnt(server, str(error))
        return None


def handle_http_response(server, message):
    # type: (MatrixServer, MatrixMessage) -> None

    status_code = message.response.status

    # TODO handle error responses
    # TODO handle try again response
    if status_code == 200:
        # TODO json.loads can fail
        response = json.loads(message.response.body, encoding='utf-8')
        handle_matrix_message(server, message.type, response)
    else:
        server_buffer_prnt(
            server,
            "ERROR IN HTTP RESPONSE {status_code}".format(
                status_code=status_code))

        server_buffer_prnt(server, message.request.request)
        server_buffer_prnt(server, message.response.body)

    return


def handle_room_info(server, room_info):
    # type: (MatrixServer, Dict) -> None
    def create_buffer(roomd_id, alias=None):
        if not alias:
            alias = "#{id}".format(id=room_id)

        buf = W.buffer_new(
            alias,
            "room_input_cb",
            server.name,
            "room_close_cb",
            server.name
        )

        # TODO set the buffer type dynamically
        W.buffer_set(buf, "localvar_set_type", 'channel')
        W.buffer_set(buf, "type", 'formated')
        W.buffer_set(buf, "localvar_set_channel", alias)

        # TODO set the nick dynamically
        W.buffer_set(buf, "localvar_set_nick", 'poljar')

        W.buffer_set(buf, "localvar_set_server", "matrix.org")

        # TODO put this in a function
        short_name = alias.rsplit(":", 1)[0]
        W.buffer_set(buf, "short_name", short_name)

        server.buffers[room_id] = buf

    def handle_aliases(room_id, event):
        if room_id not in server.buffers:
            alias = event['content']['aliases'][-1]
            create_buffer(room_id, alias)

    def handle_members(room_id, event):
        if event['membership'] == 'join':
            try:
                buf = server.buffers[room_id]
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
        now = time.time()
        msg_date = int(now - (msg_age / 1000))
        buf = server.buffers[room_id]

        # TODO if this is an initial sync tag the messages as backlog
        tag = "nick_{a},{event_id},irc_privmsg,notify_message".format(
            a=msg_author, event_id=event_id)

        W.prnt_date_tags(buf, msg_date, tag, data)

    for room_id, room in room_info['join'].iteritems():
        # TODO do we need these queues or can we just rename the buffer if and
        # when we get an alias dynamically?
        event_queue   = deque()  # type: Deque[Dict]
        message_queue = deque()  # type: Deque[Dict]

        handle_room_state(room['state']['events'])
        handle_room_timeline(room['timeline']['events'])

        # The room doesn't have an alias, create it now using the room id
        if room_id not in server.buffers:
            create_buffer(room_id)

        # TODO we don't need a separate event/message queue here
        while event_queue:
            event = event_queue.popleft()

            if event['type'] == 'm.room.member':
                handle_members(room_id, event)
            else:
                assert "Wrong event type in event queue"

        while message_queue:
            event = message_queue.popleft()

            if event['type'] == 'm.room.message':
                # TODO print out that there was an redacted message here
                if 'redacted_by' in event['unsigned']:
                    continue

                if event['content']['msgtype'] == 'm.text':
                    handle_text_message(room_id, event)
                # TODO handle different content types here
                else:
                    message = (
                        "Handling of content type {type} not implemented"
                    ).format(type=event['content']['type'])

                    server_buffer_prnt(server, message)


def handle_matrix_message(server, message_type, response):
    # type: (MatrixServer, MessageType, Dict[Any, Any]) -> None

    if message_type is MessageType.LOGIN:
        server.access_token = response["access_token"]
        message = generate_matrix_request(server, MessageType.SYNC)
        send_or_queue(server, message)

    elif message_type is MessageType.SYNC:
        next_batch = response['next_batch']

        # we got the same batch again, nothing to do
        if next_batch == server.next_batch:
            return

        room_info = response['rooms']
        handle_room_info(server, room_info)

        server.next_batch = next_batch

    else:
        server_buffer_prnt(
            server,
            "Handling of message type {type} not implemented".format(
                type=message_type))


def generate_matrix_request(server, message_type, room_id=None, data=None):
    # type: (MatrixServer, MessageType, unicode, Dict[Any, Any]) -> MatrixMessage
    # TODO clean this up
    if message_type == MessageType.LOGIN:
        path = '/_matrix/client/r0/login'
        post_data = {"type": "m.login.password",
                     "user": server.user,
                     "password": server.password}

        request = server.builder.request(path, post_data)

        return MatrixMessage(MessageType.LOGIN, request, None)

    elif message_type == MessageType.SYNC:
        path = '/_matrix/client/r0/sync?access_token={access_token}'.format(
            access_token=server.access_token)

        if server.next_batch:
            path = path + '&since={next_batch}'.format(
                next_batch=server.next_batch)

        request = server.builder.request(path)

        return MatrixMessage(MessageType.SYNC, request, None)

    elif message_type == MessageType.POST_MSG:
        path = '/_matrix/client/r0/rooms/{room}/send/m.room.message?access_token={access_token}'.format(room=room_id, access_token=server.access_token)
        request = server.builder.request(path, data)

        return MatrixMessage(MessageType.POST_MSG, request, None)

    else:
        assert "Incorrect message type"
        return None


def matrix_login(server):
    # type: (MatrixServer) -> None
    message = generate_matrix_request(server, MessageType.LOGIN)
    send_or_queue(server, message)


def send_or_queue(server, message):
    # type: (MatrixServer, MatrixMessage) -> None
    if not send(server, message):
        server.send_queue.append(message)


def send(server, message):
    # type: (MatrixServer, MatrixMessage) -> bool

    request = message.request.request
    payload = message.request.payload

    try:
        server.socket.sendall(bytes(request, 'utf-8'))
        if payload:
            server.socket.sendall(bytes(payload, 'utf-8'))

        server.receive_queue.append(message)
        return True

    except socket.error as error:
        disconnect(server)
        server_buffer_prnt(server, str(error))
        return False


@utf8_decode
def receive_cb(server_name, file_descriptor):
    server = SERVERS[server_name]

    if not server.connected:
        server_buffer_prnt(server, "NOT CONNECTED WHILE RECEIVING")
        # can this happen?
        # do reconnection

    while True:
        try:
            data = server.socket.recv(4096)
        # TODO add the other relevant exceptions
        except ssl.SSLWantReadError:
            break
        except socket.error as error:
            disconnect(server)

            # Queue the failed message for resending
            message = server.receive_queue.popleft()
            server.send_queue.appendleft(message)

            server_buffer_prnt(server, error)
            return W.WEECHAT_RC_OK

        if not data:
            server_buffer_prnt(server, "No data while reading")
            disconnect(server)
            break

        received = len(data)  # type: int
        parsed_bytes = server.http_parser.execute(data, received)

        assert parsed_bytes == received

        if server.http_parser.is_partial_body():
            server.http_buffer.append(server.http_parser.recv_body())

        if server.http_parser.is_message_complete():
            status = server.http_parser.get_status_code()
            headers = server.http_parser.get_headers()
            body = b"".join(server.http_buffer)

            message = server.receive_queue.popleft()
            message.response = HttpResponse(status, headers, body)

            # Message done, reset the parser state.
            server.http_parser = HttpParser()
            server.http_buffer = []

            handle_http_response(server, message)
            break

    return W.WEECHAT_RC_OK


def disconnect(server):
    # type: (MatrixServer) -> None
    if server.fd_hook:
        W.unhook(server.fd_hook)

    server.fd_hook    = None
    server.socket     = None
    server.connected  = False

    server_buffer_prnt(server, "Disconnected")


def server_buffer_prnt(server, string):
    # type: (MatrixServer, unicode) -> None
    assert server.server_buffer
    buffer = server.server_buffer
    now = int(time.time())
    W.prnt_date_tags(buffer, now, "", string)


def create_server_buffer(server):
    # type: (MatrixServer) -> None
    server.server_buffer = W.buffer_new(
        server.name,
        "server_buffer_cb",
        server.name,
        "",
        ""
    )

    # TODO the nick and server name should be dynamic
    W.buffer_set(server.server_buffer, "localvar_set_type", 'server')
    W.buffer_set(server.server_buffer, "localvar_set_nick", 'poljar')
    W.buffer_set(server.server_buffer, "localvar_set_server", server.name)
    W.buffer_set(server.server_buffer, "localvar_set_channel", server.name)

    # TODO this should go into the matrix config section
    if W.config_string(W.config_get('irc.look.server_buffer')) == 'merge_with_core':
        W.buffer_merge(server.server_buffer, W.buffer_search_main())


# TODO if we're reconnecting we should retry even if there was an error on the
# socket creation
@utf8_decode
def connect_cb(data, status, gnutls_rc, sock, error, ip_address):
    # pylint: disable=too-many-arguments,too-many-branches
    status_value = int(status)  # type: int
    server = SERVERS[data]

    if status_value == W.WEECHAT_HOOK_CONNECT_OK:
        file_descriptor = int(sock)  # type: int
        sock = wrap_socket(server, file_descriptor)

        if sock:
            server.socket = sock
            hook = W.hook_fd(
                server.socket.fileno(),
                1, 0, 0,
                "receive_cb",
                server.name
            )

            server.fd_hook         = hook
            server.connected       = True
            server.connecting      = False
            server.reconnect_count = 0

            server_buffer_prnt(server, "Connected")

            if not server.access_token:
                matrix_login(server)
        else:
            reconnect(server)

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


def reconnect(server):
    # type: (MatrixServer) -> None
    # TODO this needs some more work, do we want a reconnecting flag?
    server.connecting = True
    timeout = server.reconnect_count * 5 * 1000

    if timeout > 0:
        server_buffer_prnt(
            server,
            "Reconnecting in {timeout} seconds.".format(
                timeout=timeout / 1000))
        W.hook_timer(timeout, 0, 1, "reconnect_cb", server.name)
    else:
        connect(server)

    server.reconnect_count += 1


@utf8_decode
def reconnect_cb(server_name, remaining):
    server = SERVERS[server_name]
    connect(server)

    return W.WEECHAT_RC_OK


def connect(server):
    # type: (MatrixServer) -> bool
    if not server.address or not server.port:
        message = "{prefix}Server address or port not set".format(
            prefix=W.prefix("error"))
        W.prnt("", message)
        return False

    if not server.user or not server.password:
        message = "{prefix}User or password not set".format(
            prefix=W.prefix("error"))
        W.prnt("", message)
        return False

    if server.connected:
        return True

    if not server.server_buffer:
        create_server_buffer(server)

    if not server.timer_hook:
        server.timer_hook = W.hook_timer(
            1 * 1000,
            0,
            0,
            "matrix_timer_cb",
            server.name
        )

    W.hook_connect("", server.address, server.port, 1, 0, "",
                   "connect_cb", server.name)

    return W.WEECHAT_RC_OK


@utf8_decode
def room_input_cb(server_name, buffer, input_data):
    server = SERVERS[server_name]

    if not server.connected:
        message = "{prefix}you are not connected to the server".format(
            prefix=W.prefix("error"))
        W.prnt(buffer, message)
        return W.WEECHAT_RC_ERROR

    # TODO put this in a function
    room_id = list(server.buffers.keys())[list(server.buffers.values()).index(buffer)]
    body = {"msgtype": "m.text", "body": input_data}
    message = generate_matrix_request(server, MessageType.POST_MSG,
                                      data=body, room_id=room_id)
    send_or_queue(server, message)
    return W.WEECHAT_RC_OK


@utf8_decode
def room_close_cb(data, buffer):
    W.prnt("", "Buffer '%s' will be closed!" %
           W.buffer_get_string(buffer, "name"))
    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_timer_cb(server_name, remaining_calls):
    server = SERVERS[server_name]

    if not server.connected:
        if not server.connecting:
            server_buffer_prnt(server, "Reconnecting timeout blaaaa")
            reconnect(server)
        return W.WEECHAT_RC_OK

    while server.send_queue:
        message = server.send_queue.popleft()

        if not send(server, message):
            # We got an error while sending the last message return the message
            # to the queue and exit the loop
            server.send_queue.appendleft(message)
            break

    for message in server.message_queue:
        server_buffer_prnt(
            server,
            "Handling message: {message}".format(message=message))

    # TODO don't send this out here, if a SYNC fails for some reason (504 try
    # again!) we'll hammer the server unnecessarily, send it out after a
    # successful sync or after a 504 sync with a proper timeout
    if server.next_batch:
        message = generate_matrix_request(server, MessageType.SYNC)
        server.send_queue.append(message)

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_config_reload_cb(data, config_file):
    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_config_server_read_cb(
        data, config_file, section,
        option_name, value
):

    return_code = W.WEECHAT_CONFIG_OPTION_SET_ERROR

    if option_name:
        server_name, option = option_name.rsplit('.', 1)
        server = None

        if server_name in SERVERS:
            server = SERVERS[server_name]
        else:
            server = MatrixServer(server_name, config_file)
            SERVERS[server.name] = server

        # Ignore invalid options
        if option in server.options:
            return_code = W.config_option_set(server.options[option], value, 1)

    # TODO print out error message in case of erroneous return_code

    return return_code


@utf8_decode
def matrix_config_server_write_cb(data, config_file, section_name):
    if not W.config_write_line(config_file, section_name, ""):
        return W.WECHAT_CONFIG_WRITE_ERROR

    for server in SERVERS.values():
        for option in server.options.values():
            if not W.config_write_option(config_file, option):
                return W.WECHAT_CONFIG_WRITE_ERROR

    return W.WEECHAT_CONFIG_WRITE_OK


def init_matrix_config():
    config_file = W.config_new("matrix", "matrix_config_reload_cb", "")

    section = W.config_new_section(config_file, "color", 0, 0, "", "", "", "",
                                   "", "", "", "", "", "")

    # TODO color options

    section = W.config_new_section(config_file, "look", 0, 0, "", "", "", "",
                                   "", "", "", "", "", "")

    # TODO look options

    section = W.config_new_section(config_file, "network", 0, 0, "", "", "",
                                   "", "", "", "", "", "", "")

    # TODO network options

    W.config_new_section(
        config_file, "server",
        0, 0,
        "matrix_config_server_read_cb",
        "",
        "matrix_config_server_write_cb",
        "", "", "", "", "", "", ""
    )

    return config_file


def read_matrix_config():
    # type: () -> bool
    return_code = W.config_read(CONFIG)
    if return_code == weechat.WEECHAT_CONFIG_READ_OK:
        return True
    elif return_code == weechat.WEECHAT_CONFIG_READ_MEMORY_ERROR:
        return False
    elif return_code == weechat.WEECHAT_CONFIG_READ_FILE_NOT_FOUND:
        return True
    return False


@utf8_decode
def matrix_unload_cb():
    for section in ["network", "look", "color", "server"]:
        section_pointer = W.config_search_section(CONFIG, section)
        W.config_section_free_options(section_pointer)
        W.config_section_free(section_pointer)

    W.config_free(CONFIG)

    return W.WEECHAT_RC_OK


def check_server_existence(server_name, servers):
    if server_name not in servers:
        message = "{prefix}matrix: No such server: {server} found".format(
            prefix=W.prefix("error"), server=server_name)
        W.prnt("", message)
        return False
    return True


def matrix_command_help(args):
    for command in args:
        message = ""

        if command == "connect":
            message = ("{delimiter_color}[{ncolor}matrix{delimiter_color}]  "
                       "{ncolor}{cmd_color}/connect{ncolor} "
                       "<server-name> [<server-name>...]"
                       "\n\n"
                       "connect to Matrix server(s)"
                       "\n\n"
                       "server-name: server to connect to"
                       "(internal name)").format(
                           delimiter_color=W.color("chat_delimiters"),
                           cmd_color=W.color("chat_buffer"),
                           ncolor=W.color("reset"))

        elif command == "disconnect":
            message = ("{delimiter_color}[{ncolor}matrix{delimiter_color}]  "
                       "{ncolor}{cmd_color}/disconnect{ncolor} "
                       "<server-name> [<server-name>...]"
                       "\n\n"
                       "disconnect from Matrix server(s)"
                       "\n\n"
                       "server-name: server to disconnect"
                       "(internal name)").format(
                           delimiter_color=W.color("chat_delimiters"),
                           cmd_color=W.color("chat_buffer"),
                           ncolor=W.color("reset"))

        elif command == "reconnect":
            message = ("{delimiter_color}[{ncolor}matrix{delimiter_color}]  "
                       "{ncolor}{cmd_color}/reconnect{ncolor} "
                       "<server-name> [<server-name>...]"
                       "\n\n"
                       "reconnect to Matrix server(s)"
                       "\n\n"
                       "server-name: server to reconnect"
                       "(internal name)").format(
                           delimiter_color=W.color("chat_delimiters"),
                           cmd_color=W.color("chat_buffer"),
                           ncolor=W.color("reset"))

        elif command == "server":
            message = ("{delimiter_color}[{ncolor}matrix{delimiter_color}]  "
                       "{ncolor}{cmd_color}/server{ncolor} "
                       "add <server-name> <hostname>[:<port>]"
                       "\n                  "
                       "delete|list|listfull <server-name>"
                       "\n\n"
                       "list, add, or remove Matrix servers"
                       "\n\n"
                       "       list: list servers (without argument, this "
                       "list is displayed)\n"
                       "   listfull: list servers with detailed info for each "
                       "server\n"
                       "        add: add a new server\n"
                       "     delete: delete a server\n"
                       "server-name: server to reconnect (internal name)\n"
                       "   hostname: name or IP address of server\n"
                       "       port: port of server (default: 8448)\n"
                       "\n"
                       "Examples:"
                       "\n  /server listfull"
                       "\n  /server add matrix matrix.org:80"
                       "\n  /server del matrix").format(
                           delimiter_color=W.color("chat_delimiters"),
                           cmd_color=W.color("chat_buffer"),
                           ncolor=W.color("reset"))

        elif command == "help":
            message = ("{delimiter_color}[{ncolor}matrix{delimiter_color}]  "
                       "{ncolor}{cmd_color}/help{ncolor} "
                       "<matrix-command> [<matrix-command>...]"
                       "\n\n"
                       "display help about Matrix commands"
                       "\n\n"
                       "matrix-command: a Matrix command name"
                       "(internal name)").format(
                           delimiter_color=W.color("chat_delimiters"),
                           cmd_color=W.color("chat_buffer"),
                           ncolor=W.color("reset"))

        else:
            message = ("{prefix}matrix: No help available, \"{command}\" "
                       "is not a matrix command").format(
                           prefix=W.prefix("error"),
                           command=command)

        W.prnt("", "")
        W.prnt("", message)


def matrix_server_command(command, args):
    def get_value_string(value, default_value):
        if value == default_value:
            if not value:
                value = "''"
            value_string = "  ({value})".format(value=value)
        else:
            value_string = "{color}{value}{ncolor}".format(
                color=W.color("chat_value"),
                value=value,
                ncolor=W.color("reset"))

        return value_string

    def list_servers(args):
        if SERVERS:
            W.prnt("", "\nAll matrix servers:")
            for server in SERVERS:
                W.prnt("", "    {color}{server}".format(
                    color=W.color("chat_server"),
                    server=server
                ))

    def list_full_servers(args):
        for server_name in args:
            if server_name not in SERVERS:
                continue

            server = SERVERS[server_name]
            connected = ""

            W.prnt("", "")

            if server.connected:
                connected = "connected"
            else:
                connected = "not connected"

            message = ("Server: {server_color}{server}{delimiter_color}"
                       " [{ncolor}{connected}{delimiter_color}]"
                       "{ncolor}").format(
                           server_color=W.color("chat_server"),
                           server=server.name,
                           delimiter_color=W.color("chat_delimiters"),
                           connected=connected,
                           ncolor=W.color("reset"))

            W.prnt("", message)

            option = server.options["autoconnect"]
            default_value = W.config_string_default(option)
            value = W.config_string(option)

            value_string = get_value_string(value, default_value)
            message = "  autoconnect. : {value}".format(value=value_string)

            W.prnt("", message)

            option = server.options["address"]
            default_value = W.config_string_default(option)
            value = W.config_string(option)

            value_string = get_value_string(value, default_value)
            message = "  address. . . : {value}".format(value=value_string)

            W.prnt("", message)

            option = server.options["port"]
            default_value = str(W.config_integer_default(option))
            value = str(W.config_integer(option))

            value_string = get_value_string(value, default_value)
            message = "  port . . . . : {value}".format(value=value_string)

            W.prnt("", message)

            option = server.options["username"]
            default_value = W.config_string_default(option)
            value = W.config_string(option)

            value_string = get_value_string(value, default_value)
            message = "  username . . : {value}".format(value=value_string)

            W.prnt("", message)

            option = server.options["password"]
            value = W.config_string(option)

            if value:
                value = "(hidden)"

            value_string = get_value_string(value, '')
            message = "  password . . : {value}".format(value=value_string)

            W.prnt("", message)

    def delete_server(args):
        for server_name in args:
            if check_server_existence(server_name, SERVERS):
                server = SERVERS[server_name]

                if server.connected:
                    message = ("{prefix}matrix: you can not delete server "
                               "{color}{server}{ncolor} because you are "
                               "connected to it. Try \"/matrix disconnect "
                               "{color}{server}{ncolor}\" before.").format(
                                   prefix=W.prefix("error"),
                                   color=W.color("chat_server"),
                                   ncolor=W.color("reset"),
                                   server=server.name)
                    W.prnt("", message)
                    return

                for buf in server.buffers.values():
                    W.buffer_close(buf)

                if server.server_buffer:
                    W.buffer_close(server.server_buffer)

                for option in server.options.values():
                    W.config_option_free(option)

                message = ("matrix: server {color}{server}{ncolor} has been "
                           "deleted").format(
                               server=server.name,
                               color=W.color("chat_server"),
                               ncolor=W.color("reset"))

                del SERVERS[server.name]
                server = None

                W.prnt("", message)

    def add_server(args):
        if len(args) < 2:
            message = ("{prefix}matrix: Too few arguments for command "
                       "\"/matrix server add\" (see the help for the command: "
                       "/matrix help server").format(prefix=W.prefix("error"))
            W.prnt("", message)
            return
        elif len(args) > 4:
            message = ("{prefix}matrix: Too many arguments for command "
                       "\"/matrix server add\" (see the help for the command: "
                       "/matrix help server").format(prefix=W.prefix("error"))
            W.prnt("", message)
            return

        def remove_server(server):
            for option in server.options.values():
                W.config_option_free(option)
            del SERVERS[server.name]

        server_name = args[0]

        if server_name in SERVERS:
            message = ("{prefix}matrix: server {color}{server}{ncolor} "
                       "already exists, can't add it").format(
                           prefix=W.prefix("error"),
                           color=W.color("chat_server"),
                           server=server_name,
                           ncolor=W.color("reset"))
            W.prnt("", message)
            return

        server = MatrixServer(args[0], CONFIG)
        SERVERS[server.name] = server

        if len(args) >= 2:
            try:
                host, port = args[1].split(":", 1)
            except ValueError:
                host, port = args[1], None

            return_code = W.config_option_set(
                server.options["address"],
                host,
                1
            )

            if return_code == W.WEECHAT_CONFIG_OPTION_SET_ERROR:
                remove_server(server)
                message = ("{prefix}Failed to set address for server "
                           "{color}{server}{ncolor}, failed to add "
                           "server.").format(
                               prefix=W.prefix("error"),
                               color=W.color("chat_server"),
                               server=server.name,
                               ncolor=W.color("reset"))

                W.prnt("", message)
                server = None
                return

            if port:
                return_code = W.config_option_set(
                    server.options["port"],
                    port,
                    1
                )
                if return_code == W.WEECHAT_CONFIG_OPTION_SET_ERROR:
                    remove_server(server)
                    message = ("{prefix}Failed to set port for server "
                               "{color}{server}{ncolor}, failed to add "
                               "server.").format(
                                   prefix=W.prefix("error"),
                                   color=W.color("chat_server"),
                                   server=server.name,
                                   ncolor=W.color("reset"))

                    W.prnt("", message)
                    server = None
                    return

        if len(args) >= 3:
            user = args[2]
            return_code = W.config_option_set(
                server.options["username"],
                user,
                1
            )

            if return_code == W.WEECHAT_CONFIG_OPTION_SET_ERROR:
                remove_server(server)
                message = ("{prefix}Failed to set user for server "
                           "{color}{server}{ncolor}, failed to add "
                           "server.").format(
                               prefix=W.prefix("error"),
                               color=W.color("chat_server"),
                               server=server.name,
                               ncolor=W.color("reset"))

                W.prnt("", message)
                server = None
                return

        if len(args) == 4:
            password = args[3]

            return_code = W.config_option_set(
                server.options["password"],
                password,
                1
            )
            if return_code == W.WEECHAT_CONFIG_OPTION_SET_ERROR:
                remove_server(server)
                message = ("{prefix}Failed to set password for server "
                           "{color}{server}{ncolor}, failed to add "
                           "server.").format(
                               prefix=W.prefix("error"),
                               color=W.color("chat_server"),
                               server=server.name,
                               ncolor=W.color("reset"))
                W.prnt("", message)
                server = None
                return

        message = ("matrix: server {color}{server}{ncolor} "
                   "has been added").format(
                       server=server.name,
                       color=W.color("chat_server"),
                       ncolor=W.color("reset"))
        W.prnt("", message)

    # TODO the argument for list and listfull is used as a match word to
    # find/filter servers, we're currently match exactly to the whole name
    if command == 'list':
        list_servers(args)

    elif command == 'listfull':
        list_full_servers(args)

    elif command == 'add':
        add_server(args)

    elif command == 'delete':
        delete_server(args)

    else:
        print("Unknown server command")


@utf8_decode
def matrix_command_cb(data, buffer, args):
    def connect_server(args):
        for server_name in args:
            if check_server_existence(server_name, SERVERS):
                server = SERVERS[server_name]
                connect(server)

    def disconnect_server(args):
        for server_name in args:
            if check_server_existence(server_name, SERVERS):
                server = SERVERS[server_name]
                W.unhook(server.timer_hook)
                server.timer_hook = None
                disconnect(server)

    split_args = list(filter(bool, args.split(' ')))

    command, args = split_args[0], split_args[1:]

    if not command:
        # TODO print out error
        return W.WEECHAT_RC_ERROR

    elif command == 'connect':
        connect_server(args)

    elif command == 'disconnect':
        disconnect_server(args)

    elif command == 'reconnect':
        disconnect_server(args)
        connect_server(args)

    elif command == 'server':
        if len(args) >= 1:
            subcommand, args = args[0], args[1:]
            matrix_server_command(subcommand, args)
        else:
            matrix_server_command("list", "")

    elif command == 'help':
        matrix_command_help(args)

    else:
        print("Unknown command")

    return W.WEECHAT_RC_OK


def add_servers_to_completion(completion):
    for server_name in SERVERS:
        W.hook_completion_list_add(
            completion,
            server_name,
            0,
            weechat.WEECHAT_LIST_POS_SORT
        )


@utf8_decode
def server_command_completion_cb(data, completion_item, buffer, completion):
    buffer_input = weechat.buffer_get_string(buffer, "input").split()

    args = buffer_input[1:]
    commands = ['add', 'delete', 'list', 'listfull']

    def complete_commands():
        for command in commands:
            W.hook_completion_list_add(
                completion,
                command,
                0,
                weechat.WEECHAT_LIST_POS_SORT
            )

    if len(args) == 1:
        complete_commands()

    elif len(args) == 2:
        if args[1] not in commands:
            complete_commands()
        else:
            if args[1] == 'delete' or args[1] == 'listfull':
                add_servers_to_completion(completion)

    elif len(args) == 3:
        if args[1] == 'delete' or args[1] == 'listfull':
            if args[2] not in SERVERS:
                add_servers_to_completion(completion)

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_server_completion_cb(data, completion_item, buffer, completion):
    add_servers_to_completion(completion)
    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_command_completion_cb(data, completion_item, buffer, completion):
    for command in ["connect", "disconnect", "reconnect", "server", "help"]:
        W.hook_completion_list_add(
            completion,
            command,
            0,
            weechat.WEECHAT_LIST_POS_SORT)
    return W.WEECHAT_RC_OK


def create_default_server(config_file):
    server = MatrixServer('matrix.org', config_file)
    SERVERS[server.name] = server

    # TODO set this to matrix.org
    W.config_option_set(server.options["address"], "localhost", 1)

    return True


def init_hooks():
    W.hook_completion(
        "matrix_server_commands",
        "Matrix server completion",
        "server_command_completion_cb",
        ""
    )

    W.hook_completion(
        "matrix_servers",
        "Matrix server completion",
        "matrix_server_completion_cb",
        ""
    )

    W.hook_completion(
        "matrix_commands",
        "Matrix command completion",
        "matrix_command_completion_cb",
        ""
    )

    W.hook_command(
        # Command name and short description
        'matrix', 'Matrix chat protocol command',
        # Synopsis
        (
            'server add <server-name> <hostname>[:<port>] ||'
            'server delete|list|listfull <server-name> ||'
            'connect <server-name> ||'
            'disconnect <server-name> ||'
            'reconnect <server-name> ||'
            'help <matrix-command>'
        ),
        # Description
        (
            '    server: list, add, or remove Matrix servers\n'
            '   connect: connect to Matrix servers\n'
            'disconnect: disconnect from one or all Matrix servers\n'
            ' reconnect: reconnect to server(s)\n\n'
            '      help: show detailed command help\n\n'
            'Use /matrix help [command] to find out more\n'
        ),
        # Completions
        (
            'server %(matrix_server_commands)|%* ||'
            'connect %(matrix_servers) ||'
            'disconnect %(matrix_servers) ||'
            'reconnect %(matrix_servers) ||'
            'help %(matrix_commands)'
        ),
        # Function name
        'matrix_command_cb', '')


def autoconnect(servers):
    for server in servers.values():
        if server.autoconnect:
            connect(server)


if __name__ == "__main__":
    W = WeechatWrapper(weechat)

    if W.register(WEECHAT_SCRIPT_NAME,
                  WEECHAT_SCRIPT_AUTHOR,
                  WEECHAT_SCRIPT_VERSION,
                  WEECHAT_SCRIPT_LICENSE,
                  WEECHAT_SCRIPT_DESCRIPTION,
                  'matrix_unload_cb',
                  ''):

        # TODO if this fails we should abort and unload the script.
        CONFIG = init_matrix_config()
        read_matrix_config()

        init_hooks()

        if not SERVERS:
            create_default_server(CONFIG)

        autoconnect(SERVERS)
