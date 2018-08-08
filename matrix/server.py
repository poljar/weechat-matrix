# -*- coding: utf-8 -*-

# Copyright © 2018 Damir Jelić <poljar@termina.org.uk>
#
# Permission to use, copy, modify, and/or distribute this software for
# any purpose with or without fee is hereby granted, provided that the
# above copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
# RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
# CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from __future__ import unicode_literals

import os
import ssl
import socket
import time
import pprint

from collections import deque, defaultdict

from nio import (
    HttpClient,
    LoginResponse,
    SyncRepsponse,
    RoomSendResponse,
    RoomPutStateResponse,
    TransportResponse,
    TransportType,
    LocalProtocolError
)

from matrix.plugin_options import Option, DebugType
from matrix.utils import (key_from_value, prnt_debug, server_buffer_prnt,
                          create_server_buffer)
from matrix.utf import utf8_decode
from matrix.globals import W, SERVERS, SCRIPT_NAME, OPTIONS
from .buffer import RoomBuffer, OwnMessage, OwnAction

try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError


class ServerConfig(object):
    _section_name = "{}.{}".format(SCRIPT_NAME, "server")

    def __init__(self, server_name, config_ptr):
        # type: (str, str) -> None
        self._server_name = server_name
        self._ptr = config_ptr
        self.options = {}

        options = [
            Option('autoconnect', 'boolean', '', 0, 0, 'off',
                   ("automatically connect to the matrix server when weechat "
                    "is starting")),
            Option('address', 'string', '', 0, 0, '',
                   "Hostname or IP address for the server"),
            Option('port', 'integer', '', 0, 65535, '443',
                   "Port for the server"),
            Option('proxy', 'string', '', 0, 0, '',
                   ("Name of weechat proxy to use (see /help proxy)")),
            Option('ssl_verify', 'boolean', '', 0, 0, 'on',
                   ("Check that the SSL connection is fully trusted")),
            Option('username', 'string', '', 0, 0, '',
                   "Username to use on server"),
            Option(
                'password', 'string', '', 0, 0, '',
                ("Password for server (note: content is evaluated, see /help "
                 "eval)")),
            Option('device_name', 'string', '', 0, 0, 'Weechat Matrix',
                   "Device name to use while logging in to the matrix server"),
        ]

        section = W.config_search_section(config_ptr, 'server')

        for option in options:
            option_name = "{server}.{option}".format(
                server=self._server_name, option=option.name)

            self.options[option.name] = W.config_new_option(
                config_ptr, section, option_name, option.type,
                option.description, option.string_values, option.min,
                option.max, option.value, option.value, 0, "", "",
                "matrix_config_server_change_cb", self._server_name, "", "")

    def _get_str_option(self, option_name):
        return W.config_string(self.options[option_name])

    def _get_bool_option(self, option_name):
        return bool(W.config_boolean(self.options[option_name]))

    @property
    def config_section(self):
        # type: () -> str
        return "{}.{}".format(self._server_name, self._server_name)

    @property
    def autoconnect(self):
        # type: () -> bool
        return self._get_bool_option("autoconnect")

    @property
    def address(self):
        # type: () -> str
        return self._get_str_option("address")

    @property
    def port(self):
        # type: () -> int
        return W.config_integer(self.options["port"])

    @property
    def proxy(self):
        # type: () -> str
        return self._get_str_option("proxy")

    @property
    def ssl_verify(self):
        # type: () -> bool
        return self._get_bool_option("ssl_verify")

    @property
    def username(self):
        # type: () -> str
        return self._get_str_option("username")

    @property
    def password(self):
        # type: () -> str
        return W.string_eval_expression(
            self._get_str_option("password"),
            {},
            {},
            {}
        )

    @property
    def device_name(self):
        # type: () -> str
        return self._get_str_option("device_name")


class MatrixServer(object):
    # pylint: disable=too-many-instance-attributes
    def __init__(self, name, config_file):
        # type: (str, weechat.config) -> None
        # yapf: disable
        self.name = name                     # type: str
        self.user_id = ""
        self.device_id = ""                  # type: str

        self.olm = None                      # type: Olm
        self.encryption_queue = defaultdict(deque)

        self.room_buffers = dict()  # type: Dict[str, WeechatChannelBuffer]
        self.buffers = dict()                # type: Dict[str, weechat.buffer]
        self.server_buffer = None            # type: weechat.buffer
        self.fd_hook = None                  # type: weechat.hook
        self.ssl_hook = None                 # type: weechat.hook
        self.timer_hook = None               # type: weechat.hook
        self.numeric_address = ""            # type: str

        self.connected = False      # type: bool
        self.connecting = False     # type: bool
        self.reconnect_delay = 0    # type: int
        self.reconnect_time = None  # type: float
        self.sync_time = None       # type: Optional[float]
        self.socket = None          # type: ssl.SSLSocket
        self.ssl_context = ssl.create_default_context()  # type: ssl.SSLContext
        self.transport_type = None  # type: Optional[nio.TransportType]

        # Enable http2 negotiation on the ssl context.
        self.ssl_context.set_alpn_protocols(["h2", "http/1.1"])

        try:
            self.ssl_context.set_npn_protocols(["h2", "http/1.1"])
        except NotImplementedError:
            pass

        self.client = None
        self.access_token = None                         # type: str
        self.next_batch = None                           # type: str
        self.transaction_id = 0                          # type: int
        self.lag = 0                                     # type: int
        self.lag_done = False                            # type: bool

        self.send_fd_hook = None                         # type: weechat.hook
        self.send_buffer = b""                           # type: bytes
        self.device_check_timestamp = None

        self.send_queue = deque()
        self.own_message_queue = dict()  # type: Dict[OwnMessage]

        self.event_queue_timer = None
        self.event_queue = deque()  # type: Deque[RoomInfo]

        # self._create_options(config_file)
        self.config = ServerConfig(self.name, config_file)
        self._create_session_dir()
        # yapf: enable

    def _create_session_dir(self):
        path = os.path.join("matrix", self.name)
        if not W.mkdir_home(path, 0o700):
            message = ("{prefix}matrix: Error creating server session "
                       "directory").format(prefix=W.prefix("error"))
            W.prnt("", message)

    def get_session_path(self):
        home_dir = W.info_get('weechat_dir', '')
        return os.path.join(home_dir, "matrix", self.name)

    def _load_device_id(self):
        file_name = "{}{}".format(self.config.username, ".device_id")
        path = os.path.join(self.get_session_path(), file_name)

        if not os.path.isfile(path):
            return

        with open(path, 'r') as f:
            device_id = f.readline().rstrip()
            if device_id:
                self.device_id = device_id

    def save_device_id(self):
        file_name = "{}{}".format(self.config.username, ".device_id")
        path = os.path.join(self.get_session_path(), file_name)

        with open(path, 'w') as f:
            f.write(self.device_id)

    def _change_client(self):
        host = ':'.join([self.config.address, str(self.config.port)])
        self.client = HttpClient(host, self.config.username, self.device_id)

    def update_option(self, option, option_name):
        if option_name == "address":
            self._change_client()
        elif option_name == "port":
            self._change_client()
        elif option_name == "ssl_verify":
            value = W.config_boolean(option)
            if value:
                self.ssl_context.verify_mode = ssl.CERT_REQUIRED
                self.ssl_context.check_hostname = True
            else:
                self.ssl_context.check_hostname = False
                self.ssl_context.verify_mode = ssl.CERT_NONE
        elif option_name == "username":
            value = W.config_string(option)
            self.access_token = ""

            self._load_device_id()

            if self.client:
                self.client.user = value
                if self.device_id:
                    self.client.device_id = self.device_id
        else:
            pass

    def send_or_queue(self, request):
        # type: (bytes) -> None
        if not self.send(request):
            self.send_queue.append(request)

    def try_send(self, message):
        # type: (MatrixServer, bytes) -> bool

        sock = self.socket
        total_sent = 0
        message_length = len(message)

        while total_sent < message_length:
            try:
                sent = sock.send(message[total_sent:])

            except ssl.SSLWantWriteError:
                hook = W.hook_fd(sock.fileno(), 0, 1, 0, "send_cb", self.name)
                self.send_fd_hook = hook
                self.send_buffer = message[total_sent:]
                return True

            except socket.error as error:
                self._abort_send()

                errno = "error" + str(error.errno) + " " if error.errno else ""
                strerr = error.strerror if error.strerror else "Unknown reason"
                strerr = errno + strerr

                error_message = ("{prefix}Error while writing to "
                                 "socket: {error}").format(
                                     prefix=W.prefix("network"), error=strerr)

                server_buffer_prnt(self, error_message)
                server_buffer_prnt(
                    self, ("{prefix}matrix: disconnecting from server..."
                           ).format(prefix=W.prefix("network")))

                self.disconnect()
                return False

            if sent == 0:
                self._abort_send()

                server_buffer_prnt(
                    self,
                    "{prefix}matrix: Error while writing to socket".format(
                        prefix=W.prefix("network")))
                server_buffer_prnt(
                    self, ("{prefix}matrix: disconnecting from server..."
                           ).format(prefix=W.prefix("network")))
                self.disconnect()
                return False

            total_sent = total_sent + sent

        self._finalize_send()
        return True

    def _abort_send(self):
        self.current_message = None
        self.send_buffer = ""

    def _finalize_send(self):
        # type: (MatrixServer) -> None
        self.send_buffer = b""

    def error(self, message):
        buf = ""
        if self.server_buffer:
            buf = self.server_buffer

        msg = "{}{}: {}".format(W.prefix("network"), SCRIPT_NAME, message)
        W.prnt(buf, msg)

    def send(self, data):
        # type: (bytes) -> bool
        self.try_send(data)

        return True

    def reconnect(self):
        message = ("{prefix}matrix: reconnecting to server..."
                   ).format(prefix=W.prefix("network"))

        server_buffer_prnt(self, message)

        self.reconnect_time = None

        if not self.connect():
            self.schedule_reconnect()

    def schedule_reconnect(self):
        # type: (MatrixServer) -> None
        self.connecting = True
        self.reconnect_time = time.time()

        if self.reconnect_delay:
            self.reconnect_delay = self.reconnect_delay * 2
        else:
            self.reconnect_delay = 10

        message = ("{prefix}matrix: reconnecting to server in {t} "
                   "seconds").format(
                       prefix=W.prefix("network"), t=self.reconnect_delay)

        server_buffer_prnt(self, message)

    def _close_socket(self):
        # type: () -> None
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
            except socket.error:
                pass

    def disconnect(self, reconnect=True):
        # type: (bool) -> None
        if self.fd_hook:
            W.unhook(self.fd_hook)

        self._close_socket()

        self.fd_hook = None
        self.socket = None
        self.connected = False
        self.access_token = ""

        self.send_buffer = b""
        self.current_message = None
        self.transport_type = None

        try:
            self.client.disconnect()
        except LocalProtocolError:
            pass

        self.lag = 0
        W.bar_item_update("lag")
        self.reconnect_delay = 0
        self.reconnect_time = None

        if self.server_buffer:
            message = ("{prefix}matrix: disconnected from server"
                       ).format(prefix=W.prefix("network"))
            server_buffer_prnt(self, message)

        if reconnect:
            self.schedule_reconnect()

    def connect(self):
        # type: (MatrixServer) -> int
        if not self.config.address or not self.config.port:
            W.prnt("", self.config.address)
            message = "{prefix}Server address or port not set".format(
                prefix=W.prefix("error"))
            W.prnt("", message)
            return False

        if not self.config.username or not self.config.password:
            message = "{prefix}User or password not set".format(
                prefix=W.prefix("error"))
            W.prnt("", message)
            return False

        if self.connected:
            return True

        if not self.server_buffer:
            create_server_buffer(self)

        if not self.timer_hook:
            self.timer_hook = W.hook_timer(1 * 1000, 0, 0, "matrix_timer_cb",
                                           self.name)

        ssl_message = " (SSL)" if self.ssl_context.check_hostname else ""

        message = ("{prefix}matrix: Connecting to "
                   "{server}:{port}{ssl}...").format(
                       prefix=W.prefix("network"),
                       server=self.config.address,
                       port=self.config.port,
                       ssl=ssl_message)

        W.prnt(self.server_buffer, message)

        W.hook_connect(self.config.proxy,
                       self.config.address, self.config.port,
                       1, 0, "", "connect_cb",
                       self.name)

        return True

    def schedule_sync(self):
        self.sync_time = time.time()

    def sync(self, timeout=None, filter=None):
        # type: Optional[int] -> None
        self.sync_time = None
        _, request = self.client.sync(timeout, filter)
        self.send_or_queue(request)

    def login(self):
        # type: () -> None
        if self.client.logged_in:
            msg = ("{prefix}{script_name}: Already logged in, "
                   "syncing...").format(
                      prefix=W.prefix("network"),
                      script_name=SCRIPT_NAME
                  )
            W.prnt(self.server_buffer, msg)
            timeout = (0 if self.transport_type == TransportType.HTTP
                       else 30000)
            sync_filter = {"room": {"timeline": {"limit": 5000}}}
            self.sync(timeout, sync_filter)
            return

        _, request = self.client.login(
            self.config.password,
            self.config.device_name
        )
        self.send_or_queue(request)

        msg = "{prefix}matrix: Logging in...".format(
            prefix=W.prefix("network")
        )

        W.prnt(self.server_buffer, msg)

    def room_send_state(self, room_buffer, body, event_type):
        if room_buffer.room.encrypted:
            return

        _, request = self.client.room_put_state(
            room_buffer.room.room_id,
            event_type,
            body
        )
        self.send_or_queue(request)

    def room_send_message(self, room_buffer, formatted, msgtype="m.text"):
        # type: (RoomBuffer, Formatted) -> None
        if room_buffer.room.encrypted:
            return

        if msgtype == "m.emote":
            message_class = OwnAction
        else:
            message_class = OwnMessage

        own_message = message_class(
            self.user_id,
            0,
            "",
            room_buffer.room.room_id,
            formatted
        )

        body = {"msgtype": msgtype, "body": formatted.to_plain()}

        if formatted.is_formatted():
            body["format"] = "org.matrix.custom.html"
            body["formatted_body"] = formatted.to_html()

        uuid, request = self.client.room_send(
            room_buffer.room.room_id,
            "m.room.message",
            body
        )

        self.own_message_queue[uuid] = own_message
        self.send_or_queue(request)

    def _print_message_error(self, message):
        server_buffer_prnt(self,
                           ("{prefix}Unhandled {status_code} error, please "
                            "inform the developers about this.").format(
                                prefix=W.prefix("error"),
                                status_code=message.response.status))

        server_buffer_prnt(self, pprint.pformat(message.__class__.__name__))
        server_buffer_prnt(self, pprint.pformat(message.request.payload))
        server_buffer_prnt(self, pprint.pformat(message.response.body))

    def handle_own_messages(self, response):
        message = self.own_message_queue.pop(response.uuid)
        room_buffer = self.room_buffers[message.room_id]
        message = message._replace(event_id=response.event_id)

        if isinstance(message, OwnAction):
            room_buffer.self_action(message)
            return
        elif isinstance(message, OwnMessage):
            room_buffer.self_message(message)
            return

        raise NotImplementedError("Unsupported message of type {}".format(
            type(message)))

    def _handle_erorr_response(self, response):
        message = ("{prefix}matrix: {error}").format(
            prefix=W.prefix("error"), error=self.error_message)

        W.prnt(self.server.server_buffer, message)

        if self.fatal:
            self.server.disconnect(reconnect=False)

    def _handle_login(self, response):
        self.access_token = response.access_token
        self.user_id = response.user_id
        self.client.access_token = response.access_token
        self.device_id = response.device_id
        self.save_device_id()

        message = "{prefix}matrix: Logged in as {user}".format(
            prefix=W.prefix("network"), user=self.user_id)

        W.prnt(self.server_buffer, message)

        # if not self.olm:
        #     self.create_olm()
        #     self.store_olm()
        #     self.upload_keys(device_keys=True, one_time_keys=False)

        sync_filter = {"room": {"timeline": {"limit": OPTIONS.sync_limit}}}
        self.sync(timeout=0, filter=sync_filter)

    def _handle_room_info(self, response):
        for room_id, join_info in response.rooms.join.items():
            if room_id not in self.buffers:
                self.create_room_buffer(room_id)

            room_buffer = self.find_room_from_id(room_id)

            for event in join_info.state:
                room_buffer.handle_state_event(event)

            for event in join_info.timeline.events:
                room_buffer.handle_timeline_event(event)

    def _handle_sync(self, response):
        # we got the same batch again, nothing to do
        if self.next_batch == response.next_batch:
            self.schedule_sync()
            return

        self._handle_room_info(response)
        self.next_batch = response.next_batch
        self.schedule_sync()

    def handle_transport_response(self, response):
        self.error(("Error with response of type type: {}, "
                    "error code {}").format(
            response.request_info.type, response.status_code))

        # TODO better error handling.
        if response.request_info.type == "sync":
            self.disconnect()

    def handle_response(self, response):
        # type: (MatrixMessage) -> None
        self.lag = response.elapsed * 1000

        # If the response was a sync response and contained a timeout the
        # timeout is expected and should be removed from the lag.
        # TODO the timeout isn't a constant
        if isinstance(response, SyncRepsponse):
            self.lag = max(0, self.lag - (30000))

        self.lag_done = True
        W.bar_item_update("lag")

        if isinstance(response, TransportResponse):
            self.handle_transport_response(response)

        elif isinstance(response, LoginResponse):
            self._handle_login(response)

        elif isinstance(response, SyncRepsponse):
            self._handle_sync(response)

        elif isinstance(response, RoomSendResponse):
            self.handle_own_messages(response)

        elif isinstance(response, RoomPutStateResponse):
            pass

        return

    def create_room_buffer(self, room_id):
        room = self.client.rooms[room_id]
        buf = RoomBuffer(room, self.name)
        # TODO this should turned into a propper class
        self.room_buffers[room_id] = buf
        self.buffers[room_id] = buf.weechat_buffer._ptr

    def find_room_from_ptr(self, pointer):
        try:
            room_id = key_from_value(self.buffers, pointer)
            room_buffer = self.room_buffers[room_id]

            return room_buffer
        except (ValueError, KeyError):
            return None

    def find_room_from_id(self, room_id):
        room_buffer = self.room_buffers[room_id]
        return room_buffer


@utf8_decode
def matrix_config_server_read_cb(data, config_file, section, option_name,
                                 value):

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
        if option in server.config.options:
            return_code = W.config_option_set(
                server.config.options[option],
                value,
                1
            )

    # TODO print out error message in case of erroneous return_code

    return return_code


@utf8_decode
def matrix_config_server_write_cb(data, config_file, section_name):
    if not W.config_write_line(config_file, section_name, ""):
        return W.WECHAT_CONFIG_WRITE_ERROR

    for server in SERVERS.values():
        for option in server.config.options.values():
            if not W.config_write_option(config_file, option):
                return W.WECHAT_CONFIG_WRITE_ERROR

    return W.WEECHAT_CONFIG_WRITE_OK


@utf8_decode
def matrix_config_server_change_cb(server_name, option):
    # type: (str, weechat.config_option) -> int
    server = SERVERS[server_name]
    option_name = None

    # The function config_option_get_string() is used to get differing
    # properties from a config option, sadly it's only available in the plugin
    # API of weechat.
    option_name = key_from_value(server.config.options, option)
    server.update_option(option, option_name)

    return 1


@utf8_decode
def matrix_timer_cb(server_name, remaining_calls):
    server = SERVERS[server_name]

    current_time = time.time()

    if ((not server.connected) and server.reconnect_time and
            current_time >= (server.reconnect_time + server.reconnect_delay)):
        server.reconnect()
        return W.WEECHAT_RC_OK

    if not server.connected:
        return W.WEECHAT_RC_OK

    # check lag, disconnect if it's too big
    server.lag = server.client.lag * 1000
    server.lag_done = False
    W.bar_item_update("lag")

    # TODO print out message, make timeout configurable
    if server.lag > 300000:
        server.disconnect()
        return W.WEECHAT_RC_OK

    if server.sync_time and current_time > (server.sync_time + 2):
        timeout = 0 if server.transport_type == TransportType.HTTP else 30000
        sync_filter = {"room": {"timeline": {"limit": 5000}}}
        server.sync(timeout, sync_filter)

    while server.send_queue:
        message = server.send_queue.popleft()
        prnt_debug(
            DebugType.MESSAGING,
            server, ("Timer hook found message of type {t} in queue. Sending "
                     "out.".format(t=message.__class__.__name__)))

        if not server.send(message):
            # We got an error while sending the last message return the message
            # to the queue and exit the loop
            server.send_queue.appendleft(message)
            break

    if not server.next_batch:
        return W.WEECHAT_RC_OK

    # check for new devices by users in encrypted rooms periodically
    # if (not server.device_check_timestamp or
    #         current_time - server.device_check_timestamp > 600):

    #     W.prnt(server.server_buffer,
    #            "{prefix}matrix: Querying user devices.".format(
    #                prefix=W.prefix("networ")))

    #     server.device_check_timestamp = current_time

    return W.WEECHAT_RC_OK


def create_default_server(config_file):
    server = MatrixServer('matrix_org', config_file)
    SERVERS[server.name] = server

    option = W.config_get(SCRIPT_NAME + ".server." + server.name + ".address")
    W.config_option_set(option, "matrix.org", 1)

    return True


@utf8_decode
def send_cb(server_name, file_descriptor):
    # type: (str, int) -> int

    server = SERVERS[server_name]

    if server.send_fd_hook:
        W.unhook(server.send_fd_hook)
        server.send_fd_hook = None

    if server.send_buffer:
        server.try_send(server, server.send_buffer)

    return W.WEECHAT_RC_OK
