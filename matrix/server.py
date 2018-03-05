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
from builtins import str, bytes

import os
import ssl
import socket
import time
import datetime
import pprint

from collections import deque
from http_parser.pyparser import HttpParser

from matrix.plugin_options import Option, DebugType
from matrix.utils import (key_from_value, prnt_debug, server_buffer_prnt,
                          create_server_buffer, tags_for_message)
from matrix.utf import utf8_decode
from matrix.globals import W, SERVERS, OPTIONS
import matrix.api as API
from matrix.api import MatrixClient, MatrixSyncMessage, MatrixLoginMessage

from matrix.encryption import Olm, EncryptionError

try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError


class MatrixServer:
    # pylint: disable=too-many-instance-attributes
    def __init__(self, name, config_file):
        # type: (str, weechat.config) -> None
        # yapf: disable
        self.name = name                     # type: str
        self.user_id = ""
        self.address = ""                    # type: str
        self.port = 8448                     # type: int
        self.options = dict()                # type: Dict[str, weechat.config]
        self.device_name = "Weechat Matrix"  # type: str
        self.device_id = ""                  # type: str
        self.olm = None                      # type: Olm

        self.user = ""                       # type: str
        self.password = ""                   # type: str

        self.rooms = dict()                  # type: Dict[str, MatrixRoom]
        self.buffers = dict()                # type: Dict[str, weechat.buffer]
        self.server_buffer = None            # type: weechat.buffer
        self.fd_hook = None                  # type: weechat.hook
        self.ssl_hook = None                 # type: weechat.hook
        self.timer_hook = None               # type: weechat.hook
        self.numeric_address = ""            # type: str

        self.autoconnect = False                         # type: bool
        self.connected = False                           # type: bool
        self.connecting = False                          # type: bool
        self.proxy = None                                # type: str
        self.reconnect_delay = 0                         # type: int
        self.reconnect_time = None                       # type: float
        self.socket = None                               # type: ssl.SSLSocket
        self.ssl_context = ssl.create_default_context()  # type: ssl.SSLContext

        self.client = None
        self.access_token = None                         # type: str
        self.next_batch = None                           # type: str
        self.transaction_id = 0                          # type: int
        self.lag = 0                                     # type: int
        self.lag_done = False                            # type: bool

        self.send_fd_hook = None                         # type: weechat.hook
        self.send_buffer = b""                           # type: bytes
        self.current_message = None                      # type: MatrixMessage

        self.http_parser = HttpParser()                  # type: HttpParser
        self.http_buffer = []                            # type: List[bytes]

        # Queue of messages we need to send off.
        self.send_queue = deque()     # type: Deque[MatrixMessage]

        # Queue of messages we send off and are waiting a response for
        self.receive_queue = deque()  # type: Deque[MatrixMessage]

        self.event_queue_timer = None
        self.event_queue = deque()  # type: Deque[RoomInfo]

        self._create_options(config_file)
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
        file_name = "{}{}".format(self.user, ".device_id")
        path = os.path.join(self.get_session_path(), file_name)

        if not os.path.isfile(path):
            return

        with open(path, 'r') as f:
            device_id = f.readline().rstrip()
            if device_id:
                self.device_id = device_id

    def save_device_id(self):
        file_name = "{}{}".format(self.user, ".device_id")
        path = os.path.join(self.get_session_path(), file_name)

        with open(path, 'w') as f:
            f.write(self.device_id)

    def _load_olm(self):
        try:
            self.olm = Olm.from_session_dir(self)
        except FileNotFoundError:
            message = ("{prefix}matrix: Creating new Olm identity for {user}"
                       " on {server} for device {device}.").format(
                           prefix=W.prefix("network"),
                           user=self.user,
                           server=self.name,
                           device=self.device_id)
            W.prnt("", message)
            self.olm = Olm(self)
        except EncryptionError as error:
            message = ("{prefix}matrix: Error loading Olm"
                       "account: {error}.").format(
                           prefix=W.prefix("error"), error=error)
            W.prnt("", message)

    def _create_options(self, config_file):
        options = [
            Option('autoconnect', 'boolean', '', 0, 0, 'off',
                   ("automatically connect to the matrix server when weechat "
                    "is starting")),
            Option('address', 'string', '', 0, 0, '',
                   "Hostname or IP address for the server"),
            Option('port', 'integer', '', 0, 65535, '8448',
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

        section = W.config_search_section(config_file, 'server')

        for option in options:
            option_name = "{server}.{option}".format(
                server=self.name, option=option.name)

            self.options[option.name] = W.config_new_option(
                config_file, section, option_name, option.type,
                option.description, option.string_values, option.min,
                option.max, option.value, option.value, 0, "", "",
                "matrix_config_server_change_cb", self.name, "", "")

    def reset_parser(self):
        self.http_parser = HttpParser()
        self.http_buffer = []

    def _change_client(self):
        host = ':'.join([self.address, str(self.port)])
        user_agent = 'weechat-matrix/{version}'.format(version="0.1")
        self.client = MatrixClient(host, user_agent=user_agent)

    def update_option(self, option, option_name):
        if option_name == "address":
            value = W.config_string(option)
            self.address = value
            self._change_client()
        elif option_name == "autoconnect":
            value = W.config_boolean(option)
            self.autoconnect = value
        elif option_name == "port":
            value = W.config_integer(option)
            self.port = value
            self._change_client()
        elif option_name == "proxy":
            value = W.config_string(option)
            self.proxy = value
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
            self.user = value
            self.access_token = ""

            self._load_device_id()

            if self.device_id:
                self._load_olm()

        elif option_name == "password":
            value = W.config_string(option)
            self.password = W.string_eval_expression(value, {}, {}, {})
        elif option_name == "device_name":
            value = W.config_string(option)
            self.device_name = value
        else:
            pass

    def send_or_queue(self, message):
        # type: (MatrixServer, MatrixMessage) -> None
        if not self.send(message):
            prnt_debug(DebugType.MESSAGING, self,
                       ("{prefix} Failed sending message of type {t}. "
                        "Adding to queue").format(
                            prefix=W.prefix("error"),
                            t=message.__class__.__name__))
            self.send_queue.append(message)

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
        self.send_queue.appendleft(self.current_message)
        self.current_message = None
        self.send_buffer = ""

    def _finalize_send(self):
        # type: (MatrixServer) -> None
        self.current_message.send_time = time.time()
        self.receive_queue.append(self.current_message)

        self.send_buffer = b""
        self.current_message = None

    def send(self, message):
        # type: (MatrixServer, MatrixMessage) -> bool
        if self.current_message:
            return False

        self.current_message = message

        request = message.request.request
        payload = message.request.payload

        bytes_message = bytes(request, 'utf-8') + bytes(payload, 'utf-8')

        self.try_send(bytes_message)

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
        self.send_queue.clear()
        self.receive_queue.clear()

        self.send_buffer = b""
        self.current_message = None
        self.reset_parser()

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
        if not self.address or not self.port:
            message = "{prefix}Server address or port not set".format(
                prefix=W.prefix("error"))
            W.prnt("", message)
            return False

        if not self.user or not self.password:
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
                       server=self.address,
                       port=self.port,
                       ssl=ssl_message)

        W.prnt(self.server_buffer, message)

        W.hook_connect(self.proxy if self.proxy else "",
                       self.address, self.port,
                       1, 0, "", "connect_cb",
                       self.name)

        return True

    def sync(self):
        limit = None if self.next_batch else OPTIONS.sync_limit
        message = MatrixSyncMessage(self.client, self.next_batch, limit)
        self.send_queue.append(message)

    def login(self):
        # type: (MatrixServer) -> None
        message = MatrixLoginMessage(self.client, self.user, self.password,
                                     self.device_name, self.device_id)
        self.send_or_queue(message)

        msg = "{prefix}matrix: Logging in...".format(prefix=W.prefix("network"))

        W.prnt(self.server_buffer, msg)

    def _print_message_error(self, message):
        server_buffer_prnt(self,
                           ("{prefix}Unhandled {status_code} error, please "
                            "inform the developers about this.").format(
                                prefix=W.prefix("error"),
                                status_code=message.response.status))

        server_buffer_prnt(self, pprint.pformat(message.__class__.__name__))
        server_buffer_prnt(self, pprint.pformat(message.request.payload))
        server_buffer_prnt(self, pprint.pformat(message.response.body))

    def _loop_events(self, info, n):

        for i in range(n+1):
            try:
                event = info.events.popleft()
            except IndexError:
                return i

            room = self.rooms[info.room_id]
            buf = self.buffers[info.room_id]

            tags = tags_for_message("message")
            event.execute(self, room, buf, tags)

        self.event_queue.appendleft(info)
        return i

    def handle_events(self):
        n = 25

        while True:
            try:
                info = self.event_queue.popleft()
            except IndexError:
                if self.event_queue_timer:
                    W.unhook(self.event_queue_timer)
                    self.event_queue_timer = None

                self.sync()
                return

            ret = self._loop_events(info, n)

            if ret < n:
                n = n - ret
            else:
                self.event_queue.appendleft(info)

                if not self.event_queue_timer:
                    hook = W.hook_timer(1 * 100, 0, 0, "matrix_event_timer_cb",
                                        self.name)
                    self.event_queue_timer = hook

                return

    def handle_response(self, message):
        # type: (MatrixMessage) -> None

        assert message.response

        if ('content-type' in message.response.headers and
                message.response.headers['content-type'] == 'application/json'):
            ret, error = message.decode_body(self)

            if not ret:
                message = ("{prefix}matrix: Error decoding json response from "
                           "server: {error}").format(
                               prefix=W.prefix("error"), error=error)
                W.prnt(self.server_buffer, message)
                return

            event = message.event
            event.execute()
        else:
            status_code = message.response.status
            if status_code == 504:
                if isinstance(message, API.MatrixSyncMessage):
                    self.sync()
                else:
                    self._print_message_error(message)
            else:
                self._print_message_error(message)

        creation_date = datetime.datetime.fromtimestamp(message.creation_time)
        done_time = time.time()
        info_message = (
            "Message of type {t} created at {c}."
            "\nMessage lifetime information:"
            "\n    Send delay: {s} ms"
            "\n    Receive delay: {r} ms"
            "\n    Handling time: {h} ms"
            "\n    Total time: {total} ms").format(
                t=message.__class__.__name__,
                c=creation_date,
                s=(message.send_time - message.creation_time) * 1000,
                r=(message.receive_time - message.send_time) * 1000,
                h=(done_time - message.receive_time) * 1000,
                total=(done_time - message.creation_time) * 1000,
            )
        prnt_debug(DebugType.TIMING, self, info_message)

        return


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


@utf8_decode
def matrix_config_server_change_cb(server_name, option):
    # type: (str, weechat.config_option) -> int
    server = SERVERS[server_name]
    option_name = None

    # The function config_option_get_string() is used to get differing
    # properties from a config option, sadly it's only available in the plugin
    # API of weechat.
    option_name = key_from_value(server.options, option)
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
    if server.receive_queue:
        message = server.receive_queue.popleft()
        server.lag = (current_time - message.send_time) * 1000
        server.receive_queue.appendleft(message)
        server.lag_done = False
        W.bar_item_update("lag")

        # TODO print out message, make timeout configurable
        if server.lag > 300000:
            server.disconnect()
            return W.WEECHAT_RC_OK

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

    return W.WEECHAT_RC_OK


def create_default_server(config_file):
    server = MatrixServer('matrix.org', config_file)
    SERVERS[server.name] = server

    W.config_option_set(server.options["address"], "matrix.org", 1)

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
