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

import ssl
import socket
import time

from collections import deque
from http_parser.pyparser import HttpParser

from matrix.plugin_options import Option, DebugType
from matrix.utils import (
    key_from_value,
    prnt_debug,
    server_buffer_prnt,
    create_server_buffer
)
from matrix.utf import utf8_decode
from matrix.globals import W, SERVERS


class MatrixServer:
    # pylint: disable=too-many-instance-attributes
    def __init__(self, name, config_file):
        # type: (str, weechat, weechat.config) -> None
        self.name = name                     # type: str
        self.user_id = ""
        self.address = ""                    # type: str
        self.port = 8448                     # type: int
        self.options = dict()                # type: Dict[str, weechat.config]
        self.device_name = "Weechat Matrix"  # type: str

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
        self.reconnect_delay = 0                         # type: int
        self.reconnect_time = None                       # type: float
        self.socket = None                               # type: ssl.SSLSocket
        self.ssl_context = ssl.create_default_context()  # type: ssl.SSLContext

        self.access_token = None                         # type: str
        self.next_batch = None                           # type: str
        self.transaction_id = 0                          # type: int
        self.lag = 0                                     # type: int

        self.send_fd_hook = None                         # type: weechat.hook
        self.send_buffer = b""                           # type: bytes
        self.current_message = None                      # type: MatrixMessage

        self.http_parser = HttpParser()                  # type: HttpParser
        self.http_buffer = []                            # type: List[bytes]

        # Queue of messages we need to send off.
        self.send_queue = deque()     # type: Deque[MatrixMessage]

        # Queue of messages we send off and are waiting a response for
        self.receive_queue = deque()  # type: Deque[MatrixMessage]

        self.message_queue = deque()  # type: Deque[MatrixMessage]
        self.ignore_event_list = []   # type: List[str]

        self._create_options(config_file)

    def _create_options(self, config_file):
        options = [
            Option(
                'autoconnect', 'boolean', '', 0, 0, 'off',
                (
                    "automatically connect to the matrix server when weechat "
                    "is starting"
                )
            ),
            Option(
                'address', 'string', '', 0, 0, '',
                "Hostname or IP address for the server"
            ),
            Option(
                'port', 'integer', '', 0, 65535, '8448',
                "Port for the server"
            ),
            Option(
                'ssl_verify', 'boolean', '', 0, 0, 'on',
                (
                    "Check that the SSL connection is fully trusted"
                    "is starting"
                )
            ),
            Option(
                'username', 'string', '', 0, 0, '',
                "Username to use on server"
            ),
            Option(
                'password', 'string', '', 0, 0, '',
                ("Password for server (note: content is evaluated, see /help "
                 "eval)")
            ),
            Option(
                'device_name', 'string', '', 0, 0, 'Weechat Matrix',
                "Device name to use while logging in to the matrix server"
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
                "", "matrix_config_server_change_cb", self.name, "", "")

    def reset_parser(self):
        self.http_parser = HttpParser()
        self.http_buffer = []

    def update_option(self, option, option_name):
        if option_name == "address":
            value = W.config_string(option)
            self.address = value
        elif option_name == "autoconnect":
            value = W.config_boolean(option)
            self.autoconnect = value
        elif option_name == "port":
            value = W.config_integer(option)
            self.port = value
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
        elif option_name == "password":
            value = W.config_string(option)
            self.password = W.string_eval_expression(value, {}, {}, {})
        elif option_name == "device_name":
            value = W.config_string(option)
            self.device_name = value
        else:
            pass


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

    if ((not server.connected) and
            server.reconnect_time and
            current_time >= (server.reconnect_time + server.reconnect_delay)):
        matrix_server_reconnect(server)

    if not server.connected:
        return W.WEECHAT_RC_OK

    while server.send_queue:
        message = server.send_queue.popleft()
        prnt_debug(DebugType.MESSAGING, server,
                   ("Timer hook found message of type {t} in queue. Sending "
                    "out.".format(t=message.type)))

        if not send(server, message):
            # We got an error while sending the last message return the message
            # to the queue and exit the loop
            server.send_queue.appendleft(message)
            break

    return W.WEECHAT_RC_OK


def create_default_server(config_file):
    server = MatrixServer('matrix.org', W, config_file)
    SERVERS[server.name] = server

    W.config_option_set(server.options["address"], "matrix.org", 1)

    return True


def matrix_server_reconnect(server):
    message = ("{prefix}matrix: reconnecting to server...").format(
        prefix=W.prefix("network"))

    server_buffer_prnt(server, message)

    server.reconnect_time = None

    if not matrix_server_connect(server):
        matrix_server_reconnect_schedule(server)


def matrix_server_reconnect_schedule(server):
    # type: (MatrixServer) -> None
    server.connecting = True
    server.reconnect_time = time.time()

    if server.reconnect_delay:
        server.reconnect_delay = server.reconnect_delay * 2
    else:
        server.reconnect_delay = 10

    message = ("{prefix}matrix: reconnecting to server in {t} "
               "seconds").format(
                   prefix=W.prefix("network"),
                   t=server.reconnect_delay)

    server_buffer_prnt(server, message)


def matrix_server_disconnect(server, reconnect=True):
    # type: (MatrixServer) -> None
    if server.fd_hook:
        W.unhook(server.fd_hook)

    # TODO close socket
    close_socket(server.socket)

    server.fd_hook = None
    server.socket = None
    server.connected = False
    server.access_token = ""
    server.receive_queue.clear()

    server.reconnect_delay = 0
    server.reconnect_time = None

    if server.server_buffer:
        message = ("{prefix}matrix: disconnected from server").format(
            prefix=W.prefix("network"))
        server_buffer_prnt(server, message)

    if reconnect:
        matrix_server_reconnect_schedule(server)


def matrix_server_connect(server):
    # type: (MatrixServer) -> int
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

    ssl_message = " (SSL)" if server.ssl_context.check_hostname else ""

    message = "{prefix}matrix: Connecting to {server}:{port}{ssl}...".format(
        prefix=W.prefix("network"),
        server=server.address,
        port=server.port,
        ssl=ssl_message)

    W.prnt(server.server_buffer, message)

    W.hook_connect("", server.address, server.port, 1, 0, "",
                   "connect_cb", server.name)

    return True


@utf8_decode
def send_cb(server_name, file_descriptor):
    # type: (str, int) -> int

    server = SERVERS[server_name]

    if server.send_fd_hook:
        W.unhook(server.send_fd_hook)
        server.send_fd_hook = None

    if server.send_buffer:
        try_send(server, send_buffer)

    return W.WEECHAT_RC_OK


def send_or_queue(server, message):
    # type: (MatrixServer, MatrixMessage) -> None
    if not send(server, message):
        prnt_debug(DebugType.MESSAGING, server,
                   ("{prefix} Failed sending message of type {t}. "
                    "Adding to queue").format(
                        prefix=W.prefix("error"),
                        t=message.type))
        server.send_queue.append(message)


def try_send(server, message):
    # type: (MatrixServer, bytes) -> bool

    socket = server.socket
    total_sent = 0
    message_length = len(message)

    while total_sent < message_length:
        try:
            sent = socket.send(message[total_sent:])

        except ssl.SSLWantWriteError:
            hook = W.hook_fd(
                server.socket.fileno(),
                0, 1, 0,
                "send_cb",
                server.name
            )
            server.send_fd_hook = hook
            server.send_buffer = message[total_sent:]
            return True

        except OSError as error:
            disconnect(server)
            abort_send(server)
            server_buffer_prnt(server, str(error))
            return False

        if sent == 0:
            disconnect(server)
            abort_send(server)
            server_buffer_prnt(server, "Socket closed while sending data.")
            return False

        total_sent = total_sent + sent

    finalize_send(server)
    return True


def abort_send(server):
    server.send_queue.appendleft(server.current_message)
    server.current_message = None
    server.send_buffer = ""


def finalize_send(server):
    # type: (MatrixServer) -> None
    server.current_message.send_time = time.time()
    server.receive_queue.append(server.current_message)

    server.send_buffer = ""
    server.current_message = None


def send(server, message):
    # type: (MatrixServer, MatrixMessage) -> bool
    if server.current_message:
        return False

    server.current_message = message

    request = message.request.request
    payload = message.request.payload

    bytes_message = bytes(request, 'utf-8') + bytes(payload, 'utf-8')

    try_send(server, bytes_message)

    return True

def close_socket(sock):
    # type: (socket.socket) -> None
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()
