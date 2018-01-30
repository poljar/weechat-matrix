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
from builtins import str

import ssl

from collections import deque
from http_parser.pyparser import HttpParser

from matrix.plugin_options import Option, DebugType
from matrix.utils import key_from_value, prnt_debug, server_buffer_prnt
from matrix.utf import utf8_decode
from matrix.globals import W, SERVERS
from matrix.socket import send, connect


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
        self.reconnect_count = 0                         # type: int
        self.socket = None                               # type: ssl.SSLSocket
        self.ssl_context = ssl.create_default_context()  # type: ssl.SSLContext

        self.access_token = None                         # type: str
        self.next_batch = None                           # type: str
        self.transaction_id = 0                          # type: int
        self.lag = 0                                     # type: int

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

    if not server.connected:
        if not server.connecting:
            server_buffer_prnt(server, "Reconnecting timeout blaaaa")
            matrix_server_reconnect(server)
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

    for message in server.message_queue:
        server_buffer_prnt(
            server,
            "Handling message: {message}".format(message=message))

    return W.WEECHAT_RC_OK


def create_default_server(config_file):
    server = MatrixServer('matrix.org', W, config_file)
    SERVERS[server.name] = server

    W.config_option_set(server.options["address"], "matrix.org", 1)

    return True


def matrix_server_reconnect(server):
    # type: (MatrixServer) -> None
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
