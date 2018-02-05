# -*- coding: utf-8 -*-

# Weechat Matrix Protocol Script
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

import socket
import ssl
import time
import pprint

# pylint: disable=redefined-builtin
from builtins import str

# pylint: disable=unused-import
from typing import (List, Set, Dict, Tuple, Text, Optional, AnyStr, Deque, Any)

from matrix import colors
from matrix.utf import utf8_decode
from matrix.http import HttpResponse
from matrix.api import MatrixMessage, MessageType, matrix_login
from matrix.messages import handle_http_response

# Weechat searches for the registered callbacks in the scope of the main script
# file, import the callbacks here so weechat can find them.
from matrix.commands import (
    hook_commands,
    hook_page_up,
    matrix_command_cb,
    matrix_command_join_cb,
    matrix_command_part_cb,
    matrix_command_invite_cb,
    matrix_command_topic_cb,
    matrix_command_pgup_cb,
    matrix_redact_command_cb,
    matrix_command_buf_clear_cb
)

from matrix.server import (
    MatrixServer,
    create_default_server,
    send_cb,
    matrix_timer_cb,
    matrix_config_server_read_cb,
    matrix_config_server_write_cb,
    matrix_config_server_change_cb,
)

from matrix.bar_items import (
    init_bar_items,
    matrix_bar_item_name,
    matrix_bar_item_plugin,
    matrix_bar_item_lag
)

from matrix.completion import (
    init_completion,
    matrix_command_completion_cb,
    matrix_server_command_completion_cb,
    matrix_debug_completion_cb,
    matrix_message_completion_cb,
    matrix_server_completion_cb
)

from matrix.utils import (
    key_from_value,
    server_buffer_prnt,
    prnt_debug,
    tags_from_line_data,
    server_buffer_set_title
)

from matrix.plugin_options import (
    DebugType,
    RedactType,
    ServerBufferType,
)

from matrix.config import (
    matrix_config_init,
    matrix_config_read,
    matrix_config_free,
    matrix_config_change_cb,
    matrix_config_reload_cb
)

import matrix.globals

from matrix.globals import W, OPTIONS, SERVERS


WEECHAT_SCRIPT_NAME = "matrix"                                 # type: str
WEECHAT_SCRIPT_DESCRIPTION = "matrix chat plugin"              # type: str
WEECHAT_SCRIPT_AUTHOR = "Damir Jelić <poljar@termina.org.uk>"  # type: str
WEECHAT_SCRIPT_VERSION = "0.1"                                 # type: str
WEECHAT_SCRIPT_LICENSE = "ISC"                                 # type: str


def wrap_socket(server, file_descriptor):
    # type: (MatrixServer, int) -> socket.socket
    sock = None  # type: socket.socket

    temp_socket = socket.fromfd(
        file_descriptor,
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    # For python 2.7 wrap_socket() doesn't work with sockets created from an
    # file descriptor because fromfd() doesn't return a wrapped socket, the bug
    # was fixed for python 3, more info: https://bugs.python.org/issue13942
    # pylint: disable=protected-access,unidiomatic-typecheck
    if type(temp_socket) == socket._socket.socket:
        # pylint: disable=no-member
        sock = socket._socketobject(_sock=temp_socket)
    else:
        sock = temp_socket

    # fromfd() duplicates the file descriptor but doesn't retain it's blocking
    # non-blocking attribute, so mark the socket as non-blocking even though
    # weechat already did that for us
    sock.setblocking(False)

    message = "{prefix}matrix: Doing SSL handshake...".format(
        prefix=W.prefix("network"))
    W.prnt(server.server_buffer, message)

    ssl_socket = server.ssl_context.wrap_socket(
        sock,
        do_handshake_on_connect=False,
        server_hostname=server.address)  # type: ssl.SSLSocket

    server.socket = ssl_socket

    try_ssl_handshake(server)


@utf8_decode
def ssl_fd_cb(server_name, file_descriptor):
    server = SERVERS[server_name]

    if server.ssl_hook:
        W.unhook(server.ssl_hook)
        server.ssl_hook = None

    try_ssl_handshake(server)

    return W.WEECHAT_RC_OK


def try_ssl_handshake(server):
    sock = server.socket

    while True:
        try:
            sock.do_handshake()

            cipher = sock.cipher()
            cipher_message = ("{prefix}matrix: Connected using {tls}, and "
                              "{bit} bit {cipher} cipher suite.").format(
                                  prefix=W.prefix("network"),
                                  tls=cipher[1],
                                  bit=cipher[2],
                                  cipher=cipher[0])
            W.prnt(server.server_buffer, cipher_message)

            # TODO print out the certificates
            # cert = sock.getpeercert()
            # W.prnt(server.server_buffer, pprint.pformat(cert))

            finalize_connection(server)

            return True

        except ssl.SSLWantReadError:
            hook = W.hook_fd(
                server.socket.fileno(),
                1, 0, 0,
                "ssl_fd_cb",
                server.name
            )
            server.ssl_hook = hook

            return False

        except ssl.SSLWantWriteError:
            hook = W.hook_fd(
                server.socket.fileno(),
                0, 1, 0,
                "ssl_fd_cb",
                server.name
            )
            server.ssl_hook = hook

            return False

        except ssl.SSLError as error:
            str_error = error.reason if error.reason else "Unknown error"

            message = ("{prefix}Error while doing SSL handshake"
                       ": {error}").format(
                prefix=W.prefix("network"),
                error=str_error)

            server_buffer_prnt(server, message)

            server_buffer_prnt(
                server,
                ("{prefix}matrix: disconnecting from server...").format(
                    prefix=W.prefix("network")))

            server.disconnect()
            return False


@utf8_decode
def receive_cb(server_name, file_descriptor):
    server = SERVERS[server_name]

    while True:
        try:
            data = server.socket.recv(4096)
        except ssl.SSLWantReadError:
            break
        except socket.error as error:
            errno = "error" + str(error.errno) + " " if error.errno else ""
            str_error = error.strerror if error.strerror else "Unknown error"
            str_error = errno + str_error

            message = ("{prefix}Error while reading from "
                       "socket: {error}").format(
                prefix=W.prefix("network"),
                error=str_error)

            server_buffer_prnt(server, message)

            server_buffer_prnt(
                server,
                ("{prefix}matrix: disconnecting from server...").format(
                    prefix=W.prefix("network")))

            server.disconnect()

            # Queue the failed message for resending
            if server.receive_queue:
                message = server.receive_queue.popleft()
                server.send_queue.appendleft(message)

            return W.WEECHAT_RC_OK

        if not data:
            server_buffer_prnt(
                server,
                "{prefix}matrix: Error while reading from socket".format(
                    prefix=W.prefix("network")))
            server_buffer_prnt(
                server,
                ("{prefix}matrix: disconnecting from server...").format(
                    prefix=W.prefix("network")))

            # Queue the failed message for resending
            if server.receive_queue:
                message = server.receive_queue.popleft()
                server.send_queue.appendleft(message)

            server.disconnect()
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
            receive_time = time.time()
            server.lag = (receive_time - message.send_time) * 1000
            W.bar_item_update("lag")
            message.receive_time = receive_time

            prnt_debug(DebugType.MESSAGING, server,
                       ("{prefix}Received message of type {t} and "
                        "status {s}").format(
                            prefix=W.prefix("error"),
                            t=message.type,
                            s=status))

            # Message done, reset the parser state.
            server.reset_parser()

            handle_http_response(server, message)
            break

    return W.WEECHAT_RC_OK


def finalize_connection(server):
    hook = W.hook_fd(
        server.socket.fileno(),
        1, 0, 0,
        "receive_cb",
        server.name
    )

    server.fd_hook = hook
    server.connected = True
    server.connecting = False

    matrix_login(server)


@utf8_decode
def connect_cb(data, status, gnutls_rc, sock, error, ip_address):
    # pylint: disable=too-many-arguments,too-many-branches
    status_value = int(status)  # type: int
    server = SERVERS[data]

    if status_value == W.WEECHAT_HOOK_CONNECT_OK:
        file_descriptor = int(sock)  # type: int
        server.numeric_address = ip_address
        server_buffer_set_title(server)

        wrap_socket(server, file_descriptor)

        return W.WEECHAT_RC_OK

    elif status_value == W.WEECHAT_HOOK_CONNECT_ADDRESS_NOT_FOUND:
        W.prnt(
            server.server_buffer,
            '{address} not found'.format(address=ip_address)
        )

    elif status_value == W.WEECHAT_HOOK_CONNECT_IP_ADDRESS_NOT_FOUND:
        W.prnt(server.server_buffer, 'IP address not found')

    elif status_value == W.WEECHAT_HOOK_CONNECT_CONNECTION_REFUSED:
        W.prnt(server.server_buffer, 'Connection refused')

    elif status_value == W.WEECHAT_HOOK_CONNECT_PROXY_ERROR:
        W.prnt(
            server.server_buffer,
            'Proxy fails to establish connection to server'
        )

    elif status_value == W.WEECHAT_HOOK_CONNECT_LOCAL_HOSTNAME_ERROR:
        W.prnt(server.server_buffer, 'Unable to set local hostname')

    elif status_value == W.WEECHAT_HOOK_CONNECT_GNUTLS_INIT_ERROR:
        W.prnt(server.server_buffer, 'TLS init error')

    elif status_value == W.WEECHAT_HOOK_CONNECT_GNUTLS_HANDSHAKE_ERROR:
        W.prnt(server.server_buffer, 'TLS Handshake failed')

    elif status_value == W.WEECHAT_HOOK_CONNECT_MEMORY_ERROR:
        W.prnt(server.server_buffer, 'Not enough memory')

    elif status_value == W.WEECHAT_HOOK_CONNECT_TIMEOUT:
        W.prnt(server.server_buffer, 'Timeout')

    elif status_value == W.WEECHAT_HOOK_CONNECT_SOCKET_ERROR:
        W.prnt(server.server_buffer, 'Unable to create socket')
    else:
        W.prnt(
            server.server_buffer,
            'Unexpected error: {status}'.format(status=status_value)
        )

    server.schedule_reconnect()
    return W.WEECHAT_RC_OK


@utf8_decode
def room_input_cb(server_name, buffer, input_data):
    server = SERVERS[server_name]

    if not server.connected:
        message = "{prefix}matrix: you are not connected to the server".format(
            prefix=W.prefix("error"))
        W.prnt(buffer, message)
        return W.WEECHAT_RC_ERROR

    room_id = key_from_value(server.buffers, buffer)
    room = server.rooms[room_id]

    if room.encrypted:
        return W.WEECHAT_RC_OK

    formatted_data = colors.parse_input_line(input_data)

    body = {
        "msgtype": "m.text",
        "body": colors.formatted_to_plain(formatted_data)
    }

    if colors.formatted(formatted_data):
        body["format"] = "org.matrix.custom.html"
        body["formatted_body"] = colors.formatted_to_html(formatted_data)

    extra_data = {
        "author": server.user,
        "message": colors.formatted_to_weechat(W, formatted_data),
        "room_id": room_id
    }

    message = MatrixMessage(server, OPTIONS, MessageType.SEND,
                            data=body, room_id=room_id,
                            extra_data=extra_data)

    server.send_or_queue(message)
    return W.WEECHAT_RC_OK


@utf8_decode
def room_close_cb(data, buffer):
    W.prnt("", "Buffer '%s' will be closed!" %
           W.buffer_get_string(buffer, "name"))
    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_unload_cb():
    matrix_config_free(matrix.globals.CONFIG)
    return W.WEECHAT_RC_OK


def autoconnect(servers):
    for server in servers.values():
        if server.autoconnect:
            server.connect()


if __name__ == "__main__":
    if W.register(WEECHAT_SCRIPT_NAME,
                  WEECHAT_SCRIPT_AUTHOR,
                  WEECHAT_SCRIPT_VERSION,
                  WEECHAT_SCRIPT_LICENSE,
                  WEECHAT_SCRIPT_DESCRIPTION,
                  'matrix_unload_cb',
                  ''):

        # TODO if this fails we should abort and unload the script.

        matrix.globals.CONFIG = W.config_new(
            "matrix",
            "matrix_config_reload_cb",
            ""
        )
        matrix_config_init(matrix.globals.CONFIG)
        matrix_config_read(matrix.globals.CONFIG)

        hook_commands()
        init_bar_items()
        init_completion()

        if not SERVERS:
            create_default_server(matrix.globals.CONFIG)

        autoconnect(SERVERS)
