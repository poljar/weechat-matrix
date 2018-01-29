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
from matrix.server import MatrixServer
from matrix.socket import disconnect, send_or_queue, send, connect
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

from matrix.bar_items import (
    init_bar_items,
    matrix_bar_item_name,
    matrix_bar_item_plugin
)

from matrix.completion import (
    init_completion,
    matrix_command_completion_cb,
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

from matrix.config import (
    DebugType,
    RedactType,
    ServerBufferType
)

import matrix.globals

W = matrix.globals.W
GLOBAL_OPTIONS = matrix.globals.OPTIONS
CONFIG = matrix.globals.CONFIG
SERVERS = matrix.globals.SERVERS


WEECHAT_SCRIPT_NAME = "matrix"                                 # type: str
WEECHAT_SCRIPT_DESCRIPTION = "matrix chat plugin"              # type: str
WEECHAT_SCRIPT_AUTHOR = "Damir Jelić <poljar@termina.org.uk>"  # type: str
WEECHAT_SCRIPT_VERSION = "0.1"                                 # type: str
WEECHAT_SCRIPT_LICENSE = "ISC"                                 # type: str


@utf8_decode
def server_config_change_cb(server_name, option):
    # type: (str, weechat.config_option) -> int
    server = SERVERS[server_name]
    option_name = None

    # The function config_option_get_string() is used to get differing
    # properties from a config option, sadly it's only available in the plugin
    # API of weechat.
    option_name = key_from_value(server.options, option)
    server.update_option(option, option_name, W)

    return 1


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

    try:
        ssl_socket = server.ssl_context.wrap_socket(
            sock,
            server_hostname=server.address)  # type: ssl.SSLSocket

        return ssl_socket
    # TODO add finer grained error messages with the subclass exceptions
    except ssl.SSLError as error:
        server_buffer_prnt(server, str(error))
        return None


@utf8_decode
def receive_cb(server_name, file_descriptor):
    server = SERVERS[server_name]

    while True:
        try:
            data = server.socket.recv(4096)
        except ssl.SSLWantReadError:
            break
        except socket.error as error:
            disconnect(server)

            # Queue the failed message for resending
            if server.receive_queue:
                message = server.receive_queue.popleft()
                server.send_queue.appendleft(message)

            server_buffer_prnt(server, pprint.pformat(error))
            return W.WEECHAT_RC_OK

        if not data:
            server_buffer_prnt(server, "No data while reading")

            # Queue the failed message for resending
            if server.receive_queue:
                message = server.receive_queue.popleft()
                server.send_queue.appendleft(message)

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
            receive_time = time.time()
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

            server.fd_hook = hook
            server.connected = True
            server.connecting = False
            server.reconnect_count = 0
            server.numeric_address = ip_address

            server_buffer_set_title(server)
            server_buffer_prnt(server, "Connected")

            if not server.access_token:
                matrix_login(server)
        else:
            reconnect(server)
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

    reconnect(server)
    return W.WEECHAT_RC_OK


def reconnect(server):
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


@utf8_decode
def reconnect_cb(server_name, remaining):
    server = SERVERS[server_name]
    connect(server)

    return W.WEECHAT_RC_OK


@utf8_decode
def room_input_cb(server_name, buffer, input_data):
    server = SERVERS[server_name]

    if not server.connected:
        message = "{prefix}you are not connected to the server".format(
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

    message = MatrixMessage(server, GLOBAL_OPTIONS, MessageType.SEND,
                            data=body, room_id=room_id,
                            extra_data=extra_data)

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
            server = MatrixServer(server_name, W, config_file)
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
def matrix_config_change_cb(data, option):
    option_name = key_from_value(GLOBAL_OPTIONS.options, option)

    if option_name == "redactions":
        GLOBAL_OPTIONS.redaction_type = RedactType(W.config_integer(option))
    elif option_name == "server_buffer":
        GLOBAL_OPTIONS.look_server_buf = ServerBufferType(
            W.config_integer(option))
    elif option_name == "max_initial_sync_events":
        GLOBAL_OPTIONS.sync_limit = W.config_integer(option)
    elif option_name == "max_backlog_sync_events":
        GLOBAL_OPTIONS.backlog_limit = W.config_integer(option)
    elif option_name == "fetch_backlog_on_pgup":
        GLOBAL_OPTIONS.enable_backlog = W.config_boolean(option)

        if GLOBAL_OPTIONS.enable_backlog:
            if not GLOBAL_OPTIONS.page_up_hook:
                hook_page_up(CONFIG)
        else:
            if GLOBAL_OPTIONS.page_up_hook:
                W.unhook(GLOBAL_OPTIONS.page_up_hook)
                GLOBAL_OPTIONS.page_up_hook = None

    return 1


def read_matrix_config():
    # type: () -> bool
    return_code = W.config_read(CONFIG)
    if return_code == W.WEECHAT_CONFIG_READ_OK:
        return True
    elif return_code == W.WEECHAT_CONFIG_READ_MEMORY_ERROR:
        return False
    elif return_code == W.WEECHAT_CONFIG_READ_FILE_NOT_FOUND:
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


def create_default_server(config_file):
    server = MatrixServer('matrix.org', W, config_file)
    SERVERS[server.name] = server

    W.config_option_set(server.options["address"], "matrix.org", 1)

    return True


def autoconnect(servers):
    for server in servers.values():
        if server.autoconnect:
            connect(server)


if __name__ == "__main__":
    if W.register(WEECHAT_SCRIPT_NAME,
                  WEECHAT_SCRIPT_AUTHOR,
                  WEECHAT_SCRIPT_VERSION,
                  WEECHAT_SCRIPT_LICENSE,
                  WEECHAT_SCRIPT_DESCRIPTION,
                  'matrix_unload_cb',
                  ''):

        # TODO if this fails we should abort and unload the script.
        CONFIG = matrix.globals.init_matrix_config()
        read_matrix_config()

        hook_commands()
        init_bar_items()
        init_completion()

        if not SERVERS:
            create_default_server(CONFIG)

        autoconnect(SERVERS)
