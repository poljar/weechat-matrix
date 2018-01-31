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

import time
import ssl
import socket
import pprint

from builtins import bytes, str

import matrix.globals
from matrix.plugin_options import DebugType
from matrix.utils import prnt_debug, server_buffer_prnt, create_server_buffer
from matrix.utf import utf8_decode


W = matrix.globals.W


def close_socket(server):
    # type: (MatrixServer) -> None
    server.socket.shutdown(socket.SHUT_RDWR)
    server.socket.close()


def disconnect(server):
    # type: (MatrixServer) -> None
    if server.fd_hook:
        W.unhook(server.fd_hook)

    server.fd_hook = None
    server.socket = None
    server.connected = False

    server_buffer_prnt(server, "Disconnected")


def connect(server):
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

    ssl_message = " (SSL)" if server.ssl_context.check_hostname else ""

    message = "{prefix}matrix: Connecting to {server}:{port}{ssl}...".format(
        prefix=W.prefix("network"),
        server=server.address,
        port=server.port,
        ssl=ssl_message)

    W.prnt(server.server_buffer, message)

    W.hook_connect("", server.address, server.port, 1, 0, "",
                   "connect_cb", server.name)

    return W.WEECHAT_RC_OK


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
