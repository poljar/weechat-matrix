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

from builtins import bytes, str

import matrix.globals
from matrix.config import DebugType
from matrix.utils import prnt_debug, server_buffer_prnt


W = matrix.globals.W


def disconnect(server):
    # type: (MatrixServer) -> None
    if server.fd_hook:
        W.unhook(server.fd_hook)

    server.fd_hook    = None
    server.socket     = None
    server.connected  = False

    server_buffer_prnt(server, "Disconnected")


def send_or_queue(server, message):
    # type: (MatrixServer, MatrixMessage) -> None
    if not send(server, message):
        prnt_debug(DebugType.MESSAGING, server,
                   ("{prefix} Failed sending message of type {t}. "
                    "Adding to queue").format(
                        prefix=W.prefix("error"),
                        t=message.type))
        server.send_queue.append(message)


def send(server, message):
    # type: (MatrixServer, MatrixMessage) -> bool

    request = message.request.request
    payload = message.request.payload

    prnt_debug(DebugType.MESSAGING, server,
               "{prefix} Sending message of type {t}.".format(
                   prefix=W.prefix("error"),
                   t=message.type))

    try:
        start = time.time()

        # TODO we probably shouldn't use sendall here.
        server.socket.sendall(bytes(request, 'utf-8'))
        if payload:
            server.socket.sendall(bytes(payload, 'utf-8'))

        end = time.time()
        message.send_time = end
        send_time = (end - start) * 1000
        prnt_debug(DebugType.NETWORK, server,
                   ("Message done sending ({t}ms), putting message in the "
                    "receive queue.").format(t=send_time))

        server.receive_queue.append(message)
        return True

    except OSError as error:
        disconnect(server)
        server_buffer_prnt(server, str(error))
        return False
