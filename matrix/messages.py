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

import time
import pprint
import datetime

from matrix.globals import W

import matrix.api as API

from matrix.utils import server_buffer_prnt, prnt_debug
from matrix.plugin_options import DebugType


def print_message_error(server, message):
    server_buffer_prnt(server, ("{prefix}Unhandled {status_code} error, please "
                                "inform the developers about this.").format(
                                    prefix=W.prefix("error"),
                                    status_code=message.response.status))

    server_buffer_prnt(server, pprint.pformat(message.__class__.__name__))
    server_buffer_prnt(server, pprint.pformat(message.request.payload))
    server_buffer_prnt(server, pprint.pformat(message.response.body))


def handle_http_response(server, message):
    # type: (MatrixServer, MatrixMessage) -> None

    assert message.response

    if ('content-type' in message.response.headers and
            message.response.headers['content-type'] == 'application/json'):
        ret, error = message.decode_body(server)

        if not ret:
            message = ("{prefix}matrix: Error decoding json response from "
                       "server: {error}").format(
                           prefix=W.prefix("error"), error=error)
            W.prnt(server.server_buffer, message)
            return

        event = message.event
        event.execute()
    else:
        status_code = message.response.status
        if status_code == 504:
            if isinstance(message, API.MatrixSyncMessage):
                server.sync()
            else:
                print_message_error(server, message)
        else:
            print_message_error(server, message)

    creation_date = datetime.datetime.fromtimestamp(message.creation_time)
    done_time = time.time()
    info_message = ("Message of type {t} created at {c}."
                    "\nMessage lifetime information:"
                    "\n    Send delay: {s} ms"
                    "\n    Receive delay: {r} ms"
                    "\n    Handling time: {h} ms"
                    "\n    Total time: {total} ms").format(
                        t=message.type,
                        c=creation_date,
                        s=(message.send_time - message.creation_time) * 1000,
                        r=(message.receive_time - message.send_time) * 1000,
                        h=(done_time - message.receive_time) * 1000,
                        total=(done_time - message.creation_time) * 1000,
                    )
    prnt_debug(DebugType.TIMING, server, info_message)

    return
