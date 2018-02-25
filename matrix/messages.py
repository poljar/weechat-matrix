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

from operator import itemgetter

from matrix.globals import W

from matrix.api import MessageType

from matrix.utils import (server_buffer_prnt, tags_from_line_data, prnt_debug,
                          color_for_tags, add_user_to_nicklist,
                          get_prefix_for_level)
from matrix.plugin_options import DebugType


def matrix_sort_old_messages(server, room_id):
    lines = []
    buf = server.buffers[room_id]

    own_lines = W.hdata_pointer(W.hdata_get('buffer'), buf, 'own_lines')

    if own_lines:
        hdata_line = W.hdata_get('line')
        hdata_line_data = W.hdata_get('line_data')
        line = W.hdata_pointer(W.hdata_get('lines'), own_lines, 'first_line')

        while line:
            data = W.hdata_pointer(hdata_line, line, 'data')

            line_data = {}

            if data:
                date = W.hdata_time(hdata_line_data, data, 'date')
                print_date = W.hdata_time(hdata_line_data, data, 'date_printed')
                tags = tags_from_line_data(data)
                prefix = W.hdata_string(hdata_line_data, data, 'prefix')
                message = W.hdata_string(hdata_line_data, data, 'message')

                line_data = {
                    'date': date,
                    'date_printed': print_date,
                    'tags_array': ','.join(tags),
                    'prefix': prefix,
                    'message': message
                }

                lines.append(line_data)

            line = W.hdata_move(hdata_line, line, 1)

        sorted_lines = sorted(lines, key=itemgetter('date'))
        lines = []

        # We need to convert the dates to a string for hdata_update(), this
        # will reverse the list at the same time
        while sorted_lines:
            line = sorted_lines.pop()
            new_line = {k: str(v) for k, v in line.items()}
            lines.append(new_line)

        matrix_update_buffer_lines(lines, own_lines)


def matrix_update_buffer_lines(new_lines, own_lines):
    hdata_line = W.hdata_get('line')
    hdata_line_data = W.hdata_get('line_data')

    line = W.hdata_pointer(W.hdata_get('lines'), own_lines, 'first_line')

    while line:
        data = W.hdata_pointer(hdata_line, line, 'data')

        if data:
            W.hdata_update(hdata_line_data, data, new_lines.pop())

        line = W.hdata_move(hdata_line, line, 1)


def matrix_handle_message(
        server,  # type: MatrixServer
        message,  # type: MatrixMessage
):
    # type: (...) -> None
    message_type = message.type
    response = message.decoded_response

    if message_type is MessageType.LOGIN:
        event = message.event
        event.execute()

    elif message_type is MessageType.TOPIC:
        event = message.event
        event.execute()

    elif message_type is MessageType.JOIN:
        event = message.event
        event.execute()

    elif message_type is MessageType.PART:
        event = message.event
        event.execute()

    elif message_type is MessageType.INVITE:
        event = message.event
        event.execute()

    elif message_type is MessageType.SEND:
        event = message.event
        event.execute()

    elif message_type == MessageType.REDACT:
        event = message.event
        event.execute()

    elif message_type == MessageType.ROOM_MSG:
        event = message.event
        event.execute()
        matrix_sort_old_messages(server, message.room_id)

    elif message_type is MessageType.SYNC:
        event = message.event
        event.execute()

    else:
        server_buffer_prnt(
            server,
            "Handling of message type {type} not implemented".format(
                type=message_type))


def handle_http_response(server, message):
    # type: (MatrixServer, MatrixMessage) -> None

    assert message.response

    if ('content-type' in message.response.headers and
            message.response.headers['content-type'] == 'application/json'):
        ret, error = message.decode_body(server)

        if not ret:
            # TODO try to resend the message if decoding has failed?
            message = ("{prefix}matrix: Error decoding json response from "
                       "server: {error}").format(
                           prefix=W.prefix("error"), error=error)

            W.prnt(server.server_buffer, message)
            return

    status_code = message.response.status
    if status_code == 200:
        matrix_handle_message(
            server,
            message,
        )

    # TODO handle try again response
    elif status_code == 504:
        if message.type == MessageType.SYNC:
            server.sync()

    elif status_code == 403:
        if message.type == MessageType.LOGIN:
            event = message.event
            event.execute()

        elif message.type == MessageType.TOPIC:
            event = message.event
            event.execute()

        elif message.type == MessageType.REDACT:
            event = message.event
            event.execute()

        elif message.type == MessageType.SEND:
            event = message.event
            event.execute()

        elif message.type == MessageType.JOIN:
            event = message.event
            event.execute()

        elif message.type == MessageType.PART:
            event = message.event
            event.execute()

        elif message.type == MessageType.INVITE:
            event = message.event
            event.execute()

        else:
            error_message = ("{prefix}Unhandled 403 error, please inform the "
                             "developers about this: {error}").format(
                                 prefix=W.prefix("error"),
                                 error=message.response.body)
            server_buffer_prnt(server, error_message)

    elif status_code == 404:
        if message.type == MessageType.JOIN:
            event = message.event
            event.execute()

        else:
            error_message = ("{prefix}Unhandled 404 error, please inform the "
                             "developers about this: {error}").format(
                                 prefix=W.prefix("error"),
                                 error=message.response.body)
            server_buffer_prnt(server, error_message)

    else:
        server_buffer_prnt(
            server, ("{prefix}Unhandled {status_code} error, please inform "
                     "the developers about this.").format(
                         prefix=W.prefix("error"), status_code=status_code))

        server_buffer_prnt(server, pprint.pformat(message.type))
        server_buffer_prnt(server, pprint.pformat(message.request.payload))
        server_buffer_prnt(server, pprint.pformat(message.response.body))

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
