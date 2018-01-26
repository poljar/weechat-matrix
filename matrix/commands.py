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

import re

import matrix.globals

from matrix.utf import utf8_decode
from matrix.api import MatrixMessage, MessageType
from matrix.utils import key_from_value, tags_from_line_data
from matrix.socket import send_or_queue


W = matrix.globals.W
GLOBAL_OPTIONS = matrix.globals.OPTIONS
SERVERS = matrix.globals.SERVERS


def hook_commands():
    W.hook_completion(
        "matrix_server_commands",
        "Matrix server completion",
        "server_command_completion_cb",
        ""
    )

    W.hook_completion(
        "matrix_servers",
        "Matrix server completion",
        "matrix_server_completion_cb",
        ""
    )

    W.hook_completion(
        "matrix_commands",
        "Matrix command completion",
        "matrix_command_completion_cb",
        ""
    )

    W.hook_completion(
        "matrix_messages",
        "Matrix message completion",
        "matrix_message_completion_cb",
        ""
    )

    W.hook_completion(
        "matrix_debug_types",
        "Matrix debugging type completion",
        "matrix_debug_completion_cb",
        ""
    )

    W.hook_command(
        # Command name and short description
        'matrix', 'Matrix chat protocol command',
        # Synopsis
        (
            'server add <server-name> <hostname>[:<port>] ||'
            'server delete|list|listfull <server-name> ||'
            'connect <server-name> ||'
            'disconnect <server-name> ||'
            'reconnect <server-name> ||'
            'debug <debug-type> ||'
            'help <matrix-command>'
        ),
        # Description
        (
            '    server: list, add, or remove Matrix servers\n'
            '   connect: connect to Matrix servers\n'
            'disconnect: disconnect from one or all Matrix servers\n'
            ' reconnect: reconnect to server(s)\n\n'
            '      help: show detailed command help\n\n'
            '     debug: enable or disable debugging\n\n'
            'Use /matrix help [command] to find out more\n'
        ),
        # Completions
        (
            'server %(matrix_server_commands)|%* ||'
            'connect %(matrix_servers) ||'
            'disconnect %(matrix_servers) ||'
            'reconnect %(matrix_servers) ||'
            'debug %(matrix_debug_types) ||'
            'help %(matrix_commands)'
        ),
        # Function name
        'matrix_command_cb', '')

    W.hook_command(
        # Command name and short description
        'redact', 'redact messages',
        # Synopsis
        (
            '<message-number>[:<"message-part">] [<reason>]'
        ),
        # Description
        (
            "message-number: number of the message to redact (message numbers"
            "\n                start from the last recieved as "
            "1 and count up)\n"
            "  message-part: a shortened part of the message\n"
            "        reason: the redaction reason\n"
        ),
        # Completions
        (
            '%(matrix_messages)'
        ),
        # Function name
        'matrix_redact_command_cb', '')

    W.hook_command_run('/topic', 'matrix_command_topic_cb', '')
    W.hook_command_run('/buffer clear', 'matrix_command_buf_clear_cb', '')
    W.hook_command_run('/join', 'matrix_command_join_cb', '')
    W.hook_command_run('/part', 'matrix_command_part_cb', '')
    W.hook_command_run('/invite', 'matrix_command_invite_cb', '')

    if GLOBAL_OPTIONS.enable_backlog:
        hook_page_up()


def matrix_fetch_old_messages(server, room_id):
    room = server.rooms[room_id]
    prev_batch = room.prev_batch

    if not prev_batch:
        return

    message = MatrixMessage(server, GLOBAL_OPTIONS, MessageType.ROOM_MSG,
                            room_id=room_id, extra_id=prev_batch)

    send_or_queue(server, message)

    return


def hook_page_up():
    GLOBAL_OPTIONS.page_up_hook = W.hook_command_run(
        '/window page_up',
        'matrix_command_pgup_cb',
        ''
    )


@utf8_decode
def matrix_debug_completion_cb(data, completion_item, buffer, completion):
    for debug_type in ["messaging", "network", "timing"]:
        W.hook_completion_list_add(
            completion,
            debug_type,
            0,
            W.WEECHAT_LIST_POS_SORT)
    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_command_buf_clear_cb(data, buffer, command):
    for server in SERVERS.values():
        if buffer in server.buffers.values():
            room_id = key_from_value(server.buffers, buffer)
            server.rooms[room_id].prev_batch = server.next_batch

            return W.WEECHAT_RC_OK

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_command_pgup_cb(data, buffer, command):
    # TODO the highlight status of a line isn't allowed to be updated/changed
    # via hdata, therefore the highlight status of a messages can't be
    # reoredered this would need to be fixed in weechat
    # TODO we shouldn't fetch and print out more messages than
    # max_buffer_lines_number or older messages than max_buffer_lines_minutes
    for server in SERVERS.values():
        if buffer in server.buffers.values():
            window = W.window_search_with_buffer(buffer)

            first_line_displayed = bool(
                W.window_get_integer(window, "first_line_displayed")
            )

            if first_line_displayed:
                room_id = key_from_value(server.buffers, buffer)
                matrix_fetch_old_messages(server, room_id)

            return W.WEECHAT_RC_OK

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_command_join_cb(data, buffer, command):
    def join(server, args):
        split_args = args.split(" ", 1)

        # TODO handle join for non public rooms
        if len(split_args) != 2:
            message = ("{prefix}Error with command \"/join\" (help on "
                       "command: /help join)").format(
                           prefix=W.prefix("error"))
            W.prnt("", message)
            return

        _, room_id = split_args
        message = MatrixMessage(
            server,
            GLOBAL_OPTIONS,
            MessageType.JOIN,
            room_id=room_id
        )
        send_or_queue(server, message)

    for server in SERVERS.values():
        if buffer in server.buffers.values():
            join(server, command)
            return W.WEECHAT_RC_OK_EAT
        elif buffer == server.server_buffer:
            join(server, command)
            return W.WEECHAT_RC_OK_EAT

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_command_part_cb(data, buffer, command):
    def part(server, buffer, args):
        rooms = []

        split_args = args.split(" ", 1)

        if len(split_args) == 1:
            if buffer == server.server_buffer:
                message = ("{prefix}Error with command \"/part\" (help on "
                           "command: /help part)").format(
                               prefix=W.prefix("error"))
                W.prnt("", message)
                return

            rooms = [key_from_value(server.buffers, buffer)]

        else:
            _, rooms = split_args
            rooms = rooms.split(" ")

        for room_id in rooms:
            message = MatrixMessage(
                server,
                GLOBAL_OPTIONS,
                MessageType.PART,
                room_id=room_id
            )
            send_or_queue(server, message)

    for server in SERVERS.values():
        if buffer in server.buffers.values():
            part(server, buffer, command)
            return W.WEECHAT_RC_OK_EAT
        elif buffer == server.server_buffer:
            part(server, buffer, command)
            return W.WEECHAT_RC_OK_EAT

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_command_invite_cb(data, buffer, command):
    def invite(server, buf, args):
        split_args = args.split(" ", 1)

        # TODO handle join for non public rooms
        if len(split_args) != 2:
            message = ("{prefix}Error with command \"/invite\" (help on "
                       "command: /help invite)").format(
                           prefix=W.prefix("error"))
            W.prnt("", message)
            return

        _, invitee = split_args
        room_id = key_from_value(server.buffers, buf)

        body = {"user_id": invitee}

        message = MatrixMessage(
            server,
            GLOBAL_OPTIONS,
            MessageType.INVITE,
            room_id=room_id,
            data=body
        )
        send_or_queue(server, message)

    for server in SERVERS.values():
        if buffer in server.buffers.values():
            invite(server, buffer, command)
            return W.WEECHAT_RC_OK_EAT

    return W.WEECHAT_RC_OK


def event_id_from_line(buf, target_number):
    # type: (weechat.buffer, int) -> str
    own_lines = W.hdata_pointer(W.hdata_get('buffer'), buf, 'own_lines')
    if own_lines:
        line = W.hdata_pointer(
            W.hdata_get('lines'),
            own_lines,
            'last_line'
        )

        line_number = 1

        while line:
            line_data = W.hdata_pointer(
                W.hdata_get('line'),
                line,
                'data'
            )

            if line_data:
                tags = tags_from_line_data(line_data)

                # Only count non redacted user messages
                if ("matrix_message" in tags
                        and 'matrix_redacted' not in tags
                        and "matrix_new_redacted" not in tags):

                    if line_number == target_number:
                        for tag in tags:
                            if tag.startswith("matrix_id"):
                                event_id = tag[10:]
                                return event_id

                    line_number += 1

            line = W.hdata_move(W.hdata_get('line'), line, -1)

    return ""


@utf8_decode
def matrix_redact_command_cb(data, buffer, args):
    for server in SERVERS.values():
        if buffer in server.buffers.values():
            body = {}

            room_id = key_from_value(server.buffers, buffer)

            matches = re.match(r"(\d+)(:\".*\")? ?(.*)?", args)

            if not matches:
                message = ("{prefix}matrix: Invalid command arguments (see "
                           "the help for the command /help redact)").format(
                               prefix=W.prefix("error"))
                W.prnt("", message)
                return W.WEECHAT_RC_ERROR

            line_string, _, reason = matches.groups()
            line = int(line_string)

            if reason:
                body = {"reason": reason}

            event_id = event_id_from_line(buffer, line)

            if not event_id:
                message = ("{prefix}matrix: No such message with number "
                           "{number} found").format(
                               prefix=W.prefix("error"),
                               number=line)
                W.prnt("", message)
                return W.WEECHAT_RC_OK

            message = MatrixMessage(
                server,
                GLOBAL_OPTIONS,
                MessageType.REDACT,
                data=body,
                room_id=room_id,
                extra_id=event_id
            )
            send_or_queue(server, message)

            return W.WEECHAT_RC_OK

        elif buffer == server.server_buffer:
            message = ("{prefix}matrix: command \"redact\" must be "
                       "executed on a Matrix channel buffer").format(
                           prefix=W.prefix("error"))
            W.prnt("", message)
            return W.WEECHAT_RC_OK

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_message_completion_cb(data, completion_item, buffer, completion):
    own_lines = W.hdata_pointer(W.hdata_get('buffer'), buffer, 'own_lines')
    if own_lines:
        line = W.hdata_pointer(
            W.hdata_get('lines'),
            own_lines,
            'last_line'
        )

        line_number = 1

        while line:
            line_data = W.hdata_pointer(
                W.hdata_get('line'),
                line,
                'data'
            )

            if line_data:
                message = W.hdata_string(W.hdata_get('line_data'), line_data,
                                         'message')

                tags = tags_from_line_data(line_data)

                # Only add non redacted user messages to the completion
                if (message
                        and 'matrix_message' in tags
                        and 'matrix_redacted' not in tags):

                    if len(message) > GLOBAL_OPTIONS.redaction_comp_len + 2:
                        message = (
                            message[:GLOBAL_OPTIONS.redaction_comp_len]
                            + '..')

                    item = ("{number}:\"{message}\"").format(
                        number=line_number,
                        message=message)

                    W.hook_completion_list_add(
                        completion,
                        item,
                        0,
                        W.WEECHAT_LIST_POS_END)
                    line_number += 1

            line = W.hdata_move(W.hdata_get('line'), line, -1)

    return W.WEECHAT_RC_OK
