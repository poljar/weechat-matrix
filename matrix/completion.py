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

from matrix.utf import utf8_decode
from matrix.globals import W, SERVERS, OPTIONS
from matrix.utils import tags_from_line_data


def add_servers_to_completion(completion):
    for server_name in SERVERS:
        W.hook_completion_list_add(completion, server_name, 0,
                                   W.WEECHAT_LIST_POS_SORT)


@utf8_decode
def matrix_server_command_completion_cb(data, completion_item, buffer,
                                        completion):
    buffer_input = W.buffer_get_string(buffer, "input").split()

    args = buffer_input[1:]
    commands = ['add', 'delete', 'list', 'listfull']

    def complete_commands():
        for command in commands:
            W.hook_completion_list_add(completion, command, 0,
                                       W.WEECHAT_LIST_POS_SORT)

    if len(args) == 1:
        complete_commands()

    elif len(args) == 2:
        if args[1] not in commands:
            complete_commands()
        else:
            if args[1] == 'delete' or args[1] == 'listfull':
                add_servers_to_completion(completion)

    elif len(args) == 3:
        if args[1] == 'delete' or args[1] == 'listfull':
            if args[2] not in SERVERS:
                add_servers_to_completion(completion)

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_server_completion_cb(data, completion_item, buffer, completion):
    add_servers_to_completion(completion)
    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_command_completion_cb(data, completion_item, buffer, completion):
    for command in [
            "connect", "disconnect", "reconnect", "server", "help", "debug"
    ]:
        W.hook_completion_list_add(completion, command, 0,
                                   W.WEECHAT_LIST_POS_SORT)
    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_debug_completion_cb(data, completion_item, buffer, completion):
    for debug_type in ["messaging", "network", "timing"]:
        W.hook_completion_list_add(completion, debug_type, 0,
                                   W.WEECHAT_LIST_POS_SORT)
    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_message_completion_cb(data, completion_item, buffer, completion):
    own_lines = W.hdata_pointer(W.hdata_get('buffer'), buffer, 'own_lines')
    if own_lines:
        line = W.hdata_pointer(W.hdata_get('lines'), own_lines, 'last_line')

        line_number = 1

        while line:
            line_data = W.hdata_pointer(W.hdata_get('line'), line, 'data')

            if line_data:
                message = W.hdata_string(
                    W.hdata_get('line_data'), line_data, 'message')

                tags = tags_from_line_data(line_data)

                # Only add non redacted user messages to the completion
                if (message and 'matrix_message' in tags and
                        'matrix_redacted' not in tags):

                    if len(message) > OPTIONS.redaction_comp_len + 2:
                        message = (message[:OPTIONS.redaction_comp_len] + '..')

                    item = ("{number}:\"{message}\"").format(
                        number=line_number, message=message)

                    W.hook_completion_list_add(completion, item, 0,
                                               W.WEECHAT_LIST_POS_END)
                    line_number += 1

            line = W.hdata_move(W.hdata_get('line'), line, -1)

    return W.WEECHAT_RC_OK


def server_from_buffer(buffer):
    for server in SERVERS.values():
            if buffer in server.buffers.values():
                return server
            elif buffer == server.server_buffer:
                return server
    return None


@utf8_decode
def matrix_olm_user_completion_cb(data, completion_item, buffer, completion):
    server = server_from_buffer(buffer)

    if not server:
        return W.WEECHAT_RC_OK

    olm = server.olm

    for user in olm.device_keys:
        W.hook_completion_list_add(completion, user, 0,
                                   W.WEECHAT_LIST_POS_SORT)

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_olm_device_completion_cb(data, completion_item, buffer, completion):
    server = server_from_buffer(buffer)

    if not server:
        return W.WEECHAT_RC_OK

    olm = server.olm

    args = W.hook_completion_get_string(completion, "args")

    fields = args.split()

    if len(fields) < 2:
        return W.WEECHAT_RC_OK

    user = fields[1]

    if user not in olm.device_keys:
        return W.WEECHAT_RC_OK

    for device in olm.device_keys[user]:
        W.hook_completion_list_add(completion, device.device_id, 0,
                                   W.WEECHAT_LIST_POS_SORT)

    return W.WEECHAT_RC_OK


def init_completion():
    W.hook_completion("matrix_server_commands", "Matrix server completion",
                      "matrix_server_command_completion_cb", "")

    W.hook_completion("matrix_servers", "Matrix server completion",
                      "matrix_server_completion_cb", "")

    W.hook_completion("matrix_commands", "Matrix command completion",
                      "matrix_command_completion_cb", "")

    W.hook_completion("matrix_messages", "Matrix message completion",
                      "matrix_message_completion_cb", "")

    W.hook_completion("matrix_debug_types", "Matrix debugging type completion",
                      "matrix_debug_completion_cb", "")

    W.hook_completion("olm_user_ids", "Matrix olm user id completion",
                      "matrix_olm_user_completion_cb", "")

    W.hook_completion("olm_devices", "Matrix olm device id completion",
                      "matrix_olm_device_completion_cb", "")
