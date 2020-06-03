# -*- coding: utf-8 -*-

# Copyright © 2018, 2019 Damir Jelić <poljar@termina.org.uk>
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

from typing import List, Optional
from matrix.globals import SERVERS, W, SCRIPT_NAME
from matrix.utf import utf8_decode
from matrix.utils import tags_from_line_data
from nio import LocalProtocolError


def add_servers_to_completion(completion):
    for server_name in SERVERS:
        W.hook_completion_list_add(
            completion, server_name, 0, W.WEECHAT_LIST_POS_SORT
        )


@utf8_decode
def matrix_server_command_completion_cb(
    data, completion_item, buffer, completion
):
    buffer_input = W.buffer_get_string(buffer, "input").split()

    args = buffer_input[1:]
    commands = ["add", "delete", "list", "listfull"]

    def complete_commands():
        for command in commands:
            W.hook_completion_list_add(
                completion, command, 0, W.WEECHAT_LIST_POS_SORT
            )

    if len(args) == 1:
        complete_commands()

    elif len(args) == 2:
        if args[1] not in commands:
            complete_commands()
        else:
            if args[1] == "delete" or args[1] == "listfull":
                add_servers_to_completion(completion)

    elif len(args) == 3:
        if args[1] == "delete" or args[1] == "listfull":
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
        "connect",
        "disconnect",
        "reconnect",
        "server",
        "help",
        "debug",
    ]:
        W.hook_completion_list_add(
            completion, command, 0, W.WEECHAT_LIST_POS_SORT
        )
    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_debug_completion_cb(data, completion_item, buffer, completion):
    for debug_type in ["messaging", "network", "timing"]:
        W.hook_completion_list_add(
            completion, debug_type, 0, W.WEECHAT_LIST_POS_SORT
        )
    return W.WEECHAT_RC_OK


# TODO this should be configurable
REDACTION_COMP_LEN = 50


@utf8_decode
def matrix_message_completion_cb(data, completion_item, buffer, completion):
    max_events = 500

    def redacted_or_not_message(tags):
        # type: (List[str]) -> bool
        if SCRIPT_NAME + "_redacted" in tags:
            return True
        if SCRIPT_NAME + "_message" not in tags:
            return True

        return False

    def event_id_from_tags(tags):
        # type: (List[str]) -> Optional[str]
        for tag in tags:
            if tag.startswith("matrix_id"):
                event_id = tag[10:]
                return event_id

        return None

    for server in SERVERS.values():
        if buffer in server.buffers.values():
            room_buffer = server.find_room_from_ptr(buffer)
            lines = room_buffer.weechat_buffer.lines

            added = 0

            for line in lines:
                tags = line.tags
                if redacted_or_not_message(tags):
                    continue

                event_id = event_id_from_tags(tags)

                if not event_id:
                    continue

                # Make sure we'll be able to reliably detect the end of the
                # quoted snippet
                message_fmt = line.message.replace("\\", "\\\\") \
                                          .replace('"', '\\"')

                if len(message_fmt) > REDACTION_COMP_LEN + 2:
                    message_fmt = message_fmt[:REDACTION_COMP_LEN] + ".."

                item = ('{event_id}|"{message}"').format(
                    event_id=event_id, message=message_fmt
                )

                W.hook_completion_list_add(
                    completion, item, 0, W.WEECHAT_LIST_POS_END
                )
                added += 1

                if added >= max_events:
                    break

            return W.WEECHAT_RC_OK

    return W.WEECHAT_RC_OK


def server_from_buffer(buffer):
    for server in SERVERS.values():
        if buffer in server.buffers.values():
            return server
        if buffer == server.server_buffer:
            return server
    return None


@utf8_decode
def matrix_olm_user_completion_cb(data, completion_item, buffer, completion):
    server = server_from_buffer(buffer)

    if not server:
        return W.WEECHAT_RC_OK

    try:
        device_store = server.client.device_store
    except LocalProtocolError:
        return W.WEECHAT_RC_OK

    for user in device_store.users:
        W.hook_completion_list_add(
            completion, user, 0, W.WEECHAT_LIST_POS_SORT
        )

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_olm_device_completion_cb(data, completion_item, buffer, completion):
    server = server_from_buffer(buffer)

    if not server:
        return W.WEECHAT_RC_OK

    try:
        device_store = server.client.device_store
    except LocalProtocolError:
        return W.WEECHAT_RC_OK

    args = W.hook_completion_get_string(completion, "args")

    fields = args.split()

    if len(fields) < 2:
        return W.WEECHAT_RC_OK

    user = fields[-1]

    if user not in device_store.users:
        return W.WEECHAT_RC_OK

    for device in device_store.active_user_devices(user):
        W.hook_completion_list_add(
            completion, device.id, 0, W.WEECHAT_LIST_POS_SORT
        )

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_own_devices_completion_cb(
    data,
    completion_item,
    buffer,
    completion
):
    server = server_from_buffer(buffer)

    if not server:
        return W.WEECHAT_RC_OK

    olm = server.client.olm

    if not olm:
        return W.WEECHAT_RC_OK

    W.hook_completion_list_add(
        completion, olm.device_id, 0, W.WEECHAT_LIST_POS_SORT
    )

    user = olm.user_id

    if user not in olm.device_store.users:
        return W.WEECHAT_RC_OK

    for device in olm.device_store.active_user_devices(user):
        W.hook_completion_list_add(
            completion, device.id, 0, W.WEECHAT_LIST_POS_SORT
        )

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_user_completion_cb(data, completion_item, buffer, completion):
    def add_user(completion, user):
        W.hook_completion_list_add(
            completion, user, 0, W.WEECHAT_LIST_POS_SORT
        )

    for server in SERVERS.values():
        if buffer == server.server_buffer:
            return W.WEECHAT_RC_OK

        room_buffer = server.find_room_from_ptr(buffer)

        if not room_buffer:
            continue

        users = room_buffer.room.users

        users = [user[1:] for user in users]

        for user in users:
            add_user(completion, user)

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_room_completion_cb(data, completion_item, buffer, completion):
    """Completion callback for matrix room names."""
    for server in SERVERS.values():
        for room_buffer in server.room_buffers.values():
            name = room_buffer.weechat_buffer.short_name

            W.hook_completion_list_add(
                completion, name, 0, W.WEECHAT_LIST_POS_SORT
            )

    return W.WEECHAT_RC_OK


def init_completion():
    W.hook_completion(
        "matrix_server_commands",
        "Matrix server completion",
        "matrix_server_command_completion_cb",
        "",
    )

    W.hook_completion(
        "matrix_servers",
        "Matrix server completion",
        "matrix_server_completion_cb",
        "",
    )

    W.hook_completion(
        "matrix_commands",
        "Matrix command completion",
        "matrix_command_completion_cb",
        "",
    )

    W.hook_completion(
        "matrix_messages",
        "Matrix message completion",
        "matrix_message_completion_cb",
        "",
    )

    W.hook_completion(
        "matrix_debug_types",
        "Matrix debugging type completion",
        "matrix_debug_completion_cb",
        "",
    )

    W.hook_completion(
        "olm_user_ids",
        "Matrix olm user id completion",
        "matrix_olm_user_completion_cb",
        "",
    )

    W.hook_completion(
        "olm_devices",
        "Matrix olm device id completion",
        "matrix_olm_device_completion_cb",
        "",
    )

    W.hook_completion(
        "matrix_users",
        "Matrix user id completion",
        "matrix_user_completion_cb",
        "",
    )

    W.hook_completion(
        "matrix_own_devices",
        "Matrix own devices completion",
        "matrix_own_devices_completion_cb",
        "",
    )

    W.hook_completion(
        "matrix_rooms",
        "Matrix room name completion",
        "matrix_room_completion_cb",
        "",
    )
