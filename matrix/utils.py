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

from matrix.globals import W, SERVERS, OPTIONS

from matrix.plugin_options import ServerBufferType


def key_from_value(dictionary, value):
    # type: (Dict[str, Any], Any) -> str
    return list(dictionary.keys())[list(dictionary.values()).index(value)]


def prnt_debug(debug_type, server, message):
    if debug_type in OPTIONS.debug:
        W.prnt(server.server_buffer, message)


def server_buffer_prnt(server, string):
    # type: (MatrixServer, str) -> None
    assert server.server_buffer
    buffer = server.server_buffer
    now = int(time.time())
    W.prnt_date_tags(buffer, now, "", string)


def tags_from_line_data(line_data):
    # type: (weechat.hdata) -> List[str]
    tags_count = W.hdata_get_var_array_size(
        W.hdata_get('line_data'), line_data, 'tags_array')

    tags = [
        W.hdata_string(
            W.hdata_get('line_data'), line_data, '%d|tags_array' % i)
        for i in range(tags_count)
    ]

    return tags


def create_server_buffer(server):
    # type: (MatrixServer) -> None
    server.server_buffer = W.buffer_new(server.name, "server_buffer_cb",
                                        server.name, "", "")

    server_buffer_set_title(server)
    W.buffer_set(server.server_buffer, "localvar_set_type", 'server')
    W.buffer_set(server.server_buffer, "localvar_set_nick", server.user)
    W.buffer_set(server.server_buffer, "localvar_set_server", server.name)
    W.buffer_set(server.server_buffer, "localvar_set_channel", server.name)

    server_buffer_merge(server.server_buffer)


def server_buffer_merge(buffer):
    if OPTIONS.look_server_buf == ServerBufferType.MERGE_CORE:
        num = W.buffer_get_integer(W.buffer_search_main(), "number")
        W.buffer_unmerge(buffer, num + 1)
        W.buffer_merge(buffer, W.buffer_search_main())
    elif OPTIONS.look_server_buf == ServerBufferType.MERGE:
        if SERVERS:
            first = None
            for server in SERVERS.values():
                if server.server_buffer:
                    first = server.server_buffer
                    break
            if first:
                num = W.buffer_get_integer(W.buffer_search_main(), "number")
                W.buffer_unmerge(buffer, num + 1)
                if buffer is not first:
                    W.buffer_merge(buffer, first)
    else:
        num = W.buffer_get_integer(W.buffer_search_main(), "number")
        W.buffer_unmerge(buffer, num + 1)


def server_buffer_set_title(server):
    # type: (MatrixServer) -> None
    if server.numeric_address:
        ip_string = " ({address})".format(address=server.numeric_address)
    else:
        ip_string = ""

    title = ("Matrix: {address}:{port}{ip}").format(
        address=server.address, port=server.port, ip=ip_string)

    W.buffer_set(server.server_buffer, "title", title)


def color_for_tags(color):
    if color == "weechat.color.chat_nick_self":
        option = W.config_get(color)
        return W.config_string(option)
    return color


def date_from_age(age):
    # type: (float) -> int
    now = time.time()
    date = int(now - (age / 1000))
    return date


def strip_matrix_server(string):
    # type: (str) -> str
    return string.rsplit(":", 1)[0]


def shorten_sender(sender):
    # type: (str) -> str
    return strip_matrix_server(sender)[1:]


def sender_to_nick_and_color(room, sender):
    nick = sender
    nick_color_name = "default"

    if sender in room.users:
        user = room.users[sender]
        nick = user.display_name
        nick_color_name = user.nick_color
    else:
        nick = shorten_sender(sender)
        nick_color_name = W.info_get("nick_color_name", nick)

    return (nick, nick_color_name)


def tags_for_message(message_type):
    default_tags = {
        "message": ["matrix_message", "notify_message", "log1"],
        "backlog":
        ["matrix_message", "notify_message", "no_log", "no_highlight"]
    }

    return default_tags[message_type]


def add_event_tags(event_id, nick, color, tags):
    if not tags:
        tags = tags_for_message("message")

    tags.append("nick_{nick}".format(nick=nick))
    tags.append("perfix_nick_{color}".format(color=color_for_tags(color)))
    tags.append("matrix_id_{event_id}".format(event_id=event_id))

    return tags
