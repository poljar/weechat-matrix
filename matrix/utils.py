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
import math

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


def server_ts_to_weechat(timestamp):
    # type: (float) -> int
    date = int(timestamp / 1000)
    return date


def strip_matrix_server(string):
    # type: (str) -> str
    return string.rsplit(":", 1)[0]


def shorten_sender(sender):
    # type: (str) -> str
    return strip_matrix_server(sender)[1:]


def sender_to_prefix_and_color(room, sender):
    if sender in room.users:
        user = room.users[sender]
        prefix = user.prefix
        prefix_color = get_prefix_color(prefix)
        return prefix, prefix_color

    return None, None


def sender_to_nick_and_color(room, sender):
    nick = sender
    nick_color_name = "default"

    if sender in room.users:
        user = room.users[sender]
        nick = (user.display_name if user.display_name else user.name)
        nick_color_name = user.nick_color
    else:
        nick = sender
        nick_color_name = W.info_get("nick_color_name", nick)

    return (nick, nick_color_name)


def tags_for_message(message_type):
    default_tags = {
        "message": ["matrix_message", "notify_message", "log1"],
        "backlog":
        ["matrix_message", "notify_message", "no_log", "no_highlight"]
    }

    return default_tags[message_type]


def add_event_tags(event_id, nick, color=None, tags=[]):
    tags.append("nick_{nick}".format(nick=nick))

    if color:
        tags.append("prefix_nick_{color}".format(color=color_for_tags(color)))

    tags.append("matrix_id_{event_id}".format(event_id=event_id))

    return tags


def sanitize_token(string):
    # type: (str) -> str
    string = sanitize_string(string)

    if len(string) > 512:
        raise ValueError

    if string == "":
        raise ValueError

    return string


def sanitize_string(string):
    # type: (str) -> str
    if not isinstance(string, str):
        raise TypeError

    # string keys can have empty string values sometimes (e.g. room names that
    # got deleted)
    if string == "":
        return None

    remap = {
        ord('\b'): None,
        ord('\f'): None,
        ord('\n'): None,
        ord('\r'): None,
        ord('\t'): None,
        ord('\0'): None
    }

    return string.translate(remap)


def sanitize_id(string):
    # type: (str) -> str
    string = sanitize_string(string)

    if len(string) > 128:
        raise ValueError

    if string == "":
        raise ValueError

    return string


def sanitize_int(number, minimum=None, maximum=None):
    # type: (int, int, int) -> int
    if not isinstance(number, int):
        raise TypeError

    if math.isnan(number):
        raise ValueError

    if math.isinf(number):
        raise ValueError

    if minimum:
        if number < minimum:
            raise ValueError

    if maximum:
        if number > maximum:
            raise ValueError

    return number


def sanitize_ts(timestamp):
    # type: (int) -> int
    return sanitize_int(timestamp, 0)


def sanitize_power_level(level):
    # type: (int) -> int
    return sanitize_int(level, 0, 100)


def sanitize_text(string):
    # type: (str) -> str
    if not isinstance(string, str):
        raise TypeError

    # yapf: disable
    remap = {
        ord('\b'): None,
        ord('\f'): None,
        ord('\r'): None,
        ord('\0'): None
    }
    # yapf: enable

    return string.translate(remap)


def add_user_to_nicklist(buf, user_id, user):
    group_name = "999|..."

    if user.power_level >= 100:
        group_name = "000|o"
    elif user.power_level >= 50:
        group_name = "001|h"
    elif user.power_level > 0:
        group_name = "002|v"

    group = W.nicklist_search_group(buf, "", group_name)
    prefix = user.prefix if user.prefix else " "

    # TODO make it configurable so we can use a display name or user_id here
    W.nicklist_add_nick(buf, group, user_id, user.nick_color, prefix,
                        get_prefix_color(user.prefix), 1)


def get_prefix_for_level(level):
    # type: (int) -> str
    if level >= 100:
        return "&"
    elif level >= 50:
        return "@"
    elif level > 0:
        return "+"
    return ""


# TODO make this configurable
def get_prefix_color(prefix):
    # type: (str) -> str
    if prefix == "&":
        return "lightgreen"
    elif prefix == "@":
        return "lightgreen"
    elif prefix == "+":
        return "yellow"
    return ""


def string_strikethrough(string):
    return "".join(["{}\u0336".format(c) for c in string])


def line_pointer_and_tags_from_event(buff, event_id):
    # type: (str, str) -> str
    own_lines = W.hdata_pointer(W.hdata_get('buffer'), buff, 'own_lines')

    if own_lines:
        hdata_line = W.hdata_get('line')

        line_pointer = W.hdata_pointer(
            W.hdata_get('lines'), own_lines, 'last_line')

        while line_pointer:
            data_pointer = W.hdata_pointer(hdata_line, line_pointer, 'data')

            if data_pointer:
                tags = tags_from_line_data(data_pointer)

                message_id = event_id_from_tags(tags)

                if event_id == message_id:
                    return data_pointer, tags

            line_pointer = W.hdata_move(hdata_line, line_pointer, -1)

    return None, []


def event_id_from_tags(tags):
    # type: (List[str]) -> str
    for tag in tags:
        if tag.startswith("matrix_id"):
            return tag[10:]

    return ""
