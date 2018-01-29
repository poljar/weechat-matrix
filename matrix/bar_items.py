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
from matrix.utils import key_from_value

from matrix.globals import W, SERVERS


@utf8_decode
def matrix_bar_item_plugin(data, item, window, buffer, extra_info):
    # pylint: disable=unused-argument
    for server in SERVERS.values():
        if (buffer in server.buffers.values() or
                buffer == server.server_buffer):
            return "matrix{color}/{color_fg}{name}".format(
                color=W.color("bar_delim"),
                color_fg=W.color("bar_fg"),
                name=server.name)

    return ""


@utf8_decode
def matrix_bar_item_name(data, item, window, buffer, extra_info):
    # pylint: disable=unused-argument
    for server in SERVERS.values():
        if buffer in server.buffers.values():
            color = ("status_name_ssl"
                     if server.ssl_context.check_hostname else
                     "status_name")

            room_id = key_from_value(server.buffers, buffer)

            room = server.rooms[room_id]

            return "{color}{name}".format(
                color=W.color(color),
                name=room.alias)

        elif buffer in server.server_buffer:
            color = ("status_name_ssl"
                     if server.ssl_context.check_hostname else
                     "status_name")

            return "{color}server{del_color}[{color}{name}{del_color}]".format(
                color=W.color(color),
                del_color=W.color("bar_delim"),
                name=server.name)

    return ""


def init_bar_items():
    W.bar_item_new("(extra)buffer_plugin",  "matrix_bar_item_plugin",  "")
    W.bar_item_new("(extra)buffer_name", "matrix_bar_item_name", "")
