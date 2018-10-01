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

from .globals import SERVERS, W
from .utf import utf8_decode


@utf8_decode
def matrix_bar_item_plugin(data, item, window, buffer, extra_info):
    # pylint: disable=unused-argument
    for server in SERVERS.values():
        if buffer in server.buffers.values() or buffer == server.server_buffer:
            return "matrix{color}/{color_fg}{name}".format(
                color=W.color("bar_delim"),
                color_fg=W.color("bar_fg"),
                name=server.name,
            )

    return ""


@utf8_decode
def matrix_bar_item_name(data, item, window, buffer, extra_info):
    # pylint: disable=unused-argument
    for server in SERVERS.values():
        if buffer in server.buffers.values():
            color = (
                "status_name_ssl"
                if server.ssl_context.check_hostname
                else "status_name"
            )

            room_buffer = server.find_room_from_ptr(buffer)
            room = room_buffer.room

            return "{color}{name}".format(
                color=W.color(color), name=room.display_name()
            )

        if buffer == server.server_buffer:
            color = (
                "status_name_ssl"
                if server.ssl_context.check_hostname
                else "status_name"
            )

            return "{color}server{del_color}[{color}{name}{del_color}]".format(
                color=W.color(color),
                del_color=W.color("bar_delim"),
                name=server.name,
            )

    return ""


@utf8_decode
def matrix_bar_item_lag(data, item, window, buffer, extra_info):
    # pylint: disable=unused-argument
    for server in SERVERS.values():
        if buffer in server.buffers.values() or buffer == server.server_buffer:
            if server.lag >= 500:
                color = W.color("irc.color.item_lag_counting")
                if server.lag_done:
                    color = W.color("irc.color.item_lag_finished")

                lag = "{0:.3f}" if round(server.lag) < 1000 else "{0:.0f}"
                lag_string = "Lag: {color}{lag}{ncolor}".format(
                    lag=lag.format((server.lag / 1000)),
                    color=color,
                    ncolor=W.color("reset"),
                )
                return lag_string
            return ""

    return ""


@utf8_decode
def matrix_bar_item_buffer_modes(data, item, window, buffer, extra_info):
    # pylint: disable=unused-argument
    for server in SERVERS.values():
        if buffer in server.buffers.values():
            room_buffer = server.find_room_from_ptr(buffer)
            room = room_buffer.room
            modes = []

            if room.encrypted:
                modes.append("🔐")

            if (server.client
                    and server.client.room_contains_unverified(room.room_id)):
                modes.append("⚠️ ")

            if not server.connected:
                modes.append("❌")

            if room_buffer.backlog_pending:
                modes.append("⏳")

            return "".join(modes)

    return ""


def init_bar_items():
    W.bar_item_new("(extra)buffer_plugin", "matrix_bar_item_plugin", "")
    W.bar_item_new("(extra)buffer_name", "matrix_bar_item_name", "")
    W.bar_item_new("(extra)lag", "matrix_bar_item_lag", "")
    W.bar_item_new("(extra)buffer_modes", "matrix_bar_item_buffer_modes", "")
    W.bar_item_new("(extra)matrix_modes", "matrix_bar_item_buffer_modes", "")
