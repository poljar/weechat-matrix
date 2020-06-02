# -*- coding: utf-8 -*-

# Copyright © 2018, 2019 Damir Jelić <poljar@termina.org.uk>
# Copyright © 2018, 2019 Denis Kasak <dkasak@termina.org.uk>
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

from __future__ import unicode_literals, division

import time
from typing import Any, Dict, List

from .globals import W

if False:
    from .server import MatrixServer


def key_from_value(dictionary, value):
    # type: (Dict[str, Any], Any) -> str
    return list(dictionary.keys())[list(dictionary.values()).index(value)]


def server_buffer_prnt(server, string):
    # type: (MatrixServer, str) -> None
    assert server.server_buffer
    buffer = server.server_buffer
    now = int(time.time())
    W.prnt_date_tags(buffer, now, "", string)


def tags_from_line_data(line_data):
    # type: (str) -> List[str]
    tags_count = W.hdata_get_var_array_size(
        W.hdata_get("line_data"), line_data, "tags_array"
    )

    tags = [
        W.hdata_string(
            W.hdata_get("line_data"), line_data, "%d|tags_array" % i
        )
        for i in range(tags_count)
    ]

    return tags


def create_server_buffer(server):
    # type: (MatrixServer) -> None
    buffer_name = "server.{}".format(server.name)
    server.server_buffer = W.buffer_new(
        buffer_name, "server_buffer_cb", server.name, "", ""
    )

    server_buffer_set_title(server)
    W.buffer_set(server.server_buffer, "short_name", server.name)
    W.buffer_set(server.server_buffer, "localvar_set_type", "server")
    W.buffer_set(
        server.server_buffer, "localvar_set_nick", server.config.username
    )
    W.buffer_set(server.server_buffer, "localvar_set_server", server.name)
    W.buffer_set(server.server_buffer, "localvar_set_channel", server.name)

    server.buffer_merge()


def server_buffer_set_title(server):
    # type: (MatrixServer) -> None
    if server.numeric_address:
        ip_string = " ({address})".format(address=server.numeric_address)
    else:
        ip_string = ""

    title = ("Matrix: {address}:{port}{ip}").format(
        address=server.address, port=server.config.port, ip=ip_string
    )

    W.buffer_set(server.server_buffer, "title", title)


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


def string_strikethrough(string):
    return "".join(["{}\u0336".format(c) for c in string])


def string_color_and_reset(string, color):
    """Color string with color, then reset all attributes."""

    lines = string.split('\n')
    lines = ("{}{}{}".format(W.color(color), line, W.color("reset"))
             for line in lines)
    return "\n".join(lines)


def string_color(string, color):
    """Color string with color, then reset the color attribute."""

    lines = string.split('\n')
    lines = ("{}{}{}".format(W.color(color), line, W.color("resetcolor"))
             for line in lines)
    return "\n".join(lines)


def color_pair(color_fg, color_bg):
    """Make a color pair from a pair of colors."""

    if color_bg:
        return "{},{}".format(color_fg, color_bg)
    else:
        return color_fg


def text_block(text, margin=0):
    """
    Pad block of text with whitespace to form a regular block, optionally
    adding a margin.
    """

    # add vertical margin
    vertical_margin = margin // 2
    text = "{}{}{}".format(
        "\n" * vertical_margin,
        text,
        "\n" * vertical_margin
    )

    lines = text.split("\n")
    longest_len = max(len(l) for l in lines) + margin

    # pad block and add horizontal margin
    text = "\n".join(
        "{pre}{line}{post}".format(
            pre=" " * margin,
            line=l,
            post=" " * (longest_len - len(l)))
        for l in lines)

    return text


def colored_text_block(text, margin=0, color_pair=""):
    """ Like text_block, but also colors it."""
    return string_color_and_reset(text_block(text, margin=margin), color_pair)

def parse_redact_args(args):
    args = args.strip()

    had_example_text = False

    try:
        event_id, rest = args.split("|", 1)
        had_example_text = True
    except ValueError:
        try:
            event_id, rest = args.split(" ", 1)
        except ValueError:
            event_id, rest = (args, "")

    if had_example_text:
        rest = rest.lstrip()
        reason = None  # until it has been correctly determined
        if rest[0] == '"':
            escaped = False
            for i in range(1, len(rest)):
                if escaped:
                    escaped = False
                elif rest[i] == "\\":
                    escaped = True
                elif rest[i] == '"':
                    reason = rest[i+1:]
                    break
    else:
        reason = rest

    event_id = event_id.strip()
    if reason:
        reason = reason.strip()
    # The reason might be an empty string, set it to None if so
    else:
        reason = None

    return event_id, reason
