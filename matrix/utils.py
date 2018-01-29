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

import matrix.globals

from matrix.plugin_options import ServerBufferType

W = matrix.globals.W
GLOBAL_OPTIONS = matrix.globals.OPTIONS


def key_from_value(dictionary, value):
    # type: (Dict[str, Any], Any) -> str
    return list(dictionary.keys())[list(dictionary.values()).index(value)]


def prnt_debug(debug_type, server, message):
    if debug_type in GLOBAL_OPTIONS.debug:
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
        W.hdata_get('line_data'),
        line_data,
        'tags_array')

    tags = [
        W.hdata_string(
            W.hdata_get('line_data'),
            line_data,
            '%d|tags_array' % i
        ) for i in range(tags_count)]

    return tags


def create_server_buffer(server):
    # type: (MatrixServer) -> None
    server.server_buffer = W.buffer_new(
        server.name,
        "server_buffer_cb",
        server.name,
        "",
        ""
    )

    server_buffer_set_title(server)
    W.buffer_set(server.server_buffer, "localvar_set_type", 'server')
    W.buffer_set(server.server_buffer, "localvar_set_nick", server.user)
    W.buffer_set(server.server_buffer, "localvar_set_server", server.name)
    W.buffer_set(server.server_buffer, "localvar_set_channel", server.name)

    # TODO merge without core
    if GLOBAL_OPTIONS.look_server_buf == ServerBufferType.MERGE_CORE:
        W.buffer_merge(server.server_buffer, W.buffer_search_main())
    elif GLOBAL_OPTIONS.look_server_buf == ServerBufferType.MERGE:
        pass
    else:
        pass


def server_buffer_set_title(server):
    # type: (MatrixServer) -> None
    if server.numeric_address:
        ip_string = " ({address})".format(address=server.numeric_address)
    else:
        ip_string = ""

    title = ("Matrix: {address}/{port}{ip}").format(
        address=server.address,
        port=server.port,
        ip=ip_string)

    W.buffer_set(server.server_buffer, "title", title)
