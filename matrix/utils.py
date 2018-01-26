# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import time

import matrix.globals


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
