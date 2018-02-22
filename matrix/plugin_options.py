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
from collections import namedtuple
from enum import Enum, unique


@unique
class RedactType(Enum):
    STRIKETHROUGH = 0
    NOTICE = 1
    DELETE = 2


@unique
class ServerBufferType(Enum):
    MERGE_CORE = 0
    MERGE = 1
    INDEPENDENT = 2


@unique
class DebugType(Enum):
    MESSAGING = 0
    NETWORK = 1
    TIMING = 2


Option = namedtuple(
    'Option',
    ['name', 'type', 'string_values', 'min', 'max', 'value', 'description'])


class PluginOptions:

    def __init__(self):
        self.redaction_type = RedactType.STRIKETHROUGH  # type: RedactType
        self.look_server_buf = ServerBufferType.MERGE_CORE  # type: ServerBufferType

        self.sync_limit = 30  # type: int
        self.backlog_limit = 10  # type: int
        self.enable_backlog = True  # type: bool
        self.page_up_hook = None  # type: weechat.hook

        self.redaction_comp_len = 50  # type: int

        self.options = dict()  # type: Dict[str, weechat.config_option]
        self.debug = []  # type: List[DebugType]
