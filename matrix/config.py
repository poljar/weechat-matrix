# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from collections import namedtuple
from enum import Enum, unique


@unique
class RedactType(Enum):
    STRIKETHROUGH = 0
    NOTICE        = 1
    DELETE        = 2


@unique
class ServerBufferType(Enum):
    MERGE_CORE  = 0
    MERGE       = 1
    INDEPENDENT = 2


@unique
class DebugType(Enum):
    MESSAGING = 0
    NETWORK   = 1
    TIMING    = 2


Option = namedtuple(
    'Option', [
        'name',
        'type',
        'string_values',
        'min',
        'max',
        'value',
        'description'
    ])


class PluginOptions:
    def __init__(self):
        self.redaction_type  = RedactType.STRIKETHROUGH     # type: RedactType
        self.look_server_buf = ServerBufferType.MERGE_CORE  # type: ServerBufferType

        self.sync_limit         = 30    # type: int
        self.backlog_limit      = 10    # type: int
        self.enable_backlog     = True  # type: bool
        self.page_up_hook       = None  # type: weechat.hook

        self.redaction_comp_len = 50    # type: int

        self.options = dict()  # type: Dict[str, weechat.config_option]
        self.debug   = []      # type: List[DebugType]
