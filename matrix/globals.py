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

import sys
from typing import Any, Dict, Optional
from logbook import Logger
from collections import OrderedDict

from .utf import WeechatWrapper

if False:
    from .server import MatrixServer
    from .config import MatrixConfig
    from .uploads import Upload


try:
    import weechat

    W = weechat if sys.hexversion >= 0x3000000 else WeechatWrapper(weechat)
except ImportError:
    import matrix._weechat as weechat  # type: ignore

    W = weechat

SERVERS = dict()  # type: Dict[str, MatrixServer]
CONFIG = None  # type: Any
ENCRYPTION = True  # type: bool
SCRIPT_NAME = "matrix"  # type: str
BUFFER_NAME_PREFIX = "{}.".format(SCRIPT_NAME)  # type: str
TYPING_NOTICE_TIMEOUT = 4000  # 4 seconds typing notice lifetime
LOGGER = Logger("weechat-matrix")
UPLOADS = OrderedDict()  # type: Dict[str, Upload]
