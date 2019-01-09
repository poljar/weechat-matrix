# -*- coding: utf-8 -*-

# Copyright (c) 2014-2016 Ryan Huber <rhuber@gmail.com>
# Copyright (c) 2015-2016 Tollef Fog Heen <tfheen@err.no>

# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:

# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from __future__ import unicode_literals

import sys

# pylint: disable=redefined-builtin
from builtins import bytes, str
from functools import wraps

if sys.version_info.major == 3 and sys.version_info.minor >= 3:
    from collections.abc import Iterable, Mapping
else:
    from collections import Iterable, Mapping

# These functions were written by Trygve Aaberge for wee-slack and are under a
# MIT License.
# More info can be found in the wee-slack repository under the commit:
# 5e1c7e593d70972afb9a55f29d13adaf145d0166, the repository can be found at:
# https://github.com/wee-slack/wee-slack


class WeechatWrapper(object):
    def __init__(self, wrapped_class):
        self.wrapped_class = wrapped_class

    # Helper method used to encode/decode method calls.
    def wrap_for_utf8(self, method):
        def hooked(*args, **kwargs):
            result = method(*encode_to_utf8(args), **encode_to_utf8(kwargs))
            # Prevent wrapped_class from becoming unwrapped
            if result == self.wrapped_class:
                return self
            return decode_from_utf8(result)

        return hooked

    # Encode and decode everything sent to/received from weechat. We use the
    # unicode type internally in wee-slack, but has to send utf8 to weechat.
    def __getattr__(self, attr):
        orig_attr = self.wrapped_class.__getattribute__(attr)
        if callable(orig_attr):
            return self.wrap_for_utf8(orig_attr)
        return decode_from_utf8(orig_attr)

    # Ensure all lines sent to weechat specify a prefix. For lines after the
    # first, we want to disable the prefix, which is done by specifying a
    # space.
    def prnt_date_tags(self, buffer, date, tags, message):
        message = message.replace("\n", "\n \t")
        return self.wrap_for_utf8(self.wrapped_class.prnt_date_tags)(
            buffer, date, tags, message
        )


def utf8_decode(function):
    """
    Decode all arguments from byte strings to unicode strings. Use this for
    functions called from outside of this script, e.g. callbacks from weechat.
    """

    @wraps(function)
    def wrapper(*args, **kwargs):

        # Don't do anything if we're python 3
        if sys.hexversion >= 0x3000000:
            return function(*args, **kwargs)

        return function(*decode_from_utf8(args), **decode_from_utf8(kwargs))

    return wrapper


def decode_from_utf8(data):
    if isinstance(data, bytes):
        return data.decode("utf-8")
    if isinstance(data, str):
        return data
    elif isinstance(data, Mapping):
        return type(data)(map(decode_from_utf8, data.items()))
    elif isinstance(data, Iterable):
        return type(data)(map(decode_from_utf8, data))
    return data


def encode_to_utf8(data):
    if isinstance(data, str):
        return data.encode("utf-8")
    if isinstance(data, bytes):
        return data
    elif isinstance(data, Mapping):
        return type(data)(map(encode_to_utf8, data.items()))
    elif isinstance(data, Iterable):
        return type(data)(map(encode_to_utf8, data))
    return data
