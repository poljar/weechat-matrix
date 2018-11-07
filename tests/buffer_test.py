# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from matrix.buffer import WeechatChannelBuffer


class TestClass(object):
    def test_buffer(self):
        b = WeechatChannelBuffer("test_buffer_name", "example.org", "alice")
        assert b

    def test_buffer_print(self):
        b = WeechatChannelBuffer("test_buffer_name", "example.org", "alice")
        b.message("alice", "hello world", 0, 0)
        assert b
