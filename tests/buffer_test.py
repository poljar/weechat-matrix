# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from matrix.buffer import WeechatChannelBuffer
from matrix.utils import parse_redact_args


class TestClass(object):
    def test_buffer(self):
        b = WeechatChannelBuffer("test_buffer_name", "example.org", "alice")
        assert b

    def test_buffer_print(self):
        b = WeechatChannelBuffer("test_buffer_name", "example.org", "alice")
        b.message("alice", "hello world", 0, 0)
        assert b

    def test_redact_args_parse(self):
        args = '$81wbnOYZllVZJcstsnXpq7dmugA775-JT4IB-uPT680|"Hello world" No specific reason'
        event_id, reason = parse_redact_args(args)
        assert event_id == '$81wbnOYZllVZJcstsnXpq7dmugA775-JT4IB-uPT680'
        assert reason == 'No specific reason'

        args = '$15677776791893pZSXx:example.org|"Hello world" No reason at all'
        event_id, reason = parse_redact_args(args)
        assert event_id == '$15677776791893pZSXx:example.org'
        assert reason == 'No reason at all'

        args = '$15677776791893pZSXx:example.org No reason at all'
        event_id, reason = parse_redact_args(args)
        assert event_id == '$15677776791893pZSXx:example.org'
        assert reason == 'No reason at all'

        args = '$81wbnOYZllVZJcstsnXpq7dmugA775-JT4IB-uPT680 No specific reason'
        event_id, reason = parse_redact_args(args)
        assert event_id == '$81wbnOYZllVZJcstsnXpq7dmugA775-JT4IB-uPT680'
        assert reason == 'No specific reason'

        args = '$81wbnOYZllVZJcstsnXpq7dmugA775-JT4IB-uPT680'
        event_id, reason = parse_redact_args(args)
        assert event_id == '$81wbnOYZllVZJcstsnXpq7dmugA775-JT4IB-uPT680'
        assert reason == None

        args = '$15677776791893pZSXx:example.org'
        event_id, reason = parse_redact_args(args)
        assert event_id == '$15677776791893pZSXx:example.org'
        assert reason == None

        args = '   '
        event_id, reason = parse_redact_args(args)
        assert event_id == ''
        assert reason == None

        args = '$15677776791893pZSXx:example.org|"Hello world"'
        event_id, reason = parse_redact_args(args)
        assert event_id == '$15677776791893pZSXx:example.org'
        assert reason == None

        args = '$15677776791893pZSXx:example.org|"Hello world'
        event_id, reason = parse_redact_args(args)
        assert event_id == '$15677776791893pZSXx:example.org'
        assert reason == None

        args = '$15677776791893pZSXx:example.org "Hello world"'
        event_id, reason = parse_redact_args(args)
        assert event_id == '$15677776791893pZSXx:example.org'
        assert reason == '"Hello world"'
