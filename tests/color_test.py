# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import webcolors
from collections import OrderedDict
from hypothesis import given
from hypothesis.strategies import sampled_from, text

from matrix.colors import (G, Formatted, FormattedString,
                           color_html_to_weechat, color_weechat_to_html)
from matrix._weechat import MockConfig

G.CONFIG = MockConfig()

html_prism = ("<font color=maroon>T</font><font color=red>e</font><font "
              "color=olive>s</font><font color=yellow>t</font>")

weechat_prism = (
    u"\x1b[038;5;1mT\x1b[039m\x1b[038;5;9me\x1b[039m\x1b[038;5;3ms\x1b[039m\x1b[038;5;11mt\x1b[039m"
)

first_16_html_colors = list(webcolors.HTML4_HEX_TO_NAMES.values())


def test_prism():
    formatted = Formatted.from_html(html_prism)
    assert formatted.to_weechat() == weechat_prism


@given(sampled_from(first_16_html_colors))
def test_color_conversion(color_name):
    hex_color = color_weechat_to_html(color_html_to_weechat(color_name))
    new_color_name = webcolors.hex_to_name(hex_color, spec='html4')
    assert new_color_name == color_name


def test_handle_strikethrough_first():
    valid_result = '\x1b[038;5;1mf̶o̶o̶\x1b[039m'

    d1 = OrderedDict([('fgcolor', 'red'), ('strikethrough', True)])
    d2 = OrderedDict([('strikethrough', True), ('fgcolor', 'red'), ])
    f1 = Formatted([FormattedString('foo', d1)])
    f2 = Formatted([FormattedString('foo', d2)])

    assert f1.to_weechat() == valid_result
    assert f2.to_weechat() == valid_result


def test_normalize_spaces_in_inline_code():
    """Normalize spaces in inline code blocks.

    Strips leading and trailing spaces and compress consecutive infix spaces.
    """
    valid_result = "\x1b[038;5;4m* a *\x1b[00m"

    formatted = Formatted.from_input_line('`   *    a   *   `')
    assert formatted.to_weechat() == valid_result


# FIXME: this case doesn't and can't work yet (until a proper Markdown parser
# is integrated)
# @given(text().map(lambda s: '*' + s)
# def test_unpaired_prefix_asterisk_without_space_is_literal(text):
#     """An unpaired asterisk at the beginning of the line, without a space
#     after it, is considered literal.
#     """
#     formatted = Formatted.from_input_line(text)
#     assert text == formatted.to_weechat()


def test_input_line_color():
    formatted = Formatted.from_input_line("\x0304Hello")
    assert "\x1b[038;5;9mHello\x1b[039m" == formatted.to_weechat()
    assert "<font data-mx-color=#ff0000>Hello</font>" == formatted.to_html()

def test_input_line_bold():
    formatted = Formatted.from_input_line("\x02Hello")
    assert "\x1b[01mHello\x1b[021m" == formatted.to_weechat()
    assert "<strong>Hello</strong>" == formatted.to_html()

def test_input_line_bold():
    formatted = Formatted.from_input_line("\x1FHello")
    assert "\x1b[04mHello\x1b[024m" == formatted.to_weechat()
    assert "<u>Hello</u>" == formatted.to_html()

def test_input_line_markdown_emph():
    formatted = Formatted.from_input_line("*Hello*")
    assert "\x1b[03mHello\x1b[023m" == formatted.to_weechat()
    assert "<em>Hello</em>" == formatted.to_html()

def test_conversion():
    formatted = Formatted.from_input_line("*Hello*")
    formatted2 = Formatted.from_html(formatted.to_html())
    formatted.to_weechat() == formatted2.to_weechat()
