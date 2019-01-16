# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import webcolors
from collections import OrderedDict
from hypothesis import given
from hypothesis.strategies import sampled_from

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
    valid_result = '\x1b[0m* a *\x1b[00m'

    formatted = Formatted.from_input_line('`   *    a   *   `')
    assert formatted.to_weechat() == valid_result
