# -*- coding: utf-8 -*-

# Weechat Matrix Protocol Script
# Copyright © 2019 Damir Jelić <poljar@termina.org.uk>
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

from builtins import super
from enum import Enum
from typing import List

from markdown import Markdown
from markdown import Extension
from markdown.util import etree
from markdown.preprocessors import Preprocessor
from markdown.inlinepatterns import InlineProcessor, SimpleTagPattern

from matrix.colors import color_line_to_weechat, color_weechat_to_html


class Attribute(Enum):
    emph = 0
    bold = 1
    underline = 2

DEFAULT_ATTRIBUTES = {
    "bold": False,
    "italic": False,
    "underline": False,
    "fgcolor": None,
    "bgcolor": None,
}

class FormattedString:
    __slots__ = ("text", "attributes")

    def __init__(self, text, attributes):
        self.attributes = DEFAULT_ATTRIBUTES.copy()
        self.attributes.update(attributes)
        self.text = text

    def __repr__(self):
        return "FormmattedString({} {})".format(self.text, self.attributes)


class WeechatToMarkdown(Preprocessor):
    """Markdown preprocessor to turn the weechat input line into markdown."""

    @staticmethod
    def add_attribute(string, name, value):
        if name == "bold" and value:
            return "{bold_on}{text}{bold_off}".format(
                bold_on="**", text=string, bold_off="**"
            )
        if name == "italic" and value:
            return "{italic_on}{text}{italic_off}".format(
                italic_on="*", text=string, italic_off="*"
            )
        if name == "underline" and value:
            return "{underline_on}{text}{underline_off}".format(
                underline_on="~", text=string, underline_off="~"
            )

        return string

    @staticmethod
    def add_color(string, fgcolor, bgcolor):
        fgcolor_string = ""
        bgcolor_string = ""

        if fgcolor:
            fgcolor_string = " fg={}".format(
                color_weechat_to_html(fgcolor)
            )

        if bgcolor:
            bgcolor_string = " bg={}".format(
                color_weechat_to_html(bgcolor)
            )

        return "[{text}]{{{color_on}}}".format(
            text=string,
            color_on="{fg}{bg}".format(
                fg=fgcolor_string,
                bg=bgcolor_string
            ),
        )

    @staticmethod
    def format_string(formatted_string):
        text = formatted_string.text
        attributes = formatted_string.attributes.copy()

        if attributes["fgcolor"] or attributes["bgcolor"]:
            text = WeechatToMarkdown.add_color(
                text,
                attributes["fgcolor"],
                attributes["bgcolor"]
            )
        else:
            for key, value in attributes.items():
                text = WeechatToMarkdown.add_attribute(text, key, value)

        return text

    @staticmethod
    def build_string(substrings):
        md_string = map(WeechatToMarkdown.format_string, substrings)
        return "".join(md_string)

    def run(self, lines):
        emph = "\x1D"
        bold = "\x02"
        reset = "\x0F"
        underline = "\x1F"
        color = "\x03"

        text = ""  # type: str
        substrings = []  # type: List[FormattedString]
        attributes = DEFAULT_ATTRIBUTES.copy()

        line = '\n'.join(lines)

        i = 0
        while i < len(line):
            # Bold
            if line[i] == bold:
                if text:
                    substrings.append(FormattedString(text, attributes.copy()))
                text = ""
                attributes["bold"] = not attributes["bold"]
                i = i + 1

            # Color
            elif line[i] == color:
                if text:
                    substrings.append(FormattedString(text, attributes.copy()))
                text = ""
                i = i + 1

                # check if it's a valid color, add it to the attributes
                if line[i].isdigit():
                    color_string = line[i]
                    i = i + 1

                    if line[i].isdigit():
                        if color_string == "0":
                            color_string = line[i]
                        else:
                            color_string = color_string + line[i]
                        i = i + 1

                    attributes["fgcolor"] = color_line_to_weechat(color_string)
                else:
                    attributes["fgcolor"] = None

                # check if we have a background color
                if line[i] == "," and line[i + 1].isdigit():
                    color_string = line[i + 1]
                    i = i + 2

                    if line[i].isdigit():
                        if color_string == "0":
                            color_string = line[i]
                        else:
                            color_string = color_string + line[i]
                        i = i + 1

                    attributes["bgcolor"] = color_line_to_weechat(color_string)
                else:
                    attributes["bgcolor"] = None
            # Reset
            elif line[i] == reset:
                if text:
                    substrings.append(FormattedString(text, attributes.copy()))
                text = ""
                # Reset all the attributes
                attributes = DEFAULT_ATTRIBUTES.copy()
                i = i + 1

            # Italic
            elif line[i] == emph:
                if text:
                    substrings.append(FormattedString(text, attributes.copy()))
                text = ""
                attributes["italic"] = not attributes["italic"]
                i = i + 1

            # Underline
            elif line[i] == underline:
                if text:
                    substrings.append(FormattedString(text, attributes.copy()))
                text = ""
                attributes["underline"] = not attributes["underline"]
                i = i + 1

            # Normal text
            else:
                text = text + line[i]
                i = i + 1

        substrings.append(FormattedString(text, attributes))

        def is_not_empty(substring):
            return substring.text != ""

        substrings = filter(is_not_empty, substrings)

        return WeechatToMarkdown.build_string(substrings).split("\n")


class MarkdownColor(InlineProcessor):
    def handleMatch(self, m, data):
        def add_color(color_type, color):
            if color_type == "fg":
                el.set("data-mx-color", color)
            elif color_type == "bg":
                el.set("data-mx-bg-color", color)

        el = etree.Element('font')

        text = m.group(1)

        first_setting = m.group(2)
        first_color = m.group(3)

        second_setting = m.group(4)
        second_color = m.group(5)

        el.text = text

        if first_setting != second_setting:
            add_color(first_setting, first_color)

        add_color(second_setting, second_color)

        return el, m.start(0), m.end(0)


class Weechat(Extension):
    def extendMarkdown(self, md):
        self.md = md

        md.preprocessors.register(WeechatToMarkdown(md), 'weechattomd', 100)

        underline_re =  r"(~)(.*?)~"
        u_tag = SimpleTagPattern(underline_re, "u")

        color_re = (r"\[([^\]]+)\]\{\s*(fg|bg)=([a-z]+|#[\da-fA-F]{6})\s*"
                    r"(?:\s+(fg|bg)=([a-z]+|#[\da-fA-F]{6}))?\s*\}")

        font_tag = MarkdownColor(color_re)

        md.inlinePatterns.register(u_tag, "underline", 75)
        md.inlinePatterns.register(font_tag, "font", 100)


class Parser(Markdown):
    def __init__(self, source):
        super().__init__(extensions=['extra', Weechat()])
        self.html = self.convert(source)

    @property
    def weechat(self):
        raise NotImplementedError()
