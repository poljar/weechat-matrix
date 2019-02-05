# -*- coding: utf-8 -*-

# Weechat Matrix Protocol Script
# Copyright © 2019 Damir Jelić <poljar@termina.org.uk>
# Copyright © 2018, 2019 Denis Kasak <dkasak@termina.org.uk>
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

import html
from builtins import super, str
from enum import Enum
from typing import List

from markdown import Markdown
from markdown import Extension
from markdown.util import etree
from markdown.preprocessors import Preprocessor
from markdown.inlinepatterns import InlineProcessor, SimpleTagPattern

from matrix.globals import W
from matrix.colors import (
    color_line_to_weechat,
    color_weechat_to_html,
    color_html_to_weechat
)


try:
    from HTMLParser import HTMLParser
except ImportError:
    from html.parser import HTMLParser



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



class MatrixHtmlParser(HTMLParser):
    supported_tags = ["strong", "p", "h1", "h2", "h3", "h4", "h5", "h6",
                      "br", "font", "blockquote", "em", "u", "del", "pre"]

    def __init__(self):
        HTMLParser.__init__(self)
        self.text = ""  # type: str
        self.substrings = []  # type: List[FormattedString]
        self.attributes = DEFAULT_ATTRIBUTES.copy()
        self.document_tree = etree.Element("div")
        self.current_node = self.document_tree
        self.node_stack = []

    def unescape(self, text):
        """Shim to unescape HTML in both Python 2 and 3.

        The instance method was deprecated in Python 3 and html.unescape
        doesn't exist in Python 2 so this is needed.
        """
        try:
            return html.unescape(text)
        except AttributeError:
            return HTMLParser.unescape(self, text)

    def open_element(self, tag):
        new_node = etree.SubElement(self.current_node, tag)
        self.node_stack.append(self.current_node)
        self.current_node = new_node

    def close_element(self, tag):
        if not self.current_node:
            pass

        elif not self.current_node.tag == tag:
            etree.SubElement(self.current_node, tag)

        if not self.node_stack:
            self.current_node = etree.Element("div")

        self.current_node = self.node_stack.pop()

    def add_text(self, text):
        if not self.current_node.text:
            self.current_node.text = text
        else:
            self.current_node.text += text

    def handle_starttag(self, tag, attrs):
        if tag in MatrixHtmlParser.supported_tags:
            self.open_element(tag)

        if tag in ["font", "span"]:
            for key, value in attrs:
                if key in ["data-mx-color", "color"]:
                    self.current_node.set("data-mx-color", value)
                elif key in ["data-mx-bg-color"]:
                    self.current_node.set("data-mx-bg-color", value)

        if tag == "code":
            for key, value in attrs:
                if key == "class" and value.startswith("language-"):
                    self.current_node.set("class", value)

    def handle_endtag(self, tag):
        if tag in MatrixHtmlParser.supported_tags:
            self.close_element(tag)

    def handle_data(self, data):
        self.add_text(data)

    def handle_entityref(self, name):
        self.add_text(self.unescape("&{};".format(name)))

    def handle_charref(self, name):
        self.add_text(self.unescape("&#{};".format(name)))


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
    def __init__(self):
        super().__init__(extensions=['extra', Weechat()])
        self.source = None
        self.document_tree = None
        self.lines = None

    @classmethod
    def from_weechat(cls, input_string):
        """Create a parser object from the weechat input line string.

        Markdown as well as the classical weechat irc markup codes are
        supported.
        """
        parser = cls()
        parser.source = input_string

        if not input_string.strip():
            parser.document_tree = etree.Element("")
            return parser

        source = str(input_string)

        parser.lines = source.split("\n")
        for prep in parser.preprocessors:
            parser.lines = prep.run(parser.lines)

        root = parser.parser.parseDocument(parser.lines).getroot()

        for treeprocessor in parser.treeprocessors:
            newRoot = treeprocessor.run(root)
            if newRoot is not None:
                root = newRoot

        parser.document_tree = root
        return parser

    @classmethod
    def from_html(cls, html_source):
        """Create a parser object from the weechat input line string.

        Only the allowed subset of HTML in the matrix spec is supported.
        """
        # TODO this needs to be done differently so that only allowed tags are
        # parsed
        parser = cls()
        html_parser = MatrixHtmlParser()
        html_parser.feed(html_source)
        parser.source = html_source
        parser.document_tree = html_parser.document_tree

        return parser

    def _add_attribute(self, text, attribute):
        if attribute == "strong":
            return "{}{}{}".format(
                W.color("bold"),
                text,
                W.color("-bold"))

        elif attribute == "em":
            return "{}{}{}".format(
                W.color("italic"),
                text,
                W.color("-italic"))

        elif attribute == "u":
            return "{}{}{}".format(
                W.color("underline"),
                text,
                W.color("-underline"))

        elif attribute == "del":
            return "{}{}{}".format(
                "\x1b[09m",
                text,
                "\x1b[29m")

        else:
            return text

    def _to_weechat(self, element):
        text = ""

        for child in element:
            text = self._to_weechat(child)

        text = text + (element.text or "")
        text = self._add_attribute(text, element.tag)

        return text

    def to_weechat(self):
        """Convert the parsed document to a string for weechat to display."""
        out = self._to_weechat(self.document_tree)
        return out.strip()

    def to_html(self):
        """Convert the parsed document to a html string."""
        output = self.serializer(self.document_tree)

        try:
            start = output.index(
                '<%s>' % self.doc_tag) + len(self.doc_tag) + 2
            end = output.rindex('</%s>' % self.doc_tag)
            output = output[start:end].strip()
        except ValueError:  # pragma: no cover
            if output.strip().endswith('<%s />' % self.doc_tag):
                # We have an empty document
                output = ''

        # Run the text post-processors
        for pp in self.postprocessors:
            output = pp.run(output)

        return output.strip()
