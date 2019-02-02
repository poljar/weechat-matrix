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

from markdown import Markdown
from markdown import Extension
from markdown.util import etree
from markdown.preprocessors import build_preprocessors, Preprocessor
from markdown.inlinepatterns import SimpleTagPattern


class Attribute(Enum):
    emph = 0
    bold = 1
    underline = 2


class WeechatToMarkdown(Preprocessor):
    def run(self, lines):
        emph = "\x1D"
        bold = "\x02"
        reset = "\x0F"
        underline = "\x1F"

        source = '\n'.join(lines)

        stack = []

        dest = []

        def add_attribute(attr):
            if attr == Attribute.emph:
                dest.append("*")
            elif attr == Attribute.bold:
                dest.append("__")
            elif attr == Attribute.underline:
                dest.append("~")

        def add_attrs():
            for attr in reversed(stack):
                add_attribute(attr)

        def close_attr(closing_attr):
            put_back = []

            while stack:
                attr = stack.pop()

                add_attribute(attr)

                if attr == closing_attr:
                    break

                put_back.append(attr)

            while put_back:
                attr = put_back.pop()
                stack.append(attr)

                add_attribute(attr)

        def toggle_attr(attr):
            if attr in stack:
                close_attr(attr)
            else:
                stack.append(attr)
                add_attribute(attr)

        for character in source:
            if character == emph:
                toggle_attr(Attribute.emph)
            elif character == bold:
                toggle_attr(Attribute.bold)
            elif character == underline:
                toggle_attr(Attribute.underline)
            elif character == reset:
                add_attrs()
                stack = []

            else:
                dest.append(character)

        add_attrs()

        return "".join(dest).split('\n')


class Weechat(Extension):
    def extendMarkdown(self, md):
        self.md = md

        underline_re =  r"(~)(.*?)~"
        u_tag = SimpleTagPattern(underline_re, "u")
        md.inlinePatterns.register(u_tag, "underline", 75)

        md.preprocessors.register(WeechatToMarkdown(md), 'weechattomd', 100)

class Parser(Markdown):
    def __init__(self, source):
        super().__init__(extensions=['extra', Weechat()])
        self.html = self.convert(source)

    @property
    def weechat(self):
        raise NotImplementedError()
