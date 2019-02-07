# -*- coding: utf-8 -*-

import unittest
from matrix.markdown_parser import Parser, MatrixHtmlParser
from markdown.util import etree
import textwrap
import re
import sys

lorem = """Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do
eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim
veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo
consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse
cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non
proident, sunt in culpa qui officia deserunt mollit anim id est laborum."""


class TestClass(unittest.TestCase):
    def assertParserRendersHtml(self, source, expected):
        parser = Parser.from_weechat(source)
        self.assertMultiLineEqual(parser.to_html(), expected)

    def assertParserRendersWeechat(self, source, expected):
        parser = Parser.from_html(source)
        self.assertMultiLineEqual(parser.to_weechat(), expected)

    def dedent(self, text):
        if text.endswith("\n"):
            return textwrap.dedent(text.strip('/n'))
        else:
            return textwrap.dedent(text).strip()

    def strip_extra(self, text):
        return re.sub(r"\s\s+", "", text.strip().replace("\n", ""))

    def test_hr_before_paragraph(self):
        self.assertParserRendersHtml(
            # The Markdown source text used as input
            self.dedent(
                """
                ***
                An HR followed by a paragraph with no blank line.
                """
            ),
            # The expected HTML output
            self.dedent(
                """
                <hr />
                <p>An HR followed by a paragraph with no blank line.</p>
                """
            ),
        )

    # This is disabled for now, the fenced code extension needs to be rewriten
    # for this to work.
    def test_fenced_code(self):
        pass
        # self.assertParserRendersHtml(
        #     "```python\n# python code\n```",
        #     self.dedent(
        #         """
        #         <pre><code class="python"># python code
        #         </code></pre>
        #         """
        #     )
        # )

        # p = Parser.from_weechat("```python\nprint(\"hello\")\n```")
        # assert p.to_weechat() == ""

    def test_input_line_markdown_emph(self):
        self.assertParserRendersHtml(
            "*Hello*",
            "<p><em>Hello</em></p>"
        )

    def test_input_line_weechat_emph(self):
        self.assertParserRendersHtml(
            "\x1DHello\x0F",
            "<p><em>Hello</em></p>"
        )
        self.assertParserRendersHtml(
            "\x1DHello\x1D",
            "<p><em>Hello</em></p>"
        )
        self.assertParserRendersHtml(
            "\x1DHello",
            "<p><em>Hello</em></p>"
        )

    def test_input_line_weechat_strong(self):
        self.assertParserRendersHtml(
            "\x02Hello\x0F",
            "<p><strong>Hello</strong></p>"
        )
        self.assertParserRendersHtml(
            "\x02Hello\x02",
            "<p><strong>Hello</strong></p>"
        )
        self.assertParserRendersHtml(
            "\x02Hello",
            "<p><strong>Hello</strong></p>"
        )

    def test_input_line_weechat_underilne(self):
        self.assertParserRendersHtml(
            "\x1FHello\x0F",
            "<p><u>Hello</u></p>"
        )
        self.assertParserRendersHtml(
            "\x1FHello\x1F",
            "<p><u>Hello</u></p>"
        )
        self.assertParserRendersHtml(
            "\x1FHello",
            "<p><u>Hello</u></p>"
        )

    def test_input_line_combination(self):
        if sys.version_info[0] < 3:
            self.assertParserRendersHtml(
                "\x1F\x02Hello\x0F",
                "<p><strong><u>Hello</u></strong></p>"
            )
            self.assertParserRendersHtml(
                "\x1F\x02Hello\x02\x1F",
                "<p><strong><u>Hello</u></strong></p>"
            )
            self.assertParserRendersHtml(
                "\x1F\x02Hello",
                "<p><strong><u>Hello</u></strong></p>"
            )
            self.assertParserRendersHtml(
                "\x1F\x02Hello\x1F",
                "<p><strong><u>Hello</u></strong></p>"
            )
        else:
            self.assertParserRendersHtml(
                "\x1F\x02Hello\x0F",
                "<p><u><strong>Hello</strong></u></p>"
            )
            self.assertParserRendersHtml(
                "\x1F\x02Hello\x02\x1F",
                "<p><u><strong>Hello</strong></u></p>"
            )
            self.assertParserRendersHtml(
                "\x1F\x02Hello",
                "<p><u><strong>Hello</strong></u></p>"
            )
            self.assertParserRendersHtml(
                "\x1F\x02Hello\x1F",
                "<p><u><strong>Hello</strong></u></p>"
            )

    def test_input_line_md_color(self):
        self.assertParserRendersHtml(
            "[Hello]{fg=fuchsia}",
            "<p><font data-mx-color=\"fuchsia\">Hello</font></p>"
        )
        self.assertParserRendersHtml(
            "[Hello]{fg=fuchsia bg=black}",
            self.strip_extra("""
            <p>
                <font data-mx-bg-color=\"black\" data-mx-color=\"fuchsia\">
                    Hello
                </font>
            </p>
            """)
        )
        self.assertParserRendersHtml(
            "[Hello]{fg=fuchsia bg=#FFFFFF}",
            self.strip_extra("""
            <p>
                <font data-mx-bg-color=\"#FFFFFF\" data-mx-color=\"fuchsia\">
                    Hello
                </font>
            </p>
            """)
        )

        self.assertParserRendersHtml(
            "[Hello]{bg=fuchsia fg=#FFFFFF}",
            self.strip_extra("""
            <p>
                <font data-mx-bg-color=\"fuchsia\" data-mx-color=\"#FFFFFF\">
                    Hello
                </font>
            </p>
            """)
        )

    def test_input_line_weechat_color(self):
        self.assertParserRendersHtml(
            u"\x0301T\x0302e\x0303s\x0304t",
            self.strip_extra("""
            <p>
                <font data-mx-color="#000000">T</font>
                <font data-mx-color="#000080">e</font>
                <font data-mx-color="#008000">s</font>
                <font data-mx-color="#ff0000">t</font>
            </p>
            """)
        )

        self.assertParserRendersHtml(
            "\x0304Hello\x03",
            "<p><font data-mx-color=\"#ff0000\">Hello</font></p>"
        )

        self.assertParserRendersHtml(
            "\x0304,Hello\x03,",
            "<p><font data-mx-color=\"#ff0000\">,Hello</font>,</p>"
        )


    def test_to_and_from_html(self):
        parser = Parser.from_weechat("\x0301T\x0302e\x0303s\x0304t")
        assert Parser.from_html(parser.to_html()).to_html() == parser.to_html()

    def test_html_parser(self):
        parser = MatrixHtmlParser()
        parser.feed("<p><strong>Hello</strong></p>")
        assert parser.document_tree[0][0].text == "Hello"

        parser = MatrixHtmlParser()
        parser.feed("<strong>Hello</strong> <em>world</em>")
        assert (etree.tostring(parser.document_tree) ==
                b"<div><strong>Hello</strong> <em>world</em></div>")

        parser = Parser.from_html("<strong>Hello</strong> <em>world</em>")
        assert (parser.to_html() ==
                "<strong>Hello</strong> <em>world</em>")

    def test_weechat_formatter(self):
        formatted = Parser.from_weechat("*Hello*")
        assert "\x1b[03mHello\x1b[023m" == formatted.to_weechat()

        self.assertParserRendersWeechat(
            "<strong>Hello</strong>",
            "\x1b[01mHello\x1b[021m"
        )

        self.assertParserRendersWeechat(
            "<strong><em>Hello</em></strong>",
            "\x1b[01m\x1b[03mHello\x1b[023m\x1b[021m"
        )
        self.assertParserRendersWeechat(
            "<u><strong><em>Hello</em></strong></u>",
            "\x1b[04m\x1b[01m\x1b[03mHello\x1b[023m\x1b[021m\x1b[024m"
        )

    def test_weechat_formatter_del(self):
        self.assertParserRendersWeechat(
            "<del>Hello</del>",
            "\x1b[09mHello\x1b[29m"
        )
        self.assertParserRendersWeechat(
            "<strong><del>Hello</del></strong>",
            "\x1b[01m\x1b[09mHello\x1b[29m\x1b[021m"
        )
        self.assertParserRendersWeechat(
            "<del><strong>Hello</strong></del>",
            "\x1b[09m\x1b[01mHello\x1b[021m\x1b[29m"
        )

    def test_weechat_formatter_multiple_childs(self):
        self.assertParserRendersHtml(
            "***Hello*** *world*",
            "<p><strong><em>Hello</em></strong> <em>world</em></p>"
        )
        self.assertParserRendersWeechat(
            "<strong>Hello</strong> <em>world.</em>",
            "\x1b[01mHello\x1b[021m \x1b[03mworld.\x1b[023m"
        )

    def test_weechat_formatter_colors(self):
        self.assertParserRendersWeechat(
            "<font data-mx-color=fuchsia>Hello</font>",
            "\x1b[038;5;13mHello\x1b[039m"
        )
        self.assertParserRendersWeechat(
            "<font data-mx-color=>Hello</font>",
            "Hello"
        )
        self.assertParserRendersWeechat(
            "<font data-mx-bg-color=blue>Hello</font>",
            "\x1b[048;5;12mHello\x1b[039m"
        )
        self.assertParserRendersWeechat(
            "<font data-mx-color=black data-mx-bg-color=blue>Hello</font>",
            "\x1b[038;5;0;48;5;12mHello\x1b[039m"
        )
        self.assertParserRendersWeechat(
            "<strong><font data-mx-color=black "
            "data-mx-bg-color=blue>Hello</font></strong>",
            "\x1b[01m\x1b[038;5;0;48;5;12mHello\x1b[039m\x1b[021m"
        )

    def test_weechat_formatter_blockquotes(self):
        self.assertParserRendersWeechat(
            "<blockquote>{}</blockquote>".format(lorem),
            "\x1b[0m> Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed\n"
            "\x1b[0m> doeiusmod tempor incididunt ut labore et dolore magna aliqua.\n"
            "\x1b[0m> Ut enim ad minimveniam, quis nostrud exercitation ullamco\n"
            "\x1b[0m> laboris nisi ut aliquip ex ea commodoconsequat. Duis aute\n"
            "\x1b[0m> irure dolor in reprehenderit in voluptate velit essecillum\n"
            "\x1b[0m> dolore eu fugiat nulla pariatur. Excepteur sint occaecat\n"
            "\x1b[0m> cupidatat nonproident, sunt in culpa qui officia deserunt\n"
            "\x1b[0m> mollit anim id est laborum."
        )

    def test_weechat_formatter_code_blocks(self):
        self.assertParserRendersWeechat(
            "<code>Hello</code>",
            "\x1b[038;5;4mHello\x1b[00m"
        )

        self.assertParserRendersWeechat(
            "<pre><code class=language-python>print(\"Hello world\")</code></pre>",
            "\x1b[038;5;70m\x1b[01mprint\x1b[021m\x1b[039m\x1b[038;5;252m"
            "(\x1b[039m\x1b[038;5;214m\"Hello world\"\x1b[039m\x1b[038;5;252m)"
            "\x1b[039m\x1b[038;5;252m\n\x1b[039m"
        )
