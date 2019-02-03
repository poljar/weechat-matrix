import unittest
from matrix.markdown_parser import Parser
from markdown import markdown
import textwrap
import re
import pdb
import sys

class TestClass(unittest.TestCase):
    def assertParserRendersHtml(self, source, expected):
        parser = Parser.from_weechat(source)
        self.assertMultiLineEqual(parser.to_html(), expected)

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

    def test_fenced_code(self):
        self.assertParserRendersHtml(
            "```python\n# python code\n```",
            self.dedent(
                """
                <pre><code class="python"># python code
                </code></pre>
                """
            )
        )
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
