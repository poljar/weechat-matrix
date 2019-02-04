from matrix.server import MatrixServer
from matrix._weechat import MockConfig
import matrix.globals as G

G.CONFIG = MockConfig()

class TestClass(object):
    def test_address_parsing(self):
        host, extra_path = MatrixServer._parse_url("example.org")
        assert host == "example.org"
        assert extra_path == ""

        host, extra_path = MatrixServer._parse_url("example.org/_matrix")
        assert host == "example.org"
        assert extra_path == "_matrix"

        host, extra_path = MatrixServer._parse_url(
            "https://example.org/_matrix"
        )
        assert host == "example.org"
        assert extra_path == "_matrix"

        host, extra_path = MatrixServer._parse_url("https://example.org")
        assert host == "example.org"
        assert extra_path == ""
