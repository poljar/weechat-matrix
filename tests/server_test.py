from matrix.server import MatrixServer
from matrix._weechat import MockConfig
import matrix.globals as G

G.CONFIG = MockConfig()

class TestClass(object):
    def test_address_parsing(self):
        host = MatrixServer._parse_url("example.org", "443")
        assert host == "example.org:443"

        host = MatrixServer._parse_url("example.org/_matrix", "443")
        assert host == "example.org:443/_matrix"

        host = MatrixServer._parse_url("https://example.org/_matrix", "443")
        assert host == "example.org:443/_matrix"

        host = MatrixServer._parse_url("https://example.org", "443")
        assert host == "example.org:443"
