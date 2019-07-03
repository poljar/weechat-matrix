from matrix.server import MatrixServer
from matrix._weechat import MockConfig
import matrix.globals as G

G.CONFIG = MockConfig()

class TestClass(object):
    def test_address_parsing(self):
        homeserver = MatrixServer._parse_url("example.org", 8080)
        assert homeserver.hostname == "example.org"
        assert homeserver.geturl() == "https://example.org:8080"

        homeserver = MatrixServer._parse_url("example.org/_matrix", 80)
        assert homeserver.hostname == "example.org"
        assert homeserver.geturl() == "https://example.org:80/_matrix"

        homeserver = MatrixServer._parse_url(
            "https://example.org/_matrix", 80
        )
        assert homeserver.hostname == "example.org"
        assert homeserver.geturl() == "https://example.org:80/_matrix"
