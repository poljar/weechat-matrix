# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import ssl

from collections import deque

from http_parser.pyparser import HttpParser


from matrix.config import Option


class MatrixServer:
    # pylint: disable=too-many-instance-attributes
    def __init__(self, name, w, config_file):
        # type: (str, weechat, weechat.config) -> None
        self.name            = name     # type: str
        self.user_id         = ""
        self.address         = ""       # type: str
        self.port            = 8448     # type: int
        self.options         = dict()   # type: Dict[str, weechat.config]
        self.device_name     = "Weechat Matrix"  # type: str

        self.user            = ""       # type: str
        self.password        = ""       # type: str

        self.rooms           = dict()   # type: Dict[str, MatrixRoom]
        self.buffers         = dict()   # type: Dict[str, weechat.buffer]
        self.server_buffer   = None     # type: weechat.buffer
        self.fd_hook         = None     # type: weechat.hook
        self.timer_hook      = None     # type: weechat.hook
        self.numeric_address = ""       # type: str

        self.autoconnect     = False                         # type: bool
        self.connected       = False                         # type: bool
        self.connecting      = False                         # type: bool
        self.reconnect_count = 0                             # type: int
        self.socket          = None                          # type: ssl.SSLSocket
        self.ssl_context     = ssl.create_default_context()  # type: ssl.SSLContext

        self.access_token    = None                          # type: str
        self.next_batch      = None                          # type: str
        self.transaction_id  = 0                             # type: int

        self.http_parser = HttpParser()                  # type: HttpParser
        self.http_buffer = []                            # type: List[bytes]

        # Queue of messages we need to send off.
        self.send_queue    = deque()  # type: Deque[MatrixMessage]
        # Queue of messages we send off and are waiting a response for
        self.receive_queue = deque()  # type: Deque[MatrixMessage]
        self.message_queue = deque()  # type: Deque[MatrixMessage]
        self.ignore_event_list = []   # type: List[str]

        self._create_options(w, config_file)

    def _create_options(self, w, config_file):
        options = [
            Option(
                'autoconnect', 'boolean', '', 0, 0, 'off',
                (
                    "automatically connect to the matrix server when weechat "
                    "is starting"
                )
            ),
            Option(
                'address', 'string', '', 0, 0, '',
                "Hostname or IP address for the server"
            ),
            Option(
                'port', 'integer', '', 0, 65535, '8448',
                "Port for the server"
            ),
            Option(
                'ssl_verify', 'boolean', '', 0, 0, 'on',
                (
                    "Check that the SSL connection is fully trusted"
                    "is starting"
                )
            ),
            Option(
                'username', 'string', '', 0, 0, '',
                "Username to use on server"
            ),
            Option(
                'password', 'string', '', 0, 0, '',
                "Password for server"
            ),
            Option(
                'device_name', 'string', '', 0, 0, 'Weechat Matrix',
                "Device name to use while logging in to the matrix server"
            ),
        ]

        section = w.config_search_section(config_file, 'server')

        for option in options:
            option_name = "{server}.{option}".format(
                server=self.name, option=option.name)

            self.options[option.name] = w.config_new_option(
                config_file, section, option_name,
                option.type, option.description, option.string_values,
                option.min, option.max, option.value, option.value, 0, "",
                "", "server_config_change_cb", self.name, "", "")

    def reset_parser(self):
        self.http_parser = HttpParser()
        self.http_buffer = []
