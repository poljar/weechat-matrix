# -*- coding: utf-8 -*-

# Copyright © 2018 Damir Jelić <poljar@termina.org.uk>
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

from __future__ import unicode_literals
from builtins import str

from matrix.globals import W, OPTIONS


class MatrixEvent():
    def __init__(self, server):
        self.server = server

    def execute(self):
        pass


class MatrixErrorEvent(MatrixEvent):
    def __init__(self, server, error_message, fatal=False):
        self.error_message = error_message
        self.fatal = fatal
        MatrixEvent.__init__(self, server)

    def execute(self):
        message = ("{prefix}matrix: {error}").format(
            prefix=W.prefix("error"),
            error=self.error_message)

        W.prnt(self.server.server_buffer, message)

        if self.fatal:
            self.server.disconnect(reconnect=False)


class MatrixLoginEvent(MatrixEvent):
    def __init__(self, server, user_id, access_token):
        self.user_id = user_id
        self.access_token = access_token
        MatrixEvent.__init__(self, server)

    def execute(self):
        self.server.access_token = self.access_token
        self.server.user_id = self.user_id
        self.server.client.access_token = self.access_token

        self.server.sync()

    @classmethod
    def from_dict(cls, server, parsed_dict):
        try:
            return cls(
                server,
                parsed_dict["user_id"],
                parsed_dict["access_token"]
            )
        except KeyError:
            try:
                message = "Error logging in: {}.".format(parsed_dict["error"])
                return MatrixErrorEvent(
                    server,
                    message,
                    fatal=True
                )
            except KeyError:
                return MatrixErrorEvent(
                    server,
                    "Error logging in: Invalid JSON response from server.",
                    fatal=True)
