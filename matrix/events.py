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

import time

from matrix.globals import W, OPTIONS
from matrix.utils import color_for_tags


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

    @classmethod
    def from_dict(cls, server, error_prefix, fatal, parsed_dict):
        try:
            message = "{prefix}: {error}.".format(
                prefix=error_prefix,
                error=parsed_dict["error"])
            return cls(
                server,
                message,
                fatal=fatal
            )
        except KeyError:
            return cls(
                server,
                ("{prefix}: Invalid JSON response "
                 "from server.").format(prefix=error_prefix),
                fatal=fatal)


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
            return MatrixErrorEvent.from_dict(
                server,
                "Error logging in",
                True,
                parsed_dict
            )


class MatrixSendEvent(MatrixEvent):
    def __init__(self, server, room_id, event_id, message):
        self.room_id = room_id
        self.event_id = event_id
        self.message = message
        MatrixEvent.__init__(self, server)

    def execute(self):
        room_id = self.room_id
        author = self.server.user
        event_id = self.event_id
        weechat_message = self.message.to_weechat()

        date = int(time.time())

        # This message will be part of the next sync, we already printed it out
        # so ignore it in the sync.
        self.server.ignore_event_list.append(event_id)

        tag = ("notify_none,no_highlight,self_msg,log1,nick_{a},"
               "prefix_nick_{color},matrix_id_{event_id},"
               "matrix_message").format(
                   a=author,
                   color=color_for_tags("weechat.color.chat_nick_self"),
                   event_id=event_id)

        message = "{author}\t{msg}".format(author=author, msg=weechat_message)

        buf = self.server.buffers[room_id]
        W.prnt_date_tags(buf, date, tag, message)

    @classmethod
    def from_dict(cls, server, room_id, message, parsed_dict):
        try:
            return cls(
                server,
                room_id,
                parsed_dict["event_id"],
                message
            )
        except KeyError:
            return MatrixErrorEvent.from_dict(
                server,
                "Error sending message",
                False,
                parsed_dict
            )


class MatrixTopicEvent(MatrixEvent):
    def __init__(self, server, room_id, event_id, topic):
        self.room_id = room_id
        self.topic = topic
        self.event_id = event_id
        MatrixEvent.__init__(self, server)

    @classmethod
    def from_dict(cls, server, room_id, topic, parsed_dict):
        try:
            return cls(server, room_id, parsed_dict["event_id"], topic)
        except KeyError:
            return MatrixErrorEvent.from_dict(
                server,
                "Error setting topic",
                False,
                parsed_dict
            )
