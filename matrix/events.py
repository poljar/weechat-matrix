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
import math
from functools import partial

from matrix.globals import W, OPTIONS
from matrix.utils import (
    color_for_tags,
    date_from_age,
    sender_to_nick_and_color,
    tags_for_message,
    add_event_tags
)
from matrix.colors import Formatted


def sanitize_id(string):
    # type: (str) -> str
    if not isinstance(string, str):
        raise TypeError

    remap = {
        ord('\b'): None,
        ord('\f'): None,
        ord('\n'): None,
        ord('\r'): None,
        ord('\t'): None,
        ord('\0'): None
    }

    return string.translate(remap)


def sanitize_age(age):
    # type: (int) -> int
    if not isinstance(age, int):
        raise TypeError

    if math.isnan(age):
        raise ValueError

    if math.isinf(age):
        raise ValueError

    if age < 0:
        raise ValueError

    return age


def sanitize_text(string):
    # type: (str) -> str
    if not isinstance(string, str):
        raise TypeError

    remap = {
        ord('\b'): None,
        ord('\f'): None,
        ord('\r'): None,
        ord('\0'): None
    }

    return string.translate(remap)


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
            message = "{prefix}: {error}".format(
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
                sanitize_id(parsed_dict["user_id"]),
                sanitize_id(parsed_dict["access_token"])
            )
        except (KeyError, TypeError, ValueError):
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
                sanitize_id(parsed_dict["event_id"]),
                message
            )
        except (KeyError, TypeError, ValueError):
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
            return cls(
                server,
                room_id,
                sanitize_id(parsed_dict["event_id"]),
                topic
            )
        except (KeyError, TypeError, ValueError):
            return MatrixErrorEvent.from_dict(
                server,
                "Error setting topic",
                False,
                parsed_dict
            )


class MatrixRedactEvent(MatrixEvent):
    def __init__(self, server, room_id, event_id, reason):
        self.room_id = room_id
        self.topic = reason
        self.event_id = event_id
        MatrixEvent.__init__(self, server)

    @classmethod
    def from_dict(cls, server, room_id, reason, parsed_dict):
        try:
            return cls(
                server,
                room_id,
                sanitize_id(parsed_dict["event_id"]),
                reason
            )
        except (KeyError, TypeError, ValueError):
            return MatrixErrorEvent.from_dict(
                server,
                "Error redacting message",
                False,
                parsed_dict
            )


class MatrixJoinEvent(MatrixEvent):
    def __init__(self, server, room, room_id):
        self.room = room
        self.room_id = room_id
        MatrixEvent.__init__(self, server)

    @classmethod
    def from_dict(cls, server, room_id, parsed_dict):
        try:
            return cls(
                server,
                room_id,
                sanitize_id(parsed_dict["room_id"]),
            )
        except (KeyError, TypeError, ValueError):
            return MatrixErrorEvent.from_dict(
                server,
                "Error joining room",
                False,
                parsed_dict
            )


class MatrixPartEvent(MatrixEvent):
    def __init__(self, server, room_id):
        self.room_id = room_id
        MatrixEvent.__init__(self, server)

    @classmethod
    def from_dict(cls, server, room_id, parsed_dict):
        try:
            if parsed_dict == {}:
                return cls(
                    server,
                    room_id)

            raise KeyError
        except KeyError:
            return MatrixErrorEvent.from_dict(
                server,
                "Error leaving room",
                False,
                parsed_dict
            )


class MatrixInviteEvent(MatrixEvent):
    def __init__(self, server, room_id, user_id):
        self.room_id = room_id
        self.user_id = user_id
        MatrixEvent.__init__(self, server)

    @classmethod
    def from_dict(cls, server, room_id, user_id, parsed_dict):
        try:
            if parsed_dict == {}:
                return cls(
                    server,
                    room_id,
                    user_id)

            raise KeyError
        except KeyError:
            return MatrixErrorEvent.from_dict(
                server,
                "Error inviting user",
                False,
                parsed_dict
            )


class MatrixBacklogEvent(MatrixEvent):
    def __init__(self, server, room_id, end_token, messages):
        self.room_id = room_id
        self.end_token = end_token
        self.messages = messages
        MatrixEvent.__init__(self, server)

    @staticmethod
    def _message_from_event(room_id, event):
        if room_id != event["room_id"]:
            raise ValueError

        if "redacted_by" in event["unsigned"]:
            return RedactedMessage.from_dict(event)

        return Message.from_dict(event)

    @classmethod
    def from_dict(cls, server, room_id, parsed_dict):
        try:
            if not parsed_dict["chunk"]:
                return cls(server, room_id, None, [])

            end_token = sanitize_id(parsed_dict["end"])

            message_func = partial(
                MatrixBacklogEvent._message_from_event,
                room_id
            )

            message_events = list(filter(
                lambda event: event["type"] == "m.room.message",
                parsed_dict["chunk"]
            ))

            messages = [message_func(m) for m in message_events]

            return cls(
                server,
                room_id,
                end_token,
                messages)
        except (KeyError, ValueError, TypeError):
            return MatrixErrorEvent.from_dict(
                server,
                "Error fetching backlog",
                False,
                parsed_dict
            )

    def execute(self):
        room = self.server.rooms[self.room_id]
        buf = self.server.buffers[self.room_id]
        tags = tags_for_message("backlog")

        for message in self.messages:
            message.prnt(room, buf, tags)

        room.prev_batch = self.end_token


class AbstractMessage():
    def __init__(self, event_id, sender, age):
        self.event_id = event_id
        self.sender = sender
        self.age = age


class RedactedMessage(AbstractMessage):
    def __init__(self, event_id, sender, age, censor, reason=None):
        self.censor = censor
        self.reason = reason
        AbstractMessage.__init__(self, event_id, sender, age)

    @classmethod
    def from_dict(cls, event):
        event_id = sanitize_id(event["event_id"])
        sender = sanitize_id(event["sender"])
        age = event["unsigned"]["age"]

        censor = sanitize_id(
            event['unsigned']['redacted_because']['sender'])
        reason = None

        if 'reason' in event['unsigned']['redacted_because']['content']:
            reason = sanitize_text(
                event['unsigned']['redacted_because']['content']['reason'])

        return cls(event_id, sender, age, censor, reason)

    def prnt(self, room, buff, tags):
        pass


class Message(AbstractMessage):
    def __init__(
        self,
        event_id,
        sender,
        age,
        message,
        formatted_message=None
    ):
        self.message = message
        self.formatted_message = formatted_message
        AbstractMessage.__init__(self, event_id, sender, age)

    @classmethod
    def from_dict(cls, event):
        event_id = sanitize_id(event["event_id"])
        sender = sanitize_id(event["sender"])
        age = sanitize_age(event["unsigned"]["age"])

        msg = ""
        formatted_msg = None

        if event['content']['msgtype'] == 'm.text':
            msg = sanitize_text(event['content']['body'])

            if ('format' in event['content'] and
                    'formatted_body' in event['content']):
                if event['content']['format'] == "org.matrix.custom.html":
                    formatted_msg = Formatted.from_html(
                        sanitize_text(event['content']['formatted_body']))

        return cls(event_id, sender, age, msg, formatted_msg)

    def prnt(self, room, buff, tags):
        msg = (self.formatted_message.to_weechat() if
               self.formatted_message
               else self.message)

        nick, color_name = sender_to_nick_and_color(room, self.sender)
        color = color_for_tags(color_name)

        event_tags = add_event_tags(
            self.event_id,
            nick,
            color,
            tags
        )

        tags_string = ",".join(event_tags)

        data = "{author}\t{msg}".format(author=nick, msg=msg)

        date = date_from_age(self.age)
        W.prnt_date_tags(buff, date, tags_string, data)
