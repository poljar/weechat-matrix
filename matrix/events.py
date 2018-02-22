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
    add_event_tags,
)
from matrix.colors import Formatted
from matrix.rooms import matrix_create_room_buffer


def sanitize_token(string):
    # type: (str) -> str
    string = sanitize_string(string)

    if len(string) > 512:
        raise ValueError

    return string


def sanitize_string(string):
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


def sanitize_id(string):
    # type: (str) -> str
    string = sanitize_string(string)

    if len(string) > 128:
        raise ValueError

    return string


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

    remap = {ord('\b'): None, ord('\f'): None, ord('\r'): None, ord('\0'): None}

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
            prefix=W.prefix("error"), error=self.error_message)

        W.prnt(self.server.server_buffer, message)

        if self.fatal:
            self.server.disconnect(reconnect=False)

    @classmethod
    def from_dict(cls, server, error_prefix, fatal, parsed_dict):
        try:
            message = "{prefix}: {error}".format(
                prefix=error_prefix, error=sanitize_text(parsed_dict["error"]))
            return cls(server, message, fatal=fatal)
        except KeyError:
            return cls(
                server, ("{prefix}: Invalid JSON response "
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
            return cls(server, sanitize_id(parsed_dict["user_id"]),
                       sanitize_token(parsed_dict["access_token"]))
        except (KeyError, TypeError, ValueError):
            return MatrixErrorEvent.from_dict(server, "Error logging in", True,
                                              parsed_dict)


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
            return cls(server, room_id, sanitize_id(parsed_dict["event_id"]),
                       message)
        except (KeyError, TypeError, ValueError):
            return MatrixErrorEvent.from_dict(server, "Error sending message",
                                              False, parsed_dict)


class MatrixTopicEvent(MatrixEvent):

    def __init__(self, server, room_id, event_id, topic):
        self.room_id = room_id
        self.topic = topic
        self.event_id = event_id
        MatrixEvent.__init__(self, server)

    @classmethod
    def from_dict(cls, server, room_id, topic, parsed_dict):
        try:
            return cls(server, room_id, sanitize_id(parsed_dict["event_id"]),
                       topic)
        except (KeyError, TypeError, ValueError):
            return MatrixErrorEvent.from_dict(server, "Error setting topic",
                                              False, parsed_dict)


class MatrixRedactEvent(MatrixEvent):

    def __init__(self, server, room_id, event_id, reason):
        self.room_id = room_id
        self.topic = reason
        self.event_id = event_id
        MatrixEvent.__init__(self, server)

    @classmethod
    def from_dict(cls, server, room_id, reason, parsed_dict):
        try:
            return cls(server, room_id, sanitize_id(parsed_dict["event_id"]),
                       reason)
        except (KeyError, TypeError, ValueError):
            return MatrixErrorEvent.from_dict(server, "Error redacting message",
                                              False, parsed_dict)


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
            return MatrixErrorEvent.from_dict(server, "Error joining room",
                                              False, parsed_dict)


class MatrixPartEvent(MatrixEvent):

    def __init__(self, server, room_id):
        self.room_id = room_id
        MatrixEvent.__init__(self, server)

    @classmethod
    def from_dict(cls, server, room_id, parsed_dict):
        try:
            if parsed_dict == {}:
                return cls(server, room_id)

            raise KeyError
        except KeyError:
            return MatrixErrorEvent.from_dict(server, "Error leaving room",
                                              False, parsed_dict)


class MatrixInviteEvent(MatrixEvent):

    def __init__(self, server, room_id, user_id):
        self.room_id = room_id
        self.user_id = user_id
        MatrixEvent.__init__(self, server)

    @classmethod
    def from_dict(cls, server, room_id, user_id, parsed_dict):
        try:
            if parsed_dict == {}:
                return cls(server, room_id, user_id)

            raise KeyError
        except KeyError:
            return MatrixErrorEvent.from_dict(server, "Error inviting user",
                                              False, parsed_dict)


class MatrixBacklogEvent(MatrixEvent):

    def __init__(self, server, room_id, end_token, events):
        self.room_id = room_id
        self.end_token = end_token
        self.events = events
        MatrixEvent.__init__(self, server)

    @staticmethod
    def _room_event_from_dict(room_id, event_dict):
        if room_id != event_dict["room_id"]:
            raise ValueError

        if "redacted_by" in event_dict["unsigned"]:
            return RoomRedactedMessageEvent.from_dict(event_dict)

        return RoomMessageEvent.from_dict(event_dict)

    @classmethod
    def from_dict(cls, server, room_id, parsed_dict):
        try:
            end_token = sanitize_id(parsed_dict["end"])

            if not parsed_dict["chunk"]:
                return cls(server, room_id, end_token, [])

            event_func = partial(MatrixBacklogEvent._room_event_from_dict,
                                 room_id)

            message_events = list(
                filter(lambda event: event["type"] == "m.room.message",
                       parsed_dict["chunk"]))

            events = [event_func(m) for m in message_events]

            return cls(server, room_id, end_token, events)
        except (KeyError, ValueError, TypeError):
            return MatrixErrorEvent.from_dict(server, "Error fetching backlog",
                                              False, parsed_dict)

    def execute(self):
        room = self.server.rooms[self.room_id]
        buf = self.server.buffers[self.room_id]
        tags = tags_for_message("backlog")

        for event in self.events:
            event.execute(room, buf, tags)

        room.prev_batch = self.end_token
        room.backlog_pending = False
        W.bar_item_update("buffer_modes")


class MatrixSyncEvent(MatrixEvent):

    def __init__(self, server, next_batch, room_infos, invited_infos):
        self.next_batch = next_batch
        self.joined_room_infos = room_infos
        self.invited_room_infos = invited_infos

        MatrixEvent.__init__(self, server)

    @staticmethod
    def _infos_from_dict(parsed_dict):
        join_infos = []
        invite_infos = []

        for room_id, room_dict in parsed_dict['join'].items():
            if not room_id:
                continue

            join_infos.append(RoomInfo.from_dict(room_id, room_dict))

        return (join_infos, invite_infos)

    @classmethod
    def from_dict(cls, server, parsed_dict):
        try:
            next_batch = sanitize_id(parsed_dict["next_batch"])
            room_info_dict = parsed_dict["rooms"]

            join_infos, invite_infos = MatrixSyncEvent._infos_from_dict(
                room_info_dict)

            return cls(server, next_batch, join_infos, invite_infos)
        except (KeyError, ValueError, TypeError):
            return MatrixErrorEvent.from_dict(server, "Error syncing", False,
                                              parsed_dict)

    def _execute_joined_info(self, info):
        server = self.server

        if info.room_id not in server.buffers:
            matrix_create_room_buffer(server, info.room_id)

        room = server.rooms[info.room_id]
        buf = server.buffers[info.room_id]

        if not room.prev_batch:
            room.prev_batch = info.prev_batch

        tags = tags_for_message("message")
        for message in info.events:
            message.execute(room, buf, tags)

    def execute(self):
        server = self.server

        # we got the same batch again, nothing to do
        if self.next_batch == server.next_batch:
            server.sync()
            return

        map(self._execute_joined_info, self.joined_room_infos)

        server.next_batch = self.next_batch
        server.sync()


class RoomInfo():

    def __init__(self, room_id, prev_batch, events):
        # type: (str, str, List[Any]) -> None
        self.room_id = room_id
        self.prev_batch = prev_batch
        self.events = events

    @staticmethod
    def _message_from_event(event):
        # The transaction id will only be present for events that are send out
        # from this client, since we print out our own messages as soon as we
        # get a receive confirmation from the server we don't care about our
        # own messages in a sync event. More info under:
        # https://github.com/matrix-org/matrix-doc/blob/master/api/client-server/definitions/event.yaml#L53
        if "transaction_id" in event["unsigned"]:
            return None

        if "redacted_by" in event["unsigned"]:
            return RoomRedactedMessageEvent.from_dict(event)

        return RoomMessageEvent.from_dict(event)

    @staticmethod
    def _event_from_dict(event):
        if event['type'] == 'm.room.message':
            return RoomInfo._message_from_event(event)

    @classmethod
    def from_dict(cls, room_id, parsed_dict):
        prev_batch = sanitize_id(parsed_dict['timeline']['prev_batch'])

        events = []

        state_dict = parsed_dict['state']['events']
        timeline_dict = parsed_dict['timeline']['events']

        for event in timeline_dict:
            events.append(RoomInfo._event_from_dict(event))

        filtered_events = list(filter(None, events))

        return cls(room_id, prev_batch, filtered_events)


class RoomEvent():

    def __init__(self, event_id, sender, age):
        self.event_id = event_id
        self.sender = sender
        self.age = age


class RoomRedactedMessageEvent(RoomEvent):

    def __init__(self, event_id, sender, age, censor, reason=None):
        self.censor = censor
        self.reason = reason
        RoomEvent.__init__(self, event_id, sender, age)

    @classmethod
    def from_dict(cls, event):
        event_id = sanitize_id(event["event_id"])
        sender = sanitize_id(event["sender"])
        age = sanitize_age(event["unsigned"]["age"])

        censor = sanitize_id(event['unsigned']['redacted_because']['sender'])
        reason = None

        if 'reason' in event['unsigned']['redacted_because']['content']:
            reason = sanitize_text(
                event['unsigned']['redacted_because']['content']['reason'])

        return cls(event_id, sender, age, censor, reason)

    def execute(self, room, buff, tags):
        nick, color_name = sender_to_nick_and_color(room, self.sender)
        color = color_for_tags(color_name)
        date = date_from_age(self.age)

        event_tags = add_event_tags(self.event_id, nick, color, tags)

        reason = (", reason: \"{reason}\"".format(reason=self.reason)
                  if self.reason else "")

        censor, _ = sender_to_nick_and_color(room, self.censor)

        msg = ("{del_color}<{log_color}Message redacted by: "
               "{censor}{log_color}{reason}{del_color}>{ncolor}").format(
                   del_color=W.color("chat_delimiters"),
                   ncolor=W.color("reset"),
                   log_color=W.color("logger.color.backlog_line"),
                   censor=censor,
                   reason=reason)

        event_tags.append("matrix_redacted")

        tags_string = ",".join(event_tags)

        data = "{author}\t{msg}".format(author=nick, msg=msg)

        W.prnt_date_tags(buff, date, tags_string, data)


class RoomMessageEvent(RoomEvent):

    def __init__(self, event_id, sender, age, message, formatted_message=None):
        self.message = message
        self.formatted_message = formatted_message
        RoomEvent.__init__(self, event_id, sender, age)

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

    def execute(self, room, buff, tags):
        msg = (self.formatted_message.to_weechat()
               if self.formatted_message else self.message)

        nick, color_name = sender_to_nick_and_color(room, self.sender)
        color = color_for_tags(color_name)

        event_tags = add_event_tags(self.event_id, nick, color, tags)

        tags_string = ",".join(event_tags)

        data = "{author}\t{msg}".format(author=nick, msg=msg)

        date = date_from_age(self.age)
        W.prnt_date_tags(buff, date, tags_string, data)
