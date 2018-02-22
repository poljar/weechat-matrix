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

from matrix.globals import W

from matrix.colors import Formatted
from matrix.utils import (strip_matrix_server, color_for_tags, date_from_age,
                          sender_to_nick_and_color, tags_for_message,
                          add_event_tags, sanitize_id, sanitize_age,
                          sanitize_text)


class MatrixRoom:

    def __init__(self, room_id):
        # type: (str) -> None
        # yapf: disable
        self.room_id = room_id        # type: str
        self.alias = room_id          # type: str
        self.topic = ""               # type: str
        self.topic_author = ""        # type: str
        self.topic_date = None        # type: datetime.datetime
        self.prev_batch = ""          # type: str
        self.users = dict()           # type: Dict[str, MatrixUser]
        self.encrypted = False        # type: bool
        self.backlog_pending = False  # type: bool
        # yapf: enable


def matrix_create_room_buffer(server, room_id):
    # type: (MatrixServer, str) -> None
    buf = W.buffer_new(room_id, "room_input_cb", server.name, "room_close_cb",
                       server.name)

    W.buffer_set(buf, "localvar_set_type", 'channel')
    W.buffer_set(buf, "type", 'formatted')

    W.buffer_set(buf, "localvar_set_channel", room_id)

    W.buffer_set(buf, "localvar_set_nick", server.user)

    W.buffer_set(buf, "localvar_set_server", server.name)

    short_name = strip_matrix_server(room_id)
    W.buffer_set(buf, "short_name", short_name)

    W.nicklist_add_group(buf, '', "000|o", "weechat.color.nicklist_group", 1)
    W.nicklist_add_group(buf, '', "001|h", "weechat.color.nicklist_group", 1)
    W.nicklist_add_group(buf, '', "002|v", "weechat.color.nicklist_group", 1)
    W.nicklist_add_group(buf, '', "999|...", "weechat.color.nicklist_group", 1)

    W.buffer_set(buf, "nicklist", "1")
    W.buffer_set(buf, "nicklist_display_groups", "0")

    server.buffers[room_id] = buf
    server.rooms[room_id] = MatrixRoom(room_id)


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
