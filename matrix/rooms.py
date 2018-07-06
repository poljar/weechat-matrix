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

import json

from pprint import pformat

from collections import namedtuple, deque
from datetime import datetime

from matrix.globals import W, OPTIONS
from matrix.plugin_options import RedactType

from matrix.colors import Formatted
from matrix.utils import (
    strip_matrix_server, color_for_tags, server_ts_to_weechat,
    sender_to_nick_and_color, add_event_tags, sanitize_id, sanitize_ts,
    sanitize_string, sanitize_text, shorten_sender, add_user_to_nicklist,
    get_prefix_for_level, sanitize_power_level, string_strikethrough,
    line_pointer_and_tags_from_event, sender_to_prefix_and_color)

PowerLevel = namedtuple('PowerLevel', ['user', 'level'])


class MatrixRoom:

    def __init__(self, room_id):
        # type: (str) -> None
        # yapf: disable
        self.room_id = room_id        # type: str
        self.canonical_alias = None   # type: str
        self.name = None              # type: str
        self.topic = ""               # type: str
        self.topic_author = ""        # type: str
        self.topic_date = None        # type: datetime.datetime
        self.prev_batch = ""          # type: str
        self.users = dict()           # type: Dict[str, MatrixUser]
        self.encrypted = False        # type: bool
        self.backlog_pending = False  # type: bool
        # yapf: enable

    def display_name(self, own_user_id):
        """
        Calculate display name for a room.

        Prefer returning the room name if it exists, falling back to
        a group-style name if not.

        Mostly follows:
        https://matrix.org/docs/spec/client_server/r0.3.0.html#id268

        An exception is that we prepend '#' before the room name to make it
        visually distinct from private messages and unnamed groups of users
        ("direct chats") in weechat's buffer list.
        """
        if self.is_named():
            return self.named_room_name()
        else:
            return self.group_name(own_user_id)

    def named_room_name(self):
        """
        Returns the name of the room, if it's a named room. Otherwise return
        None.
        """
        if self.name:
            return "#" + self.name
        elif self.canonical_alias:
            return self.canonical_alias
        else:
            return None

    def group_name(self, own_user_id):
        """
        Returns the group-style name of the room, i.e. a name based on the room
        members.
        """
        # Sort user display names, excluding our own user and using the
        # mxid as the sorting key.
        #
        # TODO: Hook the user display name disambiguation algorithm here.
        # Currently, we use the user display names as is, which may not be
        # unique.
        users = [user.name for mxid, user
                 in sorted(self.users.items(), key=lambda t: t[0])
                 if mxid != own_user_id]

        num_users = len(users)

        if num_users == 1:
            return users[0]
        elif num_users == 2:
            return " and ".join(users)
        elif num_users >= 3:
            return "{first_user} and {num} others".format(
                first_user=users[0],
                num=num_users-1)
        else:
            return "Empty room?"


    def machine_name(self):
        """
        Calculate an unambiguous, unique machine name for a room.

        Either use the more human-friendly canonical alias, if it exists, or
        the internal room ID if not.
        """
        if self.canonical_alias:
            return self.canonical_alias
        else:
            return self.room_id

    def is_named(self):
        """
        Is this a named room?

        A named room is a room with either the name or a canonical alias set.
        """
        return self.canonical_alias or self.name

    def is_group(self):
        """
        Is this an ad hoc group of users?

        A group is an unnamed room with no canonical alias.
        """
        return not self.is_named()


class MatrixUser:

    def __init__(self, name, display_name):
        # yapf: disable
        self.name = name                  # type: str
        self.display_name = display_name  # type: str
        self.power_level = 0              # type: int
        self.nick_color = ""              # type: str
        self.prefix = ""                  # type: str
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

    # TODO make this configurable
    W.buffer_set(buf, "highlight_tags_restrict", "matrix_message")

    server.buffers[room_id] = buf
    server.rooms[room_id] = MatrixRoom(room_id)


class RoomInfo():

    def __init__(self, room_id, prev_batch, events):
        # type: (str, str, List[Any], List[Any]) -> None
        self.room_id = room_id
        self.prev_batch = prev_batch
        self.events = deque(events)

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
    def _membership_from_dict(event_dict):
        if (event_dict["content"]["membership"] not in [
                "invite", "join", "knock", "leave", "ban"
        ]):
            raise ValueError

        if event_dict["content"]["membership"] == "join":
            event = RoomMemberJoin.from_dict(event_dict)

            try:
                message = RoomMembershipMessage(
                    event.event_id, event.sender, event.timestamp,
                    "has joined", "join")

                return event, message
            except AttributeError:
                return event, None

        elif event_dict["content"]["membership"] == "leave":
            event = RoomMemberLeave.from_dict(event_dict)

            try:
                msg = ("has left" if event.sender == event.leaving_user else
                       "has been kicked")
                message = RoomMembershipMessage(
                    event.event_id, event.leaving_user, event.timestamp, msg, "quit")
                return event, message
            except AttributeError:
                return event, None

        return None, None

    @staticmethod
    def parse_event(olm, room_id, event_dict):
        # type: (Dict[Any, Any]) -> (RoomEvent, RoomEvent)
        state_event = None
        message_event = None

        if "redacted_by" in event_dict["unsigned"]:
            message_event = RoomRedactedMessageEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.message":
            message_event = RoomInfo._message_from_event(event_dict)
        elif event_dict["type"] == "m.room.member":
            state_event, message_event = (
                RoomInfo._membership_from_dict(event_dict))
        elif event_dict["type"] == "m.room.power_levels":
            state_event = RoomPowerLevels.from_dict(event_dict)
        elif event_dict["type"] == "m.room.topic":
            state_event = RoomTopicEvent.from_dict(event_dict)
            message_event = RoomTopiceMessage(
                state_event.event_id,
                state_event.sender,
                state_event.timestamp,
                state_event.topic)
        elif event_dict["type"] == "m.room.redaction":
            message_event = RoomRedactionEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.name":
            state_event = RoomNameEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.canonical_alias":
            state_event = RoomAliasEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.encryption":
            state_event = RoomEncryptionEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.encrypted":
            state_event, message_event = RoomInfo._decrypt_event(olm, room_id,
                                                                 event_dict)

        return state_event, message_event

    @staticmethod
    def _decrypt_event(olm, room_id, event_dict):
        session_id = event_dict["content"]["session_id"]
        ciphertext = event_dict["content"]["ciphertext"]
        plaintext, message_index = olm.group_decrypt(
            room_id,
            session_id,
            ciphertext
        )

        if not plaintext:
            return None, None

        parsed_plaintext = json.loads(plaintext, encoding="utf-8")

        event_dict["content"] = parsed_plaintext["content"]
        event_dict["type"] = parsed_plaintext["type"]

        return RoomInfo.parse_event(olm, room_id, event_dict)

    @staticmethod
    def _parse_events(olm, room_id, parsed_dict, messages=True, state=True):
        state_events = []
        message_events = []

        if not messages and not state:
            return []

        try:
            for event in parsed_dict:
                m_event, s_event = RoomInfo.parse_event(olm, room_id, event)
                state_events.append(m_event)
                message_events.append(s_event)
        except (ValueError, TypeError, KeyError) as error:
            message = ("{prefix}matrix: Error parsing "
                       "room event of type {type}: {error}\n{event}").format(
                           prefix=W.prefix("error"),
                           type=event["type"],
                           error=pformat(error),
                           event=pformat(event))
            W.prnt("", message)
            raise

        events = []

        if state:
            events = events + state_events

        if messages:
            events = events + message_events

        return events

    @classmethod
    def from_dict(cls, olm, room_id, parsed_dict):
        prev_batch = sanitize_id(parsed_dict['timeline']['prev_batch'])

        state_dict = parsed_dict['state']['events']
        timeline_dict = parsed_dict['timeline']['events']

        state_events = RoomInfo._parse_events(olm, room_id, state_dict, messages=False)
        timeline_events = RoomInfo._parse_events(olm, room_id, timeline_dict)

        events = state_events + timeline_events

        return cls(room_id, prev_batch, list(filter(None, events)))


class RoomEvent():

    def __init__(self, event_id, sender, timestamp):
        self.event_id = event_id
        self.sender = sender
        self.timestamp = timestamp


class RoomRedactedMessageEvent(RoomEvent):

    def __init__(self, event_id, sender, timestamp, censor, reason=None):
        self.censor = censor
        self.reason = reason
        RoomEvent.__init__(self, event_id, sender, timestamp)

    @classmethod
    def from_dict(cls, event):
        event_id = sanitize_id(event["event_id"])
        sender = sanitize_id(event["sender"])
        timestamp = sanitize_ts(event["origin_server_ts"])

        censor = sanitize_id(event['unsigned']['redacted_because']['sender'])
        reason = None

        if 'reason' in event['unsigned']['redacted_because']['content']:
            reason = sanitize_text(
                event['unsigned']['redacted_because']['content']['reason'])

        return cls(event_id, sender, timestamp, censor, reason)

    def execute(self, server, room, buff, tags):
        nick, color_name = sender_to_nick_and_color(room, self.sender)
        color = color_for_tags(color_name)
        date = server_ts_to_weechat(self.timestamp)

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

    @classmethod
    def from_dict(cls, event):
        if event['content']['msgtype'] == 'm.text':
            return RoomMessageText.from_dict(event)
        elif event['content']['msgtype'] == 'm.image':
            return RoomMessageMedia.from_dict(event)
        elif event['content']['msgtype'] == 'm.audio':
            return RoomMessageMedia.from_dict(event)
        elif event['content']['msgtype'] == 'm.file':
            return RoomMessageMedia.from_dict(event)
        elif event['content']['msgtype'] == 'm.video':
            return RoomMessageMedia.from_dict(event)
        elif event['content']['msgtype'] == 'm.emote':
            return RoomMessageEmote.from_dict(event)
        elif event['content']['msgtype'] == 'm.notice':
            return RoomMessageNotice.from_dict(event)
        return RoomMessageUnknown.from_dict(event)

    def _print_message(self, message, room, buff, tags):
        nick, color_name = sender_to_nick_and_color(room, self.sender)
        color = color_for_tags(color_name)

        event_tags = add_event_tags(self.event_id, nick, color, tags)

        tags_string = ",".join(event_tags)

        prefix, prefix_color = sender_to_prefix_and_color(room, self.sender)

        prefix_string = ("" if not prefix else "{}{}{}".format(
            W.color(prefix_color), prefix, W.color("reset")))

        data = "{prefix}{color}{author}{ncolor}\t{msg}".format(
            prefix=prefix_string,
            color=W.color(color_name),
            author=nick,
            ncolor=W.color("reset"),
            msg=message)

        date = server_ts_to_weechat(self.timestamp)
        W.prnt_date_tags(buff, date, tags_string, data)


class RoomMessageSimple(RoomMessageEvent):

    def __init__(self, event_id, sender, timestamp, message, message_type):
        self.message = message
        self.message_type = message_type
        RoomEvent.__init__(self, event_id, sender, timestamp)

    @classmethod
    def from_dict(cls, event):
        event_id = sanitize_id(event["event_id"])
        sender = sanitize_id(event["sender"])
        timestamp = sanitize_ts(event["origin_server_ts"])

        message = sanitize_text(event["content"]["body"])
        message_type = sanitize_text(event["content"]["msgtype"])

        return cls(event_id, sender, timestamp, message, message_type)


class RoomMessageUnknown(RoomMessageSimple):

    def execute(self, server, room, buff, tags):
        msg = ("Unknown message of type {t}, body: {body}").format(
            t=self.message_type, body=self.message)

        self._print_message(msg, room, buff, tags)


class RoomMessageText(RoomMessageEvent):

    def __init__(self, event_id, sender, timestamp, message, formatted_message=None):
        self.message = message
        self.formatted_message = formatted_message
        RoomEvent.__init__(self, event_id, sender, timestamp)

    @classmethod
    def from_dict(cls, event):
        event_id = sanitize_id(event["event_id"])
        sender = sanitize_id(event["sender"])
        timestamp = sanitize_ts(event["origin_server_ts"])

        msg = ""
        formatted_msg = None

        msg = sanitize_text(event['content']['body'])

        if ('format' in event['content'] and
                'formatted_body' in event['content']):
            if event['content']['format'] == "org.matrix.custom.html":
                formatted_msg = Formatted.from_html(
                    sanitize_text(event['content']['formatted_body']))

        return cls(event_id, sender, timestamp, msg, formatted_msg)

    def execute(self, server, room, buff, tags):
        msg = (self.formatted_message.to_weechat()
               if self.formatted_message else self.message)

        self._print_message(msg, room, buff, tags)


class RoomMessageEmote(RoomMessageSimple):

    def execute(self, server, room, buff, tags):
        nick, color_name = sender_to_nick_and_color(room, self.sender)
        color = color_for_tags(color_name)

        event_tags = add_event_tags(self.event_id, nick, color, tags)
        event_tags.append("matrix_action")

        tags_string = ",".join(event_tags)

        data = "{prefix}{nick_color}{author}{ncolor} {msg}".format(
            prefix=W.prefix("action"),
            nick_color=W.color(color_name),
            author=nick,
            ncolor=W.color("reset"),
            msg=self.message)

        date = server_ts_to_weechat(self.timestamp)
        W.prnt_date_tags(buff, date, tags_string, data)


class RoomMessageNotice(RoomMessageText):

    def execute(self, server, room, buff, tags):
        msg = "{color}{message}{ncolor}".format(
            color=W.color("irc.color.notice"),
            message=self.message,
            ncolor=W.color("reset"))

        self._print_message(msg, room, buff, tags)


class RoomMessageMedia(RoomMessageEvent):

    def __init__(self, event_id, sender, timestamp, url, description):
        self.url = url
        self.description = description
        RoomEvent.__init__(self, event_id, sender, timestamp)

    @classmethod
    def from_dict(cls, event):
        event_id = sanitize_id(event["event_id"])
        sender = sanitize_id(event["sender"])
        timestamp = sanitize_ts(event["origin_server_ts"])

        mxc_url = sanitize_text(event['content']['url'])
        description = sanitize_text(event["content"]["body"])

        return cls(event_id, sender, timestamp, mxc_url, description)

    def execute(self, server, room, buff, tags):
        http_url = server.client.mxc_to_http(self.url)
        url = http_url if http_url else self.url

        description = (" ({})".format(self.description)
                       if self.description else "")

        msg = "{url}{desc}".format(url=url, desc=description)

        self._print_message(msg, room, buff, tags)


class RoomMembershipMessage(RoomEvent):
    def __init__(self, event_id, sender, timestamp, message, prefix):
        self.message = message
        self.prefix = prefix
        RoomEvent.__init__(self, event_id, sender, timestamp)

    def execute(self, server, room, buff, tags):
        nick, color_name = sender_to_nick_and_color(room, self.sender)
        event_tags = add_event_tags(self.event_id, nick, None, [])
        # TODO this should be configurable
        action_color = "red" if self.prefix == "quit" else "green"

        data = ("{prefix}{color}{author}{ncolor} "
                "{del_color}({host_color}{user_id}{del_color})"
                "{action_color} {message} "
                "{channel_color}{room}{ncolor}").format(
            prefix=W.prefix(self.prefix),
            color=W.color(color_name),
            author=nick,
            ncolor=W.color("reset"),
            del_color=W.color("chat_delimiters"),
            host_color=W.color("chat_host"),
            user_id=self.sender,
            action_color=W.color(action_color),
            message=self.message,
            channel_color=W.color("chat_channel"),
            room="" if room.is_group() else room.named_room_name())
        date = server_ts_to_weechat(self.timestamp)
        tags_string = ",".join(event_tags)

        W.prnt_date_tags(buff, date, tags_string, data)


class RoomMemberJoin(RoomEvent):

    def __init__(self, event_id, sender, timestamp, display_name):
        self.display_name = display_name
        RoomEvent.__init__(self, event_id, sender, timestamp)

    @classmethod
    def from_dict(cls, event_dict):
        event_id = sanitize_id(event_dict["event_id"])
        sender = sanitize_id(event_dict["sender"])
        timestamp = sanitize_ts(event_dict["origin_server_ts"])
        display_name = None

        if event_dict["content"]:
            if "display_name" in event_dict["content"]:
                display_name = sanitize_text(
                    event_dict["content"]["displayname"])

        return cls(event_id, sender, timestamp, display_name)

    def execute(self, server, room, buff, tags):
        short_name = shorten_sender(self.sender)

        if self.sender in room.users:
            user = room.users[self.sender]
            if self.display_name:
                user.display_name = self.display_name
        else:
            user = MatrixUser(short_name, self.display_name)

        if not user.nick_color:
            if self.sender == server.user_id:
                highlight_words = [self.sender, user.name]

                if self.display_name:
                    highlight_words.append(self.display_name)

                user.nick_color = "weechat.color.chat_nick_self"
                W.buffer_set(buff, "highlight_words", ",".join(highlight_words))
            else:
                user.nick_color = W.info_get("nick_color_name", user.name)

        room.users[self.sender] = user

        nick_pointer = W.nicklist_search_nick(buff, "", self.sender)

        if not nick_pointer:
            add_user_to_nicklist(buff, self.sender, user)

        # calculate room display name and set it as the buffer list name
        room_name = room.display_name(server.user_id)

        # A user has joined an encrypted room, we need to check for new devices
        if room.encrypted:
            server.device_check_timestamp = None

        W.buffer_set(buff, "short_name", room_name)


class RoomMemberLeave(RoomEvent):

    def __init__(self, event_id, sender, leaving_user, timestamp):
        self.leaving_user = leaving_user
        RoomEvent.__init__(self, event_id, sender, timestamp)

    @classmethod
    def from_dict(cls, event_dict):
        event_id = sanitize_id(event_dict["event_id"])
        sender = sanitize_id(event_dict["sender"])
        leaving_user = sanitize_id(event_dict["state_key"])
        timestamp = sanitize_ts(event_dict["origin_server_ts"])

        return cls(event_id, sender, leaving_user, timestamp)

    def execute(self, server, room, buff, tags):
        if self.leaving_user in room.users:
            nick_pointer = W.nicklist_search_nick(buff, "", self.leaving_user)

            if nick_pointer:
                W.nicklist_remove_nick(buff, nick_pointer)

            del room.users[self.leaving_user]

            # calculate room display name and set it as the buffer list name
            room_name = room.display_name(server.user_id)
            W.buffer_set(buff, "short_name", room_name)


class RoomPowerLevels(RoomEvent):

    def __init__(self, event_id, sender, timestamp, power_levels):
        self.power_levels = power_levels
        RoomEvent.__init__(self, event_id, sender, timestamp)

    @classmethod
    def from_dict(cls, event_dict):
        event_id = sanitize_id(event_dict["event_id"])
        sender = sanitize_id(event_dict["sender"])
        timestamp = sanitize_ts(event_dict["origin_server_ts"])
        power_levels = []

        for user, level in event_dict["content"]["users"].items():
            power_levels.append(
                PowerLevel(sanitize_id(user), sanitize_power_level(level)))

        return cls(event_id, sender, timestamp, power_levels)

    def _set_power_level(self, room, buff, power_level):
        user_id = power_level.user
        level = power_level.level

        if user_id not in room.users:
            return

        user = room.users[user_id]
        user.power_level = level
        user.prefix = get_prefix_for_level(level)

        nick_pointer = W.nicklist_search_nick(buff, "", user_id)

        if nick_pointer:
            W.nicklist_remove_nick(buff, nick_pointer)
            add_user_to_nicklist(buff, user_id, user)

    def execute(self, server, room, buff, tags):
        for level in self.power_levels:
            self._set_power_level(room, buff, level)


class RoomTopiceMessage(RoomEvent):

    def __init__(self, event_id, sender, timestamp, topic):
        self.topic = topic
        RoomEvent.__init__(self, event_id, sender, timestamp)

    def execute(self, server, room, buff, tags):
        topic = self.topic

        nick, color_name = sender_to_nick_and_color(room, self.sender)

        author = ("{nick_color}{user}{ncolor}").format(
            nick_color=W.color(color_name), user=nick, ncolor=W.color("reset"))

        # TODO print old topic if configured so
        if room.is_named():
            message = ("{prefix}{nick} has changed "
                       "the topic for {chan_color}{room}{ncolor} "
                       "to \"{topic}\"").format(
                           prefix=W.prefix("network"),
                           nick=author,
                           chan_color=W.color("chat_channel"),
                           ncolor=W.color("reset"),
                           room=room.named_room_name(),
                           topic=topic)
        else:
            message = ('{prefix}{nick} has changed the topic to '
                       '"{topic}"').format(
                           prefix=W.prefix("network"),
                           nick=author,
                           topic=topic)

        tags = ["matrix_topic", "log3", "matrix_id_{}".format(self.event_id)]
        date = server_ts_to_weechat(self.timestamp)
        W.prnt_date_tags(buff, date, ",".join(tags), message)


class RoomTopicEvent(RoomEvent):

    def __init__(self, event_id, sender, timestamp, topic):
        self.topic = topic
        RoomEvent.__init__(self, event_id, sender, timestamp)

    @classmethod
    def from_dict(cls, event_dict):
        event_id = sanitize_id(event_dict["event_id"])
        sender = sanitize_id(event_dict["sender"])
        timestamp = sanitize_ts(event_dict["origin_server_ts"])

        topic = sanitize_text(event_dict["content"]["topic"])

        return cls(event_id, sender, timestamp, topic)

    def execute(self, server, room, buff, tags):
        topic = self.topic

        W.buffer_set(buff, "title", topic)

        room.topic = topic
        room.topic_author = self.sender
        room.topic_date = datetime.fromtimestamp(
            server_ts_to_weechat(self.timestamp))


class RoomRedactionEvent(RoomEvent):

    def __init__(self, event_id, sender, timestamp, redaction_id, reason=None):
        self.redaction_id = redaction_id
        self.reason = reason
        RoomEvent.__init__(self, event_id, sender, timestamp)

    @classmethod
    def from_dict(cls, event_dict):
        event_id = sanitize_id(event_dict["event_id"])
        sender = sanitize_id(event_dict["sender"])
        timestamp = sanitize_ts(event_dict["origin_server_ts"])

        redaction_id = sanitize_id(event_dict["redacts"])

        reason = (sanitize_text(event_dict["content"]["reason"])
                  if "reason" in event_dict["content"] else None)

        return cls(event_id, sender, timestamp, redaction_id, reason)

    @staticmethod
    def already_redacted(tags):
        if "matrix_redacted" in tags:
            return True
        return False

    def _redact_line(self, data_pointer, tags, room, buff):
        hdata_line_data = W.hdata_get('line_data')

        message = W.hdata_string(hdata_line_data, data_pointer, 'message')
        censor, _ = sender_to_nick_and_color(room, self.sender)

        reason = ("" if not self.reason else
                  ", reason: \"{reason}\"".format(reason=self.reason))

        redaction_msg = ("{del_color}<{log_color}Message redacted by: "
                         "{censor}{log_color}{reason}{del_color}>"
                         "{ncolor}").format(
                             del_color=W.color("chat_delimiters"),
                             ncolor=W.color("reset"),
                             log_color=W.color("logger.color.backlog_line"),
                             censor=censor,
                             reason=reason)

        new_message = ""

        if OPTIONS.redaction_type == RedactType.STRIKETHROUGH:
            plaintext_msg = W.string_remove_color(message, '')
            new_message = string_strikethrough(plaintext_msg)
        elif OPTIONS.redaction_type == RedactType.NOTICE:
            new_message = message
        elif OPTIONS.redaction_type == RedactType.DELETE:
            pass

        message = " ".join(s for s in [new_message, redaction_msg] if s)

        tags.append("matrix_redacted")

        new_data = {'tags_array': ','.join(tags), 'message': message}

        W.hdata_update(hdata_line_data, data_pointer, new_data)

    def execute(self, server, room, buff, tags):
        data_pointer, tags = line_pointer_and_tags_from_event(
            buff, self.redaction_id)

        if not data_pointer:
            return

        if RoomRedactionEvent.already_redacted(tags):
            return

        self._redact_line(data_pointer, tags, room, buff)


class RoomNameEvent(RoomEvent):

    def __init__(self, event_id, sender, timestamp, name):
        self.name = name
        RoomEvent.__init__(self, event_id, sender, timestamp)

    @classmethod
    def from_dict(cls, event_dict):
        event_id = sanitize_id(event_dict["event_id"])
        sender = sanitize_id(event_dict["sender"])
        timestamp = sanitize_ts(event_dict["origin_server_ts"])

        name = sanitize_string(event_dict['content']['name'])

        return cls(event_id, sender, timestamp, name)

    def execute(self, server, room, buff, tags):
        if not self.name:
            return

        room.name = self.name
        W.buffer_set(buff, "name", self.name)
        W.buffer_set(buff, "localvar_set_channel", self.name)

        # calculate room display name and set it as the buffer list name
        room_name = room.display_name(server.user_id)
        W.buffer_set(buff, "short_name", room_name)


class RoomAliasEvent(RoomEvent):

    def __init__(self, event_id, sender, timestamp, canonical_alias):
        self.canonical_alias = canonical_alias
        RoomEvent.__init__(self, event_id, sender, timestamp)

    @classmethod
    def from_dict(cls, event_dict):
        event_id = sanitize_id(event_dict["event_id"])
        sender = sanitize_id(event_dict["sender"])
        timestamp = sanitize_ts(event_dict["origin_server_ts"])

        canonical_alias = sanitize_id(event_dict["content"]["alias"])

        return cls(event_id, sender, timestamp, canonical_alias)

    def execute(self, server, room, buff, tags):
        if not self.canonical_alias:
            return

        # TODO: What should we do with this?
        # W.buffer_set(buff, "name", self.name)
        # W.buffer_set(buff, "localvar_set_channel", self.name)

        # calculate room display name and set it as the buffer list name
        room.canonical_alias = self.canonical_alias
        room_name = room.display_name(server.user_id)
        W.buffer_set(buff, "short_name", room_name)


class RoomEncryptionEvent(RoomEvent):

    @classmethod
    def from_dict(cls, event_dict):
        event_id = sanitize_id(event_dict["event_id"])
        sender = sanitize_id(event_dict["sender"])
        timestamp = sanitize_ts(event_dict["origin_server_ts"])

        return cls(event_id, sender, timestamp)

    def execute(self, server, room, buff, tags):
        room.encrypted = True

        message = ("{prefix}This room is encrypted, encryption is "
                   "currently unsuported. Message sending is disabled for "
                   "this room.").format(prefix=W.prefix("error"))

        W.prnt(buff, message)
