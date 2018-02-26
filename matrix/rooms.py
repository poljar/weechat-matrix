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

from collections import namedtuple
from functools import partial
from datetime import datetime

from matrix.globals import W, OPTIONS
from matrix.plugin_options import RedactType

from matrix.colors import Formatted
from matrix.utils import (strip_matrix_server, color_for_tags, date_from_age,
                          sender_to_nick_and_color, add_event_tags, sanitize_id,
                          sanitize_age, sanitize_text, shorten_sender,
                          add_user_to_nicklist, get_prefix_for_level,
                          sanitize_power_level, string_strikethrough,
                          line_pointer_and_tags_from_event)

PowerLevel = namedtuple('PowerLevel', ['user', 'level'])


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

    def __init__(self, room_id, prev_batch, membership_events, events):
        # type: (str, str, List[Any], List[Any]) -> None
        self.room_id = room_id
        self.prev_batch = prev_batch
        self.membership_events = membership_events
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
    def _membership_from_dict(event_dict):
        if (event_dict["membership"] not in [
                "invite", "join", "knock", "leave", "ban"
        ]):
            raise ValueError

        if event_dict["membership"] == "join":
            return RoomMemberJoin.from_dict(event_dict)
        elif event_dict["membership"] == "leave":
            return RoomMemberLeave.from_dict(event_dict)

        return None

    @staticmethod
    def _parse_events(parsed_dict):
        membership_events = []
        other_events = []

        try:
            for event in parsed_dict:
                if event["type"] == "m.room.message":
                    other_events.append(RoomInfo._message_from_event(event))
                elif event["type"] == "m.room.member":
                    membership_events.append(
                        RoomInfo._membership_from_dict(event))
                elif event["type"] == "m.room.power_levels":
                    other_events.append(RoomPowerLevels.from_dict(event))
                elif event["type"] == "m.room.topic":
                    other_events.append(RoomTopicEvent.from_dict(event))
                elif event["type"] == "m.room.redaction":
                    other_events.append(RoomRedactionEvent.from_dict(event))
                elif event["type"] == "m.room.name":
                    other_events.append(RoomNameEvent.from_dict(event))
                elif event["type"] == "m.room.aliases":
                    other_events.append(RoomAliasEvent.from_dict(event))
                elif event["type"] == "m.room.encryption":
                    other_events.append(RoomEncryptionEvent.from_dict(event))
        except (ValueError, TypeError, KeyError) as error:
            message = ("{prefix}matrix: Error parsing "
                       "room event of type {type}: {error}").format(
                           prefix=W.prefix("error"),
                           type=event["type"],
                           error=str(error))
            W.prnt("", message)
            raise

        return (membership_events, other_events)

    @classmethod
    def from_dict(cls, room_id, parsed_dict):
        prev_batch = sanitize_id(parsed_dict['timeline']['prev_batch'])

        state_dict = parsed_dict['state']['events']
        timeline_dict = parsed_dict['timeline']['events']

        membership_events, other_events = RoomInfo._parse_events(state_dict)
        timeline_member_events, timeline_events = RoomInfo._parse_events(
            timeline_dict)

        membership_events.extend(timeline_member_events)
        other_events.extend(timeline_events)

        return cls(room_id, prev_batch, list(filter(None, membership_events)),
                   list(filter(None, other_events)))


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

    def execute(self, server, room, buff, tags):
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
        return RoomMessageUnknown.from_dict(event)

    def _print_message(self, message, room, buff, tags):
        nick, color_name = sender_to_nick_and_color(room, self.sender)
        color = color_for_tags(color_name)

        event_tags = add_event_tags(self.event_id, nick, color, tags)

        tags_string = ",".join(event_tags)

        data = "{author}\t{msg}".format(author=nick, msg=message)

        date = date_from_age(self.age)
        W.prnt_date_tags(buff, date, tags_string, data)


class RoomMessageSimple(RoomMessageEvent):

    def __init__(self, event_id, sender, age, message, message_type):
        self.message = message
        self.message_type = message_type
        RoomEvent.__init__(self, event_id, sender, age)

    @classmethod
    def from_dict(cls, event):
        event_id = sanitize_id(event["event_id"])
        sender = sanitize_id(event["sender"])
        age = sanitize_age(event["unsigned"]["age"])

        message = sanitize_text(event["content"]["body"])
        message_type = sanitize_text(event["content"]["msgtype"])

        return cls(event_id, sender, age, message, message_type)


class RoomMessageUnknown(RoomMessageSimple):

    def execute(self, server, room, buff, tags):
        msg = ("Unknown message of type {t}, body: {body}").format(
            t=self.message_type, body=self.message)

        self._print_message(msg, room, buff, tags)


class RoomMessageText(RoomMessageEvent):

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

        msg = sanitize_text(event['content']['body'])

        if ('format' in event['content'] and
                'formatted_body' in event['content']):
            if event['content']['format'] == "org.matrix.custom.html":
                formatted_msg = Formatted.from_html(
                    sanitize_text(event['content']['formatted_body']))

        return cls(event_id, sender, age, msg, formatted_msg)

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

        date = date_from_age(self.age)
        W.prnt_date_tags(buff, date, tags_string, data)


class RoomMessageMedia(RoomMessageEvent):

    def __init__(self, event_id, sender, age, url, description):
        self.url = url
        self.description = description
        RoomEvent.__init__(self, event_id, sender, age)

    @classmethod
    def from_dict(cls, event):
        event_id = sanitize_id(event["event_id"])
        sender = sanitize_id(event["sender"])
        age = sanitize_age(event["unsigned"]["age"])

        mxc_url = sanitize_text(event['content']['url'])
        description = sanitize_text(event["content"]["body"])

        return cls(event_id, sender, age, mxc_url, description)

    def execute(self, server, room, buff, tags):
        http_url = server.client.mxc_to_http(self.url)
        url = http_url if http_url else self.url

        description = (" ({})".format(self.description)
                       if self.description else "")

        msg = "{url}{desc}".format(url=url, desc=description)

        self._print_message(msg, room, buff, tags)


class RoomMemberJoin(RoomEvent):

    def __init__(self, event_id, sender, age, display_name):
        self.display_name = display_name
        RoomEvent.__init__(self, event_id, sender, age)

    @classmethod
    def from_dict(cls, event_dict):
        event_id = sanitize_id(event_dict["event_id"])
        sender = sanitize_id(event_dict["sender"])
        age = sanitize_age(event_dict["unsigned"]["age"])
        display_name = None

        if event_dict["content"]:
            if "display_name" in event_dict["content"]:
                display_name = sanitize_text(
                    event_dict["content"]["displayname"])

        return cls(event_id, sender, age, display_name)

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


class RoomMemberLeave(RoomEvent):

    def __init__(self, event_id, sender, age):
        RoomEvent.__init__(self, event_id, sender, age)

    @classmethod
    def from_dict(cls, event_dict):
        event_id = sanitize_id(event_dict["event_id"])
        sender = sanitize_id(event_dict["sender"])
        age = sanitize_age(event_dict["unsigned"]["age"])

        return cls(event_id, sender, age)

    def execute(self, server, room, buff, tags):
        if self.sender in room.users:
            nick_pointer = W.nicklist_search_nick(buff, "", self.sender)

            if nick_pointer:
                W.nicklist_remove_nick(buff, nick_pointer)

            del room.users[self.sender]


class RoomPowerLevels(RoomEvent):

    def __init__(self, event_id, sender, age, power_levels):
        self.power_levels = power_levels
        RoomEvent.__init__(self, event_id, sender, age)

    @classmethod
    def from_dict(cls, event_dict):
        event_id = sanitize_id(event_dict["event_id"])
        sender = sanitize_id(event_dict["sender"])
        age = sanitize_age(event_dict["unsigned"]["age"])
        power_levels = []

        for user, level in event_dict["content"]["users"].items():
            power_levels.append(
                PowerLevel(sanitize_id(user), sanitize_power_level(level)))

        return cls(event_id, sender, age, power_levels)

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
        level_func = partial(self._set_power_level, room, buff)
        map(level_func, self.power_levels)


class RoomTopicEvent(RoomEvent):

    def __init__(self, event_id, sender, age, topic):
        self.topic = topic
        RoomEvent.__init__(self, event_id, sender, age)

    @classmethod
    def from_dict(cls, event_dict):
        event_id = sanitize_id(event_dict["event_id"])
        sender = sanitize_id(event_dict["sender"])
        age = sanitize_age(event_dict["unsigned"]["age"])

        topic = sanitize_text(event_dict["content"]["topic"])

        return cls(event_id, sender, age, topic)

    def execute(self, server, room, buff, tags):
        topic = self.topic

        nick, color_name = sender_to_nick_and_color(room, self.sender)

        author = ("{nick_color}{user}{ncolor}").format(
            nick_color=W.color(color_name), user=nick, ncolor=W.color("reset"))

        # TODO print old topic if configured so
        message = ("{prefix}{nick} has changed "
                   "the topic for {chan_color}{room}{ncolor} "
                   "to \"{topic}\"").format(
                       prefix=W.prefix("network"),
                       nick=author,
                       chan_color=W.color("chat_channel"),
                       ncolor=W.color("reset"),
                       room=strip_matrix_server(room.alias),
                       topic=topic)

        tags = ["matrix_topic", "log3", "matrix_id_{}".format(self.event_id)]

        date = date_from_age(self.age)

        W.buffer_set(buff, "title", topic)
        W.prnt_date_tags(buff, date, ",".join(tags), message)

        room.topic = topic
        room.topic_author = self.sender
        room.topic_date = datetime.fromtimestamp(date_from_age(self.age))


class RoomRedactionEvent(RoomEvent):

    def __init__(self, event_id, sender, age, redaction_id, reason=None):
        self.redaction_id = redaction_id
        self.reason = reason
        RoomEvent.__init__(self, event_id, sender, age)

    @classmethod
    def from_dict(cls, event_dict):
        event_id = sanitize_id(event_dict["event_id"])
        sender = sanitize_id(event_dict["sender"])
        age = sanitize_age(event_dict["unsigned"]["age"])

        redaction_id = sanitize_id(event_dict["redacts"])

        reason = (sanitize_text(event_dict["content"]["reason"])
                  if "reason" in event_dict["content"] else None)

        return cls(event_id, sender, age, redaction_id, reason)

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
            new_message = string_strikethrough(message)
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

    def __init__(self, event_id, sender, age, name):
        self.name = name
        RoomEvent.__init__(self, event_id, sender, age)

    @classmethod
    def from_dict(cls, event_dict):
        event_id = sanitize_id(event_dict["event_id"])
        sender = sanitize_id(event_dict["sender"])
        age = sanitize_age(event_dict["unsigned"]["age"])

        name = sanitize_id(event_dict['content']['name'])

        return cls(event_id, sender, age, name)

    def execute(self, server, room, buff, tags):
        if not self.name:
            return

        room.alias = self.name
        W.buffer_set(buff, "name", self.name)
        W.buffer_set(buff, "short_name", self.name)
        W.buffer_set(buff, "localvar_set_channel", self.name)


class RoomAliasEvent(RoomNameEvent):

    def __init__(self, event_id, sender, age, name):
        RoomNameEvent.__init__(self, event_id, sender, age, name)

    @classmethod
    def from_dict(cls, event_dict):
        event_id = sanitize_id(event_dict["event_id"])
        sender = sanitize_id(event_dict["sender"])
        age = sanitize_age(event_dict["unsigned"]["age"])

        name = sanitize_id(event_dict['content']['aliases'][-1])

        return cls(event_id, sender, age, name)


class RoomEncryptionEvent(RoomEvent):

    @classmethod
    def from_dict(cls, event_dict):
        event_id = sanitize_id(event_dict["event_id"])
        sender = sanitize_id(event_dict["sender"])
        age = sanitize_age(event_dict["unsigned"]["age"])

        return cls(event_id, sender, age)

    def execute(self, server, room, buff, tags):
        room.encrypted = True

        message = ("{prefix}This room is encrypted, encryption is "
                   "currently unsuported. Message sending is disabled for "
                   "this room.").format(prefix=W.prefix("error"))

        W.prnt(buff, message)
