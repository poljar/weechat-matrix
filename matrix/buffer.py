# -*- coding: utf-8 -*-

# Weechat Matrix Protocol Script
# Copyright © 2018, 2019 Damir Jelić <poljar@termina.org.uk>
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

import time
import attr
import pprint
from builtins import super
from functools import partial
from collections import deque
from typing import Dict, List, NamedTuple, Optional, Set
from uuid import UUID

from nio import (
    Api,
    PowerLevelsEvent,
    RedactedEvent,
    RedactionEvent,
    RoomAliasEvent,
    RoomEncryptionEvent,
    RoomMemberEvent,
    RoomMessage,
    RoomMessageEmote,
    RoomMessageMedia,
    RoomEncryptedMedia,
    RoomMessageNotice,
    RoomMessageText,
    RoomMessageUnknown,
    RoomNameEvent,
    RoomTopicEvent,
    MegolmEvent,
    Event,
    OlmTrustError,
    UnknownEvent,
    FullyReadEvent,
    BadEvent,
    UnknownBadEvent,
)

from . import globals as G
from .colors import Formatted
from .config import RedactType, NewChannelPosition
from .globals import SCRIPT_NAME, SERVERS, W, TYPING_NOTICE_TIMEOUT
from .utf import utf8_decode
from .message_renderer import Render
from .utils import (
    server_ts_to_weechat,
    shorten_sender,
    string_strikethrough,
    color_pair,
)


@attr.s
class OwnMessages(object):
    sender = attr.ib(type=str)
    age = attr.ib(type=int)
    event_id = attr.ib(type=str)
    uuid = attr.ib(type=str)
    room_id = attr.ib(type=str)
    formatted_message = attr.ib(type=Formatted)


class OwnMessage(OwnMessages):
    pass


class OwnAction(OwnMessage):
    pass


@utf8_decode
def room_buffer_input_cb(server_name, buffer, input_data):
    server = SERVERS[server_name]
    room_buffer = server.find_room_from_ptr(buffer)

    if not room_buffer:
        # TODO log error
        return W.WEECHAT_RC_ERROR

    if not server.connected:
        room_buffer.error("You are not connected to the server")
        return W.WEECHAT_RC_ERROR

    if not server.client.logged_in:
        room_buffer.error("You are not logged in.")
        return W.WEECHAT_RC_ERROR

    data = W.string_input_for_buffer(input_data)

    if not data:
        data = input_data

    formatted_data = Formatted.from_input_line(data)

    try:
        server.room_send_message(room_buffer, formatted_data, "m.text")
        room_buffer.last_message = None
    except OlmTrustError as e:
        if (G.CONFIG.network.resending_ignores_devices
                and room_buffer.last_message):
            room_buffer.error("Ignoring unverified devices.")

            if (room_buffer.last_message.to_weechat() ==
                    formatted_data.to_weechat()):
                server.room_send_message(room_buffer, formatted_data, "m.text",
                                         ignore_unverified_devices=True)
                room_buffer.last_message = None
        else:
            # If the item is a normal user message store it in the
            # buffer to enable the send-anyways functionality.
            room_buffer.error("Untrusted devices found in room: {}".format(e))
            room_buffer.last_message = formatted_data

    return W.WEECHAT_RC_OK


@utf8_decode
def room_buffer_close_cb(server_name, buffer):
    server = SERVERS[server_name]
    room_buffer = server.find_room_from_ptr(buffer)

    if room_buffer:
        room_id = room_buffer.room.room_id
        server.buffers.pop(room_id, None)
        server.room_buffers.pop(room_id, None)

    return W.WEECHAT_RC_OK


class WeechatUser(object):
    def __init__(self, nick, host=None, prefix="", join_time=None):
        # type: (str, str, str, int) -> None
        self.nick = nick
        self.host = host
        self.prefix = prefix
        self.color = W.info_get("nick_color_name", nick)
        self.join_time = join_time or time.time()
        self.speaking_time = None  # type: Optional[int]

    def update_speaking_time(self, new_time=None):
        self.speaking_time = new_time or time.time()

    @property
    def joined_recently(self):
        # TODO make the delay configurable
        delay = 30
        limit = time.time() - (delay * 60)
        return self.join_time < limit

    @property
    def spoken_recently(self):
        if not self.speaking_time:
            return False

        # TODO make the delay configurable
        delay = 5
        limit = time.time() - (delay * 60)
        return self.speaking_time < limit


class RoomUser(WeechatUser):
    def __init__(self, nick, user_id=None, power_level=0, join_time=None):
        # type: (str, str, int, int) -> None
        prefix = self._get_prefix(power_level)
        super().__init__(nick, user_id, prefix, join_time)

    @property
    def power_level(self):
        # This shouldn't be used since it's a lossy function. It's only here
        # for the setter
        if self.prefix == "&":
            return 100
        if self.prefix == "@":
            return 50
        if self.prefix == "+":
            return 10
        return 0

    @power_level.setter
    def power_level(self, level):
        self.prefix = self._get_prefix(level)

    @staticmethod
    def _get_prefix(power_level):
        # type: (int) -> str
        if power_level >= 100:
            return "&"
        if power_level >= 50:
            return "@"
        if power_level > 0:
            return "+"
        return ""


class WeechatChannelBuffer(object):
    tags = {
        "message": [SCRIPT_NAME + "_message", "notify_message", "log1"],
        "message_private": [
            SCRIPT_NAME + "_message",
            "notify_private",
            "log1"
        ],
        "self_message": [
            SCRIPT_NAME + "_message",
            "notify_none",
            "no_highlight",
            "self_msg",
            "log1",
        ],
        "action": [
            SCRIPT_NAME + "_message",
            SCRIPT_NAME + "_action",
            "notify_message",
            "log1",
        ],
        "action_private": [
            SCRIPT_NAME + "_message",
            SCRIPT_NAME + "_action",
            "notify_private",
            "log1",
        ],
        "notice": [SCRIPT_NAME + "_notice", "notify_message", "log1"],
        "old_message": [
            SCRIPT_NAME + "_message",
            "notify_message",
            "no_log",
            "no_highlight",
        ],
        "join": [SCRIPT_NAME + "_join", "log4"],
        "part": [SCRIPT_NAME + "_leave", "log4"],
        "kick": [SCRIPT_NAME + "_kick", "log4"],
        "invite": [SCRIPT_NAME + "_invite", "log4"],
        "topic": [SCRIPT_NAME + "_topic", "log3"],
    }

    membership_messages = {
        "join": "has joined",
        "part": "has left",
        "kick": "has been kicked from",
        "invite": "has been invited to",
    }

    class Line(object):
        def __init__(self, pointer):
            self._ptr = pointer

        @property
        def _hdata(self):
            return W.hdata_get("line_data")

        @property
        def prefix(self):
            return W.hdata_string(self._hdata, self._ptr, "prefix")

        @prefix.setter
        def prefix(self, new_prefix):
            new_data = {"prefix": new_prefix}
            W.hdata_update(self._hdata, self._ptr, new_data)

        @property
        def message(self):
            return W.hdata_string(self._hdata, self._ptr, "message")

        @message.setter
        def message(self, new_message):
            # type: (str) -> None
            new_data = {"message": new_message}
            W.hdata_update(self._hdata, self._ptr, new_data)

        @property
        def tags(self):
            tags_count = W.hdata_get_var_array_size(
                self._hdata, self._ptr, "tags_array"
            )

            tags = [
                W.hdata_string(self._hdata, self._ptr, "%d|tags_array" % i)
                for i in range(tags_count)
            ]
            return tags

        @tags.setter
        def tags(self, new_tags):
            # type: (List[str]) -> None
            new_data = {"tags_array": ",".join(new_tags)}
            W.hdata_update(self._hdata, self._ptr, new_data)

        @property
        def date(self):
            # type: () -> int
            return W.hdata_time(self._hdata, self._ptr, "date")

        @date.setter
        def date(self, new_date):
            # type: (int) -> None
            new_data = {"date": str(new_date)}
            W.hdata_update(self._hdata, self._ptr, new_data)

        @property
        def date_printed(self):
            # type: () -> int
            return W.hdata_time(self._hdata, self._ptr, "date_printed")

        @date_printed.setter
        def date_printed(self, new_date):
            # type: (int) -> None
            new_data = {"date_printed": str(new_date)}
            W.hdata_update(self._hdata, self._ptr, new_data)

        @property
        def highlight(self):
            # type: () -> bool
            return bool(W.hdata_char(self._hdata, self._ptr, "highlight"))

        def update(
            self,
            date=None,
            date_printed=None,
            tags=None,
            prefix=None,
            message=None,
            highlight=None,
        ):
            new_data = {}

            if date is not None:
                new_data["date"] = str(date)
            if date_printed is not None:
                new_data["date_printed"] = str(date_printed)
            if tags is not None:
                new_data["tags_array"] = ",".join(tags)
            if prefix is not None:
                new_data["prefix"] = prefix
            if message is not None:
                new_data["message"] = message
            if highlight is not None:
                new_data["highlight"] = highlight

            if new_data:
                W.hdata_update(self._hdata, self._ptr, new_data)

    def __init__(self, name, server_name, user):
        # type: (str, str, str) -> None

        # Previous buffer num before create
        cur_num = W.buffer_get_integer(W.current_buffer(), "number")
        self._ptr = W.buffer_new(
            name,
            "room_buffer_input_cb",
            server_name,
            "room_buffer_close_cb",
            server_name,
        )

        new_channel_position = G.CONFIG.look.new_channel_position
        if new_channel_position == NewChannelPosition.NONE:
            pass
        elif new_channel_position == NewChannelPosition.NEXT:
            self.number = cur_num + 1
        elif new_channel_position == NewChannelPosition.NEAR_SERVER:
            server = G.SERVERS[server_name]
            last_similar_buffer_num = max(
                (room.weechat_buffer.number for room
                    in server.room_buffers.values()),
                default=W.buffer_get_integer(server.server_buffer, "number")
            )
            self.number = last_similar_buffer_num + 1

        self.name = ""
        self.users = {}  # type: Dict[str, WeechatUser]
        self.smart_filtered_nicks = set()  # type: Set[str]

        self.topic_author = ""
        self.topic_date = None

        W.buffer_set(self._ptr, "localvar_set_type", "private")
        W.buffer_set(self._ptr, "type", "formatted")

        W.buffer_set(self._ptr, "localvar_set_channel", name)

        W.buffer_set(self._ptr, "localvar_set_nick", user)

        W.buffer_set(self._ptr, "localvar_set_server", server_name)

        W.nicklist_add_group(
            self._ptr, "", "000|o", "weechat.color.nicklist_group", 1
        )
        W.nicklist_add_group(
            self._ptr, "", "001|h", "weechat.color.nicklist_group", 1
        )
        W.nicklist_add_group(
            self._ptr, "", "002|v", "weechat.color.nicklist_group", 1
        )
        W.nicklist_add_group(
            self._ptr, "", "999|...", "weechat.color.nicklist_group", 1
        )

        W.buffer_set(self._ptr, "nicklist", "1")
        W.buffer_set(self._ptr, "nicklist_display_groups", "0")

        W.buffer_set(self._ptr, "highlight_words", user)

        # TODO make this configurable
        W.buffer_set(
            self._ptr, "highlight_tags_restrict", SCRIPT_NAME + "_message"
        )

    @property
    def _hdata(self):
        return W.hdata_get("buffer")

    def add_smart_filtered_nick(self, nick):
        self.smart_filtered_nicks.add(nick)

    def remove_smart_filtered_nick(self, nick):
        self.smart_filtered_nicks.discard(nick)

    def unmask_smart_filtered_nick(self, nick):
        if nick not in self.smart_filtered_nicks:
            return

        for line in self.lines:
            filtered = False
            join = False
            tags = line.tags

            if "nick_{}".format(nick) not in tags:
                continue

            if SCRIPT_NAME + "_smart_filter" in tags:
                filtered = True
            elif SCRIPT_NAME + "_join" in tags:
                join = True

            if filtered:
                tags.remove(SCRIPT_NAME + "_smart_filter")
                line.tags = tags

            if join:
                break

        self.remove_smart_filtered_nick(nick)

    @property
    def input(self):
        # type: () -> str
        """Get the bar item input text of the buffer."""
        return W.buffer_get_string(self._ptr, "input")

    @property
    def num_lines(self):
        own_lines = W.hdata_pointer(self._hdata, self._ptr, "own_lines")
        return W.hdata_integer(W.hdata_get("lines"), own_lines, "lines_count")

    @property
    def lines(self):
        own_lines = W.hdata_pointer(self._hdata, self._ptr, "own_lines")

        if own_lines:
            hdata_line = W.hdata_get("line")

            line_pointer = W.hdata_pointer(
                W.hdata_get("lines"), own_lines, "last_line"
            )

            while line_pointer:
                data_pointer = W.hdata_pointer(
                    hdata_line, line_pointer, "data"
                )

                if data_pointer:
                    yield WeechatChannelBuffer.Line(data_pointer)

                line_pointer = W.hdata_move(hdata_line, line_pointer, -1)

    def _print(self, string):
        # type: (str) -> None
        """ Print a string to the room buffer """
        W.prnt(self._ptr, string)

    def print_date_tags(self, data, date=None, tags=None):
        # type: (str, Optional[int], Optional[List[str]]) -> None
        date = date or int(time.time())
        tags = tags or []

        tags_string = ",".join(tags)
        W.prnt_date_tags(self._ptr, date, tags_string, data)

    def error(self, string):
        # type: (str) -> None
        """ Print an error to the room buffer """
        message = "{prefix}{script}: {message}".format(
            prefix=W.prefix("error"), script=SCRIPT_NAME, message=string
        )

        self._print(message)

    def info(self, string):
        message = "{prefix}{script}: {message}".format(
            prefix=W.prefix("network"), script=SCRIPT_NAME, message=string
        )
        self._print(message)

    @staticmethod
    def _color_for_tags(color):
        # type: (str) -> str
        if color == "weechat.color.chat_nick_self":
            option = W.config_get(color)
            return W.config_string(option)

        return color

    def _message_tags(self, user, message_type):
        # type: (WeechatUser, str) -> List[str]
        tags = list(self.tags[message_type])

        tags.append("nick_{nick}".format(nick=user.nick))

        color = self._color_for_tags(user.color)

        if message_type not in ("action", "notice"):
            tags.append("prefix_nick_{color}".format(color=color))

        return tags

    def _get_user(self, nick):
        # type: (str) -> WeechatUser
        if nick in self.users:
            return self.users[nick]

        # A message from a non joined user
        return WeechatUser(nick)

    def _print_message(self, user, message, date, tags, extra_prefix=""):
        prefix_string = (
            extra_prefix
            if not user.prefix
            else "{}{}{}{}".format(
                extra_prefix,
                W.color(self._get_prefix_color(user.prefix)),
                user.prefix,
                W.color("reset"),
            )
        )

        data = "{prefix}{color}{author}{ncolor}\t{msg}".format(
            prefix=prefix_string,
            color=W.color(user.color),
            author=user.nick,
            ncolor=W.color("reset"),
            msg=message,
        )

        self.print_date_tags(data, date, tags)

    def message(self, nick, message, date, extra_tags=None, extra_prefix=""):
        # type: (str, str, int, List[str], str) -> None
        user = self._get_user(nick)
        tags_type = "message_private" if self.type == "private" else "message"
        tags = self._message_tags(user, tags_type) + (extra_tags or [])
        self._print_message(user, message, date, tags, extra_prefix)

        user.update_speaking_time(date)
        self.unmask_smart_filtered_nick(nick)

    def notice(self, nick, message, date, extra_tags=None, extra_prefix=""):
        # type: (str, str, int, Optional[List[str]], str) -> None
        user = self._get_user(nick)
        user_prefix = (
            ""
            if not user.prefix
            else "{}{}{}".format(
                W.color(self._get_prefix_color(user.prefix)),
                user.prefix,
                W.color("reset"),
            )
        )

        user_string = "{}{}{}{}".format(
            user_prefix, W.color(user.color), user.nick, W.color("reset")
        )

        data = (
            "{extra_prefix}{prefix}{color}Notice"
            "{del_color}({ncolor}{user}{del_color}){ncolor}"
            ": {message}"
        ).format(
            extra_prefix=extra_prefix,
            prefix=W.prefix("network"),
            color=W.color("irc.color.notice"),
            del_color=W.color("chat_delimiters"),
            ncolor=W.color("reset"),
            user=user_string,
            message=message,
        )

        tags = self._message_tags(user, "notice") + (extra_tags or [])
        self.print_date_tags(data, date, tags)

        user.update_speaking_time(date)
        self.unmask_smart_filtered_nick(nick)

    def _format_action(self, user, message):
        nick_prefix = (
            ""
            if not user.prefix
            else "{}{}{}".format(
                W.color(self._get_prefix_color(user.prefix)),
                user.prefix,
                W.color("reset"),
            )
        )

        data = (
            "{nick_prefix}{nick_color}{author}"
            "{ncolor} {msg}").format(
            nick_prefix=nick_prefix,
            nick_color=W.color(user.color),
            author=user.nick,
            ncolor=W.color("reset"),
            msg=message,
        )
        return data

    def _print_action(self, user, message, date, tags, extra_prefix=""):
        data = self._format_action(user, message)
        data = "{extra_prefix}{prefix}{data}".format(
            extra_prefix=extra_prefix,
            prefix=W.prefix("action"),
            data=data)

        self.print_date_tags(data, date, tags)

    def action(self, nick, message, date, extra_tags=None, extra_prefix=""):
        # type: (str, str, int, Optional[List[str]], str) -> None
        user = self._get_user(nick)
        tags_type = "action_private" if self.type == "private" else "action"
        tags = self._message_tags(user, tags_type) + (extra_tags or [])
        self._print_action(user, message, date, tags, extra_prefix)

        user.update_speaking_time(date)
        self.unmask_smart_filtered_nick(nick)

    @staticmethod
    def _get_nicklist_group(user):
        # type: (WeechatUser) -> str
        group_name = "999|..."

        if user.prefix == "&":
            group_name = "000|o"
        elif user.prefix == "@":
            group_name = "001|h"
        elif user.prefix == "+":
            group_name = "002|v"

        return group_name

    @staticmethod
    def _get_prefix_color(prefix):
        # type: (str) -> str

        return G.CONFIG.color.nick_prefixes.get(prefix, "")

    def _add_user_to_nicklist(self, user):
        # type: (WeechatUser) -> None
        nick_pointer = W.nicklist_search_nick(self._ptr, "", user.nick)

        if not nick_pointer:
            group = W.nicklist_search_group(
                self._ptr, "", self._get_nicklist_group(user)
            )
            prefix = user.prefix if user.prefix else " "
            W.nicklist_add_nick(
                self._ptr,
                group,
                user.nick,
                user.color,
                prefix,
                self._get_prefix_color(user.prefix),
                1,
            )

    def _membership_message(self, user, message_type):
        # type: (WeechatUser, str) -> str
        action_color = "green" if message_type in ("join", "invite") else "red"
        prefix = "join" if message_type in ("join", "invite") else "quit"

        membership_message = self.membership_messages[message_type]

        message = (
            "{prefix}{color}{author}{ncolor} "
            "{del_color}({host_color}{host}{del_color})"
            "{action_color} {message} "
            "{channel_color}{room}{ncolor}"
        ).format(
            prefix=W.prefix(prefix),
            color=W.color(user.color),
            author=user.nick,
            ncolor=W.color("reset"),
            del_color=W.color("chat_delimiters"),
            host_color=W.color("chat_host"),
            host=user.host,
            action_color=W.color(action_color),
            message=membership_message,
            channel_color=W.color("chat_channel"),
            room=self.short_name,
        )

        return message

    def join(self, user, date, message=True, extra_tags=None):
        # type: (WeechatUser, int, Optional[bool], Optional[List[str]]) -> None
        self._add_user_to_nicklist(user)
        self.users[user.nick] = user

        if len(self.users) > 2:
            W.buffer_set(self._ptr, "localvar_set_type", "channel")

        if message:
            tags = self._message_tags(user, "join")
            msg = self._membership_message(user, "join")

            # TODO add a option to disable smart filters
            tags.append(SCRIPT_NAME + "_smart_filter")

            self.print_date_tags(msg, date, tags)
            self.add_smart_filtered_nick(user.nick)

    def invite(self, nick, date, extra_tags=None):
        # type: (str, int, Optional[List[str]]) -> None
        user = self._get_user(nick)
        tags = self._message_tags(user, "invite")
        message = self._membership_message(user, "invite")
        self.print_date_tags(message, date, tags + (extra_tags or []))

    def remove_user_from_nicklist(self, user):
        # type: (WeechatUser) -> None
        nick_pointer = W.nicklist_search_nick(self._ptr, "", user.nick)

        if nick_pointer:
            W.nicklist_remove_nick(self._ptr, nick_pointer)

    def _leave(self, nick, date, message, leave_type, extra_tags=None):
        # type: (str, int, bool, str, List[str]) -> None
        user = self._get_user(nick)
        self.remove_user_from_nicklist(user)

        if len(self.users) <= 2:
            W.buffer_set(self._ptr, "localvar_set_type", "private")

        if message:
            tags = self._message_tags(user, leave_type)

            # TODO make this configurable
            if not user.spoken_recently:
                tags.append(SCRIPT_NAME + "_smart_filter")

            msg = self._membership_message(user, leave_type)
            self.print_date_tags(msg, date, tags + (extra_tags or []))
            self.remove_smart_filtered_nick(user.nick)

        if user.nick in self.users:
            del self.users[user.nick]

    def part(self, nick, date, message=True, extra_tags=None):
        # type: (str, int, bool, Optional[List[str]]) -> None
        self._leave(nick, date, message, "part", extra_tags)

    def kick(self, nick, date, message=True, extra_tags=None):
        # type: (str, int, bool, Optional[List[str]]) -> None
        self._leave(nick, date, message, "kick", extra_tags)

    def _print_topic(self, nick, topic, date):
        user = self._get_user(nick)
        tags = self._message_tags(user, "topic")

        data = (
            "{prefix}{nick} has changed "
            "the topic for {chan_color}{room}{ncolor} "
            'to "{topic}"'
        ).format(
            prefix=W.prefix("network"),
            nick=user.nick,
            chan_color=W.color("chat_channel"),
            ncolor=W.color("reset"),
            room=self.short_name,
            topic=topic,
        )

        self.print_date_tags(data, date, tags)
        user.update_speaking_time(date)
        self.unmask_smart_filtered_nick(nick)

    @property
    def topic(self):
        return W.buffer_get_string(self._ptr, "title")

    @topic.setter
    def topic(self, topic):
        W.buffer_set(self._ptr, "title", topic)

    def change_topic(self, nick, topic, date, message=True):
        if message:
            self._print_topic(nick, topic, date)

        self.topic = topic
        self.topic_author = nick
        self.topic_date = date

    def self_message(self, nick, message, date, tags=None):
        user = self._get_user(nick)
        tags = self._message_tags(user, "self_message") + (tags or [])
        self._print_message(user, message, date, tags)

    def self_action(self, nick, message, date, tags=None):
        user = self._get_user(nick)
        tags = self._message_tags(user, "self_message") + (tags or [])
        tags.append(SCRIPT_NAME + "_action")
        self._print_action(user, message, date, tags)

    @property
    def type(self):
        return W.buffer_get_string(self._ptr, "localvar_type")

    @property
    def short_name(self):
        return W.buffer_get_string(self._ptr, "short_name")

    @short_name.setter
    def short_name(self, name):
        W.buffer_set(self._ptr, "short_name", name)

    @property
    def name(self):
        return W.buffer_get_string(self._ptr, "name")

    @name.setter
    def name(self, name):
        W.buffer_set(self._ptr, "name", name)

    @property
    def number(self):
        """Get the buffer number, starts at 1."""
        return int(W.buffer_get_integer(self._ptr, "number"))

    @number.setter
    def number(self, n):
        W.buffer_set(self._ptr, "number", str(n))

    def find_lines(self, predicate, max_lines=None):
        lines = []
        count = 0
        for line in self.lines:
            if predicate(line):
                lines.append(line)
                count += 1
                if max_lines is not None and count == max_lines:
                    return lines

        return lines


class RoomBuffer(object):
    def __init__(self, room, server_name, homeserver, prev_batch):
        self.room = room
        self.homeserver = homeserver
        self._backlog_pending = False
        self.prev_batch = prev_batch
        self.joined = True
        self.leave_event_id = None  # type: Optional[str]
        self.members_fetched = False
        self.first_view = True
        self.first_backlog_request = True
        self.unhandled_users = []   # type: List[str]
        self.inactive_users = []

        self.sent_messages_queue = dict()  # type: Dict[UUID, OwnMessage]
        self.printed_before_ack_queue = list()  # type: List[UUID]
        self.undecrypted_events = deque(maxlen=5000)

        self.typing_notice_time = None
        self._typing = False
        self.typing_enabled = True

        self.last_read_event = None
        self._read_markers_enabled = True
        self.server_name = server_name

        self.last_message = None

        buffer_name = "{}{}.{}".format(G.BUFFER_NAME_PREFIX, server_name, room.room_id)

        # This dict remembers the connection from a user_id to the name we
        # displayed in the buffer
        self.displayed_nicks = {}
        user = shorten_sender(self.room.own_user_id)

        self.weechat_buffer = WeechatChannelBuffer(
            buffer_name, server_name, user
        )

        W.buffer_set(
            self.weechat_buffer._ptr,
            "localvar_set_domain",
            self.homeserver.hostname
        )

        W.buffer_set(
            self.weechat_buffer._ptr,
            "localvar_set_room_id",
            room.room_id
        )

    @property
    def backlog_pending(self):
        return self._backlog_pending

    @backlog_pending.setter
    def backlog_pending(self, value):
        self._backlog_pending = value
        W.bar_item_update("buffer_modes")
        W.bar_item_update("matrix_modes")

    @property
    def warning_prefix(self):
        return "⚠️ "

    @property
    def typing(self):
        # type: () -> bool
        """Return our typing status."""
        return self._typing

    @typing.setter
    def typing(self, value):
        self._typing = value
        if value:
            self.typing_notice_time = time.time()
        else:
            self.typing_notice_time = None

    @property
    def typing_notice_expired(self):
        # type: () -> bool
        """Check if the typing notice has expired.

        Returns true if a new typing notice should be sent.
        """
        if not self.typing_notice_time:
            return True

        now = time.time()
        if (now - self.typing_notice_time) > (TYPING_NOTICE_TIMEOUT / 1000):
            return True
        return False

    @property
    def should_send_read_marker(self):
        # type () -> bool
        """Check if we need to send out a read receipt."""
        if not self.read_markers_enabled:
            return False

        if not self.last_read_event:
            return True

        if self.last_read_event == self.last_event_id:
            return False

        return True

    @property
    def last_event_id(self):
        # type () -> str
        """Get the event id of the last shown matrix event."""
        for line in self.weechat_buffer.lines:
            for tag in line.tags:
                if tag.startswith("matrix_id"):
                    event_id = tag[10:]
                    return event_id

        return ""

    @property
    def printed_event_ids(self):
        for line in self.weechat_buffer.lines:
            for tag in line.tags:
                if tag.startswith("matrix_id"):
                    event_id = tag[10:]
                    yield event_id

    @property
    def read_markers_enabled(self):
        # type: () -> bool
        """Check if read receipts are enabled for this room."""
        return bool(int(W.string_eval_expression(
            G.CONFIG.network.read_markers_conditions,
            {},
            {"markers_enabled": str(int(self._read_markers_enabled))},
            {"type": "condition"}
        )))

    @read_markers_enabled.setter
    def read_markers_enabled(self, value):
        self._read_markers_enabled = value

    def find_nick(self, user_id):
        # type: (str) -> str
        """Find a suitable nick from a user_id."""
        if user_id in self.displayed_nicks:
            return self.displayed_nicks[user_id]

        return user_id

    def add_user(self, user_id, date, is_state, force_add=False):
        # User is already added don't add him again.
        if user_id in self.displayed_nicks:
            return

        try:
            user = self.room.users[user_id]
        except KeyError:
            # No user found, he must have left already in an event that is
            # yet to come, so do nothing
            return

        # Adding users to the nicklist is a O(1) + search time
        # operation (the nicks are added to a linked list sorted).
        # The search time is O(N * min(a,b)) where N is the number
        # of nicks already added and a/b are the length of
        # the strings that are compared at every iteration.
        # Because the search time get's increasingly longer we're
        # going to stop adding inactive users, they will be lazily added if
        # they become active.
        if is_state and not force_add and user.power_level <= 0:
            if (len(self.displayed_nicks) >=
                    G.CONFIG.network.max_nicklist_users):
                self.inactive_users.append(user_id)
                return

        try:
            self.inactive_users.remove(user_id)
        except ValueError:
            pass

        short_name = shorten_sender(user.user_id)

        # TODO handle this special case for discord bridge users and
        # freenode bridge users better
        if (user.user_id.startswith("@_discord_") or
                user.user_id.startswith("@_slack_") or
                user.user_id.startswith("@whatsapp_") or
                user.user_id.startswith("@facebook_") or
                user.user_id.startswith("@telegram_") or
                user.user_id.startswith("@_telegram_") or
                user.user_id.startswith("@_xmpp_")):
            if user.display_name:
                short_name = user.display_name[0:50]
        elif user.user_id.startswith("@twilio_"):
            short_name = shorten_sender(user.user_id[7:])
        elif user.user_id.startswith("@freenode_"):
            short_name = shorten_sender(user.user_id[9:])
        elif user.user_id.startswith("@_ircnet_"):
            short_name = shorten_sender(user.user_id[8:])
        elif user.user_id.startswith("@gitter_"):
            short_name = shorten_sender(user.user_id[7:])

        # TODO make this configurable
        if not short_name or short_name in self.displayed_nicks.values():
            # Use the full user id, but don't include the @
            nick = user_id[1:]
        else:
            nick = short_name

        buffer_user = RoomUser(nick, user_id, user.power_level, date)
        self.displayed_nicks[user_id] = nick

        if self.room.own_user_id == user_id:
            buffer_user.color = "weechat.color.chat_nick_self"
            user.nick_color = "weechat.color.chat_nick_self"

        self.weechat_buffer.join(buffer_user, date, not is_state)

    def handle_membership_events(self, event, is_state):
        date = server_ts_to_weechat(event.server_timestamp)

        if event.content["membership"] == "join":
            if (event.state_key not in self.displayed_nicks
                    and event.state_key not in self.inactive_users):
                if len(self.room.users) > 100:
                    self.unhandled_users.append(event.state_key)
                    return

                self.add_user(event.state_key, date, is_state)
            else:
                # TODO print out profile changes
                return

        elif event.content["membership"] == "leave":
            if event.state_key in self.unhandled_users:
                self.unhandled_users.remove(event.state_key)
                return

            nick = self.find_nick(event.state_key)
            if event.sender == event.state_key:
                self.weechat_buffer.part(nick, date, not is_state)
            else:
                self.weechat_buffer.kick(nick, date, not is_state)

            if event.state_key in self.displayed_nicks:
                del self.displayed_nicks[event.state_key]

            # We left the room, remember the event id of our leave, if we
            # rejoin we get events that came before this event as well as
            # after our leave, this way we know where to continue
            if event.state_key == self.room.own_user_id:
                self.leave_event_id = event.event_id

        elif event.content["membership"] == "invite":
            if is_state:
                return

            self.weechat_buffer.invite(event.state_key, date)
            return

        self.update_buffer_name()

    def update_buffer_name(self):
        if self.room.is_named:
            if self.room.name and self.room.name != "#":
                room_name = self.room.name
                room_name = (room_name if room_name.startswith("#")
                             else "#" + room_name)
            elif self.room.canonical_alias:
                room_name = self.room.canonical_alias
            elif self.room.name == "#":
                room_name = "##"
        else:
            room_name = self.room.display_name

        if room_name is None:
            # Use placeholder room name
            room_name = 'Empty room (?)'

        self.weechat_buffer.short_name = room_name

        if G.CONFIG.human_buffer_names:
            buffer_name = "{}.{}".format(self.server_name, room_name)
            self.weechat_buffer.name = buffer_name

    def _redact_line(self, event):
        def predicate(event_id, line):
            def already_redacted(tags):
                if SCRIPT_NAME + "_redacted" in tags:
                    return True
                return False

            event_tag = SCRIPT_NAME + "_id_{}".format(event_id)
            tags = line.tags

            if event_tag in tags and not already_redacted(tags):
                return True

            return False

        def redact_string(message):
            new_message = ""

            if G.CONFIG.look.redactions == RedactType.STRIKETHROUGH:
                plaintext_msg = W.string_remove_color(message, "")
                new_message = string_strikethrough(plaintext_msg)
            elif G.CONFIG.look.redactions == RedactType.NOTICE:
                new_message = message
            elif G.CONFIG.look.redactions == RedactType.DELETE:
                pass

            return new_message

        lines = self.weechat_buffer.find_lines(
            partial(predicate, event.redacts)
        )

        # No line to redact, return early
        if not lines:
            return

        censor = self.find_nick(event.sender)
        redaction_msg = Render.redacted(censor, event.reason)

        line = lines[0]
        message = line.message
        tags = line.tags

        new_message = redact_string(message)
        message = " ".join(s for s in [new_message, redaction_msg] if s)
        tags.append("matrix_redacted")

        line.message = message
        line.tags = tags

        for line in lines[1:]:
            message = line.message
            tags = line.tags

            new_message = redact_string(message)

            if not new_message:
                new_message = redaction_msg
            elif G.CONFIG.look.redactions == RedactType.NOTICE:
                new_message += " {}".format(redaction_msg)

            tags.append("matrix_redacted")

            line.message = new_message
            line.tags = tags

    def _handle_topic(self, event, is_state):
        nick = self.find_nick(event.sender)

        self.weechat_buffer.change_topic(
            nick,
            event.topic,
            server_ts_to_weechat(event.server_timestamp),
            not is_state,
        )

    @staticmethod
    def get_event_tags(event):
        # type: (Event) -> List[str]
        tags = [SCRIPT_NAME + "_id_{}".format(event.event_id)]
        if event.sender_key:
            tags.append(SCRIPT_NAME + "_senderkey_{}".format(event.sender_key))
        if event.session_id:
            tags.append(SCRIPT_NAME + "_session_id_{}".format(
                event.session_id
            ))

        return tags

    def _handle_power_level(self, _):
        for user_id in self.room.power_levels.users:
            if user_id in self.displayed_nicks:
                nick = self.find_nick(user_id)

                user = self.weechat_buffer.users[nick]
                user.power_level = self.room.power_levels.get_user_level(
                    user_id
                )

                # There is no way to change the group of a user without
                # removing him from the nicklist
                self.weechat_buffer.remove_user_from_nicklist(user)
                self.weechat_buffer._add_user_to_nicklist(user)

    def handle_state_event(self, event):
        if isinstance(event, RoomMemberEvent):
            self.handle_membership_events(event, True)
        elif isinstance(event, RoomTopicEvent):
            self._handle_topic(event, True)
        elif isinstance(event, PowerLevelsEvent):
            self._handle_power_level(event)
        elif isinstance(event, (RoomNameEvent, RoomAliasEvent)):
            self.update_buffer_name()
        elif isinstance(event, RoomEncryptionEvent):
            pass

    def handle_own_message_in_timeline(self, event):
        """Check if our own message is already printed if not print it.
        This function is called for messages that contain a transaction id
        indicating that they were sent out using our own client. If we sent out
        a message but never got a valid server response (e.g. due to
        disconnects) this function prints them out using data from the next
        sync response"""
        uuid = UUID(event.transaction_id)
        message = self.sent_messages_queue.pop(uuid, None)

        # We already got a response to the room_send_message() API call and
        # handled the message, no need to print it out again
        if not message:
            return

        message.event_id = event.event_id
        if uuid in self.printed_before_ack_queue:
            self.replace_printed_line_by_uuid(
                event.transaction_id,
                message
            )
            self.printed_before_ack_queue.remove(uuid)
            return

        if isinstance(message, OwnAction):
            self.self_action(message)
        elif isinstance(message, OwnMessage):
            self.self_message(message)
        return

    def print_room_message(self, event, extra_tags=None):
        extra_tags = extra_tags or []
        nick = self.find_nick(event.sender)

        data = Render.message(event.body, event.formatted_body)

        extra_prefix = (self.warning_prefix if event.decrypted
                        and not event.verified else "")

        date = server_ts_to_weechat(event.server_timestamp)
        self.weechat_buffer.message(
            nick, data, date, self.get_event_tags(event) + extra_tags,
            extra_prefix
        )

    def print_room_emote(self, event, extra_tags=None):
        extra_tags = extra_tags or []
        nick = self.find_nick(event.sender)
        date = server_ts_to_weechat(event.server_timestamp)

        extra_prefix = (self.warning_prefix if event.decrypted
                        and not event.verified else "")

        self.weechat_buffer.action(
            nick, event.body, date, self.get_event_tags(event) + extra_tags,
            extra_prefix
        )

    def print_room_notice(self, event, extra_tags=None):
        extra_tags = extra_tags or []
        nick = self.find_nick(event.sender)
        date = server_ts_to_weechat(event.server_timestamp)
        extra_prefix = (self.warning_prefix if event.decrypted
                        and not event.verified else "")

        self.weechat_buffer.notice(
            nick, event.body, date, self.get_event_tags(event) + extra_tags,
            extra_prefix
        )

    def print_room_media(self, event, extra_tags=None):
        extra_tags = extra_tags or []
        nick = self.find_nick(event.sender)
        date = server_ts_to_weechat(event.server_timestamp)
        if isinstance(event, RoomMessageMedia):
            data = Render.media(event.url, event.body, self.homeserver.geturl())
        else:
            data = Render.encrypted_media(
                event.url, event.body, event.key["k"], event.hashes["sha256"],
                event.iv, self.homeserver.geturl()
            )

        extra_prefix = (self.warning_prefix if event.decrypted
                        and not event.verified else "")

        self.weechat_buffer.message(
            nick, data, date, self.get_event_tags(event) + extra_tags,
            extra_prefix
        )

    def print_unknown(self, event, extra_tags=None):
        extra_tags = extra_tags or []
        nick = self.find_nick(event.sender)
        date = server_ts_to_weechat(event.server_timestamp)
        data = Render.unknown(event.type, event.content)
        extra_prefix = (self.warning_prefix if event.decrypted
                        and not event.verified else "")

        self.weechat_buffer.message(
            nick, data, date, self.get_event_tags(event) + extra_tags,
            extra_prefix
        )

    def print_redacted(self, event, extra_tags=None):
        extra_tags = extra_tags or []

        nick = self.find_nick(event.sender)
        date = server_ts_to_weechat(event.server_timestamp)
        tags = self.get_event_tags(event)
        tags.append(SCRIPT_NAME + "_redacted")
        tags += extra_tags

        censor = self.find_nick(event.redacter)
        data = Render.redacted(censor, event.reason)

        self.weechat_buffer.message(nick, data, date, tags)

    def print_room_encryption(self, event, extra_tags=None):
        nick = self.find_nick(event.sender)
        data = Render.room_encryption(nick)
        # TODO this should also have tags
        self.weechat_buffer.info(data)

    def print_megolm(self, event, extra_tags=None):
        extra_tags = extra_tags or []
        nick = self.find_nick(event.sender)
        date = server_ts_to_weechat(event.server_timestamp)

        data = Render.megolm()

        session_id_tag = SCRIPT_NAME + "_sessionid_" + event.session_id
        self.weechat_buffer.message(
            nick,
            data,
            date,
            self.get_event_tags(event) + [session_id_tag] + extra_tags
        )

        self.undecrypted_events.append(event)

    def print_bad_event(self, event, extra_tags=None):
        extra_tags = extra_tags or []
        nick = self.find_nick(event.sender)
        date = server_ts_to_weechat(event.server_timestamp)
        data = Render.bad(event)
        extra_prefix = self.warning_prefix

        self.weechat_buffer.message(
            nick, data, date, self.get_event_tags(event) + extra_tags,
            extra_prefix
        )

    def handle_room_messages(self, event, extra_tags=None):
        if isinstance(event, RoomMessageEmote):
            self.print_room_emote(event, extra_tags)

        elif isinstance(event, RoomMessageText):
            self.print_room_message(event, extra_tags)

        elif isinstance(event, RoomMessageNotice):
            self.print_room_notice(event, extra_tags)

        elif isinstance(event, RoomMessageMedia):
            self.print_room_media(event, extra_tags)

        elif isinstance(event, RoomEncryptedMedia):
            self.print_room_media(event, extra_tags)

        elif isinstance(event, RoomMessageUnknown):
            self.print_unknown(event, extra_tags)

        elif isinstance(event, RoomEncryptionEvent):
            self.print_room_encryption(event, extra_tags)

        elif isinstance(event, MegolmEvent):
            self.print_megolm(event, extra_tags)

    def force_load_member(self, event):
        if (event.sender not in self.displayed_nicks and
            event.sender in self.room.users):

            try:
                self.unhandled_users.remove(event.sender)
            except ValueError:
                pass

            self.add_user(event.sender, 0, True, True)

    def handle_timeline_event(self, event, extra_tags=None):
        # TODO this should be done for every messagetype that gets printed in
        # the buffer
        if isinstance(event, (RoomMessage, MegolmEvent)):
            self.force_load_member(event)

        if event.transaction_id:
            self.handle_own_message_in_timeline(event)
            return

        if isinstance(event, RoomMemberEvent):
            self.handle_membership_events(event, False)

        elif isinstance(event, (RoomNameEvent, RoomAliasEvent)):
            self.update_buffer_name()

        elif isinstance(event, RoomTopicEvent):
            self._handle_topic(event, False)

        # Emotes are a subclass of RoomMessageText, so put them before the text
        # ones
        elif isinstance(event, RoomMessageEmote):
            self.print_room_emote(event, extra_tags)

        elif isinstance(event, RoomMessageText):
            self.print_room_message(event, extra_tags)

        elif isinstance(event, RoomMessageNotice):
            self.print_room_notice(event, extra_tags)

        elif isinstance(event, RoomMessageMedia):
            self.print_room_media(event, extra_tags)

        elif isinstance(event, RoomEncryptedMedia):
            self.print_room_media(event, extra_tags)

        elif isinstance(event, RoomMessageUnknown):
            self.print_unknown(event, extra_tags)

        elif isinstance(event, RedactionEvent):
            self._redact_line(event)

        elif isinstance(event, RedactedEvent):
            self.print_redacted(event, extra_tags)

        elif isinstance(event, RoomEncryptionEvent):
            self.print_room_encryption(event, extra_tags)

        elif isinstance(event, PowerLevelsEvent):
            # TODO we should print out a message for this event
            self._handle_power_level(event)

        elif isinstance(event, MegolmEvent):
            self.print_megolm(event, extra_tags)

        elif isinstance(event, UnknownEvent):
            pass

        elif isinstance(event, BadEvent):
            self.print_bad_event(event, extra_tags)

        elif isinstance(event, UnknownBadEvent):
            self.error("Unknown bad event: {}".format(
                pprint.pformat(event.source)
            ))

        else:
            W.prnt(
                "", "Unhandled event of type {}.".format(type(event).__name__)
            )

    def self_message(self, message):
        # type: (OwnMessage) -> None
        nick = self.find_nick(self.room.own_user_id)
        data = message.formatted_message.to_weechat()
        if message.event_id:
            tags = [SCRIPT_NAME + "_id_{}".format(message.event_id)]
        else:
            tags = [SCRIPT_NAME + "_uuid_{}".format(message.uuid)]
        date = message.age

        self.weechat_buffer.self_message(nick, data, date, tags)

    def self_action(self, message):
        # type: (OwnMessage) -> None
        nick = self.find_nick(self.room.own_user_id)
        date = message.age
        if message.event_id:
            tags = [SCRIPT_NAME + "_id_{}".format(message.event_id)]
        else:
            tags = [SCRIPT_NAME + "_uuid_{}".format(message.uuid)]

        self.weechat_buffer.self_action(
            nick, message.formatted_message.to_weechat(), date, tags
        )

    @staticmethod
    def _find_by_uuid_predicate(uuid, line):
        uuid_tag = SCRIPT_NAME + "_uuid_{}".format(uuid)
        tags = line.tags

        if uuid_tag in tags:
            return True
        return False

    def mark_message_as_unsent(self, uuid, _):
        """Append to already printed lines that are greyed out an error
        message"""
        lines = self.weechat_buffer.find_lines(
            partial(self._find_by_uuid_predicate, uuid)
        )
        last_line = lines[-1]

        message = last_line.message
        message += (" {del_color}<{ncolor}{error_color}Error sending "
                    "message{del_color}>{ncolor}").format(
            del_color=W.color("chat_delimiters"),
            ncolor=W.color("reset"),
            error_color=W.color(color_pair(
                G.CONFIG.color.error_message_fg,
                G.CONFIG.color.error_message_bg)))

        last_line.message = message

    def replace_printed_line_by_uuid(self, uuid, new_message):
        """Replace already printed lines that are greyed out with real ones."""
        if isinstance(new_message, OwnAction):
            displayed_nick = self.displayed_nicks[self.room.own_user_id]
            user = self.weechat_buffer._get_user(displayed_nick)
            data = self.weechat_buffer._format_action(
                user,
                new_message.formatted_message.to_weechat()
            )
            new_lines = data.split("\n")
        else:
            new_lines = new_message.formatted_message.to_weechat().split("\n")

        line_count = len(new_lines)

        lines = self.weechat_buffer.find_lines(
            partial(self._find_by_uuid_predicate, uuid), line_count
        )

        for i, line in enumerate(lines):
            line.message = new_lines[i]
            tags = line.tags

            new_tags = [
                tag for tag in tags
                if not tag.startswith(SCRIPT_NAME + "_uuid_")
            ]
            new_tags.append(SCRIPT_NAME + "_id_" + new_message.event_id)
            line.tags = new_tags

    def replace_undecrypted_line(self, event):
        """Find an undecrypted message in the buffer and replace it with the now
        decrypted event."""
        # TODO different messages need different formatting
        # To implement this, refactor out the different formatting code
        # snippets to a Formatter class and reuse them here.
        if not isinstance(event, RoomMessageText):
            return

        def predicate(event_id, line):
            event_tag = SCRIPT_NAME + "_id_{}".format(event_id)
            if event_tag in line.tags:
                return True
            return False

        lines = self.weechat_buffer.find_lines(
            partial(predicate, event.event_id)
        )

        if not lines:
            return

        formatted = None
        if event.formatted_body:
            formatted = Formatted.from_html(event.formatted_body)

        data = formatted.to_weechat() if formatted else event.body
        # TODO this isn't right if the data has multiple lines, that is
        # everything is printed on a single line and newlines are shown as a
        # space.
        # Weechat should support deleting lines and printing new ones at an
        # arbitrary position.
        # To implement this without weechat support either only handle single
        # line messages or edit the first line in place, print new ones at the
        # bottom and sort the buffer lines.
        lines[0].message = data

    def old_message(self, event):
        tags = list(self.weechat_buffer.tags["old_message"])
        # TODO events that change the room state (topics, membership changes,
        # etc...) should be printed out as well, but for this to work without
        # messing up the room state the state change will need to be separated
        # from the print logic.
        if isinstance(event, RoomMessage):
            self.force_load_member(event)
            self.handle_room_messages(event, tags)

        elif isinstance(event, MegolmEvent):
            self.print_megolm(event, tags)

        elif isinstance(event, RedactedEvent):
            self.print_redacted(event, tags)

        elif isinstance(event, BadEvent):
            self.print_bad_event(event, tags)

    def sort_messages(self):
        class LineCopy(object):
            def __init__(
                self, date, date_printed, tags, prefix, message, highlight
            ):
                self.date = date
                self.date_printed = date_printed
                self.tags = tags
                self.prefix = prefix
                self.message = message
                self.highlight = highlight

            @classmethod
            def from_line(cls, line):
                return cls(
                    line.date,
                    line.date_printed,
                    line.tags,
                    line.prefix,
                    line.message,
                    line.highlight,
                )

        lines = [
            LineCopy.from_line(line) for line in self.weechat_buffer.lines
        ]
        sorted_lines = sorted(lines, key=lambda line: line.date, reverse=True)

        for line_number, line in enumerate(self.weechat_buffer.lines):
            new = sorted_lines[line_number]
            line.update(
                new.date, new.date_printed, new.tags, new.prefix, new.message
            )

    def handle_backlog(self, response):
        self.prev_batch = response.end

        for event in response.chunk:
            # The first backlog request seems to have a race condition going on
            # where we receive a message in a sync response, get a prev_batch,
            # yet when we request older messages with the prev_batch the same
            # message might appear in the room messages response. This only
            # seems to happen if the message is relatively recently sent.
            # Because of this we check if our first backlog request contains
            # some already printed events, if so; skip printing them.
            if (self.first_backlog_request
                    and event.event_id in self.printed_event_ids):
                continue

            self.old_message(event)

        self.sort_messages()

        self.first_backlog_request = False
        self.backlog_pending = False

    def handle_joined_room(self, info):
        for event in info.state:
            self.handle_state_event(event)

        timeline_events = None

        # This is a rejoin, skip already handled events
        if not self.joined:
            leave_index = None

            for i, event in enumerate(info.timeline.events):
                if event.event_id == self.leave_event_id:
                    leave_index = i
                    break

            if leave_index:
                timeline_events = info.timeline.events[leave_index + 1:]
                # Handle our leave as a state event since we're not in the
                # nicklist anymore but we're already printed out our leave
                self.handle_state_event(info.timeline.events[leave_index])
            else:
                timeline_events = info.timeline.events

            # mark that we are now joined
            self.joined = True

        else:
            timeline_events = info.timeline.events

        for event in timeline_events:
            self.handle_timeline_event(event)

        for event in info.account_data:
            if isinstance(event, FullyReadEvent):
                if event.event_id == self.last_event_id:
                    current_buffer = W.buffer_search("", "")

                    if self.weechat_buffer._ptr == current_buffer:
                        continue

                    W.buffer_set(self.weechat_buffer._ptr, "unread", "")
                    W.buffer_set(self.weechat_buffer._ptr, "hotlist", "-1")

        # We didn't handle all joined users, the room display name might still
        # be outdated because of that, update it now.
        if self.unhandled_users:
            self.update_buffer_name()

    def handle_left_room(self, info):
        self.joined = False

        for event in info.state:
            self.handle_state_event(event)

        for event in info.timeline.events:
            self.handle_timeline_event(event)

    def error(self, string):
        # type: (str) -> None
        self.weechat_buffer.error(string)
