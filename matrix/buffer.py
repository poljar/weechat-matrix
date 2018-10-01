# -*- coding: utf-8 -*-

# Weechat Matrix Protocol Script
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

import time
from builtins import super
from functools import partial
from typing import Dict, List, NamedTuple, Optional, Set

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
    RoomMessageNotice,
    RoomMessageText,
    RoomMessageUnknown,
    RoomNameEvent,
    RoomTopicEvent,
    MegolmEvent,
    Event,
    OlmTrustError
)

from . import globals as G
from .colors import Formatted
from .config import RedactType
from .globals import SCRIPT_NAME, SERVERS, W
from .utf import utf8_decode
from .utils import server_ts_to_weechat, shorten_sender, string_strikethrough

OwnMessages = NamedTuple(
    "OwnMessages",
    [
        ("sender", str),
        ("age", int),
        ("event_id", str),
        ("room_id", str),
        ("formatted_message", Formatted),
    ],
)


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

    data = W.string_input_for_buffer(input_data)

    if not data:
        data = input_data

    formatted_data = Formatted.from_input_line(data)

    try:
        server.room_send_message(room_buffer, formatted_data, "m.text")
    except OlmTrustError as e:
        m = ("Untrusted devices found in room: {}".format(e))
        server.error(m)
        pass

    return W.WEECHAT_RC_OK


@utf8_decode
def room_buffer_close_cb(data, buffer):
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

            if date:
                new_data["date"] = str(date)
            if date_printed:
                new_data["date_printed"] = str(date_printed)
            if tags:
                new_data["tags_array"] = ",".join(tags)
            if prefix:
                new_data["prefix"] = prefix
            if message:
                new_data["message"] = message
            if highlight:
                new_data["highlight"] = highlight

            if new_data:
                W.hdata_update(self._hdata, self._ptr, new_data)

    def __init__(self, name, server_name, user):
        # type: (str, str, str) -> None
        self._ptr = W.buffer_new(
            name,
            "room_buffer_input_cb",
            server_name,
            "room_buffer_close_cb",
            server_name,
        )

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

        # short_name = strip_matrix_server(room_id)
        # W.buffer_set(self._ptr, "short_name", short_name)

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

    def _print_action(self, user, message, date, tags, extra_prefix):
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
            "{extra_prefix}{prefix}{nick_prefix}{nick_color}{author}"
            "{ncolor} {msg}").format(
            extra_prefix=extra_prefix,
            prefix=W.prefix("action"),
            nick_prefix=nick_prefix,
            nick_color=W.color(user.color),
            author=user.nick,
            ncolor=W.color("reset"),
            msg=message,
        )

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
        elif user.prefix > "+":
            group_name = "002|v"

        return group_name

    @staticmethod
    def _get_prefix_color(prefix):
        # type: (str) -> str
        # TODO make this configurable
        color = ""

        if prefix == "&":
            color = "lightgreen"
        elif prefix == "@":
            color = "lightgreen"
        elif prefix == "+":
            color = "yellow"

        return color

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

    def _remove_user_from_nicklist(self, user):
        # type: (WeechatUser) -> None
        nick_pointer = W.nicklist_search_nick(self._ptr, "", user.nick)

        if nick_pointer:
            W.nicklist_remove_nick(self._ptr, nick_pointer)

    def _leave(self, nick, date, message, leave_type, extra_tags=None):
        # type: (str, int, bool, str, List[str]) -> None
        user = self._get_user(nick)
        self._remove_user_from_nicklist(user)

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

    def find_lines(self, predicate):
        lines = []
        for line in self.lines:
            if predicate(line):
                lines.append(line)

        return lines


class RoomBuffer(object):
    def __init__(self, room, server_name, prev_batch):
        self.room = room
        self._backlog_pending = False
        self.prev_batch = prev_batch
        self.joined = True
        self.leave_event_id = None  # type: Optional[str]
        self.unhandled_users = []   # type: List[str]

        buffer_name = "{}.{}".format(server_name, room.room_id)

        # This dict remembers the connection from a user_id to the name we
        # displayed in the buffer
        self.displayed_nicks = {}
        user = shorten_sender(self.room.own_user_id)
        self.weechat_buffer = WeechatChannelBuffer(
            buffer_name, server_name, user
        )

    @property
    def backlog_pending(self):
        return self._backlog_pending

    @backlog_pending.setter
    def backlog_pending(self, value):
        self._backlog_pending = value
        W.bar_item_update("buffer_modes")

    @property
    def warning_prefix(self):
        return "⚠️ "

    def find_nick(self, user_id):
        # type: (str) -> str
        """Find a suitable nick from a user_id"""
        if user_id in self.displayed_nicks:
            return self.displayed_nicks[user_id]

        return user_id

    def add_user(self, user_id, date, is_state):
        try:
            user = self.room.users[user_id]
        except KeyError:
            # No user found, he must have left already in an event that is
            # yet to come, so do nothing
            # W.prnt("", "NOT ADDING USER {}".format(user_id))
            return

        short_name = shorten_sender(user.user_id)

        # TODO handle this special case for discord bridge users and
        # freenode bridge users better
        if user.user_id.startswith("@_discord_"):
            if user.display_name:
                short_name = user.display_name
        elif user.user_id.startswith("@freenode_"):
            short_name = shorten_sender(user.user_id[9:])

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
            if event.state_key not in self.displayed_nicks:
                # Adding users to the nicklist is a O(1) + search time
                # operation (the nicks are added to a linked list sorted).
                # The search time is O(N * min(a,b)) where N is the number
                # of nicks already added and a/b are the length of
                # the strings that are compared at every itteration.
                # Because the search time get's increasingly longer we're
                # going to add nicks later in a timer hook.
                if ((len(self.room.users) - len(self.displayed_nicks)) > 500
                        and is_state):
                    self.unhandled_users.append(event.state_key)
                else:
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

        room_name = self.room.display_name()
        self.weechat_buffer.short_name = room_name

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

        lines = self.weechat_buffer.find_lines(
            partial(predicate, event.redacts)
        )

        # No line to redact, return early
        if not lines:
            return

        # TODO multiple lines can contain a single matrix ID, we need to redact
        # them all
        line = lines[0]

        censor = self.find_nick(event.sender)
        message = line.message
        tags = line.tags

        reason = (
            ""
            if not event.reason
            else ', reason: "{reason}"'.format(reason=event.reason)
        )

        redaction_msg = (
            "{del_color}<{log_color}Message redacted by: "
            "{censor}{log_color}{reason}{del_color}>"
            "{ncolor}"
        ).format(
            del_color=W.color("chat_delimiters"),
            ncolor=W.color("reset"),
            log_color=W.color("logger.color.backlog_line"),
            censor=censor,
            reason=reason,
        )

        new_message = ""

        if G.CONFIG.look.redactions == RedactType.STRIKETHROUGH:
            plaintext_msg = W.string_remove_color(message, "")
            new_message = string_strikethrough(plaintext_msg)
        elif G.CONFIG.look.redactions == RedactType.NOTICE:
            new_message = message
        elif G.CONFIG.look.redactions == RedactType.DELETE:
            pass

        message = " ".join(s for s in [new_message, redaction_msg] if s)

        tags.append("matrix_redacted")

        line.message = message
        line.tags = tags

    def _handle_redacted_message(self, event):
        nick = self.find_nick(event.sender)
        date = server_ts_to_weechat(event.server_timestamp)
        tags = self.get_event_tags(event)
        tags.append(SCRIPT_NAME + "_redacted")

        reason = (
            ', reason: "{reason}"'.format(reason=event.reason)
            if event.reason
            else ""
        )

        censor = self.find_nick(event.redacter)

        data = (
            "{del_color}<{log_color}Message redacted by: "
            "{censor}{log_color}{reason}{del_color}>{ncolor}"
        ).format(
            del_color=W.color("chat_delimiters"),
            ncolor=W.color("reset"),
            log_color=W.color("logger.color.backlog_line"),
            censor=censor,
            reason=reason,
        )

        self.weechat_buffer.message(nick, data, date, tags)

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
                self.weechat_buffer._remove_user_from_nicklist(user)
                self.weechat_buffer._add_user_to_nicklist(user)

    def handle_state_event(self, event):
        if isinstance(event, RoomMemberEvent):
            self.handle_membership_events(event, True)
        elif isinstance(event, RoomTopicEvent):
            self._handle_topic(event, True)
        elif isinstance(event, PowerLevelsEvent):
            self._handle_power_level(event)
        elif isinstance(event, RoomEncryptionEvent):
            message = (
                "This room is encrypted, encryption is "
                "currently unsuported. Message sending is disabled for "
                "this room."
            )
            self.weechat_buffer.error(message)

    def handle_timeline_event(self, event):
        # TODO this should be done for every messagetype that gets printed in
        # the buffer
        if isinstance(event, (RoomMessage, MegolmEvent)):
            if (event.sender not in self.displayed_nicks and
                    event.sender in self.room.users):

                try:
                    self.unhandled_users.remove(event.sender)
                except ValueError:
                    pass

                self.add_user(event.sender, 0, True)

        if isinstance(event, RoomMemberEvent):
            self.handle_membership_events(event, False)

        elif isinstance(event, (RoomNameEvent, RoomAliasEvent)):
            room_name = self.room.display_name()
            self.weechat_buffer.short_name = room_name

        elif isinstance(event, RoomTopicEvent):
            self._handle_topic(event, False)

        # Emotes are a subclass of RoomMessageText, so put them before the text
        # ones
        elif isinstance(event, RoomMessageEmote):
            nick = self.find_nick(event.sender)
            date = server_ts_to_weechat(event.server_timestamp)

            extra_prefix = (self.warning_prefix if event.decrypted
                            and not event.verified else "")

            self.weechat_buffer.action(
                nick, event.body, date, self.get_event_tags(event),
                extra_prefix
            )

        elif isinstance(event, RoomMessageText):
            nick = self.find_nick(event.sender)
            formatted = None

            if event.formatted_body:
                formatted = Formatted.from_html(event.formatted_body)

            data = formatted.to_weechat() if formatted else event.body

            extra_prefix = (self.warning_prefix if event.decrypted
                            and not event.verified else "")

            date = server_ts_to_weechat(event.server_timestamp)
            self.weechat_buffer.message(
                nick, data, date, self.get_event_tags(event), extra_prefix
            )

        elif isinstance(event, RoomMessageNotice):
            nick = self.find_nick(event.sender)
            date = server_ts_to_weechat(event.server_timestamp)
            extra_prefix = (self.warning_prefix if event.decrypted
                            and not event.verified else "")

            self.weechat_buffer.notice(
                nick, event.body, date, self.get_event_tags(event),
                extra_prefix
            )

        elif isinstance(event, RoomMessageMedia):
            nick = self.find_nick(event.sender)
            date = server_ts_to_weechat(event.server_timestamp)
            http_url = Api.mxc_to_http(event.url)
            url = http_url if http_url else event.url

            description = "/{}".format(event.body) if event.body else ""
            data = "{url}{desc}".format(url=url, desc=description)

            extra_prefix = (self.warning_prefix if event.decrypted
                            and not event.verified else "")

            self.weechat_buffer.message(
                nick, data, date, self.get_event_tags(event), extra_prefix
            )

        elif isinstance(event, RoomMessageUnknown):
            nick = self.find_nick(event.sender)
            date = server_ts_to_weechat(event.server_timestamp)
            data = ("Unknown message of type {t}").format(t=event.type)
            extra_prefix = (self.warning_prefix if event.decrypted
                            and not event.verified else "")

            self.weechat_buffer.message(
                nick, data, date, self.get_event_tags(event), extra_prefix
            )

        elif isinstance(event, RedactionEvent):
            self._redact_line(event)

        elif isinstance(event, RedactedEvent):
            self._handle_redacted_message(event)

        elif isinstance(event, RoomEncryptionEvent):
            message = (
                "This room is encrypted, encryption is "
                "currently unsuported. Message sending is disabled for "
                "this room."
            )
            self.weechat_buffer.error(message)

        elif isinstance(event, PowerLevelsEvent):
            self._handle_power_level(event)

        elif isinstance(event, MegolmEvent):
            nick = self.find_nick(event.sender)
            date = server_ts_to_weechat(event.server_timestamp)

            data = ("{del_color}<{log_color}Unable to decrypt: "
                    "The sender's device has not sent us "
                    "the keys for this message{del_color}>{ncolor}").format(
                            del_color=W.color("chat_delimiters"),
                            log_color=W.color("logger.color.backlog_line"),
                            ncolor=W.color("reset"))
            session_id_tag = SCRIPT_NAME + "_sessionid_" + event.session_id
            self.weechat_buffer.message(
                nick,
                data,
                date,
                self.get_event_tags(event) + [session_id_tag]
            )

        else:
            W.prnt(
                "", "Unhandled event of type {}.".format(type(event).__name__)
            )

    def self_message(self, message):
        # type: (OwnMessage) -> None
        nick = self.find_nick(self.room.own_user_id)
        data = message.formatted_message.to_weechat()
        tags = [SCRIPT_NAME + "_id_{}".format(message.event_id)]
        date = message.age

        self.weechat_buffer.self_message(nick, data, date, tags)

    def self_action(self, message):
        # type: (OwnMessage) -> None
        nick = self.find_nick(self.room.own_user_id)
        date = message.age
        tags = [SCRIPT_NAME + "_id_{}".format(message.event_id)]

        self.weechat_buffer.self_action(
            nick, message.formatted_message.to_weechat(), date, tags
        )

    def old_redacted(self, event):
        tags = [
            SCRIPT_NAME + "_message",
            "notify_message",
            "no_log",
            "no_highlight",
        ]
        reason = (
            ', reason: "{reason}"'.format(reason=event.reason)
            if event.reason
            else ""
        )

        censor = self.find_nick(event.redacter)

        data = (
            "{del_color}<{log_color}Message redacted by: "
            "{censor}{log_color}{reason}{del_color}>{ncolor}"
        ).format(
            del_color=W.color("chat_delimiters"),
            ncolor=W.color("reset"),
            log_color=W.color("logger.color.backlog_line"),
            censor=censor,
            reason=reason,
        )

        tags += self.get_event_tags(event)
        nick = self.find_nick(event.sender)
        user = self.weechat_buffer._get_user(nick)
        date = server_ts_to_weechat(event.server_timestamp)
        self.weechat_buffer._print_message(user, data, date, tags)

    def old_message(self, event):
        tags = [
            SCRIPT_NAME + "_message",
            "notify_message",
            "no_log",
            "no_highlight",
        ]
        tags += self.get_event_tags(event)
        nick = self.find_nick(event.sender)

        formatted = None

        if event.formatted_body:
            formatted = Formatted.from_html(event.formatted_body)

        data = formatted.to_weechat() if formatted else event.body
        user = self.weechat_buffer._get_user(nick)
        date = server_ts_to_weechat(event.server_timestamp)
        self.weechat_buffer._print_message(user, data, date, tags)

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
            if isinstance(event, RoomMessageText):
                self.old_message(event)
            elif isinstance(event, RedactedEvent):
                self.old_redacted(event)

        self.sort_messages()

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

        # We didn't handle all joined users, the room display name might still
        # be outdated because of that, update it now.
        if self.unhandled_users:
            room_name = self.room.display_name()
            self.weechat_buffer.short_name = room_name

    def handle_left_room(self, info):
        self.joined = False

        for event in info.state:
            self.handle_state_event(event)

        for event in info.timeline.events:
            self.handle_timeline_event(event)

    def error(self, string):
        # type: (str) -> None
        self.weechat_buffer.error(string)
