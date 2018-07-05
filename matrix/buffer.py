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

from .globals import W, SERVERS, SCRIPT_NAME
from .utf import utf8_decode
from .colors import Formatted
from builtins import super


@utf8_decode
def room_buffer_input_cb(server_name, buffer, input_data):
    server = SERVERS[server_name]
    room, room_buffer = server.find_room_from_ptr(buffer)

    if not room_buffer:
        # TODO log error
        return

    if not server.connected:
        room_buffer.error("You are not connected to the server")
        return W.WEECHAT_RC_ERROR

    formatted_data = Formatted.from_input_line(input_data)

    server.send_room_message(room, formatted_data)

    return W.WEECHAT_RC_OK


@utf8_decode
def room_buffer_close_cb(data, buffer):
    return W.WEECHAT_RC_OK


class WeechatUser(object):
    def __init__(self, nick, host=None, prefix=""):
        # type: (str, str, str) -> None
        self.nick = nick
        self.host = host
        self.prefix = prefix
        self.color = W.info_get("nick_color_name", nick)


class RoomUser(WeechatUser):
    def __init__(self, nick, user_id=None, power_level=0):
        # type: (str, str, int) -> None
        prefix = self._get_prefix(power_level)
        return super().__init__(nick, user_id, prefix)

    @staticmethod
    def _get_prefix(power_level):
        # type: (int) -> str
        if power_level >= 100:
            return "&"
        elif power_level >= 50:
            return "@"
        elif power_level > 0:
            return "+"
        return ""


class WeechatChannelBuffer(object):
    tags = {
        "message": [
            SCRIPT_NAME + "_message",
            "notify_message",
            "log1"
        ],
        "self_message": [
            SCRIPT_NAME + "_message",
            "notify_none",
            "no_highlight",
            "self_msg",
            "log1"
        ],
        "old_message": [
            SCRIPT_NAME + "_message",
            "notify_message",
            "no_log",
            "no_highlight"
        ],
        "join": [
            SCRIPT_NAME + "_join",
            "log4"
        ],
        "part": [
            SCRIPT_NAME + "_leave",
            "log4"
        ],
        "kick": [
            SCRIPT_NAME + "_kick",
            "log4"
        ],
        "invite": [
            SCRIPT_NAME + "_invite",
            "log4"
        ],
        "topic": [
            SCRIPT_NAME + "_topic",
            "log3",
        ]
    }

    membership_messages = {
        "join": "has joined",
        "part": "has left",
        "kick": "has been kicked",
        "invite": "has been invited"
    }

    def __init__(self, name, server_name, user):
        # type: (str, str, str)
        self._ptr = W.buffer_new(
            name,
            "room_buffer_input_cb",
            server_name,
            "room_buffer_close_cb",
            server_name,
        )

        self.name = ""
        self.users = {}  # type: Dict[str, RoomUser]

        self.topic_author = ""
        self.topic_date = None

        W.buffer_set(self._ptr, "localvar_set_type", 'channel')
        W.buffer_set(self._ptr, "type", 'formatted')

        W.buffer_set(self._ptr, "localvar_set_channel", name)

        W.buffer_set(self._ptr, "localvar_set_nick", user)

        W.buffer_set(self._ptr, "localvar_set_server", server_name)

        # short_name = strip_matrix_server(room_id)
        # W.buffer_set(self._ptr, "short_name", short_name)

        W.nicklist_add_group(
            self._ptr,
            '',
            "000|o",
            "weechat.color.nicklist_group",
            1
        )
        W.nicklist_add_group(
            self._ptr,
            '',
            "001|h",
            "weechat.color.nicklist_group",
            1
        )
        W.nicklist_add_group(
            self._ptr,
            '',
            "002|v",
            "weechat.color.nicklist_group",
            1
        )
        W.nicklist_add_group(
            self._ptr,
            '',
            "999|...",
            "weechat.color.nicklist_group",
            1
        )

        W.buffer_set(self._ptr, "nicklist", "1")
        W.buffer_set(self._ptr, "nicklist_display_groups", "0")

        # TODO make this configurable
        W.buffer_set(
            self._ptr,
            "highlight_tags_restrict",
            SCRIPT_NAME + "_message"
        )

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
            W.prefix("error"),
            SCRIPT_NAME,
            string
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
        # type: (str, RoomUser, str) -> List[str]
        tags = list(self.tags[message_type])

        tags.append("nick_{nick}".format(nick=user.nick))

        color = self._color_for_tags(user.color)

        if message_type != "action":
            tags.append("prefix_nick_{color}".format(color=color))

        return tags

    def _get_user(self, nick):
        # type: (str) -> RoomUser
        if nick in self.users:
            return self.users[nick]

        # A message from a non joined user
        return RoomUser(nick)

    def message(self, nick, message, date, tags=[]):
        # type: (str, str, int, str) -> None
        user = self._get_user(nick)
        tags = tags or self._message_tags(user, "message")

        prefix_string = ("" if not user.prefix else "{}{}{}".format(
            W.color(self._get_prefix_color(user.prefix)),
            user.prefix,
            W.color("reset")
        ))

        data = "{prefix}{color}{author}{ncolor}\t{msg}".format(
            prefix=prefix_string,
            color=W.color(user.color),
            author=user.nick,
            ncolor=W.color("reset"),
            msg=message)

        self.print_date_tags(data, date, tags)

    def notice(self, nick, message, date):
        # type: (str, str, int) -> None
        data = "{color}{message}{ncolor}".format(
            color=W.color("irc.color.notice"),
            message=message,
            ncolor=W.color("reset"))

        self.message(nick, data, date)

    def action(self, nick, message, date, tags=[]):
        # type: (str, str, int) -> None
        user = self._get_user(nick)
        tags = tags or self._message_tags(user, "action")

        nick_prefix = ("" if not user.prefix else "{}{}{}".format(
            W.color(self._get_prefix_color(user.prefix)),
            user.prefix,
            W.color("reset")
        ))

        data = ("{prefix}{nick_prefix}{nick_color}{author}"
                "{ncolor} {msg}").format(
            prefix=W.prefix("action"),
            nick_prefix=nick_prefix,
            nick_color=W.color(user.color),
            author=nick,
            ncolor=W.color("reset"),
            msg=message)

        self.print_date_tags(data, date, tags)

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
                self._ptr,
                "",
                self._get_nicklist_group(user)
            )
            prefix = user.prefix if user.prefix else " "
            W.nicklist_add_nick(
                self._ptr,
                group,
                user.nick,
                user.color,
                prefix,
                self._get_prefix_color(user.prefix),
                1
            )

    def _membership_message(self, user, message_type):
        # type: (WeechatUser, str) -> str
        action_color = ("green" if message_type == "join"
                        or message_type == "invite" else "red")

        membership_message = self.membership_messages[message_type]

        message = ("{prefix}{color}{author}{ncolor} "
                   "{del_color}({host_color}{host}{del_color})"
                   "{action_color} {message} "
                   "{channel_color}{room}{ncolor}").format(
            prefix=W.prefix(message_type),
            color=W.color(user.color),
            author=user.nick,
            ncolor=W.color("reset"),
            del_color=W.color("chat_delimiters"),
            host_color=W.color("chat_host"),
            host=user.host,
            action_color=W.color(action_color),
            message=membership_message,
            channel_color=W.color("chat_channel"),
            room=self.name)

        return message

    def join(self, user, date, message=True, extra_tags=[]):
        # type: (WeechatUser, int, Optional[bool], Optional[List[str]]) -> None
        self._add_user_to_nicklist(user)
        self.users[user.nick] = user

        if message:
            tags = self._message_tags(user, "join")
            message = self._membership_message(user, "join")
            self.print_date_tags(message, date, tags)

    def invite(self, user, date, extra_tags=[]):
        # type: (WeechatUser, int, Optional[bool], Optional[List[str]]) -> None
        tags = self._message_tags(user, "invite")
        message = self._membership_message(user, "invite")
        self.print_date_tags(message, date, tags + extra_tags)

    def _remove_user_from_nicklist(self, user):
        # type: (WeechatUser) -> None
        pass

    def _leave(self, user, date, message, leave_type, extra_tags):
        # type: (WeechatUser, int, bool, str, List[str]) -> None
        self._remove_user_from_nicklist(user)

        if message:
            tags = self._message_tags(user, leave_type)
            message = self._membership_message(user, leave_type)
            self.print_date_tags(message, date, tags + extra_tags)

        if user.nick in self.users:
            del self.users[user.nick]

    def part(self, user, date, message=True, extra_tags=[]):
        # type: (WeechatUser, int, Optional[bool], Optional[List[str]]) -> None
        self._leave(user, date, message, "leave", extra_tags)

    def kick(self, user, date, message=True, extra_tags=[]):
        # type: (WeechatUser, int, Optional[bool], Optional[List[str]]) -> None
        self._leave(user, date, message, "kick", extra_tags=[])

    def _print_topic(self, nick, topic, date):
        user = self._get_user(nick)
        tags = self._message_tags(user, "topic")

        data = ("{prefix}{nick} has changed "
                "the topic for {chan_color}{room}{ncolor} "
                "to \"{topic}\"").format(
                    prefix=W.prefix("network"),
                    nick=user.nick,
                    chan_color=W.color("chat_channel"),
                    ncolor=W.color("reset"),
                    room=self.short_name,
                    topic=topic
                )

        self.print_date_tags(data, date, tags)

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

    def self_message(self, nick, message, date):
        user = self._get_user(nick)
        tags = self._message_tags(user, "self_message")
        self.message(nick, message, date, tags)

    def self_action(self, nick, message, date):
        user = self._get_user(nick)
        tags = self._message_tags(user, "self_message")
        tags.append(SCRIPT_NAME + "_action")
        self.action(nick, message, date, tags)

    @property
    def short_name(self):
        return W.buffer_get_string(self._ptr, "short_name")

    @short_name.setter
    def short_name(self, name):
        W.buffer_set(self._ptr, "short_name", name)
