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
import pprint

from collections import deque, defaultdict
from functools import partial
from operator import itemgetter

from matrix.globals import W
from matrix.utils import (tags_for_message, sanitize_id, sanitize_token,
                          sanitize_text, tags_from_line_data)

from matrix.encryption import OlmDeviceKey, OneTimeKey
from .buffer import RoomUser, OwnMessage, OwnAction

try:
    from olm.session import OlmMessage, OlmPreKeyMessage
except ImportError:
    pass


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


class MatrixKeyUploadEvent(MatrixEvent):

    def __init__(self, server, device_keys):
        self.device_keys = device_keys
        MatrixEvent.__init__(self, server)

    def execute(self):
        self.server.olm.mark_keys_as_published()
        self.server.store_olm()

        if not self.device_keys:
            return

        message = "{prefix}matrix: Uploaded Olm device keys.".format(
            prefix=W.prefix("network"))

        W.prnt(self.server.server_buffer, message)

    @classmethod
    def from_dict(cls, server, device_keys, parsed_dict):
        try:
            return cls(server, device_keys)
        except (KeyError, TypeError, ValueError):
            return MatrixErrorEvent.from_dict(server, "Error uploading device"
                                              "keys", False, parsed_dict)


class MatrixSendEvent(MatrixEvent):

    def __init__(self, server, room_id, message):
        self.room_id = room_id
        self.message = message
        MatrixEvent.__init__(self, server)

    @classmethod
    def from_dict(cls, server, room_id, message, parsed_dict):
        try:
            event_id = sanitize_id(parsed_dict["event_id"])
            sender = server.user_id
            age = 0
            formatted_message = message

            message = OwnMessage(sender, age, event_id, formatted_message)

            return cls(server, room_id, message)
        except (KeyError, TypeError, ValueError):
            return MatrixErrorEvent.from_dict(server, "Error sending message",
                                              False, parsed_dict)


class MatrixEmoteEvent(MatrixSendEvent):

    @classmethod
    def from_dict(cls, server, room_id, message, parsed_dict):
        try:
            event_id = sanitize_id(parsed_dict["event_id"])
            sender = server.user_id
            age = 0
            formatted_message = message

            message = OwnAction(sender, age, event_id, formatted_message)

            return cls(server, room_id, message)
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


class MatrixKickEvent(MatrixEvent):

    def __init__(self, server, room_id, user_id, reason):
        self.room_id = room_id
        self.user_id = user_id
        self.reason = reason
        MatrixEvent.__init__(self, server)

    @classmethod
    def from_dict(cls, server, room_id, user_id, reason, parsed_dict):
        try:
            if parsed_dict == {}:
                return cls(server, room_id, user_id, reason)

            raise KeyError
        except KeyError:
            return MatrixErrorEvent.from_dict(server, "Error kicking user",
                                              False, parsed_dict)


class MatrixKeyQueryEvent(MatrixEvent):

    def __init__(self, server, keys):
        self.keys = keys
        MatrixEvent.__init__(self, server)

    @staticmethod
    def _get_keys(key_dict):
        keys = {}

        for key_type, key in key_dict.items():
            key_type, _ = key_type.split(":")
            keys[key_type] = key

        return keys

    @classmethod
    def from_dict(cls, server, parsed_dict):
        keys = defaultdict(list)
        try:
            for user_id, device_dict in parsed_dict["device_keys"].items():
                for device_id, key_dict in device_dict.items():
                    device_keys = MatrixKeyQueryEvent._get_keys(
                        key_dict.pop("keys"))
                    keys[user_id].append(OlmDeviceKey(user_id, device_id,
                                                      device_keys))
            return cls(server, keys)
        except KeyError:
            # TODO error message
            return MatrixErrorEvent.from_dict(server, "Error kicking user",
                                              False, parsed_dict)

    def execute(self):
        # TODO move this logic into an Olm method
        olm = self.server.olm

        if olm.device_keys == self.keys:
            return

        olm.device_keys = self.keys
        # TODO invalidate megolm sessions for rooms that got new devices


class MatrixKeyClaimEvent(MatrixEvent):

    def __init__(self, server, room_id, keys):
        self.keys = keys
        self.room_id = room_id
        MatrixEvent.__init__(self, server)

    @classmethod
    def from_dict(cls, server, room_id, parsed_dict):
        W.prnt("", pprint.pformat(parsed_dict))
        keys = []
        try:
            for user_id, user_dict in parsed_dict["one_time_keys"].items():
                for device_id, device_dict in user_dict.items():
                    for key_dict in device_dict.values():
                        # TODO check the signature of the key
                        key = OneTimeKey(user_id, device_id, key_dict["key"])
                        keys.append(key)

            return cls(server, room_id, keys)
        except KeyError:
            return MatrixErrorEvent.from_dict(
                server, ("Error claiming onetime keys."), False, parsed_dict)

    def execute(self):
        server = self.server
        olm = server.olm

        for key in self.keys:
            olm.create_session(key.user_id, key.device_id, key.key)

        while server.encryption_queue[self.room_id]:
            formatted_message = server.encryption_queue[self.room_id].popleft()
            room, _ = server.find_room_from_id(self.room_id)
            server.send_room_message(room, formatted_message, True)


class MatrixToDeviceEvent(MatrixEvent):

    def __init__(self, server):
        MatrixEvent.__init__(self, server)

    @classmethod
    def from_dict(cls, server, parsed_dict):
        try:
            if parsed_dict == {}:
                return cls(server)

            raise KeyError
        except KeyError:
            return MatrixErrorEvent.from_dict(server, ("Error sending to "
                                                       "device message"),
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
