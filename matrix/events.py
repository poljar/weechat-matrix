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
from matrix.rooms import (matrix_create_room_buffer, RoomInfo, RoomMessageText,
                          RoomMessageEvent, RoomRedactedMessageEvent,
                          RoomMessageEmote)

from matrix.encryption import OlmDeviceKey, OneTimeKey

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


class MatrixLoginEvent(MatrixEvent):

    def __init__(self, server, user_id, device_id, access_token):
        self.user_id = user_id
        self.access_token = access_token
        self.device_id = device_id
        MatrixEvent.__init__(self, server)

    def execute(self):
        self.server.access_token = self.access_token
        self.server.user_id = self.user_id
        self.server.client.access_token = self.access_token
        self.server.device_id = self.device_id
        self.server.save_device_id()

        message = "{prefix}matrix: Logged in as {user}".format(
            prefix=W.prefix("network"), user=self.user_id)

        W.prnt(self.server.server_buffer, message)

        if not self.server.olm:
            self.server.create_olm()
            self.server.store_olm()
            self.server.upload_keys(device_keys=True, one_time_keys=False)

        self.server.sync()

    @classmethod
    def from_dict(cls, server, parsed_dict):
        try:
            return cls(server, sanitize_id(parsed_dict["user_id"]),
                       sanitize_id(parsed_dict["device_id"]),
                       sanitize_token(parsed_dict["access_token"]))
        except (KeyError, TypeError, ValueError):
            return MatrixErrorEvent.from_dict(server, "Error logging in", True,
                                              parsed_dict)


class MatrixSendEvent(MatrixEvent):

    def __init__(self, server, room_id, message):
        self.room_id = room_id
        self.message = message
        MatrixEvent.__init__(self, server)

    def execute(self):
        tags = [
            "matrix_message", "notify_none", "no_highlight", "self_msg", "log1"
        ]

        buff = self.server.buffers[self.room_id]
        room = self.server.rooms[self.room_id]

        self.message.execute(self.server, room, buff, tags)

    @classmethod
    def from_dict(cls, server, room_id, message, parsed_dict):
        try:
            event_id = sanitize_id(parsed_dict["event_id"])
            sender = server.user_id
            age = 0
            plain_message = message.to_plain()
            formatted_message = message

            message = RoomMessageText(event_id, sender, age, plain_message,
                                      formatted_message)

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
            plain_message = message.to_plain()
            formatted_message = message

            message = RoomMessageEmote(event_id, sender, age, plain_message,
                                       formatted_message)

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
            server.send_room_message(self.room_id, formatted_message, True)


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

    @staticmethod
    def buffer_sort_messages(buff):
        lines = []

        own_lines = W.hdata_pointer(W.hdata_get('buffer'), buff, 'own_lines')

        if own_lines:
            hdata_line = W.hdata_get('line')
            hdata_line_data = W.hdata_get('line_data')
            line = W.hdata_pointer(
                W.hdata_get('lines'), own_lines, 'first_line')

            while line:
                data = W.hdata_pointer(hdata_line, line, 'data')

                line_data = {}

                if data:
                    date = W.hdata_time(hdata_line_data, data, 'date')
                    print_date = W.hdata_time(hdata_line_data, data,
                                              'date_printed')
                    tags = tags_from_line_data(data)
                    prefix = W.hdata_string(hdata_line_data, data, 'prefix')
                    message = W.hdata_string(hdata_line_data, data, 'message')
                    highlight = W.hdata_char(hdata_line_data, data, "highlight")

                    line_data = {
                        'date': date,
                        'date_printed': print_date,
                        'tags_array': ','.join(tags),
                        'prefix': prefix,
                        'message': message,
                        'highlight': highlight
                    }

                    lines.append(line_data)

                line = W.hdata_move(hdata_line, line, 1)

            sorted_lines = sorted(lines, key=itemgetter('date'))
            lines = []

            # We need to convert the dates to a string for hdata_update(), this
            # will reverse the list at the same time
            while sorted_lines:
                line = sorted_lines.pop()
                new_line = {k: str(v) for k, v in line.items()}
                lines.append(new_line)

            MatrixBacklogEvent.update_buffer_lines(lines, own_lines)

    @staticmethod
    def update_buffer_lines(new_lines, own_lines):
        hdata_line = W.hdata_get('line')
        hdata_line_data = W.hdata_get('line_data')

        line = W.hdata_pointer(W.hdata_get('lines'), own_lines, 'first_line')

        while line:
            data = W.hdata_pointer(hdata_line, line, 'data')

            if data:
                W.hdata_update(hdata_line_data, data, new_lines.pop())

            line = W.hdata_move(hdata_line, line, 1)

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
        buff = self.server.buffers[self.room_id]
        tags = tags_for_message("backlog")

        for event in self.events:
            event.execute(self.server, room, buff, list(tags))

        room.prev_batch = self.end_token
        MatrixBacklogEvent.buffer_sort_messages(buff)
        room.backlog_pending = False
        W.bar_item_update("buffer_modes")


class MatrixSyncEvent(MatrixEvent):

    def __init__(self, server, next_batch, room_infos, invited_infos,
                 one_time_key_count):
        self.next_batch = next_batch
        self.joined_room_infos = room_infos
        self.invited_room_infos = invited_infos
        self.one_time_key_count = one_time_key_count

        MatrixEvent.__init__(self, server)

    @staticmethod
    def _infos_from_dict(olm, parsed_dict):
        join_infos = []
        invite_infos = []

        for room_id, room_dict in parsed_dict['join'].items():
            if not room_id:
                continue

            join_infos.append(RoomInfo.from_dict(olm, room_id, room_dict))

        return (join_infos, invite_infos)

    @staticmethod
    def _get_olm_device_event(server, parsed_dict):
        device_key = server.olm.account.identity_keys["curve25519"]

        if device_key not in parsed_dict["content"]["ciphertext"]:
            return None

        sender = sanitize_id(parsed_dict["sender"])
        sender_key = sanitize_id(parsed_dict["content"]["sender_key"])

        ciphertext = parsed_dict["content"]["ciphertext"].pop(device_key)

        message = None

        if ciphertext["type"] == 0:
            message = OlmPreKeyMessage(ciphertext["body"])
        elif ciphertext["type"] == 1:
            message = OlmMessage(ciphertext["body"])
        else:
            raise ValueError("Invalid Olm message type")

        olm = server.olm
        plaintext = olm.decrypt(sender, sender_key, message)

        if not plaintext:
            return None

        # TODO check sender key
        decrypted_sender = plaintext["sender"]
        decrypted_recepient = plaintext["recipient"]
        decrypted_recepient_key = plaintext["recipient_keys"]["ed25519"]

        if (sender != decrypted_sender or
                server.user_id != decrypted_recepient or
                olm.account.identity_keys["ed25519"] !=
                decrypted_recepient_key):
            error_message = ("{prefix}matrix: Mismatch in decrypted Olm "
                             "message").format(prefix=W.prefix("error"))
            W.prnt("", error_message)
            return None

        if plaintext["type"] != "m.room_key":
            return None

        MatrixSyncEvent._handle_key_event(server, sender_key, plaintext)

    @staticmethod
    def _handle_key_event(server, sender_key, parsed_dict):
        # type: (MatrixServer, str, Dict[Any, Any] -> None
        olm = server.olm
        content = parsed_dict.pop("content")

        if content["algorithm"] != "m.megolm.v1.aes-sha2":
            return

        room_id = content["room_id"]
        session_id = content["session_id"]
        session_key = content["session_key"]

        if session_id in olm.inbound_group_sessions[room_id]:
            return

        olm.create_group_session(room_id, session_id, session_key)

    @staticmethod
    def _get_to_device_events(server, parsed_dict):
        # type: (MatrixServer, Dict[Any, Any]) -> None
        for event in parsed_dict["events"]:
            if event["type"] == "m.room.encrypted":
                if (event["content"]["algorithm"] ==
                        'm.olm.v1.curve25519-aes-sha2'):
                    MatrixSyncEvent._get_olm_device_event(server, event)

    @classmethod
    def from_dict(cls, server, parsed_dict):
        try:
            next_batch = sanitize_id(parsed_dict["next_batch"])
            one_time_key_count = 0

            if "device_one_time_keys_count" in parsed_dict:
                if ("signed_curve25519" in
                        parsed_dict["device_one_time_keys_count"]):
                    one_time_key_count = (
                        parsed_dict["device_one_time_keys_count"]["signed_curve25519"])

            MatrixSyncEvent._get_to_device_events(
                server, parsed_dict.pop("to_device"))

            room_info_dict = parsed_dict["rooms"]

            join_infos, invite_infos = MatrixSyncEvent._infos_from_dict(
                    server.olm, room_info_dict)

            return cls(server, next_batch, join_infos, invite_infos,
                       one_time_key_count)
        except (KeyError, ValueError, TypeError):
            return MatrixErrorEvent.from_dict(server, "Error syncing", False,
                                              parsed_dict)

    def _queue_joined_info(self):
        server = self.server

        while self.joined_room_infos:
            info = self.joined_room_infos.pop()

            if info.room_id not in server.buffers:
                matrix_create_room_buffer(server, info.room_id)

            room = server.rooms[info.room_id]

            if not room.prev_batch:
                room.prev_batch = info.prev_batch

            server.event_queue.append(info)

    def execute(self):
        server = self.server

        # we got the same batch again, nothing to do
        if self.next_batch == server.next_batch:
            server.sync()
            return

        self._queue_joined_info()
        server.next_batch = self.next_batch
        server.check_one_time_keys(self.one_time_key_count)

        server.handle_events()
