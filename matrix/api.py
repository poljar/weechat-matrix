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
import json
from enum import Enum, unique

try:
    from urllib import quote, urlencode
except ImportError:
    from urllib.parse import quote, urlencode

from matrix.globals import OPTIONS

from matrix.http import RequestType, HttpRequest
from matrix.colors import formatted_to_plain, formatted_to_html, is_formatted

MATRIX_API_PATH = "/_matrix/client/r0"  # type: str


@unique
class MessageType(Enum):
    LOGIN = 0
    SYNC = 1
    SEND = 2
    TOPIC = 3
    REDACT = 4
    ROOM_MSG = 5
    JOIN = 6
    PART = 7
    INVITE = 8


class MatrixClient:
    def __init__(
            self,
            host,             # type: str
            access_token="",  # type: str
            user_agent=""     # type: str
    ):
        self.host = host
        self.user_agent = user_agent
        self.access_token = access_token
        self.txn_id = 0     # type: int

    def _get_txn_id(self):
        txn_id = self.txn_id
        self.txn_id = self.txn_id + 1
        return txn_id

    def login(self, user, password, device_name=""):
        # type (str, str, str) -> HttpRequest
        path = ("{api}/login").format(api=MATRIX_API_PATH)

        post_data = {
            "type": "m.login.password",
            "user": user,
            "password": password
        }

        if device_name:
            post_data["initial_device_display_name"] = device_name

        return HttpRequest(RequestType.POST, self.host, path, post_data)

    def sync(self, next_batch="", sync_filter=None):
        # type: (str, Dict[Any, Any]) -> HttpRequest
        assert self.access_token

        query_parameters = {"access_token": self.access_token}

        if sync_filter:
            query_parameters["filter"] = json.dumps(
                sync_filter,
                separators=(",", ":")
            )

        if next_batch:
            query_parameters["since"] = next_batch

        path = ("{api}/sync?{query_params}").format(
            api=MATRIX_API_PATH,
            query_params=urlencode(query_parameters)
        )

        return HttpRequest(RequestType.GET, self.host, path)

    def room_send_message(self, room_id, content, formatted_content=None):
        # type: (str, Dict[str, str]) -> HttpRequest
        query_parameters = {"access_token": self.access_token}

        body = {
            "msgtype": "m.text",
            "body": content
        }

        if formatted_content:
            body["format"] = "org.matrix.custom.html"
            body["formatted_body"] = formatted_content

        path = ("{api}/rooms/{room}/send/m.room.message/"
                "{tx_id}?{query_parameters}").format(
                    api=MATRIX_API_PATH,
                    room=quote(room_id),
                    tx_id=quote(str(self._get_txn_id())),
                    query_parameters=urlencode(query_parameters))

        return HttpRequest(RequestType.PUT, self.host, path, body)

    def room_topic(self, room_id, topic):
        # type: (str, str) -> HttpRequest
        query_parameters = {"access_token": self.access_token}

        content = {"topic": topic}

        path = ("{api}/rooms/{room}/state/m.room.topic?"
                "{query_parameters}").format(
                    api=MATRIX_API_PATH,
                    room=quote(room_id),
                    query_parameters=urlencode(query_parameters))

        return HttpRequest(RequestType.PUT, self.host, path, content)

    def room_redact(self, room_id, event_id, reason):
        # type: (str, str, str) -> HttpRequest
        query_parameters = {"access_token": self.access_token}
        content = {}

        if reason:
            content["reason"] = reason

        path = ("{api}/rooms/{room}/redact/{event_id}/{tx_id}?"
                "{query_parameters}").format(
                    api=MATRIX_API_PATH,
                    room=quote(room_id),
                    event_id=quote(event_id),
                    tx_id=quote(str(self._get_txn_id())),
                    query_parameters=urlencode(query_parameters))

        return HttpRequest(RequestType.PUT, self.host, path, content)

    def room_get_messages(
            self,
            room_id,
            start_token,
            end_token="",
            limit=10,
            direction='b'
    ):
        query_parameters = {
            "access_token": self.access_token,
            "from": start_token,
            "dir": direction,
            "limit": str(limit)
        }

        if end_token:
            query_parameters["to"] = end_token

        path = ("{api}/rooms/{room}/messages?{query_parameters}").format(
            api=MATRIX_API_PATH,
            room=quote(room_id),
            query_parameters=urlencode(query_parameters))

        return HttpRequest(RequestType.GET, self.host, path)

    def room_join(self, room_id):
        query_parameters = {"access_token": self.access_token}

        path = ("{api}/rooms/{room_id}/join?"
                "{query_parameters}").format(
                    api=MATRIX_API_PATH,
                    room_id=quote(room_id),
                    query_parameters=urlencode(query_parameters))

        return HttpRequest(RequestType.POST, self.host, path)

    def room_leave(self, room_id):
        query_parameters = {"access_token": self.access_token}

        path = ("{api}/rooms/{room_id}/leave?"
                "{query_parameters}").format(
                    api=MATRIX_API_PATH,
                    room_id=quote(room_id),
                    query_parameters=urlencode(query_parameters))

        return HttpRequest(RequestType.POST, self.host, path)

    def room_invite(self, room_id, user_id):
        query_parameters = {"access_token": self.access_token}

        content = {"user_id": user_id}

        path = ("{api}/rooms/{room_id}/invite?"
                "{query_parameters}").format(
                    api=MATRIX_API_PATH,
                    room_id=quote(room_id),
                    query_parameters=urlencode(query_parameters))

        return HttpRequest(RequestType.POST, self.host, path, content)


class MatrixMessage:
    def __init__(
            self,
            server,           # type: MatrixServer
            options,          # type: PluginOptions
            message_type,     # type: MessageType
            room_id=None,     # type: str
            **kwargs
    ):
        # type: (...) -> None
        # pylint: disable=dangerous-default-value
        self.type = message_type          # type: MessageType

        for key, value in kwargs.items():
            setattr(self, key, value)

        self.request = None               # type: HttpRequest
        self.response = None              # type: HttpResponse
        self.decoded_response = None      # type: Dict[Any, Any]

        self.creation_time = time.time()  # type: float
        self.send_time = None             # type: float
        self.receive_time = None          # type: float

        if message_type == MessageType.LOGIN:
            self.request = server.client.login(
                server.user,
                server.password,
                server.device_name
            )

        elif message_type == MessageType.SYNC:
            sync_filter = {
                "room": {
                    "timeline": {"limit": options.sync_limit}
                }
            }

            self.request = server.client.sync(server.next_batch, sync_filter)

        elif message_type == MessageType.SEND:
            assert self.formatted_message

            data = {"content": formatted_to_plain(self.formatted_message)}

            if is_formatted(self.formatted_message):
                data["formatted_content"] = formatted_to_html(
                    self.formatted_message)

            self.room_id = room_id
            self.request = server.client.room_send_message(room_id, **data)

        elif message_type == MessageType.TOPIC:
            assert self.topic
            self.request = server.client.room_topic(room_id, self.topic)

        elif message_type == MessageType.REDACT:
            assert self.event_id

            self.request = server.client.room_redact(
                room_id,
                self.event_id,
                self.reason
            )

        elif message_type == MessageType.ROOM_MSG:
            assert self.token

            self.request = server.client.room_get_messages(
                room_id,
                start_token=self.token,
                limit=options.backlog_limit,
            )

        elif message_type == MessageType.JOIN:
            self.request = server.client.room_join(room_id)

        elif message_type == MessageType.PART:
            self.request = server.client.room_leave(room_id)

        elif message_type == MessageType.INVITE:
            assert self.user_id
            self.request = server.client.room_invite(room_id, self.user_id)


class MatrixUser:
    def __init__(self, name, display_name):
        self.name = name                  # type: str
        self.display_name = display_name  # type: str
        self.power_level = 0              # type: int
        self.nick_color = ""              # type: str
        self.prefix = ""                  # type: str


class MatrixRoom:
    def __init__(self, room_id):
        # type: (str) -> None
        self.room_id = room_id  # type: str
        self.alias = room_id    # type: str
        self.topic = ""         # type: str
        self.topic_author = ""  # type: str
        self.topic_date = None  # type: datetime.datetime
        self.prev_batch = ""    # type: str
        self.users = dict()     # type: Dict[str, MatrixUser]
        self.encrypted = False  # type: bool


def get_transaction_id(server):
    # type: (MatrixServer) -> int
    transaction_id = server.transaction_id
    server.transaction_id += 1
    return transaction_id


def matrix_sync(server):
    message = MatrixMessage(server, OPTIONS, MessageType.SYNC)
    server.send_queue.append(message)


def matrix_login(server):
    # type: (MatrixServer) -> None
    message = MatrixMessage(
        server,
        OPTIONS,
        MessageType.LOGIN
    )
    server.send_or_queue(message)
