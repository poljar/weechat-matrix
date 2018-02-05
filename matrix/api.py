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

MATRIX_API_PATH = "/_matrix/client/r0"  # type: str


@unique
class MessageType(Enum):
    LOGIN = 0
    SYNC = 1
    SEND = 2
    STATE = 3
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

    def room_message(self, room_id, content):
        # type: (str, Dict[str, str]) -> HttpRequest
        query_parameters = {"access_token": self.access_token}

        path = ("{api}/rooms/{room}/send/m.room.message/"
                "{tx_id}?{query_parameters}").format(
            api=MATRIX_API_PATH,
            room=quote(room_id),
            tx_id=quote(str(self._get_txn_id())),
            query_parameters=urlencode(query_parameters))

        return HttpRequest(RequestType.PUT, self.host, path, content)


class MatrixMessage:
    def __init__(
            self,
            server,           # type: MatrixServer
            options,          # type: PluginOptions
            message_type,     # type: MessageType
            room_id=None,     # type: str
            extra_id=None,    # type: str
            data={},          # type: Dict[str, Any]
            extra_data=None   # type: Dict[str, Any]
    ):
        # type: (...) -> None
        # pylint: disable=dangerous-default-value
        self.type = message_type          # type: MessageType
        self.request = None               # type: HttpRequest
        self.response = None              # type: HttpResponse
        self.extra_data = extra_data      # type: Dict[str, Any]

        self.creation_time = time.time()  # type: float
        self.send_time = None             # type: float
        self.receive_time = None          # type: float

        host = ':'.join([server.address, str(server.port)])

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
            self.request = server.client.room_message(room_id, data)

        elif message_type == MessageType.STATE:
            path = ("{api}/rooms/{room}/state/{event_type}?"
                    "access_token={access_token}").format(
                        api=MATRIX_API_PATH,
                        room=room_id,
                        event_type=extra_id,
                        access_token=server.access_token)

            self.request = HttpRequest(
                RequestType.PUT,
                host,
                path,
                data
            )

        elif message_type == MessageType.REDACT:
            path = ("{api}/rooms/{room}/redact/{event_id}/{tx_id}?"
                    "access_token={access_token}").format(
                        api=MATRIX_API_PATH,
                        room=room_id,
                        event_id=extra_id,
                        tx_id=get_transaction_id(server),
                        access_token=server.access_token)

            self.request = HttpRequest(
                RequestType.PUT,
                host,
                path,
                data
            )

        elif message_type == MessageType.ROOM_MSG:
            path = ("{api}/rooms/{room}/messages?from={prev_batch}&"
                    "dir=b&limit={message_limit}&"
                    "access_token={access_token}").format(
                        api=MATRIX_API_PATH,
                        room=room_id,
                        prev_batch=extra_id,
                        message_limit=options.backlog_limit,
                        access_token=server.access_token)
            self.request = HttpRequest(
                RequestType.GET,
                host,
                path,
            )

        elif message_type == MessageType.JOIN:
            path = ("{api}/rooms/{room_id}/join?"
                    "access_token={access_token}").format(
                        api=MATRIX_API_PATH,
                        room_id=room_id,
                        access_token=server.access_token)

            self.request = HttpRequest(
                RequestType.POST,
                host,
                path,
                data
            )

        elif message_type == MessageType.PART:
            path = ("{api}/rooms/{room_id}/leave?"
                    "access_token={access_token}").format(
                        api=MATRIX_API_PATH,
                        room_id=room_id,
                        access_token=server.access_token)

            self.request = HttpRequest(
                RequestType.POST,
                host,
                path,
                data
            )

        elif message_type == MessageType.INVITE:
            path = ("{api}/rooms/{room}/invite?"
                    "access_token={access_token}").format(
                        api=MATRIX_API_PATH,
                        room=room_id,
                        access_token=server.access_token)

            self.request = HttpRequest(
                RequestType.POST,
                host,
                path,
                data
            )


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
