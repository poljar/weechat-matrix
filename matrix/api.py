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

        if message_type == MessageType.LOGIN:
            path = ("{api}/login").format(api=MATRIX_API_PATH)
            self.request = HttpRequest(
                RequestType.POST,
                server.address,
                server.port,
                path,
                data
            )

        elif message_type == MessageType.SYNC:
            sync_filter = {
                "room": {
                    "timeline": {"limit": options.sync_limit}
                }
            }

            path = ("{api}/sync?access_token={access_token}&"
                    "filter={sync_filter}").format(
                        api=MATRIX_API_PATH,
                        access_token=server.access_token,
                        sync_filter=json.dumps(sync_filter,
                                               separators=(',', ':')))

            if server.next_batch:
                path = path + '&since={next_batch}'.format(
                    next_batch=server.next_batch)

            self.request = HttpRequest(
                RequestType.GET,
                server.address,
                server.port,
                path
            )

        elif message_type == MessageType.SEND:
            path = ("{api}/rooms/{room}/send/m.room.message/{tx_id}?"
                    "access_token={access_token}").format(
                        api=MATRIX_API_PATH,
                        room=room_id,
                        tx_id=get_transaction_id(server),
                        access_token=server.access_token)

            self.request = HttpRequest(
                RequestType.PUT,
                server.address,
                server.port,
                path,
                data
            )

        elif message_type == MessageType.STATE:
            path = ("{api}/rooms/{room}/state/{event_type}?"
                    "access_token={access_token}").format(
                        api=MATRIX_API_PATH,
                        room=room_id,
                        event_type=extra_id,
                        access_token=server.access_token)

            self.request = HttpRequest(
                RequestType.PUT,
                server.address,
                server.port,
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
                server.address,
                server.port,
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
                server.address,
                server.port,
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
                server.address,
                server.port,
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
                server.address,
                server.port,
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
                server.address,
                server.port,
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
    post_data = {"type": "m.login.password",
                 "user": server.user,
                 "password": server.password,
                 "initial_device_display_name": server.device_name}

    message = MatrixMessage(
        server,
        OPTIONS,
        MessageType.LOGIN,
        data=post_data
    )
    server.send_or_queue(message)
