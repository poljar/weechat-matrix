# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import time
import json
from enum import Enum, unique

from matrix.http import RequestType, HttpRequest


MATRIX_API_PATH = "/_matrix/client/r0"  # type: str


@unique
class MessageType(Enum):
    LOGIN    = 0
    SYNC     = 1
    SEND     = 2
    STATE    = 3
    REDACT   = 4
    ROOM_MSG = 5
    JOIN     = 6
    PART     = 7
    INVITE   = 8


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
        self.type       = message_type  # type: MessageType
        self.request    = None          # type: HttpRequest
        self.response   = None          # type: HttpResponse
        self.extra_data = extra_data    # type: Dict[str, Any]

        self.creation_time = time.time()  # type: float
        self.send_time     = None         # type: float
        self.receive_time  = None         # type: float

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


def get_transaction_id(server):
    # type: (MatrixServer) -> int
    transaction_id = server.transaction_id
    server.transaction_id += 1
    return transaction_id
