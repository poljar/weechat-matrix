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
from functools import partial

try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError

try:
    from urllib import quote, urlencode
    from urlparse import urlparse
except ImportError:
    from urllib.parse import quote, urlencode, urlparse

from matrix.http import RequestType, HttpRequest
import matrix.events as MatrixEvents

MATRIX_API_PATH = "/_matrix/client/r0"  # type: str


class MatrixClient:

    def __init__(
            self,
            host,  # type: str
            access_token="",  # type: str
            user_agent=""  # type: str
    ):
        # type: (...) -> None
        self.host = host
        self.user_agent = user_agent
        self.access_token = access_token
        self.txn_id = 0  # type: int

    def _get_txn_id(self):
        txn_id = self.txn_id
        self.txn_id = self.txn_id + 1
        return txn_id

    def login(self, user, password, device_name="", device_id=""):
        # type (str, str, str) -> HttpRequest
        path = ("{api}/login").format(api=MATRIX_API_PATH)

        post_data = {
            "type": "m.login.password",
            "user": user,
            "password": password
        }

        if device_id:
            post_data["device_id"] = device_id

        if device_name:
            post_data["initial_device_display_name"] = device_name

        return HttpRequest(RequestType.POST, self.host, path, post_data)

    def sync(self, next_batch="", sync_filter=None):
        # type: (str, Dict[Any, Any]) -> HttpRequest
        assert self.access_token

        query_parameters = {"access_token": self.access_token}

        if sync_filter:
            query_parameters["filter"] = json.dumps(
                sync_filter, separators=(",", ":"))

        if next_batch:
            query_parameters["since"] = next_batch

        path = ("{api}/sync?{query_params}").format(
            api=MATRIX_API_PATH, query_params=urlencode(query_parameters))

        return HttpRequest(RequestType.GET, self.host, path)

    def room_send_message(self,
                          room_id,
                          message_type,
                          content,
                          formatted_content=None):
        # type: (str, str, str) -> HttpRequest
        query_parameters = {"access_token": self.access_token}

        body = {"msgtype": message_type, "body": content}

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

    def room_redact(self, room_id, event_id, reason=None):
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

    def room_get_messages(self,
                          room_id,
                          start_token,
                          end_token="",
                          limit=10,
                          direction='b'):
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

        path = ("{api}/join/{room_id}?"
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

    def room_kick(self, room_id, user_id, reason=None):
        query_parameters = {"access_token": self.access_token}

        content = {"user_id": user_id}

        if reason:
            content["reason"] = reason

        path = ("{api}/rooms/{room_id}/kick?"
                "{query_parameters}").format(
                    api=MATRIX_API_PATH,
                    room_id=quote(room_id),
                    query_parameters=urlencode(query_parameters))

        h = HttpRequest(RequestType.POST, self.host, path, content)
        return h

    def keys_upload(self, user_id, device_id, account, keys=None,
                    one_time_keys=None):
        query_parameters = {"access_token": self.access_token}

        path = ("{api}/keys/upload?"
                "{query_parameters}").format(
                    api=MATRIX_API_PATH,
                    query_parameters=urlencode(query_parameters))

        content = {}

        # TODO one time keys
        if keys:
            device_keys = {
                "algorithms": [
                    "m.olm.v1.curve25519-aes-sha2",
                    "m.megolm.v1.aes-sha2"
                ],
                "device_id": device_id,
                "user_id": user_id,
                "keys": {
                    "curve25519:" + device_id: keys["curve25519"],
                    "ed25519:" + device_id: keys["ed25519"]
                }
            }

            signature = account.sign(json.dumps(
                device_keys,
                ensure_ascii=False,
                separators=(',', ':'),
                sort_keys=True,
            ))

            device_keys["signatures"] = {
                user_id: {
                    "ed25519:" + device_id: signature
                }
            }

            content["device_keys"] = device_keys

        return HttpRequest(RequestType.POST, self.host, path, content)

    def mxc_to_http(self, mxc):
        # type: (str) -> str
        url = urlparse(mxc)

        if url.scheme != "mxc":
            return None

        if not url.netloc or not url.path:
            return None

        http_url = ("https://{host}/_matrix/media/r0/download/"
                    "{server_name}{mediaId}").format(
                        host=self.host,
                        server_name=url.netloc,
                        mediaId=url.path)

        return http_url


class MatrixMessage():

    def __init__(
            self,
            request_func,  # type: Callable[[...], HttpRequest]
            func_args,
    ):
        # type: (...) -> None
        # yapf: disable

        self.request = None               # type: HttpRequest
        self.response = None              # type: HttpResponse
        self.decoded_response = None      # type: Dict[Any, Any]

        self.creation_time = time.time()  # type: float
        self.send_time = None             # type: float
        self.receive_time = None          # type: float
        self.event = None

        self.request = request_func(**func_args)
        # yapf: enable

    def decode_body(self, server):
        try:
            self.decoded_response = json.loads(
                self.response.body, encoding='utf-8')
            return (True, None)
        except Exception as error:
            return (False, error)

    def _decode(self, server, object_hook):
        try:
            parsed_dict = json.loads(
                self.response.body,
                encoding='utf-8',
            )

            self.event = object_hook(parsed_dict)

            return (True, None)

        except JSONDecodeError as error:
            return (False, error)


class MatrixLoginMessage(MatrixMessage):

    def __init__(self, client, user, password, device_name, device_id=None):
        data = {"user": user, "password": password, "device_name": device_name}

        if device_id:
            data["device_id"] = device_id

        MatrixMessage.__init__(self, client.login, data)

    def decode_body(self, server):
        object_hook = partial(MatrixEvents.MatrixLoginEvent.from_dict, server)

        return self._decode(server, object_hook)


class MatrixSyncMessage(MatrixMessage):

    def __init__(self, client, next_batch=None, limit=None):
        data = {}

        if next_batch:
            data["next_batch"] = next_batch

        if limit:
            data["sync_filter"] = {"room": {"timeline": {"limit": limit}}}

        MatrixMessage.__init__(self, client.sync, data)

    def decode_body(self, server):
        object_hook = partial(MatrixEvents.MatrixSyncEvent.from_dict, server)

        return self._decode(server, object_hook)


class MatrixSendMessage(MatrixMessage):

    def __init__(self,
                 client,
                 room_id,
                 formatted_message,
                 message_type="m.text"):
        self.room_id = room_id
        self.formatted_message = formatted_message

        data = {
            "room_id": self.room_id,
            "message_type": message_type,
            "content": self.formatted_message.to_plain()
        }

        if self.formatted_message.is_formatted():
            data["formatted_content"] = self.formatted_message.to_html()

        MatrixMessage.__init__(self, client.room_send_message, data)

    def decode_body(self, server):
        object_hook = partial(
            MatrixEvents.MatrixSendEvent.from_dict,
            server,
            self.room_id,
            self.formatted_message,
        )

        return self._decode(server, object_hook)


class MatrixEmoteMessage(MatrixSendMessage):

    def __init__(self, client, room_id, formatted_message):
        MatrixSendMessage.__init__(self, client, room_id, formatted_message,
                                   "m.emote")

    def decode_body(self, server):
        object_hook = partial(
            MatrixEvents.MatrixEmoteEvent.from_dict,
            server,
            self.room_id,
            self.formatted_message,
        )

        return self._decode(server, object_hook)


class MatrixTopicMessage(MatrixMessage):

    def __init__(self, client, room_id, topic):
        self.room_id = room_id
        self.topic = topic

        data = {"room_id": self.room_id, "topic": self.topic}

        MatrixMessage.__init__(self, client.room_topic, data)

    def decode_body(self, server):
        object_hook = partial(
            MatrixEvents.MatrixTopicEvent.from_dict,
            server,
            self.room_id,
            self.topic,
        )

        return self._decode(server, object_hook)


class MatrixRedactMessage(MatrixMessage):

    def __init__(self, client, room_id, event_id, reason=None):
        self.room_id = room_id
        self.event_id = event_id
        self.reason = reason

        data = {"room_id": self.room_id, "event_id": self.event_id}

        if reason:
            data["reason"] = reason

        MatrixMessage.__init__(self, client.room_redact, data)

    def decode_body(self, server):
        object_hook = partial(
            MatrixEvents.MatrixRedactEvent.from_dict,
            server,
            self.room_id,
            self.reason,
        )

        return self._decode(server, object_hook)


class MatrixBacklogMessage(MatrixMessage):

    def __init__(self, client, room_id, token, limit):
        self.room_id = room_id

        data = {
            "room_id": self.room_id,
            "start_token": token,
            "direction": "b",
            "limit": limit
        }

        MatrixMessage.__init__(self, client.room_get_messages, data)

    def decode_body(self, server):
        object_hook = partial(MatrixEvents.MatrixBacklogEvent.from_dict, server,
                              self.room_id)

        return self._decode(server, object_hook)


class MatrixJoinMessage(MatrixMessage):

    def __init__(self, client, room_id):
        self.room_id = room_id

        data = {"room_id": self.room_id}

        MatrixMessage.__init__(self, client.room_join, data)

    def decode_body(self, server):
        object_hook = partial(MatrixEvents.MatrixJoinEvent.from_dict, server,
                              self.room_id)

        return self._decode(server, object_hook)


class MatrixPartMessage(MatrixMessage):

    def __init__(self, client, room_id):
        self.room_id = room_id

        data = {"room_id": self.room_id}

        MatrixMessage.__init__(self, client.room_leave, data)

    def decode_body(self, server):
        object_hook = partial(MatrixEvents.MatrixPartEvent.from_dict, server,
                              self.room_id)

        return self._decode(server, object_hook)


class MatrixInviteMessage(MatrixMessage):

    def __init__(self, client, room_id, user_id):
        self.room_id = room_id
        self.user_id = user_id

        data = {"room_id": self.room_id, "user_id": self.user_id}

        MatrixMessage.__init__(self, client.room_invite, data)

    def decode_body(self, server):
        object_hook = partial(MatrixEvents.MatrixInviteEvent.from_dict, server,
                              self.room_id, self.user_id)

        return self._decode(server, object_hook)


class MatrixKickMessage(MatrixMessage):

    def __init__(self, client, room_id, user_id, reason=None):
        self.room_id = room_id
        self.user_id = user_id
        self.reason = reason

        data = {"room_id": self.room_id,
                "user_id": self.user_id,
                "reason": reason}

        MatrixMessage.__init__(self, client.room_kick, data)

    def decode_body(self, server):
        object_hook = partial(
            MatrixEvents.MatrixKickEvent.from_dict,
            server,
            self.room_id,
            self.user_id,
            self.reason)

        return self._decode(server, object_hook)


class MatrixKeyUploadMessage(MatrixMessage):

    def __init__(self, client, user_id, device_id, account, keys=None,
                 one_time_keys=None):
        data = {
            "device_id": device_id,
            "user_id": user_id,
            "account": account,
            "keys": keys,
            "one_time_keys": one_time_keys
        }

        MatrixMessage.__init__(self, client.keys_upload, data)

    def decode_body(self, server):
        object_hook = partial(MatrixEvents.MatrixKeyUploadEvent.from_dict,
                              server)

        return self._decode(server, object_hook)
