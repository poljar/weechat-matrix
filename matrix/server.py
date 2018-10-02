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

import os
import pprint
import socket
import ssl
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, Optional, List, NamedTuple, DefaultDict

from nio import (
    HttpClient,
    LocalProtocolError,
    LoginResponse,
    Response,
    Rooms,
    RoomSendResponse,
    SyncResponse,
    ShareGroupSessionResponse,
    KeysClaimResponse,
    TransportResponse,
    TransportType,
    RoomMessagesResponse,
    RequestType,
    EncryptionError,
    GroupEncryptionError,
    OlmTrustError,
)

from . import globals as G
from .buffer import OwnAction, OwnMessage, RoomBuffer
from .config import ConfigSection, Option, ServerBufferType
from .globals import SCRIPT_NAME, SERVERS, W
from .utf import utf8_decode
from .utils import create_server_buffer, key_from_value, server_buffer_prnt

from .colors import Formatted


try:
    FileNotFoundError  # type: ignore
except NameError:
    FileNotFoundError = IOError


EncrytpionQueueItem = NamedTuple(
    "EncrytpionQueueItem",
    [
        ("message_type", str),
        ("formatted_message", Formatted),
    ],
)


class ServerConfig(ConfigSection):
    def __init__(self, server_name, config_ptr):
        # type: (str, str) -> None
        self._server_name = server_name
        self._config_ptr = config_ptr
        self._option_ptrs = {}  # type: Dict[str, str]

        options = [
            Option(
                "autoconnect",
                "boolean",
                "",
                0,
                0,
                "off",
                (
                    "automatically connect to the matrix server when weechat "
                    "is starting"
                ),
            ),
            Option(
                "address",
                "string",
                "",
                0,
                0,
                "",
                "Hostname or IP address for the server",
            ),
            Option(
                "port", "integer", "", 0, 65535, "443", "Port for the server"
            ),
            Option(
                "proxy",
                "string",
                "",
                0,
                0,
                "",
                ("Name of weechat proxy to use (see /help proxy)"),
            ),
            Option(
                "ssl_verify",
                "boolean",
                "",
                0,
                0,
                "on",
                ("Check that the SSL connection is fully trusted"),
            ),
            Option(
                "username", "string", "", 0, 0, "", "Username to use on server"
            ),
            Option(
                "password",
                "string",
                "",
                0,
                0,
                "",
                (
                    "Password for server (note: content is evaluated, see "
                    "/help eval)"
                ),
            ),
            Option(
                "device_name",
                "string",
                "",
                0,
                0,
                "Weechat Matrix",
                "Device name to use while logging in to the matrix server",
            ),
        ]

        section = W.config_search_section(config_ptr, "server")
        self._ptr = section

        for option in options:
            option_name = "{server}.{option}".format(
                server=self._server_name, option=option.name
            )

            self._option_ptrs[option.name] = W.config_new_option(
                config_ptr,
                section,
                option_name,
                option.type,
                option.description,
                option.string_values,
                option.min,
                option.max,
                option.value,
                option.value,
                0,
                "",
                "",
                "matrix_config_server_change_cb",
                self._server_name,
                "",
                "",
            )

    autoconnect = ConfigSection.option_property("autoconnect", "boolean")
    address = ConfigSection.option_property("address", "string")
    port = ConfigSection.option_property("port", "integer")
    proxy = ConfigSection.option_property("proxy", "string")
    ssl_verify = ConfigSection.option_property("ssl_verify", "boolean")
    username = ConfigSection.option_property("username", "string")
    device_name = ConfigSection.option_property("device_name", "string")
    password = ConfigSection.option_property(
        "password", "string", evaluate=True
    )

    def free(self):
        W.config_section_free_options(self._ptr)


class MatrixServer(object):
    # pylint: disable=too-many-instance-attributes
    def __init__(self, name, config_ptr):
        # type: (str, str) -> None
        # yapf: disable
        self.name = name                     # type: str
        self.user_id = ""
        self.device_id = ""                  # type: str

        self.room_buffers = dict()  # type: Dict[str, RoomBuffer]
        self.buffers = dict()                # type: Dict[str, str]
        self.server_buffer = None            # type: Optional[str]
        self.fd_hook = None                  # type: Optional[str]
        self.ssl_hook = None                 # type: Optional[str]
        self.timer_hook = None               # type: Optional[str]
        self.numeric_address = ""            # type: Optional[str]

        self.connected = False      # type: bool
        self.connecting = False     # type: bool
        self.keys_queried = False   # type: bool
        self.reconnect_delay = 0    # type: int
        self.reconnect_time = None  # type: Optional[float]
        self.sync_time = None       # type: Optional[float]
        self.socket = None          # type: Optional[ssl.SSLSocket]
        self.ssl_context = ssl.create_default_context()  # type: ssl.SSLContext
        self.transport_type = None  # type: Optional[TransportType]

        # Enable http2 negotiation on the ssl context.
        self.ssl_context.set_alpn_protocols(["h2", "http/1.1"])

        try:
            self.ssl_context.set_npn_protocols(["h2", "http/1.1"])
        except NotImplementedError:
            pass

        self.client = None
        self.access_token = None                         # type: Optional[str]
        self.next_batch = None                           # type: Optional[str]
        self.transaction_id = 0                          # type: int
        self.lag = 0                                     # type: int
        self.lag_done = False                            # type: bool

        self.send_fd_hook = None                         # type: Optional[str]
        self.send_buffer = b""                           # type: bytes
        self.device_check_timestamp = None               # type: Optional[int]

        self.own_message_queue = dict()  # type: Dict[str, OwnMessage]
        self.encryption_queue = defaultdict(deque)  \
            # type: DefaultDict[str, Deque[EncrytpionQueueItem]]
        self.backlog_queue = dict()      # type: Dict[str, str]

        self.unhandled_users = dict()    # type: Dict[str, List[str]]
        self.lazy_load_hook = None       # type: Optional[str]

        self.keys_claimed = defaultdict(bool)
        self.group_session_shared = defaultdict(bool)

        self.config = ServerConfig(self.name, config_ptr)
        self._create_session_dir()
        # yapf: enable

    def _create_session_dir(self):
        path = os.path.join("matrix", self.name)
        if not W.mkdir_home(path, 0o700):
            message = (
                "{prefix}matrix: Error creating server session " "directory"
            ).format(prefix=W.prefix("error"))
            W.prnt("", message)

    def get_session_path(self):
        home_dir = W.info_get("weechat_dir", "")
        return os.path.join(home_dir, "matrix", self.name)

    def _load_device_id(self):
        file_name = "{}{}".format(self.config.username, ".device_id")
        path = os.path.join(self.get_session_path(), file_name)

        if not os.path.isfile(path):
            return

        with open(path, "r") as device_file:
            device_id = device_file.readline().rstrip()
            if device_id:
                self.device_id = device_id

    def save_device_id(self):
        file_name = "{}{}".format(self.config.username, ".device_id")
        path = os.path.join(self.get_session_path(), file_name)

        with open(path, "w") as device_file:
            device_file.write(self.device_id)

    def _change_client(self):
        host = ":".join([self.config.address, str(self.config.port)])
        self.client = HttpClient(
            host,
            self.config.username,
            self.device_id,
            self.get_session_path()
        )

    def update_option(self, option, option_name):
        if option_name == "address":
            self._change_client()
        elif option_name == "port":
            self._change_client()
        elif option_name == "ssl_verify":
            value = W.config_boolean(option)
            if value:
                self.ssl_context.verify_mode = ssl.CERT_REQUIRED
                self.ssl_context.check_hostname = True
            else:
                self.ssl_context.check_hostname = False
                self.ssl_context.verify_mode = ssl.CERT_NONE
        elif option_name == "username":
            value = W.config_string(option)
            self.access_token = ""

            self._load_device_id()

            if self.client:
                self.client.user = value
                if self.device_id:
                    self.client.device_id = self.device_id
        else:
            pass

    def send_or_queue(self, request):
        # type: (bytes) -> None
        self.send(request)

    def try_send(self, message):
        # type: (MatrixServer, bytes) -> bool

        sock = self.socket

        if not sock:
            return False

        total_sent = 0
        message_length = len(message)

        while total_sent < message_length:
            try:
                sent = sock.send(message[total_sent:])

            except ssl.SSLWantWriteError:
                hook = W.hook_fd(sock.fileno(), 0, 1, 0, "send_cb", self.name)
                self.send_fd_hook = hook
                self.send_buffer = message[total_sent:]
                return True

            except socket.error as error:
                self._abort_send()

                errno = "error" + str(error.errno) + " " if error.errno else ""
                strerr = error.strerror if error.strerror else "Unknown reason"
                strerr = errno + strerr

                error_message = (
                    "{prefix}Error while writing to " "socket: {error}"
                ).format(prefix=W.prefix("network"), error=strerr)

                server_buffer_prnt(self, error_message)
                server_buffer_prnt(
                    self,
                    ("{prefix}matrix: disconnecting from server...").format(
                        prefix=W.prefix("network")
                    ),
                )

                self.disconnect()
                return False

            if sent == 0:
                self._abort_send()

                server_buffer_prnt(
                    self,
                    "{prefix}matrix: Error while writing to socket".format(
                        prefix=W.prefix("network")
                    ),
                )
                server_buffer_prnt(
                    self,
                    ("{prefix}matrix: disconnecting from server...").format(
                        prefix=W.prefix("network")
                    ),
                )
                self.disconnect()
                return False

            total_sent = total_sent + sent

        self._finalize_send()
        return True

    def _abort_send(self):
        self.send_buffer = b""

    def _finalize_send(self):
        # type: (MatrixServer) -> None
        self.send_buffer = b""

    def info(self, message):
        buf = ""
        if self.server_buffer:
            buf = self.server_buffer

        msg = "{}{}: {}".format(W.prefix("network"), SCRIPT_NAME, message)
        W.prnt(buf, msg)

    def error(self, message):
        buf = ""
        if self.server_buffer:
            buf = self.server_buffer

        msg = "{}{}: {}".format(W.prefix("error"), SCRIPT_NAME, message)
        W.prnt(buf, msg)

    def send(self, data):
        # type: (bytes) -> bool
        self.try_send(data)

        return True

    def reconnect(self):
        message = ("{prefix}matrix: reconnecting to server...").format(
            prefix=W.prefix("network")
        )

        server_buffer_prnt(self, message)

        self.reconnect_time = None

        if not self.connect():
            self.schedule_reconnect()

    def schedule_reconnect(self):
        # type: (MatrixServer) -> None
        self.connecting = True
        self.reconnect_time = time.time()

        if self.reconnect_delay:
            self.reconnect_delay = self.reconnect_delay * 2
        else:
            self.reconnect_delay = 10

        message = (
            "{prefix}matrix: reconnecting to server in {t} " "seconds"
        ).format(prefix=W.prefix("network"), t=self.reconnect_delay)

        server_buffer_prnt(self, message)

    def _close_socket(self):
        # type: () -> None
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
            except socket.error:
                pass

    def disconnect(self, reconnect=True):
        # type: (bool) -> None
        if self.fd_hook:
            W.unhook(self.fd_hook)

        self._close_socket()

        self.fd_hook = None
        self.socket = None
        self.connected = False
        self.access_token = ""

        self.send_buffer = b""
        self.transport_type = None

        if self.client:
            try:
                self.client.disconnect()
            except LocalProtocolError:
                pass

        self.lag = 0
        W.bar_item_update("lag")
        self.reconnect_time = None

        if self.server_buffer:
            message = ("{prefix}matrix: disconnected from server").format(
                prefix=W.prefix("network")
            )
            server_buffer_prnt(self, message)

        if reconnect:
            self.schedule_reconnect()
        else:
            self.reconnect_delay = 0

    def connect(self):
        # type: (MatrixServer) -> int
        if not self.config.address or not self.config.port:
            W.prnt("", self.config.address)
            message = "{prefix}Server address or port not set".format(
                prefix=W.prefix("error")
            )
            W.prnt("", message)
            return False

        if not self.config.username or not self.config.password:
            message = "{prefix}User or password not set".format(
                prefix=W.prefix("error")
            )
            W.prnt("", message)
            return False

        if self.connected:
            return True

        if not self.server_buffer:
            create_server_buffer(self)

        if not self.timer_hook:
            self.timer_hook = W.hook_timer(
                1 * 1000, 0, 0, "matrix_timer_cb", self.name
            )

        ssl_message = " (SSL)" if self.ssl_context.check_hostname else ""

        message = (
            "{prefix}matrix: Connecting to " "{server}:{port}{ssl}..."
        ).format(
            prefix=W.prefix("network"),
            server=self.config.address,
            port=self.config.port,
            ssl=ssl_message,
        )

        W.prnt(self.server_buffer, message)

        W.hook_connect(
            self.config.proxy,
            self.config.address,
            self.config.port,
            1,
            0,
            "",
            "connect_cb",
            self.name,
        )

        return True

    def schedule_sync(self):
        self.sync_time = time.time()

    def sync(self, timeout=None, sync_filter=None):
        # type: (Optional[int], Optional[Dict[Any, Any]]) -> None
        if not self.client:
            return

        self.sync_time = None
        _, request = self.client.sync(timeout, sync_filter)
        self.send_or_queue(request)

    def login(self):
        # type: () -> None
        if not self.client:
            return

        if self.client.logged_in:
            msg = (
                "{prefix}{script_name}: Already logged in, " "syncing..."
            ).format(prefix=W.prefix("network"), script_name=SCRIPT_NAME)
            W.prnt(self.server_buffer, msg)
            timeout = 0 if self.transport_type == TransportType.HTTP else 30000
            sync_filter = {"room": {"timeline": {"limit": 5000}}}
            self.sync(timeout, sync_filter)
            return

        _, request = self.client.login(
            self.config.password, self.config.device_name
        )
        self.send_or_queue(request)

        msg = "{prefix}matrix: Logging in...".format(
            prefix=W.prefix("network")
        )

        W.prnt(self.server_buffer, msg)

    def room_send_state(self, room_buffer, body, event_type):
        if room_buffer.room.encrypted:
            return

        _, request = self.client.room_put_state(
            room_buffer.room.room_id, event_type, body
        )
        self.send_or_queue(request)

    def room_send_redaction(self, room_buffer, event_id, reason=None):
        _, request = self.client.room_redact(
            room_buffer.room.room_id, event_id, reason
        )
        self.send_or_queue(request)

    def room_kick(self, room_buffer, user_id, reason=None):
        _, request = self.client.room_kick(
            room_buffer.room.room_id, user_id, reason
        )
        self.send_or_queue(request)

    def room_invite(self, room_buffer, user_id):
        _, request = self.client.room_invite(room_buffer.room.room_id, user_id)
        self.send_or_queue(request)

    def room_join(self, room_id):
        _, request = self.client.join(room_id)
        self.send_or_queue(request)

    def room_leave(self, room_id):
        _, request = self.client.room_leave(room_id)
        self.send_or_queue(request)

    def room_get_messages(self, room_id):
        room_buffer = self.find_room_from_id(room_id)

        # We're already fetching old messages
        if room_buffer.backlog_pending:
            return

        if not room_buffer.prev_batch:
            return

        uuid, request = self.client.room_messages(
            room_id,
            room_buffer.prev_batch,
            limit=10)

        room_buffer.backlog_pending = True
        self.backlog_queue[uuid] = room_id
        self.send_or_queue(request)

    def room_send_message(
        self,
        room_buffer,  # type: RoomBuffer
        formatted,    # type: Formatted
        msgtype="m.text",  # type: str
    ):
        # type: (...) -> bool
        room = room_buffer.room

        assert self.client

        body = {"msgtype": msgtype, "body": formatted.to_plain()}

        if formatted.is_formatted():
            body["format"] = "org.matrix.custom.html"
            body["formatted_body"] = formatted.to_html()

        try:
            uuid, request = self.client.room_send(
                room.room_id, "m.room.message", body
            )
        except GroupEncryptionError:
            request = None
            try:
                if not self.group_session_shared[room.room_id]:
                    _, request = self.client.share_group_session(room.room_id)
                    self.group_session_shared[room.room_id] = True
            except EncryptionError:
                if not self.keys_claimed[room.room_id]:
                    _, request = self.client.keys_claim(room.room_id)
                    self.keys_claimed[room.room_id] = True

            message = EncrytpionQueueItem(msgtype, formatted)
            self.encryption_queue[room.room_id].append(message)
            if request:
                self.send_or_queue(request)
            return False

        if msgtype == "m.emote":
            message_class = OwnAction
        else:
            message_class = OwnMessage

        own_message = message_class(
            self.user_id, 0, "", room.room_id, formatted
        )

        self.own_message_queue[uuid] = own_message
        self.send_or_queue(request)
        return True

    def keys_upload(self):
        _, request = self.client.keys_upload()
        self.send_or_queue(request)

    def keys_query(self):
        _, request = self.client.keys_query()
        self.keys_queried = True
        self.send_or_queue(request)

    def _print_message_error(self, message):
        server_buffer_prnt(
            self,
            (
                "{prefix}Unhandled {status_code} error, please "
                "inform the developers about this."
            ).format(
                prefix=W.prefix("error"), status_code=message.response.status
            ),
        )

        server_buffer_prnt(self, pprint.pformat(message.__class__.__name__))
        server_buffer_prnt(self, pprint.pformat(message.request.payload))
        server_buffer_prnt(self, pprint.pformat(message.response.body))

    def handle_own_messages(self, response):
        message = self.own_message_queue.pop(response.uuid)
        room_buffer = self.room_buffers[message.room_id]
        message = message._replace(event_id=response.event_id)

        if isinstance(message, OwnAction):
            room_buffer.self_action(message)
            return
        if isinstance(message, OwnMessage):
            room_buffer.self_message(message)
            return

        raise NotImplementedError(
            "Unsupported message of type {}".format(type(message))
        )

    def handle_backlog_response(self, response):
        room_id = self.backlog_queue.pop(response.uuid)
        room_buffer = self.find_room_from_id(room_id)

        room_buffer.handle_backlog(response)

    def _handle_login(self, response):
        self.access_token = response.access_token
        self.user_id = response.user_id
        self.client.access_token = response.access_token
        self.device_id = response.device_id
        self.save_device_id()

        message = "{prefix}matrix: Logged in as {user}".format(
            prefix=W.prefix("network"), user=self.user_id
        )

        W.prnt(self.server_buffer, message)

        if not self.client.olm_account_shared:
            self.keys_upload()

        sync_filter = {
            "room": {
                "timeline": {"limit": G.CONFIG.network.max_initial_sync_events}
            }
        }
        self.sync(timeout=0, sync_filter=sync_filter)

    def _handle_room_info(self, response):
        for room_id, info in response.rooms.invite.items():
            room = self.client.invited_rooms.get(room_id, None)

            if room:
                if room.inviter:
                    inviter_msg = " by {}{}".format(
                        W.color("chat_nick_other"), room.inviter
                    )
                else:
                    inviter_msg = ""

                self.info(
                    "You have been invited to {} {}({}{}{}){}"
                    "{}".format(
                        room.display_name(),
                        W.color("chat_delimiters"),
                        W.color("chat_channel"),
                        room_id,
                        W.color("chat_delimiters"),
                        W.color("reset"),
                        inviter_msg,
                    )
                )
            else:
                self.info("You have been invited to {}.".format(room_id))

        for room_id, info in response.rooms.leave.items():
            if room_id not in self.buffers:
                continue

            room_buffer = self.find_room_from_id(room_id)
            room_buffer.handle_left_room(info)

        should_lazy_hook = False

        for room_id, info in response.rooms.join.items():
            if room_id not in self.buffers:
                self.create_room_buffer(room_id, info.timeline.prev_batch)

            room_buffer = self.find_room_from_id(room_id)
            room_buffer.handle_joined_room(info)

            if room_buffer.unhandled_users:
                should_lazy_hook = True

        if should_lazy_hook:
            hook = W.hook_timer(1 * 100, 0, 0, "matrix_load_users_cb",
                                self.name)
            self.lazy_load_hook = hook

    def add_unhandled_users(self, rooms, n):
        # type: (List[RoomBuffer], int) -> bool
        total_users = 0

        while total_users <= n:
            try:
                room_buffer = rooms.pop()
            except IndexError:
                return False

            handled_users = 0

            users = room_buffer.unhandled_users

            for user_id in users:
                room_buffer.add_user(user_id, 0, True)
                handled_users += 1
                total_users += 1

                if total_users >= n:
                    room_buffer.unhandled_users = users[handled_users:]
                    rooms.append(room_buffer)
                    return True

            room_buffer.unhandled_users = []

        return False

    def _handle_sync(self, response):
        # we got the same batch again, nothing to do
        if self.next_batch == response.next_batch:
            self.schedule_sync()
            return

        self._handle_room_info(response)

        self.next_batch = response.next_batch

        if self.client.should_upload_keys:
            self.keys_upload()

        if self.client.should_query_keys and not self.keys_queried:
            self.keys_query()

        self.schedule_sync()

    def handle_transport_response(self, response):
        self.error(
            ("Error with response of type type: {}, " "error code {}").format(
                response.request_info.type, response.status_code
            )
        )

        # TODO better error handling.
        if response.request_info.type in (RequestType.sync, RequestType.login):
            self.disconnect()

    def handle_response(self, response):
        # type: (Response) -> None
        self.lag = response.elapsed * 1000

        # If the response was a sync response and contained a timeout the
        # timeout is expected and should be removed from the lag.
        # TODO the timeout isn't a constant
        if isinstance(response, SyncResponse):
            self.lag = max(0, self.lag - (30000))

        self.lag_done = True
        W.bar_item_update("lag")

        if isinstance(response, TransportResponse):
            self.handle_transport_response(response)

        elif isinstance(response, LoginResponse):
            self._handle_login(response)

        elif isinstance(response, SyncResponse):
            self._handle_sync(response)

        elif isinstance(response, RoomSendResponse):
            self.handle_own_messages(response)

        elif isinstance(response, RoomMessagesResponse):
            self.handle_backlog_response(response)

        elif isinstance(response, KeysClaimResponse):
            self.keys_claimed[response.room_id] = False
            try:
                _, request = self.client.share_group_session(
                    response.room_id,
                    ignore_missing_sessions=True
                )
            except OlmTrustError as e:
                m = ("Untrusted devices found in room: {}".format(e))
                self.error(m)
                return

            self.send(request)

        elif isinstance(response, ShareGroupSessionResponse):
            room_id = response.room_id
            self.group_session_shared[response.room_id] = False
            room_buffer = self.room_buffers[room_id]

            while self.encryption_queue[room_id]:
                message = self.encryption_queue[room_id].popleft()
                try:
                    if not self.room_send_message(room_buffer,
                                                  message.formatted_message,
                                                  message.message_type):
                        self.encryption_queue.pop()
                        self.encryption_queue[room_id].appendleft(message)
                        break
                except OlmTrustError:
                    break

    def create_room_buffer(self, room_id, prev_batch):
        room = self.client.rooms[room_id]
        buf = RoomBuffer(room, self.name, prev_batch)
        # TODO this should turned into a propper class
        self.room_buffers[room_id] = buf
        self.buffers[room_id] = buf.weechat_buffer._ptr

    def find_room_from_ptr(self, pointer):
        try:
            room_id = key_from_value(self.buffers, pointer)
            room_buffer = self.room_buffers[room_id]

            return room_buffer
        except (ValueError, KeyError):
            return None

    def find_room_from_id(self, room_id):
        room_buffer = self.room_buffers[room_id]
        return room_buffer

    def buffer_merge(self):
        if not self.server_buffer:
            return

        buf = self.server_buffer

        if G.CONFIG.look.server_buffer == ServerBufferType.MERGE_CORE:
            num = W.buffer_get_integer(W.buffer_search_main(), "number")
            W.buffer_unmerge(buf, num + 1)
            W.buffer_merge(buf, W.buffer_search_main())
        elif G.CONFIG.look.server_buffer == ServerBufferType.MERGE:
            if SERVERS:
                first = None
                for server in SERVERS.values():
                    if server.server_buffer:
                        first = server.server_buffer
                        break
                if first:
                    num = W.buffer_get_integer(
                        W.buffer_search_main(), "number"
                    )
                    W.buffer_unmerge(buf, num + 1)
                    if buf is not first:
                        W.buffer_merge(buf, first)
        else:
            num = W.buffer_get_integer(W.buffer_search_main(), "number")
            W.buffer_unmerge(buf, num + 1)


@utf8_decode
def matrix_config_server_read_cb(
    data, config_file, section, option_name, value
):

    return_code = W.WEECHAT_CONFIG_OPTION_SET_ERROR

    if option_name:
        server_name, option = option_name.rsplit(".", 1)
        server = None

        if server_name in SERVERS:
            server = SERVERS[server_name]
        else:
            server = MatrixServer(server_name, config_file)
            SERVERS[server.name] = server

        # Ignore invalid options
        if option in server.config._option_ptrs:
            return_code = W.config_option_set(
                server.config._option_ptrs[option], value, 1
            )

    # TODO print out error message in case of erroneous return_code

    return return_code


@utf8_decode
def matrix_config_server_write_cb(data, config_file, section_name):
    if not W.config_write_line(config_file, section_name, ""):
        return W.WECHAT_CONFIG_WRITE_ERROR

    for server in SERVERS.values():
        for option in server.config._option_ptrs.values():
            if not W.config_write_option(config_file, option):
                return W.WECHAT_CONFIG_WRITE_ERROR

    return W.WEECHAT_CONFIG_WRITE_OK


@utf8_decode
def matrix_config_server_change_cb(server_name, option):
    # type: (str, str) -> int
    server = SERVERS[server_name]
    option_name = None

    # The function config_option_get_string() is used to get differing
    # properties from a config option, sadly it's only available in the plugin
    # API of weechat.
    option_name = key_from_value(server.config._option_ptrs, option)
    server.update_option(option, option_name)

    return 1


@utf8_decode
def matrix_load_users_cb(server_name, remaining_calls):
    server = SERVERS[server_name]
    start = time.time()

    rooms = [x for x in server.room_buffers.values() if x.unhandled_users]

    while server.add_unhandled_users(rooms, 100):
        current = time.time()

        if current - start >= 0.1:
            return W.WEECHAT_RC_OK

    # We are done adding users, we can unhook now.
    W.unhook(server.lazy_load_hook)
    server.lazy_load_hook = None

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_timer_cb(server_name, remaining_calls):
    server = SERVERS[server_name]

    current_time = time.time()

    if (
        (not server.connected)
        and server.reconnect_time
        and current_time >= (server.reconnect_time + server.reconnect_delay)
    ):
        server.reconnect()
        return W.WEECHAT_RC_OK

    if not server.connected:
        return W.WEECHAT_RC_OK

    # check lag, disconnect if it's too big
    server.lag = server.client.lag * 1000
    server.lag_done = False
    W.bar_item_update("lag")

    # TODO print out message, make timeout configurable
    if server.lag > 300000:
        server.disconnect()
        return W.WEECHAT_RC_OK

    if server.sync_time and current_time > (server.sync_time + 2):
        timeout = 0 if server.transport_type == TransportType.HTTP else 30000
        sync_filter = {"room": {"timeline": {"limit": 5000}}}
        server.sync(timeout, sync_filter)

    if not server.next_batch:
        return W.WEECHAT_RC_OK

    return W.WEECHAT_RC_OK


def create_default_server(config_file):
    server = MatrixServer("matrix_org", config_file._ptr)
    SERVERS[server.name] = server

    option = W.config_get(SCRIPT_NAME + ".server." + server.name + ".address")
    W.config_option_set(option, "matrix.org", 1)

    return True


@utf8_decode
def send_cb(server_name, file_descriptor):
    # type: (str, int) -> int

    server = SERVERS[server_name]

    if server.send_fd_hook:
        W.unhook(server.send_fd_hook)
        server.send_fd_hook = None

    if server.send_buffer:
        server.try_send(server.send_buffer)

    return W.WEECHAT_RC_OK
