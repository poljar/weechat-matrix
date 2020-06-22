# -*- coding: utf-8 -*-

# Copyright © 2018, 2019 Damir Jelić <poljar@termina.org.uk>
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
import copy
from collections import defaultdict, deque
from atomicwrites import atomic_write
from typing import (
    Any,
    Deque,
    Dict,
    Optional,
    List,
    NamedTuple,
    DefaultDict,
    Type,
    Union,
)

from uuid import UUID

from nio import (
    Api,
    HttpClient,
    ClientConfig,
    LocalProtocolError,
    LoginResponse,
    LoginInfoResponse,
    Response,
    Rooms,
    RoomSendResponse,
    RoomSendError,
    SyncResponse,
    ShareGroupSessionResponse,
    ShareGroupSessionError,
    KeysQueryResponse,
    KeysClaimResponse,
    DevicesResponse,
    UpdateDeviceResponse,
    DeleteDevicesAuthResponse,
    DeleteDevicesResponse,
    TransportType,
    RoomMessagesResponse,
    EncryptionError,
    GroupEncryptionError,
    OlmTrustError,
    ErrorResponse,
    SyncError,
    LoginError,
    JoinedMembersResponse,
    JoinedMembersError,
    RoomKeyEvent,
    KeyVerificationStart,
    KeyVerificationCancel,
    KeyVerificationKey,
    KeyVerificationMac,
    KeyVerificationEvent,
    ToDeviceMessage,
    ToDeviceResponse,
    ToDeviceError
)

from . import globals as G
from .buffer import OwnAction, OwnMessage, RoomBuffer
from .config import ConfigSection, Option, ServerBufferType
from .globals import SCRIPT_NAME, SERVERS, W, TYPING_NOTICE_TIMEOUT
from .utf import utf8_decode
from .utils import create_server_buffer, key_from_value, server_buffer_prnt
from .uploads import Upload

from .colors import Formatted, FormattedString, DEFAULT_ATTRIBUTES

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse  # type: ignore

try:
    FileNotFoundError  # type: ignore
except NameError:
    FileNotFoundError = IOError


EncryptionQueueItem = NamedTuple(
    "EncryptionQueueItem",
    [
        ("message_type", str),
        ("message", Union[Formatted, Upload]),
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
                (
                    "Hostname or address of the server (note: content is "
                    "evaluated, see /help eval)"
                )
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
                ("Name of weechat proxy to use (see /help proxy) (note: "
                 "content is evaluated, see /help eval)"),
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
                "username",
                "string",
                "",
                0,
                0,
                "",
                (
                    "Username to use on the server (note: content is "
                    "evaluated, see /help eval)"
                )
            ),
            Option(
                "password",
                "string",
                "",
                0,
                0,
                "",
                (
                    "Password for the server (note: content is evaluated, see "
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
                (
                    "Device name to use when logging in, this "
                    "is only used on the firt login. Afther that the /devices "
                    "command can be used to change the device name. (note: "
                    "content is evaluated, see /help eval)"
                )
            ),
            Option(
                "autoreconnect_delay",
                "integer",
                "",
                0,
                86400,
                "10",
                ("Delay (in seconds) before trying to reconnect to server"),
            ),
            Option(
                "sso_helper_listening_port",
                "integer",
                "",
                0,
                65535,
                "0",
                ("The port that the SSO helpers web server  should listen on"),
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
    address = ConfigSection.option_property("address", "string", evaluate=True)
    port = ConfigSection.option_property("port", "integer")
    proxy = ConfigSection.option_property("proxy", "string", evaluate=True)
    ssl_verify = ConfigSection.option_property("ssl_verify", "boolean")
    username = ConfigSection.option_property("username", "string",
        evaluate=True)
    device_name = ConfigSection.option_property("device_name", "string",
        evaluate=True)
    reconnect_delay = ConfigSection.option_property("autoreconnect_delay", "integer")
    password = ConfigSection.option_property(
        "password", "string", evaluate=True
    )
    sso_helper_listening_port = ConfigSection.option_property(
        "sso_helper_listening_port",
        "integer"
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

        self._connected = False     # type: bool
        self.connecting = False     # type: bool
        self.reconnect_delay = 0    # type: int
        self.reconnect_time = None  # type: Optional[float]
        self.sync_time = None       # type: Optional[float]
        self.socket = None          # type: Optional[ssl.SSLSocket]
        self.ssl_context = ssl.create_default_context()  # type: ssl.SSLContext
        self.transport_type = None  # type: Optional[TransportType]

        self.sso_hook = None

        # Enable http2 negotiation on the ssl context.
        self.ssl_context.set_alpn_protocols(["h2", "http/1.1"])

        try:
            self.ssl_context.set_npn_protocols(["h2", "http/1.1"])
        except NotImplementedError:
            pass

        self.address = None
        self.homeserver = None
        self.client = None  # type: Optional[HttpClient]
        self.access_token = None                         # type: Optional[str]
        self.next_batch = None                           # type: Optional[str]
        self.transaction_id = 0                          # type: int
        self.lag = 0                                     # type: int
        self.lag_done = False                            # type: bool
        self.busy = False                                # type: bool
        self.first_sync = True

        self.send_fd_hook = None                         # type: Optional[str]
        self.send_buffer = b""                           # type: bytes
        self.device_check_timestamp = None               # type: Optional[int]

        self.device_deletion_queue = dict()              # type: Dict[str, str]

        self.encryption_queue = defaultdict(deque)  \
            # type: DefaultDict[str, Deque[EncryptionQueueItem]]
        self.backlog_queue = dict()      # type: Dict[str, str]

        self.user_gc_time = time.time()    # type: float
        self.member_request_list = []         # type: List[str]
        self.rooms_with_missing_members = []  # type: List[str]
        self.lazy_load_hook = None       # type: Optional[str]

        # These flags remember if we made some requests so that we don't
        # make them again while we wait on a response, the flags need to be
        # cleared when we disconnect.
        self.keys_queried = False                      # type: bool
        self.keys_claimed = defaultdict(bool)          # type: Dict[str, bool]
        self.group_session_shared = defaultdict(bool)  # type: Dict[str, bool]
        self.ignore_while_sharing = defaultdict(bool)  # type: Dict[str, bool]
        self.to_device_sent = []  # type: List[ToDeviceMessage]

        # Try to load the device id, the device id is loaded every time the
        # user changes but some login flows don't use a user so try to load the
        # device for a main user.
        self._load_device_id("main")
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

    @property
    def connected(self):
        return self._connected

    @connected.setter
    def connected(self, value):
        self._connected = value
        W.bar_item_update("buffer_modes")
        W.bar_item_update("matrix_modes")

    def get_session_path(self):
        home_dir = W.info_get("weechat_dir", "")
        return os.path.join(home_dir, "matrix", self.name)

    def _load_device_id(self, user=None):
        user = user or self.config.username

        file_name = "{}{}".format(user, ".device_id")
        path = os.path.join(self.get_session_path(), file_name)

        if not os.path.isfile(path):
            return

        with open(path, "r") as device_file:
            device_id = device_file.readline().rstrip()
            if device_id:
                self.device_id = device_id

    def save_device_id(self):
        file_name = "{}{}".format(self.config.username or "main", ".device_id")
        path = os.path.join(self.get_session_path(), file_name)

        with atomic_write(path, overwrite=True) as device_file:
            device_file.write(self.device_id)

    @staticmethod
    def _parse_url(address, port):
        if not address.startswith("http"):
            address = "https://{}".format(address)

        parsed_url = urlparse(address)

        homeserver = parsed_url._replace(
            netloc=parsed_url.hostname + ":{}".format(port)
        )

        return homeserver

    def _change_client(self):
        homeserver = MatrixServer._parse_url(
            self.config.address,
            self.config.port
        )
        self.address = homeserver.hostname
        self.homeserver = homeserver

        config = ClientConfig(store_sync_tokens=True)

        self.client = HttpClient(
            homeserver.geturl(),
            self.config.username,
            self.device_id,
            self.get_session_path(),
            config=config
        )
        self.client.add_to_device_callback(
            self.key_verification_cb,
            KeyVerificationEvent
        )

    def key_verification_cb(self, event):
        if isinstance(event, KeyVerificationStart):
            self.info_highlight("{user} via {device} has started a key "
                                "verification process.\n"
                                "To accept use /olm verification "
                                "accept {user} {device}".format(
                                    user=event.sender,
                                    device=event.from_device
                                ))

        elif isinstance(event, KeyVerificationKey):
            sas = self.client.key_verifications.get(event.transaction_id, None)
            if not sas:
                return

            if sas.canceled:
                return

            device = sas.other_olm_device
            emoji = sas.get_emoji()

            emojis = [x[0] for x in emoji]
            descriptions = [x[1] for x in emoji]

            centered_width = 12

            def center_emoji(emoji, width):
                # Assume each emoji has width 2
                emoji_width = 2

                # These are emojis that need VARIATION-SELECTOR-16 (U+FE0F) so
                # that they are rendered with coloured glyphs. For these, we
                # need to add an extra space after them so that they are
                # rendered properly in weechat.
                variation_selector_emojis = [
                    '☁️',
                    '❤️',
                    '☂️',
                    '✏️',
                    '✂️',
                    '☎️',
                    '✈️'
                ]

                # Hack to make weechat behave properly when one of the above is
                # printed.
                if emoji in variation_selector_emojis:
                    emoji += " "

                # This is a trick to account for the fact that emojis are wider
                # than other monospace characters.
                placeholder = '.' * emoji_width

                return placeholder.center(width).replace(placeholder, emoji)

            emoji_str = u"".join(center_emoji(e, centered_width)
                                 for e in emojis)
            desc = u"".join(d.center(centered_width) for d in descriptions)
            short_string = u"\n".join([emoji_str, desc])

            self.info_highlight(u"Short authentication string for "
                                u"{user} via {device}:\n{string}\n"
                                u"Confirm that the strings match with "
                                u"/olm verification confirm {user} "
                                u"{device}".format(
                                    user=device.user_id,
                                    device=device.id,
                                    string=short_string
                                ))

        elif isinstance(event, KeyVerificationMac):
            try:
                sas = self.client.key_verifications[event.transaction_id]
            except KeyError:
                return

            device = sas.other_olm_device

            if sas.verified:
                self.info_highlight("Device {} of user {} successfully "
                                    "verified".format(
                                        device.id,
                                        device.user_id
                                    ))

        elif isinstance(event, KeyVerificationCancel):
            self.info_highlight("The interactive device verification with "
                                "user {} got canceled: {}.".format(
                                    event.sender,
                                    event.reason
                                ))

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

    def info_highlight(self, message):
        buf = ""
        if self.server_buffer:
            buf = self.server_buffer

        msg = "{}{}: {}".format(W.prefix("network"), SCRIPT_NAME, message)
        W.prnt_date_tags(buf, 0, "notify_highlight", msg)

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
            self.reconnect_delay = (
                self.reconnect_delay
                * G.CONFIG.network.autoreconnect_delay_growing
            )
        else:
            self.reconnect_delay = self.config.reconnect_delay

        if G.CONFIG.network.autoreconnect_delay_max > 0:
            self.reconnect_delay = min(self.reconnect_delay,
                G.CONFIG.network.autoreconnect_delay_max)

        message = (
            "{prefix}matrix: reconnecting to server in {t} " "seconds"
        ).format(prefix=W.prefix("network"), t=self.reconnect_delay)

        server_buffer_prnt(self, message)

    def _close_socket(self):
        # type: () -> None
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except socket.error:
                pass

            try:
                self.socket.close()
            except OSError:
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
        self.member_request_list = []

        if self.client:
            try:
                self.client.disconnect()
            except LocalProtocolError:
                pass

        self.lag = 0
        W.bar_item_update("lag")
        self.reconnect_time = None

        # Clear our request flags.
        self.keys_queried = False
        self.keys_claimed = defaultdict(bool)
        self.group_session_shared = defaultdict(bool)
        self.ignore_while_sharing = defaultdict(bool)
        self.to_device_sent = []

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
            message = "{prefix}Server address or port not set".format(
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
            server=self.address,
            port=self.config.port,
            ssl=ssl_message,
        )

        W.prnt(self.server_buffer, message)

        W.hook_connect(
            self.config.proxy,
            self.address,
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
        _, request = self.client.sync(timeout, sync_filter,
            full_state=self.first_sync)

        self.send_or_queue(request)

    def login_info(self):
        # type: () -> None
        if not self.client:
            return

        if self.client.logged_in:
            self.login()
            return

        _, request = self.client.login_info()
        self.send(request)

    """Start a local HTTP server to listen for SSO tokens."""
    def start_login_sso(self):
        # type: () -> None
        if self.sso_hook:
            # If there is a stale SSO process hanging around kill it. We could
            # let it stay around but the URL that needs to be opened by the
            # user is printed out in the callback.
            W.hook_set(self.sso_hook, "signal", "term")
            self.sso_hook = None

        process_args = {
            "buffer_flush": "1",
            "arg1": "--port",
            "arg2": str(self.config.sso_helper_listening_port)
        }

        self.sso_hook = W.hook_process_hashtable(
            "matrix_sso_helper",
            process_args,
            0,
            "sso_login_cb",
            self.name
        )

    def login(self, token=None):
        # type: (...) -> None
        assert self.client is not None
        if self.client.logged_in:
            msg = (
                "{prefix}{script_name}: Already logged in, " "syncing..."
            ).format(prefix=W.prefix("network"), script_name=SCRIPT_NAME)
            W.prnt(self.server_buffer, msg)
            timeout = 0 if self.transport_type == TransportType.HTTP else 30000
            limit = (G.CONFIG.network.max_initial_sync_events if self.first_sync else 500)
            sync_filter = {
                "room": {
                    "timeline": {"limit": limit},
                    "state": {"lazy_load_members": True}
                }
            }
            self.sync(timeout, sync_filter)
            return

        if (not self.config.username or not self.config.password) and not token:
            message = "{prefix}User or password not set".format(
                prefix=W.prefix("error")
            )
            W.prnt("", message)
            return self.disconnect()

        if token:
            _, request = self.client.login(
                device_name=self.config.device_name, token=token
            )
        else:
            _, request = self.client.login(
                password=self.config.password, device_name=self.config.device_name
            )
        self.send_or_queue(request)

        msg = "{prefix}matrix: Logging in...".format(
            prefix=W.prefix("network")
        )

        W.prnt(self.server_buffer, msg)

    def devices(self):
        _, request = self.client.devices()
        self.send_or_queue(request)

    def delete_device(self, device_id, auth=None):
        uuid, request = self.client.delete_devices([device_id], auth)
        self.device_deletion_queue[uuid] = device_id
        self.send_or_queue(request)
        return

    def rename_device(self, device_id, display_name):
        content = {
            "display_name": display_name
        }

        _, request = self.client.update_device(device_id, content)
        self.send_or_queue(request)

    def room_send_state(self, room_buffer, body, event_type):
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
        if not self.connected or not self.client.logged_in:
            return False

        room_buffer = self.find_room_from_id(room_id)

        # We're already fetching old messages
        if room_buffer.backlog_pending:
            return False

        if not room_buffer.prev_batch:
            return False

        uuid, request = self.client.room_messages(
            room_id,
            room_buffer.prev_batch,
            limit=10)

        room_buffer.backlog_pending = True
        self.backlog_queue[uuid] = room_id
        self.send_or_queue(request)

        return True

    def room_send_read_marker(self, room_id, event_id):
        """Send read markers for the provided room.

        Args:
            room_id(str): the room for which the read markers should
                be sent.
            event_id(str): the event id where to set the marker
        """
        if not self.connected or not self.client.logged_in:
            return

        _, request = self.client.room_read_markers(
            room_id,
            fully_read_event=event_id,
            read_event=event_id)
        self.send(request)

    def room_send_typing_notice(self, room_buffer):
        """Send a typing notice for the provided room.

        Args:
            room_buffer(RoomBuffer): the room for which the typing notice needs
                to be sent.
        """
        if not self.connected or not self.client.logged_in:
            return

        input = room_buffer.weechat_buffer.input

        typing_enabled = bool(int(W.string_eval_expression(
            G.CONFIG.network.typing_notice_conditions,
            {},
            {"typing_enabled": str(int(room_buffer.typing_enabled))},
            {"type": "condition"}
        )))

        if not typing_enabled:
            return

        # Don't send a typing notice if the user is typing in a weechat command
        if input.startswith("/") and not input.startswith("//"):
            return

        # Don't send a typing notice if we only typed a couple of letters.
        elif len(input) < 4 and not room_buffer.typing:
            return

        # If we were typing already and our input bar now has no letters or
        # only a couple of letters stop the typing notice.
        elif len(input) < 4:
            _, request = self.client.room_typing(
                room_buffer.room.room_id,
                typing_state=False)
            room_buffer.typing = False
            self.send(request)
            return

        # Don't send out a typing notice if we already sent one out and it
        # didn't expire yet.
        if not room_buffer.typing_notice_expired:
            return

        _, request = self.client.room_typing(
            room_buffer.room.room_id,
            typing_state=True,
            timeout=TYPING_NOTICE_TIMEOUT)

        room_buffer.typing = True
        self.send(request)

    def room_send_upload(
        self,
        upload
    ):
        """Send a room message containing the mxc URI of an upload."""
        try:
            room_buffer = self.find_room_from_id(upload.room_id)
        except (ValueError, KeyError):
            return True

        assert self.client

        if room_buffer.room.encrypted:
            assert upload.encrypt

        content = upload.content

        try:
            uuid = self.room_send_event(upload.room_id, content)
        except (EncryptionError, GroupEncryptionError):
            message = EncryptionQueueItem(upload.msgtype, upload)
            self.encryption_queue[upload.room_id].append(message)
            return False

        attributes = DEFAULT_ATTRIBUTES.copy()
        formatted = Formatted([FormattedString(
            upload.render,
            attributes
        )])

        own_message = OwnMessage(
            self.user_id, 0, "", uuid, upload.room_id, formatted
        )

        room_buffer.sent_messages_queue[uuid] = own_message
        self.print_unconfirmed_message(room_buffer, own_message)

        return True

    def share_group_session(
        self,
        room_id,
        ignore_missing_sessions=False,
        ignore_unverified_devices=False
    ):

        self.ignore_while_sharing[room_id] = ignore_unverified_devices

        _, request = self.client.share_group_session(
            room_id,
            ignore_missing_sessions=ignore_missing_sessions,
            ignore_unverified_devices=ignore_unverified_devices
        )
        self.send(request)
        self.group_session_shared[room_id] = True

    def room_send_event(
        self,
        room_id,    # type: str
        content,    # type: Dict[str, str]
        event_type="m.room.message",      # type: str
        ignore_unverified_devices=False,  # type: bool
    ):
        # type: (...) -> UUID
        assert self.client

        try:
            uuid, request = self.client.room_send(
                room_id, event_type, content
            )
            self.send(request)
            return uuid
        except GroupEncryptionError:
            try:
                if not self.group_session_shared[room_id]:
                    self.share_group_session(
                        room_id,
                        ignore_unverified_devices=ignore_unverified_devices
                    )
                raise

            except EncryptionError:
                if not self.keys_claimed[room_id]:
                    _, request = self.client.keys_claim(room_id)
                    self.keys_claimed[room_id] = True
                    self.send(request)
                raise

    def room_send_message(
        self,
        room_buffer,  # type: RoomBuffer
        formatted,    # type: Formatted
        msgtype="m.text",  # type: str
        ignore_unverified_devices=False,  # type: bool
        in_reply_to_event_id="",  # type: str
    ):
        # type: (...) -> bool
        room = room_buffer.room

        assert self.client

        content = {"msgtype": msgtype, "body": formatted.to_plain()}

        if formatted.is_formatted() or in_reply_to_event_id:
            content["format"] = "org.matrix.custom.html"
            content["formatted_body"] = formatted.to_html()
            if in_reply_to_event_id:
                content["m.relates_to"] = {
                    "m.in_reply_to": {"event_id": in_reply_to_event_id}
                }

        try:
            uuid = self.room_send_event(
                room.room_id,
                content,
                ignore_unverified_devices=ignore_unverified_devices
            )
        except (EncryptionError, GroupEncryptionError):
            message = EncryptionQueueItem(msgtype, formatted)
            self.encryption_queue[room.room_id].append(message)
            return False

        if msgtype == "m.emote":
            message_class = OwnAction  # type: Type
        else:
            message_class = OwnMessage

        own_message = message_class(
            self.user_id, 0, "", uuid, room.room_id, formatted
        )

        room_buffer.sent_messages_queue[uuid] = own_message
        self.print_unconfirmed_message(room_buffer, own_message)

        return True

    def print_unconfirmed_message(self, room_buffer, message):
        """Print an outgoing message before getting a receive confirmation.

        The message is printed out greyed out and only printed out if the
        client is configured to do so. The message needs to be later modified
        to contain proper coloring, this is done in the
        replace_printed_line_by_uuid() method of the RoomBuffer class.

        Args:
            room_buffer(RoomBuffer): the buffer of the room where the message
                needs to be printed out
            message(OwnMessages): the message that should be printed out
        """
        if G.CONFIG.network.print_unconfirmed_messages:
            room_buffer.printed_before_ack_queue.append(message.uuid)
            plain_message = message.formatted_message.to_weechat()
            plain_message = W.string_remove_color(plain_message, "")
            attributes = DEFAULT_ATTRIBUTES.copy()
            attributes["fgcolor"] = G.CONFIG.color.unconfirmed_message_fg
            attributes["bgcolor"] = G.CONFIG.color.unconfirmed_message_bg
            new_formatted = Formatted([FormattedString(
                plain_message,
                attributes
            )])

            new_message = copy.copy(message)
            new_message.formatted_message = new_formatted

            if isinstance(new_message, OwnAction):
                room_buffer.self_action(new_message)
            elif isinstance(new_message, OwnMessage):
                room_buffer.self_message(new_message)

    def keys_upload(self):
        _, request = self.client.keys_upload()
        self.send_or_queue(request)

    def keys_query(self):
        _, request = self.client.keys_query()
        self.keys_queried = True
        self.send_or_queue(request)

    def get_joined_members(self, room_id):
        if not self.connected or not self.client.logged_in:
            return

        if room_id in self.member_request_list:
            return

        self.member_request_list.append(room_id)
        _, request = self.client.joined_members(room_id)
        self.send(request)

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

    def handle_own_messages_error(self, response):
        room_buffer = self.room_buffers[response.room_id]

        if response.uuid not in room_buffer.printed_before_ack_queue:
            return

        message = room_buffer.sent_messages_queue.pop(response.uuid)
        room_buffer.mark_message_as_unsent(response.uuid, message)
        room_buffer.printed_before_ack_queue.remove(response.uuid)

    def handle_own_messages(self, response):
        def send_marker():
            if not room_buffer.read_markers_enabled:
                return

            self.room_send_read_marker(response.room_id, response.event_id)
            room_buffer.last_read_event = response.event_id

        room_buffer = self.room_buffers[response.room_id]

        message = room_buffer.sent_messages_queue.pop(response.uuid, None)

        # The message might have been returned in a sync response before we got
        # a room send response.
        if not message:
            return

        message.event_id = response.event_id
        # We already printed the message, just modify it to contain the proper
        # colors and formatting.
        if response.uuid in room_buffer.printed_before_ack_queue:
            room_buffer.replace_printed_line_by_uuid(response.uuid, message)
            room_buffer.printed_before_ack_queue.remove(response.uuid)
            send_marker()
            return

        if isinstance(message, OwnAction):
            room_buffer.self_action(message)
            send_marker()
            return
        if isinstance(message, OwnMessage):
            room_buffer.self_message(message)
            send_marker()
            return

        raise NotImplementedError(
            "Unsupported message of type {}".format(type(message))
        )

    def handle_backlog_response(self, response):
        room_id = self.backlog_queue.pop(response.uuid)
        room_buffer = self.find_room_from_id(room_id)
        room_buffer.first_view = False

        room_buffer.handle_backlog(response)

    def handle_devices_response(self, response):
        if not response.devices:
            m = "{}{}: No devices found for this account".format(
                    W.prefix("error"),
                    SCRIPT_NAME)
            W.prnt(self.server_buffer, m)

        header = (W.prefix("network") + SCRIPT_NAME + ": Devices for "
                  "server {}{}{}:\n"
                  "  Device ID         Device Name                       "
                  "Last Seen").format(
                      W.color("chat_server"),
                      self.name,
                      W.color("reset")
                  )
        W.prnt(self.server_buffer, header)

        lines = []
        for device in response.devices:
            last_seen_date = ("?" if not device.last_seen_date else
                              device.last_seen_date.strftime("%Y/%m/%d %H:%M"))
            last_seen = "{ip} @ {date}".format(
                ip=device.last_seen_ip or "?",
                date=last_seen_date
            )
            device_color = ("chat_self" if device.id == self.device_id else
                            W.info_get("nick_color_name", device.id))
            bold = W.color("bold") if device.id == self.device_id else ""
            line = "  {}{}{:<18}{}{:<34}{:<}".format(
                bold,
                W.color(device_color),
                device.id,
                W.color("resetcolor"),
                device.display_name or "",
                last_seen
                )
            lines.append(line)
        W.prnt(self.server_buffer, "\n".join(lines))

    """Handle a login info response and chose one of the available flows

    This currently supports only SSO and password logins. If both are available
    password takes precedence over SSO if a username and password is provided.

    """
    def _handle_login_info(self, response):
        if ("m.login.sso" in response.flows
                and (not self.config.username or self.config.password)):
            self.start_login_sso()
        elif "m.login.password" in response.flows:
            self.login()
        else:
            self.error("No supported login flow found")
            self.disconnect()

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
                "timeline": {
                    "limit": G.CONFIG.network.max_initial_sync_events
                },
                "state": {"lazy_load_members": True}
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

                self.info_highlight(
                    "You have been invited to {} {}({}{}{}){}"
                    "{}".format(
                        room.display_name,
                        W.color("chat_delimiters"),
                        W.color("chat_channel"),
                        room_id,
                        W.color("chat_delimiters"),
                        W.color("reset"),
                        inviter_msg,
                    )
                )
            else:
                self.info_highlight("You have been invited to {}.".format(
                    room_id
                ))

        for room_id, info in response.rooms.leave.items():
            if room_id not in self.buffers:
                continue

            room_buffer = self.find_room_from_id(room_id)
            room_buffer.handle_left_room(info)

        for room_id, info in response.rooms.join.items():
            if room_id not in self.buffers:
                self.create_room_buffer(room_id, info.timeline.prev_batch)

            room_buffer = self.find_room_from_id(room_id)
            room_buffer.handle_joined_room(info)

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

    def _hook_lazy_user_adding(self):
        if not self.lazy_load_hook:
            hook = W.hook_timer(1 * 1000, 0, 0,
                                "matrix_load_users_cb", self.name)
            self.lazy_load_hook = hook

    def decrypt_printed_messages(self, key_event):
        """Decrypt already printed messages and send them to the buffer"""
        try:
            room_buffer = self.find_room_from_id(key_event.room_id)
        except KeyError:
            return

        decrypted_events = []

        for undecrypted_event in room_buffer.undecrypted_events:
            if undecrypted_event.session_id != key_event.session_id:
                continue

            event = self.client.decrypt_event(undecrypted_event)
            if event:
                decrypted_events.append((undecrypted_event, event))

        for event_pair in decrypted_events:
            undecrypted_event, event = event_pair
            room_buffer.undecrypted_events.remove(undecrypted_event)
            room_buffer.replace_undecrypted_line(event)

    def start_verification(self, device):
        _, request = self.client.start_key_verification(device)
        self.send(request)
        self.info("Starting an interactive device verification with "
                  "{} {}".format(device.user_id, device.id))

    def accept_sas(self, sas):
        _, request = self.client.accept_key_verification(sas.transaction_id)
        self.send(request)

    def cancel_sas(self, sas):
        _, request = self.client.cancel_key_verification(sas.transaction_id)
        self.send(request)

    def to_device(self, message):
        _, request = self.client.to_device(message)
        self.send(request)

    def confirm_sas(self, sas):
        _, request = self.client.confirm_short_auth_string(sas.transaction_id)
        self.send(request)

        device = sas.other_olm_device

        if sas.verified:
            self.info("Device {} of user {} successfully verified".format(
                device.id,
                device.user_id
            ))
        else:
            self.info("Waiting for {} to confirm...".format(device.user_id))

    def _handle_sync(self, response):
        # we got the same batch again, nothing to do
        self.first_sync = False

        if self.next_batch == response.next_batch:
            self.schedule_sync()
            return

        self._handle_room_info(response)

        for event in response.to_device_events:
            if isinstance(event, RoomKeyEvent):
                message = {
                    "sender": event.sender,
                    "sender_key": event.sender_key,
                    "room_id": event.room_id,
                    "session_id": event.session_id,
                    "algorithm": event.algorithm,
                    "server": self.name,
                }
                W.hook_hsignal_send("matrix_room_key_received", message)

                # TODO try to decrypt some cached undecrypted messages with the
                # new key
                # self.decrypt_printed_messages(event)

        if self.client.should_upload_keys:
            self.keys_upload()

        if self.client.should_query_keys and not self.keys_queried:
            self.keys_query()

        for room_buffer in self.room_buffers.values():
            # It's our initial sync, we need to fetch room members, so add
            # the room to the missing members queue.
            # 3 reasons we fetch room members here:
            #   * If the lazy load room users setting is off, otherwise we will
            #       fetch them when we switch to the buffer
            #   * If the room is encrypted, encryption needs the full member
            #       list for it to work.
            #   * If we are the only member, it is unlikely really an empty
            #       room and since we don't want a bunch of "Empty room?"
            #       buffers in our buffer list we fetch members here.
            if not self.next_batch:
                if (not G.CONFIG.network.lazy_load_room_users
                        or room_buffer.room.encrypted
                        or room_buffer.room.member_count <= 1):
                    self.rooms_with_missing_members.append(
                        room_buffer.room.room_id
                    )
            if room_buffer.unhandled_users:
                self._hook_lazy_user_adding()
                break

        self.next_batch = response.next_batch
        self.schedule_sync()
        W.bar_item_update("matrix_typing_notice")

        if self.rooms_with_missing_members:
            self.get_joined_members(self.rooms_with_missing_members.pop())

    def handle_delete_device_auth(self, response):
        device_id = self.device_deletion_queue.pop(response.uuid, None)

        if not device_id:
            return

        for flow in response.flows:
            if "m.login.password" in flow["stages"]:
                session = response.session
                auth = {
                    "type": "m.login.password",
                    "session": session,
                    "user": self.client.user_id,
                    "password": self.config.password
                }
                self.delete_device(device_id, auth)
                return

        self.error("No supported auth method for device deletion found.")

    def handle_error_response(self, response):
        self.error("Error: {}".format(str(response)))

        if isinstance(response, (SyncError, LoginError)):
            self.disconnect()
        elif isinstance(response, JoinedMembersError):
            self.rooms_with_missing_members.append(response.room_id)
            self.get_joined_members(self.rooms_with_missing_members.pop())
        elif isinstance(response, RoomSendError):
            self.handle_own_messages_error(response)
        elif isinstance(response, ShareGroupSessionError):
            self.group_session_shared[response.room_id] = False
            self.share_group_session(
                response.room_id,
                False,
                self.ignore_while_sharing[response.room_id]
            )

        elif isinstance(response, ToDeviceError):
            try:
                self.to_device_sent.remove(response.to_device_message)
            except ValueError:
                pass

    def handle_response(self, response):
        # type: (Response) -> None
        response_lag = response.elapsed

        current_lag = 0

        if self.client:
            current_lag = self.client.lag

        if response_lag >= current_lag:
            self.lag = response_lag * 1000
            self.lag_done = True
            W.bar_item_update("lag")

        if isinstance(response, ErrorResponse):
            self.handle_error_response(response)

        elif isinstance(response, ToDeviceResponse):
            try:
                self.to_device_sent.remove(response.to_device_message)
            except ValueError:
                pass

        elif isinstance(response, LoginResponse):
            self._handle_login(response)

        elif isinstance(response, LoginInfoResponse):
            self._handle_login_info(response)

        elif isinstance(response, SyncResponse):
            self._handle_sync(response)

        elif isinstance(response, RoomSendResponse):
            self.handle_own_messages(response)

        elif isinstance(response, RoomMessagesResponse):
            self.handle_backlog_response(response)

        elif isinstance(response, DevicesResponse):
            self.handle_devices_response(response)

        elif isinstance(response, UpdateDeviceResponse):
            self.info("Device name successfully updated")

        elif isinstance(response, DeleteDevicesAuthResponse):
            self.handle_delete_device_auth(response)

        elif isinstance(response, DeleteDevicesResponse):
            self.info("Device successfully deleted")

        elif isinstance(response, KeysQueryResponse):
            self.keys_queried = False
            W.bar_item_update("buffer_modes")
            W.bar_item_update("matrix_modes")

            for user_id, device_dict in response.changed.items():
                for device in device_dict.values():
                    message = {
                        "user_id": user_id,
                        "device_id": device.id,
                        "ed25519": device.ed25519,
                        "curve25519": device.curve25519,
                        "deleted": str(device.deleted)
                    }
                    W.hook_hsignal_send("matrix_device_changed", message)

        elif isinstance(response, JoinedMembersResponse):
            self.member_request_list.remove(response.room_id)
            room_buffer = self.room_buffers[response.room_id]
            users = [user.user_id for user in response.members]

            # Don't add the users directly use the lazy load hook.
            room_buffer.unhandled_users += users
            self._hook_lazy_user_adding()
            room_buffer.members_fetched = True
            room_buffer.update_buffer_name()

            # Fetch the users for the next room.
            if self.rooms_with_missing_members:
                self.get_joined_members(self.rooms_with_missing_members.pop())
            # We are done adding all the users, do a full key query now since
            # the client knows all the encrypted room members.
            else:
                if self.client.should_query_keys and not self.keys_queried:
                    self.keys_query()

        elif isinstance(response, KeysClaimResponse):
            self.keys_claimed[response.room_id] = False
            try:
                self.share_group_session(
                    response.room_id,
                    True,
                    self.ignore_while_sharing[response.room_id]
                )
            except OlmTrustError as e:
                m = ("Untrusted devices found in room: {}".format(e))
                room_buffer = self.find_room_from_id(response.room_id)
                room_buffer.error(m)

                try:
                    item = self.encryption_queue[response.room_id][0]
                    if item.message_type not in ["m.file", "m.video",
                                                 "m.audio", "m.image"]:
                        room_buffer.last_message = item.message
                except IndexError:
                    pass

                self.encryption_queue[response.room_id].clear()
                return

        elif isinstance(response, ShareGroupSessionResponse):
            room_id = response.room_id
            self.group_session_shared[response.room_id] = False
            ignore_unverified = self.ignore_while_sharing[response.room_id]
            self.ignore_while_sharing[response.room_id] = False

            room_buffer = self.room_buffers[room_id]

            while self.encryption_queue[room_id]:
                item = self.encryption_queue[room_id].popleft()
                try:
                    if item.message_type in [
                        "m.file",
                        "m.video",
                        "m.audio",
                        "m.image"
                    ]:
                        ret = self.room_send_upload(item.message)
                    else:
                        assert isinstance(item.message, Formatted)
                        ret = self.room_send_message(
                            room_buffer,
                            item.message,
                            item.message_type,
                            ignore_unverified_devices=ignore_unverified
                        )

                    if not ret:
                        self.encryption_queue[room_id].pop()
                        self.encryption_queue[room_id].appendleft(item)
                        break

                except OlmTrustError:
                    self.encryption_queue[room_id].clear()

                    # If the item is a normal user message store it in the
                    # buffer to enable the send-anyways functionality.
                    if item.message_type not in ["m.file", "m.video",
                                                 "m.audio", "m.image"]:
                        room_buffer.last_message = item.message

                    break

    def create_room_buffer(self, room_id, prev_batch):
        room = self.client.rooms[room_id]
        buf = RoomBuffer(room, self.name, self.homeserver, prev_batch)

        # We sadly don't get a correct summary on full_state from synapse so we
        # can't trust it that the members are fully synced
        # if room.members_synced:
        #     buf.members_fetched = True

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

    def garbage_collect_users(self):
        """ Remove inactive users.
        This tries to keep the number of users added to the nicklist less than
            the configuration option matrix.network.max_nicklist_users. It
            removes users that have not been active for a day until there are
            less than max_nicklist_users or no users are left for removal.
            It never removes users that have a bigger power level than the
            default one.
        This function is run every hour by the server timer callback"""

        now = time.time()
        self.user_gc_time = now

        def day_passed(t1, t2):
            return (t2 - t1) > 86400

        for room_buffer in self.room_buffers.values():
            to_remove = max(
                (len(room_buffer.displayed_nicks) -
                    G.CONFIG.network.max_nicklist_users),
                0
            )

            if not to_remove:
                continue

            removed = 0
            removed_user_ids = []

            for user_id, nick in room_buffer.displayed_nicks.items():
                user = room_buffer.weechat_buffer.users[nick]

                if (not user.speaking_time or
                        day_passed(user.speaking_time, now)):
                    room_buffer.weechat_buffer.part(nick, 0, False)
                    removed_user_ids.append(user_id)
                    removed += 1

                if removed >= to_remove:
                    break

            for user_id in removed_user_ids:
                del room_buffer.displayed_nicks[user_id]

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
        return W.WEECHAT_CONFIG_WRITE_ERROR

    for server in SERVERS.values():
        for option in server.config._option_ptrs.values():
            if not W.config_write_option(config_file, option):
                return W.WEECHAT_CONFIG_WRITE_ERROR

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

    if not server.connected or not server.client.logged_in:
        return W.WEECHAT_RC_OK

    # check lag, disconnect if it's too big
    server.lag = server.client.lag * 1000
    server.lag_done = False
    W.bar_item_update("lag")

    if server.lag > G.CONFIG.network.lag_reconnect * 1000:
        server.disconnect()
        return W.WEECHAT_RC_OK

    for i, message in enumerate(server.client.outgoing_to_device_messages):
        if i >= 5:
            break

        if message in server.to_device_sent:
            continue

        server.to_device(message)
        server.to_device_sent.append(message)

    if server.sync_time and current_time > server.sync_time:
        timeout = 0 if server.transport_type == TransportType.HTTP else 30000
        sync_filter = {
            "room": {
                "timeline": {"limit": 500},
                "state": {"lazy_load_members": True}
            }
        }
        server.sync(timeout, sync_filter)

    if current_time > (server.user_gc_time + 3600):
        server.garbage_collect_users()

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
