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

import os

# See if there is a `venv` directory next to our script, and use that if
# present. This first resolves symlinks, so this also works when we are
# loaded through a symlink (e.g. from autoload).
# See https://virtualenv.pypa.io/en/latest/userguide/#using-virtualenv-without-bin-python
# This does not support pyvenv or the python3 venv module, which do not
# create an activate_this.py: https://stackoverflow.com/questions/27462582
activate_this = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'venv', 'bin', 'activate_this.py')
if os.path.exists(activate_this):
    exec(open(activate_this).read(), {'__file__': activate_this})

import socket
import ssl
import textwrap
# pylint: disable=redefined-builtin
from builtins import str
from itertools import chain
# pylint: disable=unused-import
from typing import Any, AnyStr, Deque, Dict, List, Optional, Set, Text, Tuple

import logbook
import json
import OpenSSL.crypto as crypto
from future.utils import bytes_to_native_str as n
from logbook import Logger, StreamHandler

try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError  # type: ignore


from nio import RemoteProtocolError, RemoteTransportError, TransportType

from matrix import globals as G
from matrix.bar_items import (
    init_bar_items,
    matrix_bar_item_buffer_modes,
    matrix_bar_item_lag,
    matrix_bar_item_name,
    matrix_bar_item_plugin,
    matrix_bar_nicklist_count,
    matrix_bar_typing_notices_cb
)
from matrix.buffer import room_buffer_close_cb, room_buffer_input_cb
# Weechat searches for the registered callbacks in the scope of the main script
# file, import the callbacks here so weechat can find them.
from matrix.commands import (hook_commands, hook_page_up,
                             matrix_command_buf_clear_cb, matrix_command_cb,
                             matrix_command_pgup_cb, matrix_invite_command_cb,
                             matrix_join_command_cb, matrix_kick_command_cb,
                             matrix_me_command_cb, matrix_part_command_cb,
                             matrix_redact_command_cb, matrix_topic_command_cb,
                             matrix_olm_command_cb, matrix_devices_command_cb,
                             matrix_room_command_cb, matrix_uploads_command_cb,
                             matrix_upload_command_cb, matrix_send_anyways_cb,
                             matrix_reply_command_cb)
from matrix.completion import (init_completion, matrix_command_completion_cb,
                               matrix_debug_completion_cb,
                               matrix_message_completion_cb,
                               matrix_olm_device_completion_cb,
                               matrix_olm_user_completion_cb,
                               matrix_server_command_completion_cb,
                               matrix_server_completion_cb,
                               matrix_user_completion_cb,
                               matrix_own_devices_completion_cb,
                               matrix_room_completion_cb)
from matrix.config import (MatrixConfig, config_log_category_cb,
                           config_log_level_cb, config_server_buffer_cb,
                           matrix_config_reload_cb, config_pgup_cb)
from matrix.globals import SCRIPT_NAME, SERVERS, W
from matrix.server import (MatrixServer, create_default_server,
                           matrix_config_server_change_cb,
                           matrix_config_server_read_cb,
                           matrix_config_server_write_cb, matrix_timer_cb,
                           send_cb, matrix_load_users_cb)
from matrix.utf import utf8_decode
from matrix.utils import server_buffer_prnt, server_buffer_set_title

from matrix.uploads import UploadsBuffer, upload_cb

try:
    from urllib.parse import urlunparse
except ImportError:
    from urlparse import urlunparse

# yapf: disable
WEECHAT_SCRIPT_NAME = SCRIPT_NAME
WEECHAT_SCRIPT_DESCRIPTION = "matrix chat plugin"              # type: str
WEECHAT_SCRIPT_AUTHOR = "Damir Jelić <poljar@termina.org.uk>"  # type: str
WEECHAT_SCRIPT_VERSION = "0.2.0"                               # type: str
WEECHAT_SCRIPT_LICENSE = "ISC"                                 # type: str
# yapf: enable


logger = Logger("matrix-cli")


def print_certificate_info(buff, sock, cert):
    cert_pem = ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))

    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

    public_key = x509.get_pubkey()

    key_type = ("RSA" if public_key.type() == crypto.TYPE_RSA else "DSA")
    key_size = str(public_key.bits())
    sha256_fingerprint = x509.digest(n(b"SHA256"))
    sha1_fingerprint = x509.digest(n(b"SHA1"))
    signature_algorithm = x509.get_signature_algorithm()

    key_info = ("key info: {key_type} key {bits} bits, signed using "
                "{algo}").format(
                    key_type=key_type, bits=key_size,
                    algo=n(signature_algorithm))

    validity_info = ("        Begins on:  {before}\n"
                     "        Expires on: {after}").format(
                         before=cert["notBefore"], after=cert["notAfter"])

    rdns = chain(*cert["subject"])
    subject = ", ".join(["{}={}".format(name, value) for name, value in rdns])

    rdns = chain(*cert["issuer"])
    issuer = ", ".join(["{}={}".format(name, value) for name, value in rdns])

    subject = "subject: {sub}, serial number {serial}".format(
        sub=subject, serial=cert["serialNumber"])

    issuer = "issuer: {issuer}".format(issuer=issuer)

    fingerprints = ("        SHA1:   {}\n"
                    "        SHA256: {}").format(n(sha1_fingerprint),
                                                 n(sha256_fingerprint))

    wrapper = textwrap.TextWrapper(
        initial_indent="    - ", subsequent_indent="        ")

    message = ("{prefix}matrix: received certificate\n"
               " - certificate info:\n"
               "{subject}\n"
               "{issuer}\n"
               "{key_info}\n"
               "    - period of validity:\n{validity_info}\n"
               "    - fingerprints:\n{fingerprints}").format(
                   prefix=W.prefix("network"),
                   subject=wrapper.fill(subject),
                   issuer=wrapper.fill(issuer),
                   key_info=wrapper.fill(key_info),
                   validity_info=validity_info,
                   fingerprints=fingerprints)

    W.prnt(buff, message)


def wrap_socket(server, file_descriptor):
    # type: (MatrixServer, int) -> None
    sock = None  # type: socket.socket

    temp_socket = socket.fromfd(file_descriptor, socket.AF_INET,
                                socket.SOCK_STREAM)

    # fromfd() duplicates the file descriptor, we can close the one we got from
    # weechat now since we use the one from our socket when calling hook_fd()
    os.close(file_descriptor)

    # For python 2.7 wrap_socket() doesn't work with sockets created from an
    # file descriptor because fromfd() doesn't return a wrapped socket, the bug
    # was fixed for python 3, more info: https://bugs.python.org/issue13942
    # pylint: disable=protected-access,unidiomatic-typecheck
    if type(temp_socket) == socket._socket.socket:
        # pylint: disable=no-member
        sock = socket._socketobject(_sock=temp_socket)
    else:
        sock = temp_socket

    # fromfd() duplicates the file descriptor but doesn't retain it's blocking
    # non-blocking attribute, so mark the socket as non-blocking even though
    # weechat already did that for us
    sock.setblocking(False)

    message = "{prefix}matrix: Doing SSL handshake...".format(
        prefix=W.prefix("network"))
    W.prnt(server.server_buffer, message)

    ssl_socket = server.ssl_context.wrap_socket(
        sock, do_handshake_on_connect=False,
        server_hostname=server.address)  # type: ssl.SSLSocket

    server.socket = ssl_socket

    try_ssl_handshake(server)


@utf8_decode
def ssl_fd_cb(server_name, file_descriptor):
    server = SERVERS[server_name]

    if server.ssl_hook:
        W.unhook(server.ssl_hook)
        server.ssl_hook = None

    try_ssl_handshake(server)

    return W.WEECHAT_RC_OK


def try_ssl_handshake(server):
    sock = server.socket

    while True:
        try:
            sock.do_handshake()

            cipher = sock.cipher()
            cipher_message = ("{prefix}matrix: Connected using {tls}, and "
                              "{bit} bit {cipher} cipher suite.").format(
                                  prefix=W.prefix("network"),
                                  tls=cipher[1],
                                  bit=cipher[2],
                                  cipher=cipher[0])
            W.prnt(server.server_buffer, cipher_message)

            cert = sock.getpeercert()
            if cert:
                print_certificate_info(server.server_buffer, sock, cert)

            finalize_connection(server)

            return True

        except ssl.SSLWantReadError:
            hook = W.hook_fd(server.socket.fileno(), 1, 0, 0, "ssl_fd_cb",
                             server.name)
            server.ssl_hook = hook

            return False

        except ssl.SSLWantWriteError:
            hook = W.hook_fd(server.socket.fileno(), 0, 1, 0, "ssl_fd_cb",
                             server.name)
            server.ssl_hook = hook

            return False

        except (ssl.SSLError, ssl.CertificateError, socket.error) as error:
            try:
                str_error = error.reason if error.reason else "Unknown error"
            except AttributeError:
                str_error = str(error)

            message = ("{prefix}Error while doing SSL handshake"
                       ": {error}").format(
                           prefix=W.prefix("network"), error=str_error)

            server_buffer_prnt(server, message)

            server_buffer_prnt(
                server, ("{prefix}matrix: disconnecting from server..."
                         ).format(prefix=W.prefix("network")))

            server.disconnect()
            return False


@utf8_decode
def receive_cb(server_name, file_descriptor):
    server = SERVERS[server_name]

    while True:
        try:
            data = server.socket.recv(4096)
        except ssl.SSLWantReadError:
            break
        except socket.error as error:
            errno = "error" + str(error.errno) + " " if error.errno else ""
            str_error = error.strerror if error.strerror else "Unknown error"
            str_error = errno + str_error

            message = ("{prefix}Error while reading from "
                       "socket: {error}").format(
                           prefix=W.prefix("network"), error=str_error)

            server_buffer_prnt(server, message)

            server_buffer_prnt(
                server, ("{prefix}matrix: disconnecting from server..."
                         ).format(prefix=W.prefix("network")))

            server.disconnect()

            return W.WEECHAT_RC_OK

        if not data:
            server_buffer_prnt(
                server,
                "{prefix}matrix: Error while reading from socket".format(
                    prefix=W.prefix("network")))
            server_buffer_prnt(
                server, ("{prefix}matrix: disconnecting from server..."
                         ).format(prefix=W.prefix("network")))

            server.disconnect()
            break

        try:
            server.client.receive(data)
        except (RemoteTransportError, RemoteProtocolError) as e:
            server.error(str(e))
            server.disconnect()
            break

        response = server.client.next_response()

        # Check if we need to send some data back
        data_to_send = server.client.data_to_send()

        if data_to_send:
            server.send(data_to_send)

        if response:
            server.handle_response(response)
            break

    return W.WEECHAT_RC_OK


def finalize_connection(server):
    hook = W.hook_fd(
        server.socket.fileno(),
        1,
        0,
        0,
        "receive_cb",
        server.name
    )

    server.fd_hook = hook
    server.connected = True
    server.connecting = False
    server.reconnect_delay = 0

    negotiated_protocol = (server.socket.selected_alpn_protocol() or
            server.socket.selected_npn_protocol())

    if negotiated_protocol == "h2":
        server.transport_type = TransportType.HTTP2
    else:
        server.transport_type = TransportType.HTTP

    data = server.client.connect(server.transport_type)
    server.send(data)

    server.login_info()


@utf8_decode
def sso_login_cb(server_name, command, return_code, out, err):
    try:
        server = SERVERS[server_name]
    except KeyError:
        message = (
            "{}{}: SSO callback ran, but no server for it was found.").format(
                W.prefix("error"), SCRIPT_NAME)
        W.prnt("", message)

    if return_code == W.WEECHAT_HOOK_PROCESS_ERROR:
        server.error("Error while running the matrix_sso_helper. Please "
                     "make sure that the helper script is executable and can "
                     "be found in your PATH.")
        server.sso_hook = None
        server.disconnect()
        return W.WEECHAT_RC_OK

    # The child process exited mark the hook as done.
    if return_code == 0:
        server.sso_hook = None

    if err != "":
        W.prnt("", "stderr: %s" % err)

    if out == "":
        return W.WEECHAT_RC_OK

    try:
        ret = json.loads(out)
        msgtype = ret.get("type")

        if msgtype == "redirectUrl":
            redirect_url = "http://{}:{}".format(ret["host"], ret["port"])

            login_url = (
                "{}/_matrix/client/r0/login/sso/redirect?redirectUrl={}"
            ).format(server.homeserver.geturl(), redirect_url)

            server.info_highlight(
                "The server requested a single sign-on, please open "
                "this URL in your browser. Note that the "
                "browser needs to run on the same host as Weechat.")
            server.info_highlight(login_url)

            message = {
                "server": server.name,
                "url": login_url
            }
            W.hook_hsignal_send("matrix_sso_login", message)

        elif msgtype == "token":
            token = ret["loginToken"]
            server.login(token=token)

        elif msgtype == "error":
            server.error("Error in the SSO helper {}".format(ret["message"]))

        else:
            server.error("Unknown SSO login message received from child "
                         "process.")

    except JSONDecodeError:
        server.error(
            "Error decoding SSO login message from child process: {}".format(
                out
        ))

    return W.WEECHAT_RC_OK


@utf8_decode
def connect_cb(data, status, gnutls_rc, sock, error, ip_address):
    # pylint: disable=too-many-arguments,too-many-branches
    status_value = int(status)  # type: int
    server = SERVERS[data]

    if status_value == W.WEECHAT_HOOK_CONNECT_OK:
        file_descriptor = int(sock)  # type: int
        server.numeric_address = ip_address
        server_buffer_set_title(server)

        wrap_socket(server, file_descriptor)

        return W.WEECHAT_RC_OK

    elif status_value == W.WEECHAT_HOOK_CONNECT_ADDRESS_NOT_FOUND:
        server.error('{address} not found'.format(address=ip_address))

    elif status_value == W.WEECHAT_HOOK_CONNECT_IP_ADDRESS_NOT_FOUND:
        server.error('IP address not found')

    elif status_value == W.WEECHAT_HOOK_CONNECT_CONNECTION_REFUSED:
        server.error('Connection refused')

    elif status_value == W.WEECHAT_HOOK_CONNECT_PROXY_ERROR:
        server.error('Proxy fails to establish connection to server')

    elif status_value == W.WEECHAT_HOOK_CONNECT_LOCAL_HOSTNAME_ERROR:
        server.error('Unable to set local hostname')

    elif status_value == W.WEECHAT_HOOK_CONNECT_GNUTLS_INIT_ERROR:
        server.error('TLS init error')

    elif status_value == W.WEECHAT_HOOK_CONNECT_GNUTLS_HANDSHAKE_ERROR:
        server.error('TLS Handshake failed')

    elif status_value == W.WEECHAT_HOOK_CONNECT_MEMORY_ERROR:
        server.error('Not enough memory')

    elif status_value == W.WEECHAT_HOOK_CONNECT_TIMEOUT:
        server.error('Timeout')

    elif status_value == W.WEECHAT_HOOK_CONNECT_SOCKET_ERROR:
        server.error('Unable to create socket')
    else:
        server.error('Unexpected error: {status}'.format(status=status_value))

    server.disconnect(reconnect=True)
    return W.WEECHAT_RC_OK


@utf8_decode
def room_close_cb(data, buffer):
    W.prnt("",
           "Buffer '%s' will be closed!" % W.buffer_get_string(buffer, "name"))
    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_unload_cb():
    for server in SERVERS.values():
        server.config.free()

    G.CONFIG.free()

    return W.WEECHAT_RC_OK


def autoconnect(servers):
    for server in servers.values():
        if server.config.autoconnect:
            server.connect()


def debug_buffer_close_cb(data, buffer):
    G.CONFIG.debug_buffer = ""
    return W.WEECHAT_RC_OK


def server_buffer_cb(server_name, buffer, input_data):
    message = ("{}{}: this buffer is not a room buffer!").format(
            W.prefix("error"), SCRIPT_NAME)
    W.prnt(buffer, message)
    return W.WEECHAT_RC_OK


class WeechatHandler(StreamHandler):
    def __init__(self, level=logbook.NOTSET, format_string=None, filter=None,
                 bubble=False):
        StreamHandler.__init__(
            self,
            object(),
            level,
            format_string,
            None,
            filter,
            bubble
        )

    def write(self, item):
        buf = ""

        if G.CONFIG.network.debug_buffer:
            if not G.CONFIG.debug_buffer:
                G.CONFIG.debug_buffer = W.buffer_new(
                    "Matrix Debug", "", "", "debug_buffer_close_cb", "")

            buf = G.CONFIG.debug_buffer

        W.prnt(buf, item)


def buffer_switch_cb(_, _signal, buffer_ptr):
    """Do some buffer operations when we switch buffers.

    This function is called every time we switch a buffer. The pointer of
    the new buffer is given to us by weechat.

    If it is one of our room buffers we check if the members for the room
    aren't fetched and fetch them now if they aren't.

    Read receipts are send out from here as well.
    """
    for server in SERVERS.values():
        if buffer_ptr == server.server_buffer:
            return W.WEECHAT_RC_OK

        if buffer_ptr not in server.buffers.values():
            continue

        room_buffer = server.find_room_from_ptr(buffer_ptr)
        if not room_buffer:
            continue

        last_event_id = room_buffer.last_event_id

        if room_buffer.should_send_read_marker:
            # A buffer may not have any events, in that case no event id is
            # here returned
            if last_event_id:
                server.room_send_read_marker(
                    room_buffer.room.room_id, last_event_id)
                room_buffer.last_read_event = last_event_id

        if not room_buffer.members_fetched:
            room_id = room_buffer.room.room_id
            server.get_joined_members(room_id)

        # The buffer is empty and we are seeing it for the first time.
        # Let us fetch some messages from the room history so it doesn't feel so
        # empty.
        if room_buffer.first_view and room_buffer.weechat_buffer.num_lines < 10:
            # TODO we may want to fetch 10 - num_lines messages here for
            # consistency reasons.
            server.room_get_messages(room_buffer.room.room_id)

        break

    return W.WEECHAT_RC_OK


def typing_notification_cb(data, signal, buffer_ptr):
    """Send out typing notifications if the user is typing.

    This function is called every time the input text is changed.
    It checks if we are on a buffer we own, and if we are sends out a typing
    notification if the room is configured to send them out.
    """
    for server in SERVERS.values():
        room_buffer = server.find_room_from_ptr(buffer_ptr)
        if room_buffer:
            server.room_send_typing_notice(room_buffer)
            return W.WEECHAT_RC_OK

        if buffer_ptr == server.server_buffer:
            return W.WEECHAT_RC_OK

    return W.WEECHAT_RC_OK


def buffer_command_cb(data, _, command):
    """Override the buffer command to allow switching buffers by short name."""
    command = command[7:].strip()

    buffer_subcommands = ["list", "add", "clear", "move", "swap", "cycle",
                          "merge", "unmerge", "hide", "unhide", "renumber",
                          "close", "notify", "localvar", "set", "get"]

    if not command:
        return W.WEECHAT_RC_OK

    command_words = command.split()

    if len(command_words) >= 1:
        if command_words[0] in buffer_subcommands:
            return W.WEECHAT_RC_OK

        elif command_words[0].startswith("*"):
            return W.WEECHAT_RC_OK

        try:
            int(command_words[0])
            return W.WEECHAT_RC_OK
        except ValueError:
            pass

    room_buffers = []

    for server in SERVERS.values():
        room_buffers.extend(server.room_buffers.values())

    sorted_buffers = sorted(
        room_buffers,
        key=lambda b: b.weechat_buffer.number
    )

    for room_buffer in sorted_buffers:
        buffer = room_buffer.weechat_buffer

        if command in buffer.short_name:
            displayed = W.current_buffer() == buffer._ptr

            if displayed:
                continue

            W.buffer_set(buffer._ptr, 'display', '1')
            return W.WEECHAT_RC_OK_EAT

    return W.WEECHAT_RC_OK


if __name__ == "__main__":
    if W.register(WEECHAT_SCRIPT_NAME, WEECHAT_SCRIPT_AUTHOR,
                  WEECHAT_SCRIPT_VERSION, WEECHAT_SCRIPT_LICENSE,
                  WEECHAT_SCRIPT_DESCRIPTION, 'matrix_unload_cb', ''):

        if not W.mkdir_home("matrix", 0o700):
            message = ("{prefix}matrix: Error creating session "
                       "directory").format(prefix=W.prefix("error"))
            W.prnt("", message)

        handler = WeechatHandler()
        handler.format_string = "{record.channel}: {record.message}"
        handler.push_application()

        # TODO if this fails we should abort and unload the script.
        G.CONFIG = MatrixConfig()
        G.CONFIG.read()

        hook_commands()
        init_bar_items()
        init_completion()

        W.hook_command_run("/buffer", "buffer_command_cb", "")
        W.hook_signal("buffer_switch", "buffer_switch_cb", "")
        W.hook_signal("input_text_changed", "typing_notification_cb", "")

        if not SERVERS:
            create_default_server(G.CONFIG)

        autoconnect(SERVERS)
