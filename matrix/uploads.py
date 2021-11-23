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

"""Module implementing upload functionality."""

from __future__ import unicode_literals

import attr
import time
import json
from typing import Dict, Any
from uuid import uuid1, UUID
from enum import Enum

try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError  # type: ignore

from .globals import SCRIPT_NAME, SERVERS, W, UPLOADS
from .utf import utf8_decode
from .message_renderer import Render
from matrix import globals as G
from nio import Api


class UploadState(Enum):
    created = 0
    active = 1
    finished = 2
    error = 3
    aborted = 4


@attr.s
class Proxy(object):
    ptr = attr.ib(type=str)

    @property
    def name(self):
        return W.infolist_string(self.ptr, "name")

    @property
    def address(self):
        return W.infolist_string(self.ptr, "address")

    @property
    def type(self):
        return W.infolist_string(self.ptr, "type_string")

    @property
    def port(self):
        return str(W.infolist_integer(self.ptr, "port"))

    @property
    def user(self):
        return W.infolist_string(self.ptr, "username")

    @property
    def password(self):
        return W.infolist_string(self.ptr, "password")


@attr.s
class Upload(object):
    """Class representing an upload to a matrix server."""

    server_name = attr.ib(type=str)
    server_address = attr.ib(type=str)
    access_token = attr.ib(type=str)
    room_id = attr.ib(type=str)
    filepath = attr.ib(type=str)
    encrypt = attr.ib(type=bool, default=False)
    file_keys = attr.ib(type=Dict, default=None)

    done = 0
    total = 0

    uuid = None
    buffer = None
    upload_hook = None
    content_uri = None
    file_name = None
    mimetype = "?"
    state = UploadState.created

    def __attrs_post_init__(self):
        self.uuid = uuid1()
        self.buffer = ""

        server = SERVERS[self.server_name]

        proxy_name = server.config.proxy
        proxy = None
        proxies_list = None

        if proxy_name:
            proxies_list = W.infolist_get("proxy", "", proxy_name)
            if proxies_list:
                W.infolist_next(proxies_list)
                proxy = Proxy(proxies_list)

        process_args = {
            "arg1": self.filepath,
            "arg2": self.server_address,
            "arg3": self.access_token,
            "buffer_flush": "1",
        }

        arg_count = 3

        if self.encrypt:
            arg_count += 1
            process_args["arg{}".format(arg_count)] = "--encrypt"

        if not server.config.ssl_verify:
            arg_count += 1
            process_args["arg{}".format(arg_count)] = "--insecure"

        if proxy:
            arg_count += 1
            process_args["arg{}".format(arg_count)] = "--proxy-type"
            arg_count += 1
            process_args["arg{}".format(arg_count)] = proxy.type

            arg_count += 1
            process_args["arg{}".format(arg_count)] = "--proxy-address"
            arg_count += 1
            process_args["arg{}".format(arg_count)] = proxy.address

            arg_count += 1
            process_args["arg{}".format(arg_count)] = "--proxy-port"
            arg_count += 1
            process_args["arg{}".format(arg_count)] = proxy.port

            if proxy.user:
                arg_count += 1
                process_args["arg{}".format(arg_count)] = "--proxy-user"
                arg_count += 1
                process_args["arg{}".format(arg_count)] = proxy.user

            if proxy.password:
                arg_count += 1
                process_args["arg{}".format(arg_count)] = "--proxy-password"
                arg_count += 1
                process_args["arg{}".format(arg_count)] = proxy.password

        self.upload_hook = W.hook_process_hashtable(
            "matrix_upload",
            process_args,
            0,
            "upload_cb",
            str(self.uuid)
        )

        if proxies_list:
            W.infolist_free(proxies_list)

    def abort(self):
        pass

    @property
    def msgtype(self):
        # type: () -> str
        assert self.mimetype
        return Api.mimetype_to_msgtype(self.mimetype)

    @property
    def content(self):
        # type: () -> Dict[Any, Any]
        assert self.content_uri

        if self.encrypt:
            content = {
                "body": self.file_name,
                "msgtype": self.msgtype,
                "file": self.file_keys,
            }
            content["file"]["url"] = self.content_uri
            content["file"]["mimetype"] = self.mimetype

            # TODO thumbnail if it's an image

            return content

        return {
            "msgtype": self.msgtype,
            "body": self.file_name,
            "url": self.content_uri,
        }

    @property
    def render(self):
        # type: () -> str
        assert self.content_uri

        if self.encrypt:
            return Render.encrypted_media(
                self.content_uri,
                self.file_name,
                self.file_keys["key"]["k"],
                self.file_keys["hashes"]["sha256"],
                self.file_keys["iv"],
                mime=self.file_keys.get("mimetype"),
            )

        return Render.media(self.content_uri, self.file_name)


@attr.s
class UploadsBuffer(object):
    """Weechat buffer showing the uploads for a server."""

    _ptr = ""           # type: str
    _selected_line = 0  # type: int
    uploads = UPLOADS

    def __attrs_post_init__(self):
        self._ptr = W.buffer_new(
            SCRIPT_NAME + ".uploads",
            "",
            "",
            "",
            "",
        )
        W.buffer_set(self._ptr, "type", "free")
        W.buffer_set(self._ptr, "title", "Upload list")
        W.buffer_set(self._ptr, "key_bind_meta2-A", "/uploads up")
        W.buffer_set(self._ptr, "key_bind_meta2-B", "/uploads down")
        W.buffer_set(self._ptr, "localvar_set_type", "uploads")

        self.render()

    def move_line_up(self):
        self._selected_line = max(self._selected_line - 1, 0)
        self.render()

    def move_line_down(self):
        self._selected_line = min(
            self._selected_line + 1,
            len(self.uploads) - 1
        )
        self.render()

    def display(self):
        """Display the buffer."""
        W.buffer_set(self._ptr, "display", "1")

    def render(self):
        """Render the new state of the upload buffer."""
        # This function is under the MIT license.
        # Copyright (c) 2016 Vladimir Ignatev
        def progress(count, total):
            bar_len = 60

            if total == 0:
                bar = '-' * bar_len
                return "[{}] {}%".format(bar, "?")

            filled_len = int(round(bar_len * count / float(total)))
            percents = round(100.0 * count / float(total), 1)
            bar = '=' * filled_len + '-' * (bar_len - filled_len)

            return "[{}] {}%".format(bar, percents)

        W.buffer_clear(self._ptr)
        header = "{}{}{}{}{}{}{}{}".format(
            W.color("green"),
            "Actions (letter+enter):",
            W.color("lightgreen"),
            "  [A] Accept",
            "  [C] Cancel",
            "  [R] Remove",
            "  [P] Purge finished",
            "  [Q] Close this buffer"
        )
        W.prnt_y(self._ptr, 0, header)

        for line_number, upload in enumerate(self.uploads.values()):
            line_color = "{},{}".format(
                "white" if line_number == self._selected_line else "default",
                "blue" if line_number == self._selected_line else "default",
            )
            first_line = ("%s%s %-24s %s%s%s %s (%s.%s)" % (
                          W.color(line_color),
                          "*** " if line_number == self._selected_line else "    ",
                          upload.room_id,
                          "\"",
                          upload.filepath,
                          "\"",
                          upload.mimetype,
                          SCRIPT_NAME,
                          upload.server_name,
                          ))
            W.prnt_y(self._ptr, (line_number * 2) + 2, first_line)

            status_color = "{},{}".format("green", "blue")
            status = "{}{}{}".format(
                W.color(status_color),
                upload.state.name,
                W.color(line_color)
            )

            second_line = ("{color}{prefix} {status} {progressbar} "
                           "{done} / {total}").format(
                color=W.color(line_color),
                prefix="*** " if line_number == self._selected_line else "    ",
                status=status,
                progressbar=progress(upload.done, upload.total),
                done=W.string_format_size(upload.done),
                total=W.string_format_size(upload.total))

            W.prnt_y(self._ptr, (line_number * 2) + 3, second_line)


def find_upload(uuid):
    return UPLOADS.get(uuid, None)


def handle_child_message(upload, message):
    if message["type"] == "progress":
        upload.done = message["data"]

    elif message["type"] == "status":
        if message["status"] == "started":
            upload.state = UploadState.active
            upload.total = message["total"]
            upload.mimetype = message["mimetype"]
            upload.file_name = message["file_name"]

        elif message["status"] == "done":
            upload.state = UploadState.finished
            upload.content_uri = message["url"]
            upload.file_keys = message.get("file_keys", None)

            server = SERVERS.get(upload.server_name, None)

            if not server:
                return

            server.room_send_upload(upload)

        elif message["status"] == "error":
            upload.state = UploadState.error

    if G.CONFIG.upload_buffer:
        G.CONFIG.upload_buffer.render()


@utf8_decode
def upload_cb(data, command, return_code, out, err):
    upload = find_upload(UUID(data))

    if not upload:
        return W.WEECHAT_RC_OK

    if return_code == W.WEECHAT_HOOK_PROCESS_ERROR:
        W.prnt("", "Error with command '%s'" % command)
        return W.WEECHAT_RC_OK

    if err != "":
        W.prnt("", "Error with command '%s'" % err)
        upload.state = UploadState.error

    if out != "":
        upload.buffer += out
        messages = upload.buffer.split("\n")
        upload.buffer = ""

        for m in messages:
            try:
                message = json.loads(m)
            except (JSONDecodeError, TypeError):
                upload.buffer += m
                continue

            handle_child_message(upload, message)

    return W.WEECHAT_RC_OK
