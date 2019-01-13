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

"""Module implementing upload functionality."""

from __future__ import unicode_literals

import attr
import time
import json
from enum import Enum

try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError  # type: ignore

from .globals import SCRIPT_NAME, SERVERS, W, CALLS
from .utf import utf8_decode
from matrix import globals as G


def find_call(call_id):
    return CALLS.get(call_id, None)


@utf8_decode
def webrtc_cb(data, command, return_code, out, err):
    call = find_call(data)

    if not call:
        return W.WEECHAT_RC_OK

    if return_code == W.WEECHAT_HOOK_PROCESS_ERROR:
        W.prnt("", "Error with command '%s'" % command)
        return W.WEECHAT_RC_OK

    if err != "":
        W.prnt("", "Webrtc log: '%s'" % err.strip())

    if out != "":
        call.buffer += out
        messages = call.buffer.split("\n")
        call.buffer = ""

        for m in messages:
            try:
                message = json.loads(m)
            except (ValueError, TypeError):
                call.buffer += m
                continue

            print(message)
            call.handle_child_message(message)

    return W.WEECHAT_RC_OK


@attr.s
class CallProcess(object):
    server_name = attr.ib()
    room_id = attr.ib()
    call_id = attr.ib()
    version = attr.ib()
    offer = attr.ib()

    hook = None
    buffer = ""

    def __attrs_post_init__(self):
        self.hook = W.hook_process_hashtable(
            "matrix_webrtc",
            {
                "buffer_flush": "1",
                "stdin": "true",
                "arg1": "answer",
            },
            0,
            "webrtc_cb",
            str(self.call_id)
        )

        print("Sending offer to child")
        self.send(json.dumps(self.offer))

    def send_answer(self, answer):
        print("SENDING ANSWER")
        server = SERVERS.get(self.server_name, None)
        assert server
        content = {
            "version": self.version,
            "call_id": self.call_id,
            "answer": answer
        }
        # TODO this can fail for an encrypted room
        server.room_send_event(
            self.room_id, content, "m.call.answer"
        )

    def handle_child_message(self, message):
        if message["type"] == "answer":
            self.send_answer(message)

    def hangup(self):
        print("Hanging up")
        W.hook_set(self.hook, "signal", "quit")

    def send(self, message):
        message += "\n"
        W.hook_set(self.hook, "stdin", message)

    def add_candidate(self, candidate):
        print("Sending candidate to child")
        candidate["type"] = "candidate"
        self.send(json.dumps(candidate))
