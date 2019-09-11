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


"""Module for rendering matrix messages in Weechat."""

from __future__ import unicode_literals
from nio import Api
from .globals import W
from .colors import Formatted


class Render(object):
    """Class collecting methods for rendering matrix messages in Weechat."""

    @staticmethod
    def _media(url, description):
        return ("{del_color}<{ncolor}{desc}{del_color}>{ncolor} "
                "{del_color}[{ncolor}{url}{del_color}]{ncolor}").format(
                    del_color=W.color("chat_delimiters"),
                    ncolor=W.color("reset"),
                    desc=description, url=url)

    @staticmethod
    def media(mxc, body, homeserver=None):
        """Render a mxc media URI."""
        url = Api.mxc_to_http(mxc, homeserver)
        description = "{}".format(body) if body else "file"
        return Render._media(url, description)

    @staticmethod
    def encrypted_media(mxc, body, key, hash,  iv, homeserver=None):
        """Render a mxc media URI of an encrypted file."""
        http_url = Api.encrypted_mxc_to_plumb(
            mxc,
            key,
            hash,
            iv,
            homeserver
        )
        url = http_url if http_url else mxc
        description = "{}".format(body) if body else "file"
        return Render._media(url, description)

    @staticmethod
    def message(body, formatted_body):
        """Render a room message."""
        if formatted_body:
            formatted = Formatted.from_html(formatted_body)
            return formatted.to_weechat()

        return body

    @staticmethod
    def redacted(censor, reason=None):
        """Render a redacted event message."""
        reason = (
            ', reason: "{reason}"'.format(reason=reason)
            if reason
            else ""
        )

        data = (
            "{del_color}<{log_color}Message redacted by: "
            "{censor}{log_color}{reason}{del_color}>{ncolor}"
        ).format(
            del_color=W.color("chat_delimiters"),
            ncolor=W.color("reset"),
            log_color=W.color("logger.color.backlog_line"),
            censor=censor,
            reason=reason,
        )

        return data

    @staticmethod
    def room_encryption(nick):
        """Render a room encryption event."""
        return "{nick} has enabled encryption in this room".format(nick=nick)

    @staticmethod
    def unknown(message_type, content=None):
        """Render a message of an unknown type."""
        content = (
            ': "{content}"'.format(content=content)
            if content
            else ""
        )
        return "Unknown message of type {t}{c}".format(
            t=message_type,
            c=content
        )

    @staticmethod
    def megolm():
        """Render an undecrypted megolm event."""
        return ("{del_color}<{log_color}Unable to decrypt: "
                "The sender's device has not sent us "
                "the keys for this message{del_color}>{ncolor}").format(
                    del_color=W.color("chat_delimiters"),
                    log_color=W.color("logger.color.backlog_line"),
                    ncolor=W.color("reset"))

    @staticmethod
    def bad(event):
        """Render a malformed event of a known type"""
        return "Bad event received, event type: {t}".format(t=event.type)
