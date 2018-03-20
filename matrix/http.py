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

import json
from enum import Enum, unique


@unique
class RequestType(Enum):
    GET = 0
    POST = 1
    PUT = 2


class HttpResponse:

    def __init__(self, status, headers, body):
        self.status = status  # type: int
        self.headers = headers  # type: Dict[str, str]
        self.body = body  # type: bytes


# yapf: disable
class HttpRequest:
    def __init__(
            self,
            request_type,                        # type: RequestType
            host,                                # type: str
            location,                            # type: str
            data=None,                           # type: Dict[str, Any]
            user_agent='weechat-matrix/{version}'.format(
                version="0.1")  # type: str
    ):
        # type: (...) -> None
        user_agent = 'User-Agent: {agent}'.format(agent=user_agent)
        host_header = 'Host: {host}'.format(host=host)
        keepalive = "Connection: keep-alive"
        request_list = []              # type: List[str]
        accept_header = 'Accept: */*'  # type: str
        end_separator = '\r\n'         # type: str
        payload = ""                   # type: str
        # yapf: enable

        if request_type == RequestType.GET:
            get = 'GET {location} HTTP/1.1'.format(location=location)
            request_list = [
                get, host_header, user_agent, keepalive, accept_header,
                end_separator
            ]

        elif (request_type == RequestType.POST or
              request_type == RequestType.PUT):

            json_data = json.dumps(data, separators=(',', ':'))

            if request_type == RequestType.POST:
                method = "POST"
            else:
                method = "PUT"

            request_line = '{method} {location} HTTP/1.1'.format(
                method=method, location=location)

            type_header = 'Content-Type: application/x-www-form-urlencoded'
            length_header = 'Content-Length: {length}'.format(
                length=len(json_data))

            request_list = [
                request_line, host_header, user_agent, keepalive,
                accept_header, length_header, type_header, end_separator
            ]
            payload = json_data

        request = '\r\n'.join(request_list)

        self.request = request
        self.payload = payload
