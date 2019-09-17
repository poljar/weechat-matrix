#!/usr/bin/env -S python3 -u
# Copyright 2019 The Matrix.org Foundation CIC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import asyncio
import argparse
import socket
import json
from random import choice
from aiohttp import web

# The browsers ban some known ports, the dynamic port range doesn't contain any
# banned ports, so we use that.
port_range = range(49152, 65535)

shutdown_task = None


def to_weechat(message):
    print(json.dumps(message))


async def get_token(request):
    global shutdown_task

    async def shutdown():
        await asyncio.sleep(1)
        raise KeyboardInterrupt

    token = request.query.get("loginToken")

    if not token:
        raise KeyboardInterrupt

    message = {
        "type": "token",
        "loginToken": token
    }

    # Send the token to weechat.
    to_weechat(message)
    # Initiate a shutdown.
    shutdown_task = asyncio.ensure_future(shutdown())
    # Respond to the browser.
    return web.Response(text="Continuing in Weechat.")


def bind_socket(port=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if port is not None and port != 0:
        sock.bind(("localhost", port))
        return sock

    while True:
        port = choice(port_range)

        try:
            sock.bind(("localhost", port))
        except OSError:
            continue

        return sock


async def wait_for_shutdown_task(_):
    if not shutdown_task:
        return

    try:
        await shutdown_task
    except KeyboardInterrupt:
        pass


def main():
    parser = argparse.ArgumentParser(
        description="Start a web server that waits for a SSO token to be "
                    "passed with a GET request"
    )
    parser.add_argument(
        "-p", "--port",
        help=("the port that the web server will be listening on, if 0 a "
              "random port should be chosen"
        ),
        type=int,
        default=0
    )

    args = parser.parse_args()

    app = web.Application()
    app.add_routes([web.get('/', get_token)])

    if not 0 <= args.port <= 65535:
        raise ValueError("Port needs to be 0-65535")

    try:
        sock = bind_socket(args.port)
    except OSError as e:
        message = {
            "type": "error",
            "message": str(e),
            "code": e.errno
        }
        to_weechat(message)
        return

    host, port = sock.getsockname()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    message = {
        "type": "redirectUrl",
        "host": host,
        "port": port
    }

    to_weechat(message)

    app.on_shutdown.append(wait_for_shutdown_task)
    web.run_app(app, sock=sock, handle_signals=True, print=None)


if __name__ == "__main__":
    main()
