#!/usr/bin/env -S python3 -u
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


import os
import json
import magic
import requests
import argparse
from urllib.parse import urlparse
from itertools import zip_longest
import urllib3

from nio import Api, UploadResponse, UploadError
from nio.crypto import encrypt_attachment

from json.decoder import JSONDecodeError

urllib3.disable_warnings()


def to_stdout(message):
    print(json.dumps(message), flush=True)


def error(e):
    message = {
        "type": "status",
        "status": "error",
        "message": str(e)
    }
    to_stdout(message)
    os.sys.exit()


def mime_from_file(file):
    try:
        t = magic.from_file(file, mime=True)
    except AttributeError:
        try:
            m = magic.open(magic.MIME)
            m.load()
            t, _ = m.file(file).split(';')
        except AttributeError:
            error('Your \'magic\' module is unsupported. '
                  'Install either https://github.com/ahupp/python-magic '
                  'or https://github.com/file/file/tree/master/python '
                  '(official \'file\' python bindings, available as the '
                  'python-magic package on many distros)')

            raise SystemExit

    return t


class Upload(object):
    def __init__(self, file, chunksize=1 << 13):
        self.file = file
        self.filename = os.path.basename(file)
        self.chunksize = chunksize
        self.totalsize = os.path.getsize(file)
        self.mimetype = mime_from_file(file)
        self.readsofar = 0

    def send_progress(self):
        message = {
            "type": "progress",
            "data": self.readsofar
        }
        to_stdout(message)

    def __iter__(self):
        with open(self.file, 'rb') as file:
            while True:
                data = file.read(self.chunksize)

                if not data:
                    break

                self.readsofar += len(data)
                self.send_progress()

                yield data

    def __len__(self):
        return self.totalsize


def chunk_bytes(iterable, n):
    args = [iter(iterable)] * n
    return (
        bytes(
            (filter(lambda x: x is not None, chunk))
        ) for chunk in zip_longest(*args)
    )


class EncryptedUpload(Upload):
    def __init__(self, file, chunksize=1 << 13):
        super().__init__(file, chunksize)
        self.source_mimetype = self.mimetype
        self.mimetype = "application/octet-stream"

        with open(self.filename, "rb") as file:
            self.ciphertext, self.file_keys = encrypt_attachment(file.read())

    def send_progress(self):
        message = {
            "type": "progress",
            "data": self.readsofar
        }
        to_stdout(message)

    def __iter__(self):
        for chunk in chunk_bytes(self.ciphertext, self.chunksize):
            self.readsofar += len(chunk)
            self.send_progress()
            yield chunk

    def __len__(self):
        return len(self.ciphertext)


class IterableToFileAdapter(object):
    def __init__(self, iterable):
        self.iterator = iter(iterable)
        self.length = len(iterable)

    def read(self, size=-1):
        return next(self.iterator, b'')

    def __len__(self):
        return self.length


def upload_process(args):
    file_path = os.path.expanduser(args.file)
    thumbnail = None

    try:
        if args.encrypt:
            upload = EncryptedUpload(file_path)

            if upload.source_mimetype.startswith("image"):
                # TODO create a thumbnail
                thumbnail = None
        else:
            upload = Upload(file_path)

    except (FileNotFoundError, OSError, IOError) as e:
        error(e)

    try:
        url = urlparse(args.homeserver)
    except ValueError as e:
        error(e)

    upload_url = ("https://{}".format(args.homeserver)
                  if not url.scheme else args.homeserver)
    _, api_path, _ = Api.upload(args.access_token, upload.filename)
    upload_url += api_path

    headers = {
        "Content-type": upload.mimetype,
    }

    proxies = {}

    if args.proxy_address:
        user = args.proxy_user or ""

        if args.proxy_password:
            user += ":{}".format(args.proxy_password)

        if user:
            user += "@"

        proxies = {
            "https": "{}://{}{}:{}/".format(
                args.proxy_type,
                user,
                args.proxy_address,
                args.proxy_port
            )
        }

    message = {
        "type": "status",
        "status": "started",
        "total": upload.totalsize,
        "file_name": upload.filename,
    }

    if isinstance(upload, EncryptedUpload):
        message["mimetype"] = upload.source_mimetype
    else:
        message["mimetype"] = upload.mimetype

    to_stdout(message)

    session = requests.Session()
    session.trust_env = False

    try:
        r = session.post(
            url=upload_url,
            auth=None,
            headers=headers,
            data=IterableToFileAdapter(upload),
            verify=(not args.insecure),
            proxies=proxies
        )
    except (requests.exceptions.RequestException, OSError) as e:
        error(e)

    try:
        json_response = json.loads(r.content)
    except JSONDecodeError:
        error(r.content)

    response = UploadResponse.from_dict(json_response)

    if isinstance(response, UploadError):
        error(str(response))

    message = {
        "type": "status",
        "status": "done",
        "url": response.content_uri
    }

    if isinstance(upload, EncryptedUpload):
        message["file_keys"] = upload.file_keys

    to_stdout(message)

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Encrypt and upload matrix attachments"
    )
    parser.add_argument("file", help="the file that will be uploaded")
    parser.add_argument(
        "homeserver",
        type=str,
        help="the address of the homeserver"
    )
    parser.add_argument(
        "access_token",
        type=str,
        help="the access token to use for the upload"
    )
    parser.add_argument(
        "--encrypt",
        action="store_const",
        const=True,
        default=False,
        help="encrypt the file before uploading it"
    )
    parser.add_argument(
        "--insecure",
        action="store_const",
        const=True,
        default=False,
        help="disable SSL certificate verification"
    )
    parser.add_argument(
        "--proxy-type",
        choices=[
            "http",
            "socks4",
            "socks5"
        ],
        default="http",
        help="type of the proxy that will be used to establish a connection"
    )
    parser.add_argument(
        "--proxy-address",
        type=str,
        help="address of the proxy that will be used to establish a connection"
    )
    parser.add_argument(
        "--proxy-port",
        type=int,
        default=8080,
        help="port of the proxy that will be used to establish a connection"
    )
    parser.add_argument(
        "--proxy-user",
        type=str,
        help="user that will be used for authentication on the proxy"
    )
    parser.add_argument(
        "--proxy-password",
        type=str,
        help="password that will be used for authentication on the proxy"
    )

    args = parser.parse_args()
    upload_process(args)


if __name__ == "__main__":
    main()
