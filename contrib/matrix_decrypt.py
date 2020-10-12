#!/usr/bin/env python3
# matrix_decrypt - Download and decrypt an encrypted attachment
# from a matrix server

# Copyright © 2019 Damir Jelić <poljar@termina.org.uk>
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

import argparse
import requests
import tempfile
import subprocess

from urllib.parse import urlparse, parse_qs
from nio.crypto import decrypt_attachment


def save_file(data):
    """Save data to a temporary file and return its name."""
    tmp_dir = tempfile.gettempdir()

    with tempfile.NamedTemporaryFile(
        prefix='plumber-',
        dir=tmp_dir,
        delete=False
    ) as f:
        f.write(data)
        f.flush()
        return f.name


def main():
    parser = argparse.ArgumentParser(
        description='Download and decrypt matrix attachments'
    )
    parser.add_argument('url', help='the url of the attachment')
    parser.add_argument('file', nargs='?', help='save attachment to <file>')
    parser.add_argument('--plumber',
                        help='program that gets called with the '
                             'dowloaded file')

    args = parser.parse_args()
    url = urlparse(args.url)
    query = parse_qs(url.query)

    if not query["key"] or not query["iv"] or not query["hash"]:
        print("Missing decryption argument")
        return -1

    key = query["key"][0]
    iv = query["iv"][0]
    hash = query["hash"][0]

    http_url = "https://{}{}".format(url.netloc, url.path)

    request = requests.get(http_url)

    if not request.ok:
        print("Error downloading file")
        return -2

    plumber = args.plumber
    plaintext = decrypt_attachment(request.content, key, hash, iv)

    if args.file is None:
        file_name = save_file(plaintext)
        if plumber is None:
            plumber = "xdg-open"
    else:
        file_name = args.file
        open(file_name, "wb").write(plaintext)

    if plumber is not None:
        subprocess.run([plumber, file_name])

    return 0


if __name__ == "__main__":
    main()
