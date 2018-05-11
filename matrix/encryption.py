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
import json
import sqlite3
import pprint

# pylint: disable=redefined-builtin
from builtins import str, bytes

from collections import defaultdict
from functools import wraps
from future.moves.itertools import zip_longest

import matrix.globals

try:
    from olm.account import Account, OlmAccountError
    from olm.session import (Session, InboundSession, OlmSessionError,
                             OlmMessage, OlmPreKeyMessage)
    from olm.group_session import (
        InboundGroupSession,
        OutboundGroupSession,
        OlmGroupSessionError
    )
except ImportError:
    matrix.globals.ENCRYPTION = False

from matrix.globals import W, SERVERS
from matrix.utils import sanitize_id
from matrix.utf import utf8_decode


def own_buffer_or_error(f):

    @wraps(f)
    def wrapper(data, buffer, *args, **kwargs):

        for server in SERVERS.values():
            if buffer in server.buffers.values():
                return f(server.name, buffer, *args, **kwargs)
            elif buffer == server.server_buffer:
                return f(server.name, buffer, *args, **kwargs)

        W.prnt("", "{prefix}matrix: command \"olm\" must be executed on a "
               "matrix buffer (server or channel)".format(
                   prefix=W.prefix("error")))

        return W.WEECHAT_RC_OK

    return wrapper


def encrypt_enabled(f):

    @wraps(f)
    def wrapper(*args, **kwds):
        if matrix.globals.ENCRYPTION:
            return f(*args, **kwds)
        return None

    return wrapper


@encrypt_enabled
def matrix_hook_olm_command():
    W.hook_command(
        # Command name and short description
        "olm",
        "Matrix olm encryption command",
        # Synopsis
        ("info all|blacklisted|private|unverified|verified <filter>||"
         "blacklist <device-id> ||"
         "unverify <device-id> ||"
         "verify <device-id>"),
        # Description
        ("     info: show info about known devices and their keys\n"
         "blacklist: blacklist a device\n"
         " unverify: unverify a device\n"
         "   verify: verify a device\n\n"
         "Examples:\n"),
        # Completions
        ('info all|blacklisted|private|unverified|verified ||'
         'blacklist %(device_ids) ||'
         'unverify %(device_ids) ||'
         'verify %(device_ids)'),
        # Function name
        'matrix_olm_command_cb',
        '')


def olm_cmd_parse_args(args):
    split_args = args.split()

    command = split_args.pop(0) if split_args else "info"

    rest_args = split_args if split_args else []

    return command, rest_args


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


def partition_key(key):
    groups = grouper(key, 4, " ")
    return ' '.join(''.join(g) for g in groups)


@own_buffer_or_error
@utf8_decode
def matrix_olm_command_cb(server_name, buffer, args):
    server = SERVERS[server_name]
    command, args = olm_cmd_parse_args(args)

    if not command or command == "info":
        olm = server.olm

        if not args or args[0] == "private":
            device_msg = ("  - Device ID:       {}\n".format(server.device_id)
                          if server.device_id else "")
            id_key = partition_key(olm.account.identity_keys()["curve25519"])
            fp_key = partition_key(olm.account.identity_keys()["ed25519"])
            message = ("{prefix}matrix: Identity keys:\n"
                       "  - User:            {user}\n"
                       "{device_msg}"
                       "  - Identity key:    {id_key}\n"
                       "  - Fingerprint key: {fp_key}\n").format(
                           prefix=W.prefix("network"),
                           user=server.user,
                           device_msg=device_msg,
                           id_key=id_key,
                           fp_key=fp_key)
            W.prnt(server.server_buffer, message)
        elif args[0] == "all":
            for user, keys in olm.device_keys.items():
                message = ("{prefix}matrix: Identity keys:\n"
                           "  - User: {user}\n").format(
                               prefix=W.prefix("network"),
                               user=user)
                W.prnt(server.server_buffer, message)

                for key in keys:
                    id_key = partition_key(key.keys["curve25519"])
                    fp_key = partition_key(key.keys["ed25519"])
                    device_msg = ("    - Device ID:       {}\n".format(
                        key.device_id) if key.device_id else "")
                    message = ("{device_msg}"
                               "    - Identity key:    {id_key}\n"
                               "    - Fingerprint key: {fp_key}\n\n").format(
                                   device_msg=device_msg,
                                   id_key=id_key,
                                   fp_key=fp_key)
                    W.prnt(server.server_buffer, message)
    else:
        message = ("{prefix}matrix: Command not implemented.".format(
            prefix=W.prefix("error")))
        W.prnt(server.server_buffer, message)

    return W.WEECHAT_RC_OK


class EncryptionError(Exception):
    pass


class OlmDeviceKey():
    def __init__(self, user_id, device_id, key_dict):
        # type: (str, str, Dict[str, str])
        self.user_id = user_id
        self.device_id = device_id
        self.keys = key_dict


class Olm():

    @encrypt_enabled
    def __init__(
        self,
        user,
        device_id,
        session_path,
        database=None,
        account=None,
        sessions=None,
        inbound_group_sessions=None
    ):
        # type: (str, str, str, Account, Dict[str, List[Session]) -> None
        self.user = user
        self.device_id = device_id
        self.session_path = session_path
        self.database = database
        self.device_keys = {}

        if not database:
            db_file = "{}_{}.db".format(user, device_id)
            db_path = os.path.join(session_path, db_file)
            self.database = sqlite3.connect(db_path)
            Olm._check_db_tables(self.database)

        if account:
            self.account = account

        else:
            self.account = Account()
            self._insert_acc_to_db()

        if not sessions:
            sessions = defaultdict(lambda: defaultdict(list))

        if not inbound_group_sessions:
            inbound_group_sessions = defaultdict(dict)

        self.sessions = sessions
        self.inbound_group_sessions = inbound_group_sessions
        self.outbound_group_sessions = {}

    def _create_session(self, sender, sender_key, message):
        W.prnt("", "matrix: Creating session for {}".format(sender))
        session = InboundSession(self.account, message, sender_key)
        W.prnt("", "matrix: Created session for {}".format(sender))
        self.account.remove_one_time_keys(session)
        self._update_acc_in_db()

        return session

    def create_group_session(self, room_id, session_id, session_key):
        W.prnt("", "matrix: Creating group session for {}".format(room_id))
        session = InboundGroupSession(session_key)
        self.inbound_group_sessions[room_id][session_id] = session
        self._store_inbound_group_session(room_id, session)

    def create_outbound_group_session(self, room_id):
        session = OutboundGroupSession()
        self.outbound_group_sessions[room_id] = session
        self.create_group_session(room_id, session.id, session.session_key)

    @encrypt_enabled
    def get_missing_sessions(self, users):
        # type: (List[str]) -> Dict[str, Dict[str, str]]
        missing = {}

        for user in users:
            devices = []

            for key in self.device_keys[user]:
                # we don't need a session for our own device, skip it
                if key.device_id == self.device_id:
                    continue

                if not self.sessions[user][key.device_id]:
                    devices.append(key.device_id)

            if devices:
                missing[user] = {device: "ed25519" for device in devices}

        return missing

    @encrypt_enabled
    def decrypt(self, sender, sender_key, message):
        plaintext = None

        for device_id, session_list in self.sessions[sender].items():
            for session in session_list:
                W.prnt("", "Trying session for device {}".format(device_id))
                try:
                    if isinstance(message, OlmPreKeyMessage):
                        if not session.matches(message):
                            continue

                    W.prnt("", "Decrypting using existing session")
                    plaintext = session.decrypt(message)
                    parsed_plaintext = json.loads(plaintext, encoding='utf-8')
                    W.prnt("", "Decrypted using existing session")
                    return parsed_plaintext
                except OlmSessionError:
                    pass

        try:
            session = self._create_session(sender, sender_key, message)
        except OlmSessionError:
            return None

        try:
            plaintext = session.decrypt(message)
            parsed_plaintext = json.loads(plaintext, encoding='utf-8')

            device_id = sanitize_id(parsed_plaintext["sender_device"])
            self.sessions[sender][device_id].append(session)
            self._store_session(sender, device_id, session)
            return parsed_plaintext
        except OlmSessionError:
            return None

    def group_encrypt(self, room_id, plaintext_dict):
        # type: (str, Dict[str, str]) -> Dict[str, str], Bool
        is_new = False
        plaintext_dict["room_id"] = room_id

        if not room_id in self.outbound_group_sessions:
            self.create_outbound_group_session(room_id)
            is_new = True

        session = self.outbound_group_sessions[room_id]

        ciphertext = session.encrypt(Olm._to_json(plaintext_dict))

        payload_dict = {
            "algorithm": "m.megolm.v1.aes-sha2",
            "sender_key": self.account.identity_keys()["curve25519"],
            "ciphertext": ciphertext,
            "session_id": session.id,
            "device_id": self.device_id
        }

        return payload_dict, is_new

    @encrypt_enabled
    def group_decrypt(self, room_id, session_id, ciphertext):
        if session_id not in self.inbound_group_sessions[room_id]:
            return None

        session = self.inbound_group_sessions[room_id][session_id]
        try:
            plaintext = session.decrypt(ciphertext)
        except OlmGroupSessionError:
            return None

        return plaintext

    def share_group_session(self, room_id, own_id, users):
        group_session = self.outbound_group_sessions[room_id]

        key_content = {
            "algorithm": "m.megolm.v1.aes-sha2",
            "room_id": room_id,
            "session_id": group_session.id,
            "session_key": group_session.session_key,
            "chain_index": group_session.message_index
        }

        payload_dict = {
            "type": "m.room_key",
            "content": key_content,
            # TODO we don't have the user_id in the Olm class
            "sender": own_id,
            "sender_device": self.device_id,
            "keys": {
                "ed25519": self.account.identity_keys()["ed25519"]
            }
        }

        to_device_dict = {
            "messages": {}
        }

        for user in users:

            for key in self.device_keys[user]:
                if key.device_id == self.device_id:
                    continue

                device_payload_dict = payload_dict.copy()
                # TODO sort the sessions
                session = self.sessions[user][key.device_id][0]
                device_payload_dict["recipient"] = user
                device_payload_dict["recipient_keys"] = {
                    "ed25519": key.keys["ed25519"]
                }

                W.prnt("", pprint.pformat(device_payload_dict))

                olm_message = session.encrypt(Olm._to_json(device_payload_dict))

                olm_dict = {
                    "algorithm": "m.olm.v1.curve25519-aes-sha2",
                    "sender_key": self.account.identity_keys()["curve25519"],
                    "ciphertext": {
                        key.keys["curve25519"]: {
                            "type": (0 if isinstance(olm_message,
                                OlmPreKeyMessage) else 1),
                            "body": olm_message.ciphertext
                        }
                    }
                }

                to_device_dict["messages"][user] = {
                    key.device_id: olm_dict
                }

        return to_device_dict
        # return {}

    @classmethod
    @encrypt_enabled
    def from_session_dir(cls, user, device_id, session_path):
        # type: (Server) -> Olm
        db_file = "{}_{}.db".format(user, device_id)
        db_path = os.path.join(session_path, db_file)
        database = sqlite3.connect(db_path)
        Olm._check_db_tables(database)

        cursor = database.cursor()

        cursor.execute("select pickle from olmaccount where user = ?", (user,))
        row = cursor.fetchone()
        account_pickle = row[0]

        cursor.execute("select user, device_id, pickle from olmsessions")
        db_sessions = cursor.fetchall()

        cursor.execute("select room_id, pickle from inbound_group_sessions")
        db_inbound_group_sessions = cursor.fetchall()

        cursor.close()

        sessions = defaultdict(lambda: defaultdict(list))
        inbound_group_sessions = defaultdict(dict)

        try:
            account = Account.from_pickle(bytes(account_pickle, "utf-8"))

            for db_session in db_sessions:
                sessions[db_session[0]][db_session[1]].append(
                    Session.from_pickle(bytes(db_session[2], "utf-8")))

            for db_session in db_inbound_group_sessions:
                session = InboundGroupSession.from_pickle(
                    bytes(db_session[1], "utf-8"))
                inbound_group_sessions[db_session[0]][session.id] = session

            return cls(user, device_id, session_path, database, account,
                       sessions, inbound_group_sessions)
        except (OlmAccountError, OlmSessionError) as error:
            raise EncryptionError(error)

    def _update_acc_in_db(self):
        cursor = self.database.cursor()
        cursor.execute("update olmaccount set pickle=? where user = ?",
                       (self.account.pickle(), self.user))
        self.database.commit()
        cursor.close()

    def _update_sessions_in_db(self):
        cursor = self.database.cursor()

        for user, session_dict in self.sessions.items():
            for device_id, session_list in session_dict.items():
                for session in session_list:
                    cursor.execute("""update olmsessions set pickle=?
                                      where user = ? and session_id = ? and
                                      device_id = ?""",
                                   (session.pickle(), user, session.id(),
                                    device_id))
        self.database.commit()

        cursor.close()

    def _update_inbound_group_sessions(self):
        cursor = self.database.cursor()

        for room_id, session_dict in self.inbound_group_sessions.items():
            for session in session_dict.values():
                cursor.execute("""update inbound_group_sessions set pickle=?
                                  where room_id = ? and session_id = ?""",
                               (session.pickle(), room_id, session.id()))
        self.database.commit()

        cursor.close()

    def _store_session(self, user, device_id, session):
        cursor = self.database.cursor()

        cursor.execute("insert into olmsessions values(?,?,?,?)",
                       (user, device_id, session.id(), session.pickle()))

        self.database.commit()

        cursor.close()

    def _store_inbound_group_session(self, room_id, session):
        cursor = self.database.cursor()

        cursor.execute("insert into inbound_group_sessions values(?,?,?)",
                       (room_id, session.id, session.pickle()))

        self.database.commit()

        cursor.close()

    def _insert_acc_to_db(self):
        cursor = self.database.cursor()
        cursor.execute("insert into olmaccount values (?,?)",
                       (self.user, self.account.pickle()))
        self.database.commit()
        cursor.close()

    @staticmethod
    def _check_db_tables(database):
        cursor = database.cursor()
        cursor.execute("""select name from sqlite_master where type='table'
                          and name='olmaccount'""")
        if not cursor.fetchone():
            cursor.execute("create table olmaccount (user text, pickle text)")
            database.commit()

        cursor.execute("""select name from sqlite_master where type='table'
                          and name='olmsessions'""")
        if not cursor.fetchone():
            cursor.execute("""create table olmsessions (user text,
                              device_id text, session_id text, pickle text)""")
            database.commit()

        cursor.execute("""select name from sqlite_master where type='table'
                          and name='inbound_group_sessions'""")
        if not cursor.fetchone():
            cursor.execute("""create table inbound_group_sessions
                              (room_id text, session_id text, pickle text)""")
            database.commit()

        cursor.close()

    @encrypt_enabled
    def to_session_dir(self):
        # type: (Server) -> None
        try:
            self._update_acc_in_db()
            self._update_sessions_in_db()
        except OlmAccountError as error:
            raise EncryptionError(error)

    def sign_json(self, json_dict):
        signature = self.account.sign(json.dumps(
            json_dict,
            ensure_ascii=False,
            separators=(',', ':'),
            sort_keys=True,
        ))

        return signature

    @staticmethod
    def _to_json(json_dict):
        # type: (Dict[Any, Any]) -> str
        return json.dumps(
            json_dict,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True
        )

    @encrypt_enabled
    def mark_keys_as_published(self):
        self.account.mark_keys_as_published()
