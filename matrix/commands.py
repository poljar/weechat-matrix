# -*- coding: utf-8 -*-

# Copyright © 2018, 2019 Damir Jelić <poljar@termina.org.uk>
# Copyright © 2018, 2019 Denis Kasak <dkasak@termina.org.uk>
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
import argparse
import os
import re
from builtins import str
from future.moves.itertools import zip_longest
from collections import defaultdict
from functools import partial
from nio import EncryptionError

from . import globals as G
from .colors import Formatted
from .globals import SERVERS, W, UPLOADS, SCRIPT_NAME
from .server import MatrixServer
from .utf import utf8_decode
from .utils import key_from_value, tags_from_line_data
from .uploads import UploadsBuffer, Upload


class ParseError(Exception):
    pass


class WeechatArgParse(argparse.ArgumentParser):
    def print_usage(self, file=None):
        pass

    def error(self, message):
        message = (
            "{prefix}Error: {message} for command {command} "
            "(see /help {command})"
        ).format(prefix=W.prefix("error"), message=message, command=self.prog)
        W.prnt("", message)
        raise ParseError


class WeechatCommandParser(object):
    @staticmethod
    def _run_parser(parser, args):
        try:
            parsed_args = parser.parse_args(args.split())
            return parsed_args
        except ParseError:
            return None

    @staticmethod
    def topic(args):
        parser = WeechatArgParse(prog="topic")

        parser.add_argument("-delete", action="store_true")
        parser.add_argument("topic", nargs="*")

        return WeechatCommandParser._run_parser(parser, args)

    @staticmethod
    def kick(args):
        parser = WeechatArgParse(prog="kick")
        parser.add_argument("user_id")
        parser.add_argument("reason", nargs="*")

        return WeechatCommandParser._run_parser(parser, args)

    @staticmethod
    def invite(args):
        parser = WeechatArgParse(prog="invite")
        parser.add_argument("user_id")

        return WeechatCommandParser._run_parser(parser, args)

    @staticmethod
    def join(args):
        parser = WeechatArgParse(prog="join")
        parser.add_argument("room_id")
        return WeechatCommandParser._run_parser(parser, args)

    @staticmethod
    def part(args):
        parser = WeechatArgParse(prog="part")
        parser.add_argument("room_id", nargs="?")
        return WeechatCommandParser._run_parser(parser, args)

    @staticmethod
    def devices(args):
        parser = WeechatArgParse(prog="devices")
        subparsers = parser.add_subparsers(dest="subcommand")
        subparsers.add_parser("list")

        delete_parser = subparsers.add_parser("delete")
        delete_parser.add_argument("device_id")

        name_parser = subparsers.add_parser("set-name")
        name_parser.add_argument("device_id")
        name_parser.add_argument("device_name", nargs="*")

        return WeechatCommandParser._run_parser(parser, args)

    @staticmethod
    def olm(args):
        parser = WeechatArgParse(prog="olm")
        subparsers = parser.add_subparsers(dest="subcommand")

        info_parser = subparsers.add_parser("info")
        info_parser.add_argument(
            "category", nargs="?", default="private",
            choices=[
                "all",
                "blacklisted",
                "private",
                "unverified",
                "verified"
            ])
        info_parser.add_argument("filter", nargs="?")

        verify_parser = subparsers.add_parser("verify")
        verify_parser.add_argument("user_filter")
        verify_parser.add_argument("device_filter", nargs="?")

        unverify_parser = subparsers.add_parser("unverify")
        unverify_parser.add_argument("user_filter")
        unverify_parser.add_argument("device_filter", nargs="?")

        blacklist_parser = subparsers.add_parser("blacklist")
        blacklist_parser.add_argument("user_filter")
        blacklist_parser.add_argument("device_filter", nargs="?")

        unblacklist_parser = subparsers.add_parser("unblacklist")
        unblacklist_parser.add_argument("user_filter")
        unblacklist_parser.add_argument("device_filter", nargs="?")

        ignore_parser = subparsers.add_parser("ignore")
        ignore_parser.add_argument("user_filter")
        ignore_parser.add_argument("device_filter", nargs="?")

        unignore_parser = subparsers.add_parser("unignore")
        unignore_parser.add_argument("user_filter")
        unignore_parser.add_argument("device_filter", nargs="?")

        export_parser = subparsers.add_parser("export")
        export_parser.add_argument("file")
        export_parser.add_argument("passphrase")

        import_parser = subparsers.add_parser("import")
        import_parser.add_argument("file")
        import_parser.add_argument("passphrase")

        return WeechatCommandParser._run_parser(parser, args)

    @staticmethod
    def room(args):
        parser = WeechatArgParse(prog="room")
        subparsers = parser.add_subparsers(dest="subcommand")
        typing_notification = subparsers.add_parser("typing-notifications")
        typing_notification.add_argument(
            "state",
            choices=["enable", "disable", "toggle"]
        )

        read_markers = subparsers.add_parser("read-markers")
        read_markers.add_argument(
            "state",
            choices=["enable", "disable", "toggle"]
        )

        return WeechatCommandParser._run_parser(parser, args)

    @staticmethod
    def uploads(args):
        parser = WeechatArgParse(prog="uploads")
        subparsers = parser.add_subparsers(dest="subcommand")
        subparsers.add_parser("list")
        subparsers.add_parser("listfull")
        subparsers.add_parser("up")
        subparsers.add_parser("down")

        return WeechatCommandParser._run_parser(parser, args)

    @staticmethod
    def upload(args):
        parser = WeechatArgParse(prog="upload")
        parser.add_argument("file")
        return WeechatCommandParser._run_parser(parser, args)


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


def partition_key(key):
    groups = grouper(key, 4, " ")
    return ' '.join(''.join(g) for g in groups)


def hook_commands():
    W.hook_command(
        # Command name and short description
        "matrix",
        "Matrix chat protocol command",
        # Synopsis
        (
            "server add <server-name> <hostname>[:<port>] ||"
            "server delete|list|listfull <server-name> ||"
            "connect <server-name> ||"
            "disconnect <server-name> ||"
            "reconnect <server-name> ||"
            "help <matrix-command>"
        ),
        # Description
        (
            "    server: list, add, or remove Matrix servers\n"
            "   connect: connect to Matrix servers\n"
            "disconnect: disconnect from one or all Matrix servers\n"
            " reconnect: reconnect to server(s)\n"
            "      help: show detailed command help\n\n"
            "Use /matrix help [command] to find out more.\n"
        ),
        # Completions
        (
            "server %(matrix_server_commands)|%* ||"
            "connect %(matrix_servers) ||"
            "disconnect %(matrix_servers) ||"
            "reconnect %(matrix_servers) ||"
            "help %(matrix_commands)"
        ),
        # Function name
        "matrix_command_cb",
        "",
    )

    W.hook_command(
        # Command name and short description
        "redact",
        "redact messages",
        # Synopsis
        ('<event-id>[:"<message-part>"] [<reason>]'),
        # Description
        (
            "    event-id: event id of the message that will be redacted\n"
            "message-part: an initial part of the message (ignored, only "
            "used\n"
            "              as visual feedback when using completion)\n"
            "      reason: the redaction reason\n"
        ),
        # Completions
        ("%(matrix_messages)"),
        # Function name
        "matrix_redact_command_cb",
        "",
    )

    W.hook_command(
        # Command name and short description
        "topic",
        "get/set the room topic",
        # Synopsis
        ("[<topic>|-delete]"),
        # Description
        ("  topic: topic to set\n" "-delete: delete room topic"),
        # Completions
        "",
        # Callback
        "matrix_topic_command_cb",
        "",
    )

    W.hook_command(
        # Command name and short description
        "me",
        "send an emote message to the current room",
        # Synopsis
        ("<message>"),
        # Description
        ("message: message to send"),
        # Completions
        "",
        # Callback
        "matrix_me_command_cb",
        "",
    )

    W.hook_command(
        # Command name and short description
        "kick",
        "kick a user from the current room",
        # Synopsis
        ("<user-id> [<reason>]"),
        # Description
        (
            "user-id: user-id to kick\n"
            " reason: reason why the user was kicked"
        ),
        # Completions
        ("%(matrix_users)"),
        # Callback
        "matrix_kick_command_cb",
        "",
    )

    W.hook_command(
        # Command name and short description
        "invite",
        "invite a user to the current room",
        # Synopsis
        ("<user-id>"),
        # Description
        ("user-id: user-id to invite"),
        # Completions
        ("%(matrix_users)"),
        # Callback
        "matrix_invite_command_cb",
        "",
    )

    W.hook_command(
        # Command name and short description
        "join",
        "join a room",
        # Synopsis
        ("<room-id>|<room-alias>"),
        # Description
        (
            "   room-id: room-id of the room to join\n"
            "room-alias: room alias of the room to join"
        ),
        # Completions
        "",
        # Callback
        "matrix_join_command_cb",
        "",
    )

    W.hook_command(
        # Command name and short description
        "part",
        "leave a room",
        # Synopsis
        ("[<room-name>]"),
        # Description
        ("   room-name: room name of the room to leave"),
        # Completions
        "",
        # Callback
        "matrix_part_command_cb",
        "",
    )

    W.hook_command(
        # Command name and short description
        "devices",
        "list, delete or rename matrix devices",
        # Synopsis
        ("list ||"
         "delete <device-id> ||"
         "set-name <name>"
         ),
        # Description
        ("device-id: device id of the device to delete\n"
         "     name: new device name to set\n"),
        # Completions
        ("list ||"
         "delete %(matrix_own_devices) ||"
         "set-name %(matrix_own_devices)"),
        # Callback
        "matrix_devices_command_cb",
        "",
    )

    W.hook_command(
        # Command name and short description
        "olm",
        "Matrix olm encryption configuration command",
        # Synopsis
        ("info all|blacklisted|ignored|private|unverified|verified <filter>||"
         "blacklist <user-id> <device-id> ||"
         "unverify <user-id> <device-id> ||"
         "verify <user-id> <device-id> ||"
         "ignore <user-id> <device-id> ||"
         "unignore <user-id> <device-id> ||"
         "export <file-name> <passphrase> ||"
         "import <file-name> <passphrase>"
         ),
        # Description
        ("       info: show info about known devices and their keys\n"
         "  blacklist: blacklist a device\n"
         "unblacklist: unblacklist a device\n"
         "   unverify: unverify a device\n"
         "     verify: verify a device\n"
         "     ignore: ignore an unverifiable but non-blacklist-worthy device\n"
         "   unignore: unignore a device\n"
         "     export: export encryption keys\n"
         "     import: import encryption keys\n\n"
         "Examples:"
         "\n  /olm verify @example:example.com *"
         "\n  /olm info all example*"
         ),
        # Completions
        ('info all|blacklisted|ignored|private|unverified|verified ||'
         'blacklist %(olm_user_ids) %(olm_devices) ||'
         'unblacklist %(olm_user_ids) %(olm_devices) ||'
         'unverify %(olm_user_ids) %(olm_devices) ||'
         'verify %(olm_user_ids) %(olm_devices) ||'
         'ignore %(olm_user_ids) %(olm_devices) ||'
         'unignore %(olm_user_ids) %(olm_devices) ||'
         'export %(filename) ||'
         'import %(filename)'
         ),
        # Function name
        'matrix_olm_command_cb',
        '')

    W.hook_command(
        # Command name and short description
        "room",
        "change room state",
        # Synopsis
        ("typing-notifications <state>||"
         "read-markers <state>"
         ),
        # Description
        ("state: one of enable, disable or toggle\n"),
        # Completions
        ("typing-notifications enable|disable|toggle||"
         "read-markers enable|disable|toggle"
        ),
        # Callback
        "matrix_room_command_cb",
        "",
    )

    # W.hook_command(
    #     # Command name and short description
    #     "uploads",
    #     "Open the uploads buffer or list uploads in the core buffer",
    #     # Synopsis
    #     ("list||"
    #      "listfull"
    #      ),
    #     # Description
    #     (""),
    #     # Completions
    #     ("list ||"
    #      "listfull"),
    #     # Callback
    #     "matrix_uploads_command_cb",
    #     "",
    # )

    W.hook_command(
        # Command name and short description
        "upload",
        "Upload a file to a room",
        # Synopsis
        ("<file>"),
        # Description
        (""),
        # Completions
        ("%(filename)"),
        # Callback
        "matrix_upload_command_cb",
        "",
    )

    W.hook_command_run("/buffer clear", "matrix_command_buf_clear_cb", "")

    if G.CONFIG.network.fetch_backlog_on_pgup:
        hook_page_up()


def format_device(device_id, fp_key):
    fp_key = partition_key(fp_key)
    message = ("    - Device ID:    {device_color}{device_id}{ncolor}\n"
               "      - Device key: {key_color}{fp_key}{ncolor}").format(
                       device_color=W.color("chat_channel"),
                       device_id=device_id,
                       ncolor=W.color("reset"),
                       key_color=W.color("chat_server"),
                       fp_key=fp_key)
    return message


def olm_info_command(server, args):
    def print_devices(
        device_store,
        filter_regex,
        device_category="All",
        predicate=None,
    ):
        user_strings = []
        try:
            filter_regex = re.compile(args.filter) if args.filter else None
        except re.error as e:
            server.error("Invalid regular expression: {}.".format(e.args[0]))
            return

        for user_id in sorted(device_store.users):
            device_strings = []
            for device in device_store.active_user_devices(user_id):
                if filter_regex:
                    if (not filter_regex.search(user_id) and
                            not filter_regex.search(device.id)):
                        continue

                if predicate:
                    if not predicate(device):
                        continue

                device_strings.append(format_device(
                    device.id,
                    device.ed25519
                ))

            if not device_strings:
                continue

            d_string = "\n".join(device_strings)
            message = ("  - User: {user_color}{user}{ncolor}\n").format(
                    user_color=W.color("chat_nick"),
                    user=user_id,
                    ncolor=W.color("reset"))
            message += d_string
            user_strings.append(message)

        if not user_strings:
            message = ("{prefix}matrix: No matching devices "
                       "found.").format(prefix=W.prefix("error"))
            W.prnt(server.server_buffer, message)
            return

        server.info("{} devices:\n".format(device_category))
        W.prnt(server.server_buffer, "\n".join(user_strings))

    olm = server.client.olm

    if args.category == "private":
        fp_key = partition_key(olm.account.identity_keys["ed25519"])
        message = ("Identity keys:\n"
                   "  - User:        {user_color}{user}{ncolor}\n"
                   "  - Device ID:   {device_color}{device_id}{ncolor}\n"
                   "  - Device key:  {key_color}{fp_key}{ncolor}\n"
                   "").format(
                       user_color=W.color("chat_self"),
                       ncolor=W.color("reset"),
                       user=olm.user_id,
                       device_color=W.color("chat_channel"),
                       device_id=olm.device_id,
                       key_color=W.color("chat_server"),
                       fp_key=fp_key)
        server.info(message)

    elif args.category == "all":
        print_devices(olm.device_store, args.filter)

    elif args.category == "verified":
        print_devices(
            olm.device_store,
            args.filter,
            "Verified",
            olm.is_device_verified
        )

    elif args.category == "unverified":
        def predicate(device):
            return not olm.is_device_verified(device)

        print_devices(
            olm.device_store,
            args.filter,
            "Unverified",
            predicate
        )

    elif args.category == "blacklisted":
        print_devices(
            olm.device_store,
            args.filter,
            "Blacklisted",
            olm.is_device_blacklisted
        )


def olm_action_command(server, args, category, error_category, prefix, action):
    device_store = server.client.olm.device_store
    users = []

    if args.user_filter == "*":
        users = device_store.users
    else:
        users = [x for x in device_store.users if args.user_filter in x]

    user_devices = {
        user: device_store.active_user_devices(user) for user in users
    }

    if args.device_filter and args.device_filter != "*":
        filtered_user_devices = {}
        for user, device_list in user_devices.items():
            filtered_devices = filter(
                lambda x: args.device_filter in x.id,
                device_list
            )
            filtered_user_devices[user] = list(filtered_devices)
        user_devices = filtered_user_devices

    changed_devices = defaultdict(list)

    for user, device_list in user_devices.items():
        for device in device_list:
            if action(device):
                changed_devices[user].append(device)

    if not changed_devices:
        message = ("{prefix}matrix: No matching {error_category} devices "
                   "found.").format(
                       prefix=W.prefix("error"),
                       error_category=error_category
                   )
        W.prnt(server.server_buffer, message)
        return

    user_strings = []
    for user_id, device_list in changed_devices.items():
        device_strings = []
        message = ("  - User: {user_color}{user}{ncolor}\n").format(
                user_color=W.color("chat_nick"),
                user=user_id,
                ncolor=W.color("reset"))
        for device in device_list:
            device_strings.append(format_device(
                device.id,
                device.ed25519
            ))
        if not device_strings:
            continue

        d_string = "\n".join(device_strings)
        message += d_string
        user_strings.append(message)

    W.prnt(server.server_buffer,
           "{}matrix: {} key(s):\n".format(W.prefix("prefix"), category))
    W.prnt(server.server_buffer, "\n".join(user_strings))
    pass


def olm_verify_command(server, args):
    olm_action_command(
        server,
        args,
        "Verified",
        "unverified",
        "join",
        server.client.verify_device
    )


def olm_unverify_command(server, args):
    olm_action_command(
        server,
        args,
        "Unverified",
        "verified",
        "quit",
        server.client.unverify_device
    )


def olm_blacklist_command(server, args):
    olm_action_command(
        server,
        args,
        "Blacklisted",
        "unblacklisted",
        "join",
        server.client.blacklist_device
    )


def olm_unblacklist_command(server, args):
    olm_action_command(
        server,
        args,
        "Unblacklisted",
        "blacklisted",
        "join",
        server.client.unblacklist_device
    )


def olm_ignore_command(server, args):
    olm_action_command(
        server,
        args,
        "Ignored",
        "ignored",
        "join",
        server.client.ignore_device
    )


def olm_unignore_command(server, args):
    olm_action_command(
        server,
        args,
        "Unignored",
        "unignored",
        "join",
        server.client.unignore_device
    )


def olm_export_command(server, args):
    file_path = os.path.expanduser(args.file)
    try:
        server.client.export_keys(file_path, args.passphrase)
    except (OSError, IOError) as e:
        server.error("Error exporting keys: {}".format(str(e)))

    server.info("Succesfully exported keys")

def olm_import_command(server, args):
    file_path = os.path.expanduser(args.file)
    try:
        server.client.import_keys(file_path, args.passphrase)
    except (OSError, IOError, EncryptionError) as e:
        server.error("Error importing keys: {}".format(str(e)))

    server.info("Succesfully imported keys")


@utf8_decode
def matrix_olm_command_cb(data, buffer, args):
    def command(server, data, buffer, args):
        parsed_args = WeechatCommandParser.olm(args)
        if not parsed_args:
            return W.WEECHAT_RC_OK

        if not server.client.olm:
            W.prnt(server.server_buffer, "{}matrix: Olm account isn't "
                   "loaded.".format(W.prefix("error")))
            return W.WEECHAT_RC_OK

        if not parsed_args.subcommand or parsed_args.subcommand == "info":
            olm_info_command(server, parsed_args)
        elif parsed_args.subcommand == "export":
            olm_export_command(server, parsed_args)
        elif parsed_args.subcommand == "import":
            olm_import_command(server, parsed_args)
        elif parsed_args.subcommand == "verify":
            olm_verify_command(server, parsed_args)
        elif parsed_args.subcommand == "unverify":
            olm_unverify_command(server, parsed_args)
        elif parsed_args.subcommand == "blacklist":
            olm_blacklist_command(server, parsed_args)
        elif parsed_args.subcommand == "unblacklist":
            olm_unblacklist_command(server, parsed_args)
        elif parsed_args.subcommand == "ignore":
            olm_ignore_command(server, parsed_args)
        elif parsed_args.subcommand == "unignore":
            olm_unignore_command(server, parsed_args)
        else:
            message = ("{prefix}matrix: Command not implemented.".format(
                prefix=W.prefix("error")))
            W.prnt(server.server_buffer, message)

        W.bar_item_update("buffer_modes")
        W.bar_item_update("matrix_modes")

        return W.WEECHAT_RC_OK

    for server in SERVERS.values():
        if buffer in server.buffers.values():
            return command(server, data, buffer, args)
        elif buffer == server.server_buffer:
            return command(server, data, buffer, args)

    W.prnt("", "{prefix}matrix: command \"olm\" must be executed on a "
           "matrix buffer (server or channel)".format(
               prefix=W.prefix("error")
           ))

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_devices_command_cb(data, buffer, args):
    for server in SERVERS.values():
        if buffer in server.buffers.values() or buffer == server.server_buffer:
            parsed_args = WeechatCommandParser.devices(args)
            if not parsed_args:
                return W.WEECHAT_RC_OK

            if not parsed_args.subcommand or parsed_args.subcommand == "list":
                server.devices()
            elif parsed_args.subcommand == "delete":
                server.delete_device(parsed_args.device_id)
            elif parsed_args.subcommand == "set-name":
                new_name = " ".join(parsed_args.device_name).strip("\"")
                server.rename_device(parsed_args.device_id, new_name)

            return W.WEECHAT_RC_OK

    W.prnt("", "{prefix}matrix: command \"devices\" must be executed on a "
           "matrix buffer (server or channel)".format(
               prefix=W.prefix("error")
           ))

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_me_command_cb(data, buffer, args):
    for server in SERVERS.values():
        if buffer in server.buffers.values():

            if not server.connected:
                message = (
                    "{prefix}matrix: you are not connected to " "the server"
                ).format(prefix=W.prefix("error"))
                W.prnt(server.server_buffer, message)
                return W.WEECHAT_RC_ERROR

            room_buffer = server.find_room_from_ptr(buffer)

            if not args:
                return W.WEECHAT_RC_OK

            formatted_data = Formatted.from_input_line(args)

            server.room_send_message(room_buffer, formatted_data, "m.emote")
            return W.WEECHAT_RC_OK

        if buffer == server.server_buffer:
            message = (
                '{prefix}matrix: command "me" must be '
                "executed on a Matrix channel buffer"
            ).format(prefix=W.prefix("error"))
            W.prnt("", message)
            return W.WEECHAT_RC_OK

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_topic_command_cb(data, buffer, args):
    parsed_args = WeechatCommandParser.topic(args)
    if not parsed_args:
        return W.WEECHAT_RC_OK

    for server in SERVERS.values():
        if buffer == server.server_buffer:
            server.error(
                'command "topic" must be ' "executed on a Matrix room buffer"
            )
            return W.WEECHAT_RC_OK

        room = server.find_room_from_ptr(buffer)
        if not room:
            continue

        if not parsed_args.topic and not parsed_args.delete:
            # TODO print the current topic
            return W.WEECHAT_RC_OK

        if parsed_args.delete and parsed_args.topic:
            # TODO error message
            return W.WEECHAT_RC_OK

        topic = "" if parsed_args.delete else " ".join(parsed_args.topic)
        content = {"topic": topic}
        server.room_send_state(room, content, "m.room.topic")

        return W.WEECHAT_RC_OK


def matrix_fetch_old_messages(server, room_id):
    room_buffer = server.find_room_from_id(room_id)
    room = room_buffer.room

    if room_buffer.backlog_pending:
        return

    prev_batch = room.prev_batch

    if not prev_batch:
        return

    raise NotImplementedError


def check_server_existence(server_name, servers):
    if server_name not in servers:
        message = "{prefix}matrix: No such server: {server}".format(
            prefix=W.prefix("error"), server=server_name
        )
        W.prnt("", message)
        return False
    return True


def hook_page_up():
    G.CONFIG.page_up_hook = W.hook_command_run(
        "/window page_up", "matrix_command_pgup_cb", ""
    )


@utf8_decode
def matrix_command_buf_clear_cb(data, buffer, command):
    for server in SERVERS.values():
        if buffer in server.buffers.values():
            room_buffer = server.find_room_from_ptr(buffer)
            room_buffer.room.prev_batch = server.next_batch

            return W.WEECHAT_RC_OK

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_command_pgup_cb(data, buffer, command):
    # TODO the highlight status of a line isn't allowed to be updated/changed
    # via hdata, therefore the highlight status of a messages can't be
    # reoredered this would need to be fixed in weechat
    # TODO we shouldn't fetch and print out more messages than
    # max_buffer_lines_number or older messages than max_buffer_lines_minutes
    for server in SERVERS.values():
        if buffer in server.buffers.values():
            window = W.window_search_with_buffer(buffer)

            first_line_displayed = bool(
                W.window_get_integer(window, "first_line_displayed")
            )

            if first_line_displayed:
                room_id = key_from_value(server.buffers, buffer)
                server.room_get_messages(room_id)

            return W.WEECHAT_RC_OK

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_join_command_cb(data, buffer, args):
    parsed_args = WeechatCommandParser.join(args)
    if not parsed_args:
        return W.WEECHAT_RC_OK

    for server in SERVERS.values():
        if buffer in server.buffers.values() or buffer == server.server_buffer:
            server.room_join(parsed_args.room_id)
            break

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_part_command_cb(data, buffer, args):
    parsed_args = WeechatCommandParser.part(args)
    if not parsed_args:
        return W.WEECHAT_RC_OK

    for server in SERVERS.values():
        if buffer in server.buffers.values() or buffer == server.server_buffer:
            room_id = parsed_args.room_id

            if not room_id:
                if buffer == server.server_buffer:
                    server.error(
                        'command "part" must be '
                        "executed on a Matrix room buffer or a room "
                        "name needs to be given"
                    )
                    return W.WEECHAT_RC_OK

                room_buffer = server.find_room_from_ptr(buffer)
                room_id = room_buffer.room.room_id

            server.room_leave(room_id)
            break

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_invite_command_cb(data, buffer, args):
    parsed_args = WeechatCommandParser.invite(args)
    if not parsed_args:
        return W.WEECHAT_RC_OK

    for server in SERVERS.values():
        if buffer == server.server_buffer:
            server.error(
                'command "invite" must be ' "executed on a Matrix room buffer"
            )
            return W.WEECHAT_RC_OK

        room = server.find_room_from_ptr(buffer)
        if not room:
            continue

        user_id = parsed_args.user_id
        user_id = user_id if user_id.startswith("@") else "@" + user_id

        server.room_invite(room, user_id)
        break

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_room_command_cb(data, buffer, args):
    parsed_args = WeechatCommandParser.room(args)
    if not parsed_args:
        return W.WEECHAT_RC_OK

    for server in SERVERS.values():
        if buffer == server.server_buffer:
            server.error(
                'command "room" must be ' "executed on a Matrix room buffer"
            )
            return W.WEECHAT_RC_OK

        room = server.find_room_from_ptr(buffer)
        if not room:
            continue

        if not parsed_args.subcommand or parsed_args.subcommand == "list":
            server.error("command no subcommand found")
            return W.WEECHAT_RC_OK

        if parsed_args.subcommand == "typing-notifications":
            if parsed_args.state == "enable":
                room.typing_enabled = True
            elif parsed_args.state == "disable":
                room.typing_enabled = False
            elif parsed_args.state == "toggle":
                room.typing_enabled = not room.typing_enabled
            break

        elif parsed_args.subcommand == "read-markers":
            if parsed_args.state == "enable":
                room.read_markers_enabled = True
            elif parsed_args.state == "disable":
                room.read_markers_enabled = False
            elif parsed_args.state == "toggle":
                room.read_markers_enabled = not room.read_markers_enabled
            break

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_uploads_command_cb(data, buffer, args):
    if not args:
        if not G.CONFIG.upload_buffer:
            G.CONFIG.upload_buffer = UploadsBuffer()
        G.CONFIG.upload_buffer.display()
        return W.WEECHAT_RC_OK

    parsed_args = WeechatCommandParser.uploads(args)
    if not parsed_args:
        return W.WEECHAT_RC_OK

    if parsed_args.subcommand == "list":
        pass
    elif parsed_args.subcommand == "listfull":
        pass
    elif parsed_args.subcommand == "up":
        if G.CONFIG.upload_buffer:
            G.CONFIG.upload_buffer.move_line_up()
    elif parsed_args.subcommand == "down":
        if G.CONFIG.upload_buffer:
            G.CONFIG.upload_buffer.move_line_down()

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_upload_command_cb(data, buffer, args):
    parsed_args = WeechatCommandParser.upload(args)
    if not parsed_args:
        return W.WEECHAT_RC_OK

    for server in SERVERS.values():
        if buffer == server.server_buffer:
            server.error(
                'command "upload" must be ' "executed on a Matrix room buffer"
            )
            return W.WEECHAT_RC_OK

        room_buffer = server.find_room_from_ptr(buffer)
        if not room_buffer:
            continue

        upload = Upload(
            server.name,
            server.config.address,
            server.client.access_token,
            room_buffer.room.room_id,
            parsed_args.file,
            room_buffer.room.encrypted
        )
        UPLOADS[upload.uuid] = upload

        if G.CONFIG.upload_buffer:
            G.CONFIG.upload_buffer.render()

        break

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_kick_command_cb(data, buffer, args):
    parsed_args = WeechatCommandParser.kick(args)
    if not parsed_args:
        return W.WEECHAT_RC_OK

    for server in SERVERS.values():
        if buffer == server.server_buffer:
            server.error(
                'command "kick" must be ' "executed on a Matrix room buffer"
            )
            return W.WEECHAT_RC_OK

        room = server.find_room_from_ptr(buffer)
        if not room:
            continue

        user_id = parsed_args.user_id
        user_id = user_id if user_id.startswith("@") else "@" + user_id
        reason = " ".join(parsed_args.reason) if parsed_args.reason else None

        server.room_kick(room, user_id, reason)
        break

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_redact_command_cb(data, buffer, args):
    def already_redacted(line):
        if SCRIPT_NAME + "_redacted" in line.tags:
            return True
        return False

    def predicate(event_id, line):
        event_tag = SCRIPT_NAME + "_id_{}".format(event_id)
        tags = line.tags

        if event_tag in tags:
            return True

        return False

    for server in SERVERS.values():
        if buffer in server.buffers.values():
            room_buffer = server.find_room_from_ptr(buffer)

            matches = re.match(
                r"^(\$[a-zA-Z0-9]+:([a-z0-9])(([a-z0-9-]{1,61})?[a-z0-9]{1})?"
                r"(\.[a-z0-9](([a-z0-9-]{1,61})?[a-z0-9]{1})?)?"
                r"(\.[a-zA-Z]{2,4})+)(:\".*\")? ?(.*)?$",
                args
            )

            if not matches:
                message = (
                    "{prefix}matrix: Invalid command "
                    "arguments (see /help redact)"
                ).format(prefix=W.prefix("error"))
                W.prnt("", message)
                return W.WEECHAT_RC_ERROR

            groups = matches.groups()
            event_id, reason = (groups[0], groups[-1])

            lines = room_buffer.weechat_buffer.find_lines(
                partial(predicate, event_id), max_lines=1
            )

            if not lines:
                room_buffer.error(
                    "No such message with event id "
                    "{event_id} found.".format(event_id=event_id))
                return W.WEECHAT_RC_OK

            if already_redacted(lines[0]):
                room_buffer.error("Event already redacted.")
                return W.WEECHAT_RC_OK

            server.room_send_redaction(room_buffer, event_id, reason)

            return W.WEECHAT_RC_OK

        if buffer == server.server_buffer:
            message = (
                '{prefix}matrix: command "redact" must be '
                "executed on a Matrix channel buffer"
            ).format(prefix=W.prefix("error"))
            W.prnt("", message)
            return W.WEECHAT_RC_OK

    return W.WEECHAT_RC_OK


def matrix_command_help(args):
    if not args:
        message = (
            "{prefix}matrix: Too few arguments for command "
            '"/matrix help" (see /matrix help help)'
        ).format(prefix=W.prefix("error"))
        W.prnt("", message)
        return

    for command in args:
        message = ""

        if command == "connect":
            message = (
                "{delimiter_color}[{ncolor}matrix{delimiter_color}]  "
                "{ncolor}{cmd_color}/connect{ncolor} "
                "<server-name> [<server-name>...]"
                "\n\n"
                "connect to Matrix server(s)"
                "\n\n"
                "server-name: server to connect to"
                "(internal name)"
            ).format(
                delimiter_color=W.color("chat_delimiters"),
                cmd_color=W.color("chat_buffer"),
                ncolor=W.color("reset"),
            )

        elif command == "disconnect":
            message = (
                "{delimiter_color}[{ncolor}matrix{delimiter_color}]  "
                "{ncolor}{cmd_color}/disconnect{ncolor} "
                "<server-name> [<server-name>...]"
                "\n\n"
                "disconnect from Matrix server(s)"
                "\n\n"
                "server-name: server to disconnect"
                "(internal name)"
            ).format(
                delimiter_color=W.color("chat_delimiters"),
                cmd_color=W.color("chat_buffer"),
                ncolor=W.color("reset"),
            )

        elif command == "reconnect":
            message = (
                "{delimiter_color}[{ncolor}matrix{delimiter_color}]  "
                "{ncolor}{cmd_color}/reconnect{ncolor} "
                "<server-name> [<server-name>...]"
                "\n\n"
                "reconnect to Matrix server(s)"
                "\n\n"
                "server-name: server to reconnect"
                "(internal name)"
            ).format(
                delimiter_color=W.color("chat_delimiters"),
                cmd_color=W.color("chat_buffer"),
                ncolor=W.color("reset"),
            )

        elif command == "server":
            message = (
                "{delimiter_color}[{ncolor}matrix{delimiter_color}]  "
                "{ncolor}{cmd_color}/server{ncolor} "
                "add <server-name> <hostname>[:<port>]"
                "\n                  "
                "delete|list|listfull <server-name>"
                "\n\n"
                "list, add, or remove Matrix servers"
                "\n\n"
                "       list: list servers (without argument, this "
                "list is displayed)\n"
                "   listfull: list servers with detailed info for each "
                "server\n"
                "        add: add a new server\n"
                "     delete: delete a server\n"
                "server-name: server to reconnect (internal name)\n"
                "   hostname: name or IP address of server\n"
                "       port: port of server (default: 8448)\n"
                "\n"
                "Examples:"
                "\n  /matrix server listfull"
                "\n  /matrix server add matrix matrix.org:80"
                "\n  /matrix server delete matrix"
            ).format(
                delimiter_color=W.color("chat_delimiters"),
                cmd_color=W.color("chat_buffer"),
                ncolor=W.color("reset"),
            )

        elif command == "help":
            message = (
                "{delimiter_color}[{ncolor}matrix{delimiter_color}]  "
                "{ncolor}{cmd_color}/help{ncolor} "
                "<matrix-command> [<matrix-command>...]"
                "\n\n"
                "display help about Matrix commands"
                "\n\n"
                "matrix-command: a Matrix command name"
                "(internal name)"
            ).format(
                delimiter_color=W.color("chat_delimiters"),
                cmd_color=W.color("chat_buffer"),
                ncolor=W.color("reset"),
            )

        else:
            message = (
                '{prefix}matrix: No help available, "{command}" '
                "is not a matrix command"
            ).format(prefix=W.prefix("error"), command=command)

        W.prnt("", "")
        W.prnt("", message)

        return


def matrix_server_command_listfull(args):
    def get_value_string(value, default_value):
        if value == default_value:
            if not value:
                value = "''"
            value_string = "  ({value})".format(value=value)
        else:
            value_string = "{color}{value}{ncolor}".format(
                color=W.color("chat_value"),
                value=value,
                ncolor=W.color("reset"),
            )

        return value_string

    for server_name in args:
        if server_name not in SERVERS:
            continue

        server = SERVERS[server_name]
        connected = ""

        W.prnt("", "")

        if server.connected:
            connected = "connected"
        else:
            connected = "not connected"

        message = (
            "Server: {server_color}{server}{delimiter_color}"
            " [{ncolor}{connected}{delimiter_color}]"
            "{ncolor}"
        ).format(
            server_color=W.color("chat_server"),
            server=server.name,
            delimiter_color=W.color("chat_delimiters"),
            connected=connected,
            ncolor=W.color("reset"),
        )

        W.prnt("", message)

        option = server.config._option_ptrs["autoconnect"]
        default_value = W.config_string_default(option)
        value = W.config_string(option)

        value_string = get_value_string(value, default_value)
        message = "  autoconnect. : {value}".format(value=value_string)

        W.prnt("", message)

        option = server.config._option_ptrs["address"]
        default_value = W.config_string_default(option)
        value = W.config_string(option)

        value_string = get_value_string(value, default_value)
        message = "  address. . . : {value}".format(value=value_string)

        W.prnt("", message)

        option = server.config._option_ptrs["port"]
        default_value = str(W.config_integer_default(option))
        value = str(W.config_integer(option))

        value_string = get_value_string(value, default_value)
        message = "  port . . . . : {value}".format(value=value_string)

        W.prnt("", message)

        option = server.config._option_ptrs["username"]
        default_value = W.config_string_default(option)
        value = W.config_string(option)

        value_string = get_value_string(value, default_value)
        message = "  username . . : {value}".format(value=value_string)

        W.prnt("", message)

        option = server.config._option_ptrs["password"]
        value = W.config_string(option)

        if value:
            value = "(hidden)"

        value_string = get_value_string(value, "")
        message = "  password . . : {value}".format(value=value_string)

        W.prnt("", message)


def matrix_server_command_delete(args):
    for server_name in args:
        if check_server_existence(server_name, SERVERS):
            server = SERVERS[server_name]

            if server.connected:
                message = (
                    "{prefix}matrix: you can not delete server "
                    "{color}{server}{ncolor} because you are "
                    'connected to it. Try "/matrix disconnect '
                    '{color}{server}{ncolor}" before.'
                ).format(
                    prefix=W.prefix("error"),
                    color=W.color("chat_server"),
                    ncolor=W.color("reset"),
                    server=server.name,
                )
                W.prnt("", message)
                return

            for buf in server.buffers.values():
                W.buffer_close(buf)

            if server.server_buffer:
                W.buffer_close(server.server_buffer)

            for option in server.config._option_ptrs.values():
                W.config_option_free(option)

            message = (
                "matrix: server {color}{server}{ncolor} has been " "deleted"
            ).format(
                server=server.name,
                color=W.color("chat_server"),
                ncolor=W.color("reset"),
            )

            del SERVERS[server.name]
            server = None

            W.prnt("", message)


def matrix_server_command_add(args):
    if len(args) < 2:
        message = (
            "{prefix}matrix: Too few arguments for command "
            '"/matrix server add" (see /matrix help server)'
        ).format(prefix=W.prefix("error"))
        W.prnt("", message)
        return
    if len(args) > 4:
        message = (
            "{prefix}matrix: Too many arguments for command "
            '"/matrix server add" (see /matrix help server)'
        ).format(prefix=W.prefix("error"))
        W.prnt("", message)
        return

    def remove_server(server):
        for option in server.config._option_ptrs.values():
            W.config_option_free(option)
        del SERVERS[server.name]

    server_name = args[0]

    if server_name in SERVERS:
        message = (
            "{prefix}matrix: server {color}{server}{ncolor} "
            "already exists, can't add it"
        ).format(
            prefix=W.prefix("error"),
            color=W.color("chat_server"),
            server=server_name,
            ncolor=W.color("reset"),
        )
        W.prnt("", message)
        return

    server = MatrixServer(server_name, G.CONFIG._ptr)
    SERVERS[server.name] = server

    if len(args) >= 2:
        try:
            host, port = args[1].split(":", 1)
        except ValueError:
            host, port = args[1], None

        return_code = W.config_option_set(
            server.config._option_ptrs["address"], host, 1
        )

        if return_code == W.WEECHAT_CONFIG_OPTION_SET_ERROR:
            remove_server(server)
            message = (
                "{prefix}Failed to set address for server "
                "{color}{server}{ncolor}, failed to add "
                "server."
            ).format(
                prefix=W.prefix("error"),
                color=W.color("chat_server"),
                server=server.name,
                ncolor=W.color("reset"),
            )

            W.prnt("", message)
            server = None
            return

        if port:
            return_code = W.config_option_set(
                server.config._option_ptrs["port"], port, 1
            )
            if return_code == W.WEECHAT_CONFIG_OPTION_SET_ERROR:
                remove_server(server)
                message = (
                    "{prefix}Failed to set port for server "
                    "{color}{server}{ncolor}, failed to add "
                    "server."
                ).format(
                    prefix=W.prefix("error"),
                    color=W.color("chat_server"),
                    server=server.name,
                    ncolor=W.color("reset"),
                )

                W.prnt("", message)
                server = None
                return

    if len(args) >= 3:
        user = args[2]
        return_code = W.config_option_set(
            server.config._option_ptrs["username"], user, 1
        )

        if return_code == W.WEECHAT_CONFIG_OPTION_SET_ERROR:
            remove_server(server)
            message = (
                "{prefix}Failed to set user for server "
                "{color}{server}{ncolor}, failed to add "
                "server."
            ).format(
                prefix=W.prefix("error"),
                color=W.color("chat_server"),
                server=server.name,
                ncolor=W.color("reset"),
            )

            W.prnt("", message)
            server = None
            return

    if len(args) == 4:
        password = args[3]

        return_code = W.config_option_set(
            server.config._option_ptrs["password"], password, 1
        )
        if return_code == W.WEECHAT_CONFIG_OPTION_SET_ERROR:
            remove_server(server)
            message = (
                "{prefix}Failed to set password for server "
                "{color}{server}{ncolor}, failed to add "
                "server."
            ).format(
                prefix=W.prefix("error"),
                color=W.color("chat_server"),
                server=server.name,
                ncolor=W.color("reset"),
            )
            W.prnt("", message)
            server = None
            return

    message = (
        "matrix: server {color}{server}{ncolor} " "has been added"
    ).format(
        server=server.name,
        color=W.color("chat_server"),
        ncolor=W.color("reset"),
    )
    W.prnt("", message)


def matrix_server_command(command, args):
    def list_servers(_):
        if SERVERS:
            W.prnt("", "\nAll matrix servers:")
            for server in SERVERS:
                W.prnt(
                    "",
                    "    {color}{server}".format(
                        color=W.color("chat_server"), server=server
                    ),
                )

    # TODO the argument for list and listfull is used as a match word to
    # find/filter servers, we're currently match exactly to the whole name
    if command == "list":
        list_servers(args)
    elif command == "listfull":
        matrix_server_command_listfull(args)
    elif command == "add":
        matrix_server_command_add(args)
    elif command == "delete":
        matrix_server_command_delete(args)
    else:
        message = (
            "{prefix}matrix: Error: unknown matrix server command, "
            '"{command}" (type /matrix help server for help)'
        ).format(prefix=W.prefix("error"), command=command)
        W.prnt("", message)


@utf8_decode
def matrix_command_cb(data, buffer, args):
    def connect_server(args):
        for server_name in args:
            if check_server_existence(server_name, SERVERS):
                server = SERVERS[server_name]
                server.connect()

    def disconnect_server(args):
        for server_name in args:
            if check_server_existence(server_name, SERVERS):
                server = SERVERS[server_name]
                if server.connected or server.reconnect_time:
                    # W.unhook(server.timer_hook)
                    # server.timer_hook = None
                    server.access_token = ""
                    server.disconnect(reconnect=False)

    split_args = list(filter(bool, args.split(" ")))

    if len(split_args) < 1:
        message = (
            "{prefix}matrix: Too few arguments for command "
            '"/matrix" '
            "(see /help matrix)"
        ).format(prefix=W.prefix("error"))
        W.prnt("", message)
        return W.WEECHAT_RC_ERROR

    command, args = split_args[0], split_args[1:]

    if command == "connect":
        connect_server(args)

    elif command == "disconnect":
        disconnect_server(args)

    elif command == "reconnect":
        disconnect_server(args)
        connect_server(args)

    elif command == "server":
        if len(args) >= 1:
            subcommand, args = args[0], args[1:]
            matrix_server_command(subcommand, args)
        else:
            matrix_server_command("list", "")

    elif command == "help":
        matrix_command_help(args)

    else:
        message = (
            "{prefix}matrix: Error: unknown matrix command, "
            '"{command}" (type /help matrix for help)'
        ).format(prefix=W.prefix("error"), command=command)
        W.prnt("", message)

    return W.WEECHAT_RC_OK
