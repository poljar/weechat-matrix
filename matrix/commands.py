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

import re
import argparse

import matrix.globals
from matrix.globals import W, OPTIONS, SERVERS

from matrix.utf import utf8_decode
from matrix.utils import key_from_value, tags_from_line_data
from matrix.server import MatrixServer
from matrix.colors import Formatted


class ParseError(Exception):
    pass


class WeechatArgParse(argparse.ArgumentParser):
    def print_usage(self, file):
        pass

    def error(self, message):
        m = ("{prefix}Error: {message} for command {command} "
             "(see /help {command})").format(prefix=W.prefix("error"),
                                             message=message,
                                             command=self.prog)
        W.prnt("", m)
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


def hook_commands():
    W.hook_command(
        # Command name and short description
        'matrix',
        'Matrix chat protocol command',
        # Synopsis
        ('server add <server-name> <hostname>[:<port>] ||'
         'server delete|list|listfull <server-name> ||'
         'connect <server-name> ||'
         'disconnect <server-name> ||'
         'reconnect <server-name> ||'
         'help <matrix-command>'),
        # Description
        ('    server: list, add, or remove Matrix servers\n'
         '   connect: connect to Matrix servers\n'
         'disconnect: disconnect from one or all Matrix servers\n'
         ' reconnect: reconnect to server(s)\n\n'
         '      help: show detailed command help\n\n'
         'Use /matrix help [command] to find out more.\n'),
        # Completions
        ('server %(matrix_server_commands)|%* ||'
         'connect %(matrix_servers) ||'
         'disconnect %(matrix_servers) ||'
         'reconnect %(matrix_servers) ||'
         'help %(matrix_commands)'),
        # Function name
        'matrix_command_cb',
        '')

    W.hook_command(
        # Command name and short description
        'redact',
        'redact messages',
        # Synopsis
        ('<message-number>[:"<message-part>"] [<reason>]'),
        # Description
        ("message-number: number of message to redact (starting from 1 for\n"
         "                the last message received, counting up)\n"
         "  message-part: an initial part of the message (ignored, only used\n"
         "                as visual feedback when using completion)\n"
         "        reason: the redaction reason\n"),
        # Completions
        ('%(matrix_messages)'),
        # Function name
        'matrix_redact_command_cb',
        '')

    W.hook_command(
        # Command name and short description
        "topic",
        "get/set the room topic",
        # Synopsis
        ("[<topic>|-delete]"),
        # Description
        ("  topic: topic to set\n"
         "-delete: delete room topic"),
        # Completions
        "",
        # Callback
        "matrix_topic_command_cb",
        "")

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
        "")

    W.hook_command(
        # Command name and short description
        "kick",
        "kick a user from the current room",
        # Synopsis
        ("<user-id> [<reason>]"),
        # Description
        ("user-id: user-id to kick\n"
         " reason: reason why the user was kicked"),
        # Completions
        ("%(matrix_users)"),
        # Callback
        "matrix_kick_command_cb",
        "")

    # TODO those should be hook_command() calls
    # W.hook_command_run('/join', 'matrix_command_join_cb', '')
    # W.hook_command_run('/part', 'matrix_command_part_cb', '')
    # W.hook_command_run('/invite', 'matrix_command_invite_cb', '')

    W.hook_command_run('/buffer clear', 'matrix_command_buf_clear_cb', '')

    # if OPTIONS.enable_backlog:
        # hook_page_up()


@utf8_decode
def matrix_me_command_cb(data, buffer, args):
    for server in SERVERS.values():
        if buffer in server.buffers.values():

            if not server.connected:
                message = ("{prefix}matrix: you are not connected to "
                           "the server").format(prefix=W.prefix("error"))
                W.prnt(server.server_buffer, message)
                return W.WEECHAT_RC_ERROR

            room_buffer = server.find_room_from_ptr(buffer)

            if not args:
                return W.WEECHAT_RC_OK

            formatted_data = Formatted.from_input_line(args)

            server.room_send_message(room_buffer, formatted_data, "m.emote")
            return W.WEECHAT_RC_OK

        elif buffer == server.server_buffer:
            message = ("{prefix}matrix: command \"me\" must be "
                       "executed on a Matrix channel buffer"
                       ).format(prefix=W.prefix("error"))
            W.prnt("", message)
            return W.WEECHAT_RC_OK


@utf8_decode
def matrix_topic_command_cb(data, buffer, args):
    parsed_args = WeechatCommandParser.topic(args)
    if not parsed_args:
        return W.WEECHAT_RC_OK

    for server in SERVERS.values():
        if buffer == server.server_buffer:
            server.error("command \"topic\" must be "
                         "executed on a Matrix room buffer")
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
            prefix=W.prefix("error"), server=server_name)
        W.prnt("", message)
        return False
    return True


def hook_page_up():
    OPTIONS.page_up_hook = W.hook_command_run('/window page_up',
                                              'matrix_command_pgup_cb', '')


@utf8_decode
def matrix_command_buf_clear_cb(data, buffer, command):
    for server in SERVERS.values():
        if buffer in server.buffers.values():
            room_id = key_from_value(server.buffers, buffer)
            server.rooms[room_id].prev_batch = server.next_batch

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
                W.window_get_integer(window, "first_line_displayed"))

            if first_line_displayed:
                room_id = key_from_value(server.buffers, buffer)
                matrix_fetch_old_messages(server, room_id)

            return W.WEECHAT_RC_OK

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_command_join_cb(data, buffer, command):

    def join(server, args):
        split_args = args.split(" ", 1)

        # TODO handle join for non public rooms
        if len(split_args) != 2:
            message = ("{prefix}Error with command \"/join\" (help on "
                       "command: /help join)").format(prefix=W.prefix("error"))
            W.prnt("", message)
            return

        _, room_id = split_args

        raise NotImplementedError

    for server in SERVERS.values():
        if buffer in server.buffers.values():
            join(server, command)
            return W.WEECHAT_RC_OK_EAT
        elif buffer == server.server_buffer:
            join(server, command)
            return W.WEECHAT_RC_OK_EAT

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_command_part_cb(data, buffer, command):

    def part(server, buffer, args):
        rooms = []

        split_args = args.split(" ", 1)

        if len(split_args) == 1:
            if buffer == server.server_buffer:
                message = (
                    "{prefix}Error with command \"/part\" (help on "
                    "command: /help part)").format(prefix=W.prefix("error"))
                W.prnt("", message)
                return

            rooms = [key_from_value(server.buffers, buffer)]

        else:
            _, rooms = split_args
            rooms = rooms.split(" ")

        raise NotImplementedError

    for server in SERVERS.values():
        if buffer in server.buffers.values():
            part(server, buffer, command)
            return W.WEECHAT_RC_OK_EAT
        elif buffer == server.server_buffer:
            part(server, buffer, command)
            return W.WEECHAT_RC_OK_EAT

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_command_invite_cb(data, buffer, command):

    def invite(server, buf, args):
        split_args = args.split(" ", 1)

        # TODO handle join for non public rooms
        if len(split_args) != 2:
            message = (
                "{prefix}Error with command \"/invite\" (help on "
                "command: /help invite)").format(prefix=W.prefix("error"))
            W.prnt("", message)
            return

        _, invitee = split_args
        room_id = key_from_value(server.buffers, buf)

        raise NotImplementedError

    for server in SERVERS.values():
        if buffer in server.buffers.values():
            invite(server, buffer, command)
            return W.WEECHAT_RC_OK_EAT

    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_kick_command_cb(data, buffer, args):
    parsed_args = WeechatCommandParser.kick(args)
    if not parsed_args:
        return W.WEECHAT_RC_OK

    for server in SERVERS.values():
        if buffer == server.server_buffer:
            server.error("command \"kick\" must be "
                         "executed on a Matrix room buffer")
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


def event_id_from_line(buf, target_number):
    # type: (weechat.buffer, int) -> str
    own_lines = W.hdata_pointer(W.hdata_get('buffer'), buf, 'own_lines')
    if own_lines:
        line = W.hdata_pointer(W.hdata_get('lines'), own_lines, 'last_line')

        line_number = 1

        while line:
            line_data = W.hdata_pointer(W.hdata_get('line'), line, 'data')

            if line_data:
                tags = tags_from_line_data(line_data)

                # Only count non redacted user messages
                if ("matrix_message" in tags and
                        'matrix_redacted' not in tags and
                        "matrix_new_redacted" not in tags):

                    if line_number == target_number:
                        for tag in tags:
                            if tag.startswith("matrix_id"):
                                event_id = tag[10:]
                                return event_id

                    line_number += 1

            line = W.hdata_move(W.hdata_get('line'), line, -1)

    return ""


@utf8_decode
def matrix_redact_command_cb(data, buffer, args):
    for server in SERVERS.values():
        if buffer in server.buffers.values():
            room_buffer = server.find_room_from_ptr(buffer)

            matches = re.match(r"(\d+)(:\".*\")? ?(.*)?", args)

            if not matches:
                message = ("{prefix}matrix: Invalid command "
                           "arguments (see /help redact)"
                           ).format(prefix=W.prefix("error"))
                W.prnt("", message)
                return W.WEECHAT_RC_ERROR

            line_string, _, reason = matches.groups()
            line = int(line_string)

            event_id = event_id_from_line(buffer, line)

            if not event_id:
                message = ("{prefix}matrix: No such message with number "
                           "{number} found").format(
                               prefix=W.prefix("error"), number=line)
                W.prnt("", message)
                return W.WEECHAT_RC_OK

            server.room_send_redaction(room_buffer, event_id, reason)

            return W.WEECHAT_RC_OK

        elif buffer == server.server_buffer:
            message = ("{prefix}matrix: command \"redact\" must be "
                       "executed on a Matrix channel buffer"
                       ).format(prefix=W.prefix("error"))
            W.prnt("", message)
            return W.WEECHAT_RC_OK

    return W.WEECHAT_RC_OK


def matrix_command_help(args):
    if not args:
        message = ("{prefix}matrix: Too few arguments for command "
                   "\"/matrix help\" (see /matrix help help)"
                   ).format(prefix=W.prefix("error"))
        W.prnt("", message)
        return

    for command in args:
        message = ""

        if command == "connect":
            message = ("{delimiter_color}[{ncolor}matrix{delimiter_color}]  "
                       "{ncolor}{cmd_color}/connect{ncolor} "
                       "<server-name> [<server-name>...]"
                       "\n\n"
                       "connect to Matrix server(s)"
                       "\n\n"
                       "server-name: server to connect to"
                       "(internal name)").format(
                           delimiter_color=W.color("chat_delimiters"),
                           cmd_color=W.color("chat_buffer"),
                           ncolor=W.color("reset"))

        elif command == "disconnect":
            message = ("{delimiter_color}[{ncolor}matrix{delimiter_color}]  "
                       "{ncolor}{cmd_color}/disconnect{ncolor} "
                       "<server-name> [<server-name>...]"
                       "\n\n"
                       "disconnect from Matrix server(s)"
                       "\n\n"
                       "server-name: server to disconnect"
                       "(internal name)").format(
                           delimiter_color=W.color("chat_delimiters"),
                           cmd_color=W.color("chat_buffer"),
                           ncolor=W.color("reset"))

        elif command == "reconnect":
            message = ("{delimiter_color}[{ncolor}matrix{delimiter_color}]  "
                       "{ncolor}{cmd_color}/reconnect{ncolor} "
                       "<server-name> [<server-name>...]"
                       "\n\n"
                       "reconnect to Matrix server(s)"
                       "\n\n"
                       "server-name: server to reconnect"
                       "(internal name)").format(
                           delimiter_color=W.color("chat_delimiters"),
                           cmd_color=W.color("chat_buffer"),
                           ncolor=W.color("reset"))

        elif command == "server":
            message = ("{delimiter_color}[{ncolor}matrix{delimiter_color}]  "
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
                       "\n  /matrix server del matrix").format(
                           delimiter_color=W.color("chat_delimiters"),
                           cmd_color=W.color("chat_buffer"),
                           ncolor=W.color("reset"))

        elif command == "help":
            message = ("{delimiter_color}[{ncolor}matrix{delimiter_color}]  "
                       "{ncolor}{cmd_color}/help{ncolor} "
                       "<matrix-command> [<matrix-command>...]"
                       "\n\n"
                       "display help about Matrix commands"
                       "\n\n"
                       "matrix-command: a Matrix command name"
                       "(internal name)").format(
                           delimiter_color=W.color("chat_delimiters"),
                           cmd_color=W.color("chat_buffer"),
                           ncolor=W.color("reset"))

        else:
            message = ("{prefix}matrix: No help available, \"{command}\" "
                       "is not a matrix command").format(
                           prefix=W.prefix("error"), command=command)

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
                ncolor=W.color("reset"))

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

        message = ("Server: {server_color}{server}{delimiter_color}"
                   " [{ncolor}{connected}{delimiter_color}]"
                   "{ncolor}").format(
                       server_color=W.color("chat_server"),
                       server=server.name,
                       delimiter_color=W.color("chat_delimiters"),
                       connected=connected,
                       ncolor=W.color("reset"))

        W.prnt("", message)

        option = server.config.options["autoconnect"]
        default_value = W.config_string_default(option)
        value = W.config_string(option)

        value_string = get_value_string(value, default_value)
        message = "  autoconnect. : {value}".format(value=value_string)

        W.prnt("", message)

        option = server.config.options["address"]
        default_value = W.config_string_default(option)
        value = W.config_string(option)

        value_string = get_value_string(value, default_value)
        message = "  address. . . : {value}".format(value=value_string)

        W.prnt("", message)

        option = server.config.options["port"]
        default_value = str(W.config_integer_default(option))
        value = str(W.config_integer(option))

        value_string = get_value_string(value, default_value)
        message = "  port . . . . : {value}".format(value=value_string)

        W.prnt("", message)

        option = server.config.options["username"]
        default_value = W.config_string_default(option)
        value = W.config_string(option)

        value_string = get_value_string(value, default_value)
        message = "  username . . : {value}".format(value=value_string)

        W.prnt("", message)

        option = server.config.options["password"]
        value = W.config_string(option)

        if value:
            value = "(hidden)"

        value_string = get_value_string(value, '')
        message = "  password . . : {value}".format(value=value_string)

        W.prnt("", message)


def matrix_server_command_delete(args):
    for server_name in args:
        if check_server_existence(server_name, SERVERS):
            server = SERVERS[server_name]

            if server.connected:
                message = ("{prefix}matrix: you can not delete server "
                           "{color}{server}{ncolor} because you are "
                           "connected to it. Try \"/matrix disconnect "
                           "{color}{server}{ncolor}\" before.").format(
                               prefix=W.prefix("error"),
                               color=W.color("chat_server"),
                               ncolor=W.color("reset"),
                               server=server.name)
                W.prnt("", message)
                return

            for buf in server.buffers.values():
                W.buffer_close(buf)

            if server.server_buffer:
                W.buffer_close(server.server_buffer)

            for option in server.config.options.values():
                W.config_option_free(option)

            message = ("matrix: server {color}{server}{ncolor} has been "
                       "deleted").format(
                           server=server.name,
                           color=W.color("chat_server"),
                           ncolor=W.color("reset"))

            del SERVERS[server.name]
            server = None

            W.prnt("", message)


def matrix_server_command_add(args):
    if len(args) < 2:
        message = ("{prefix}matrix: Too few arguments for command "
                   "\"/matrix server add\" (see /matrix help server)"
                  ).format(prefix=W.prefix("error"))
        W.prnt("", message)
        return
    elif len(args) > 4:
        message = ("{prefix}matrix: Too many arguments for command "
                   "\"/matrix server add\" (see /matrix help server)"
                  ).format(prefix=W.prefix("error"))
        W.prnt("", message)
        return

    def remove_server(server):
        for option in server.config.options.values():
            W.config_option_free(option)
        del SERVERS[server.name]

    server_name = args[0]

    if server_name in SERVERS:
        message = ("{prefix}matrix: server {color}{server}{ncolor} "
                   "already exists, can't add it").format(
                       prefix=W.prefix("error"),
                       color=W.color("chat_server"),
                       server=server_name,
                       ncolor=W.color("reset"))
        W.prnt("", message)
        return

    server = MatrixServer(server_name, matrix.globals.CONFIG)
    SERVERS[server.name] = server

    if len(args) >= 2:
        try:
            host, port = args[1].split(":", 1)
        except ValueError:
            host, port = args[1], None

        return_code = W.config_option_set(
            server.config.options["address"],
            host,
            1
        )

        if return_code == W.WEECHAT_CONFIG_OPTION_SET_ERROR:
            remove_server(server)
            message = ("{prefix}Failed to set address for server "
                       "{color}{server}{ncolor}, failed to add "
                       "server.").format(
                           prefix=W.prefix("error"),
                           color=W.color("chat_server"),
                           server=server.name,
                           ncolor=W.color("reset"))

            W.prnt("", message)
            server = None
            return

        if port:
            return_code = W.config_option_set(
                server.config.options["port"],
                port,
                1
            )
            if return_code == W.WEECHAT_CONFIG_OPTION_SET_ERROR:
                remove_server(server)
                message = ("{prefix}Failed to set port for server "
                           "{color}{server}{ncolor}, failed to add "
                           "server.").format(
                               prefix=W.prefix("error"),
                               color=W.color("chat_server"),
                               server=server.name,
                               ncolor=W.color("reset"))

                W.prnt("", message)
                server = None
                return

    if len(args) >= 3:
        user = args[2]
        return_code = W.config_option_set(
            server.config.options["username"],
            user,
            1
        )

        if return_code == W.WEECHAT_CONFIG_OPTION_SET_ERROR:
            remove_server(server)
            message = ("{prefix}Failed to set user for server "
                       "{color}{server}{ncolor}, failed to add "
                       "server.").format(
                           prefix=W.prefix("error"),
                           color=W.color("chat_server"),
                           server=server.name,
                           ncolor=W.color("reset"))

            W.prnt("", message)
            server = None
            return

    if len(args) == 4:
        password = args[3]

        return_code = W.config_option_set(
            server.config.options["password"],
            password,
            1
        )
        if return_code == W.WEECHAT_CONFIG_OPTION_SET_ERROR:
            remove_server(server)
            message = ("{prefix}Failed to set password for server "
                       "{color}{server}{ncolor}, failed to add "
                       "server.").format(
                           prefix=W.prefix("error"),
                           color=W.color("chat_server"),
                           server=server.name,
                           ncolor=W.color("reset"))
            W.prnt("", message)
            server = None
            return

    message = ("matrix: server {color}{server}{ncolor} "
               "has been added").format(
                   server=server.name,
                   color=W.color("chat_server"),
                   ncolor=W.color("reset"))
    W.prnt("", message)


def matrix_server_command(command, args):

    def list_servers(_):
        if SERVERS:
            W.prnt("", "\nAll matrix servers:")
            for server in SERVERS:
                W.prnt("", "    {color}{server}".format(
                    color=W.color("chat_server"), server=server))

    # TODO the argument for list and listfull is used as a match word to
    # find/filter servers, we're currently match exactly to the whole name
    if command == 'list':
        list_servers(args)
    elif command == 'listfull':
        matrix_server_command_listfull(args)
    elif command == 'add':
        matrix_server_command_add(args)
    elif command == 'delete':
        matrix_server_command_delete(args)
    else:
        message = ("{prefix}matrix: Error: unknown matrix server command, "
                   "\"{command}\" (type /matrix help server for help)").format(
                       prefix=W.prefix("error"), command=command)
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

    split_args = list(filter(bool, args.split(' ')))

    if len(split_args) < 1:
        message = ("{prefix}matrix: Too few arguments for command "
                   "\"/matrix\" (see /help matrix)").format(prefix=W.prefix("error"))
        W.prnt("", message)
        return W.WEECHAT_RC_ERROR

    command, args = split_args[0], split_args[1:]

    if command == 'connect':
        connect_server(args)

    elif command == 'disconnect':
        disconnect_server(args)

    elif command == 'reconnect':
        disconnect_server(args)
        connect_server(args)

    elif command == 'server':
        if len(args) >= 1:
            subcommand, args = args[0], args[1:]
            matrix_server_command(subcommand, args)
        else:
            matrix_server_command("list", "")

    elif command == 'help':
        matrix_command_help(args)

    else:
        message = ("{prefix}matrix: Error: unknown matrix command, "
                   "\"{command}\" (type /help matrix for help)").format(
                       prefix=W.prefix("error"), command=command)
        W.prnt("", message)

    return W.WEECHAT_RC_OK
