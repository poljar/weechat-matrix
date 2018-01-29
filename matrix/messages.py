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

import time
import json
import pprint
import datetime

from operator import itemgetter

import matrix.colors as colors

from matrix.globals import W, OPTIONS

from matrix.api import (
    MessageType,
    matrix_sync,
    MatrixMessage,
    MatrixRoom,
    MatrixUser
)

from matrix.socket import send_or_queue, disconnect, close_socket
from matrix.utils import server_buffer_prnt, tags_from_line_data, prnt_debug
from matrix.plugin_options import RedactType, DebugType

def strip_matrix_server(string):
    # type: (str) -> str
    return string.rsplit(":", 1)[0]


def add_user_to_nicklist(buf, user):
    group_name = "999|..."

    if user.power_level >= 100:
        group_name = "000|o"
    elif user.power_level >= 50:
        group_name = "001|h"
    elif user.power_level > 0:
        group_name = "002|v"

    group = W.nicklist_search_group(buf, "", group_name)
    # TODO make it configurable so we can use a display name or user_id here
    W.nicklist_add_nick(
        buf,
        group,
        user.display_name,
        user.nick_color,
        user.prefix,
        get_prefix_color(user.prefix),
        1
    )


def matrix_create_room_buffer(server, room_id):
    # type: (MatrixServer, str) -> None
    buf = W.buffer_new(
        room_id,
        "room_input_cb",
        server.name,
        "room_close_cb",
        server.name
    )

    W.buffer_set(buf, "localvar_set_type", 'channel')
    W.buffer_set(buf, "type", 'formatted')

    W.buffer_set(buf, "localvar_set_channel", room_id)

    W.buffer_set(buf, "localvar_set_nick", server.user)

    W.buffer_set(buf, "localvar_set_server", server.name)

    short_name = strip_matrix_server(room_id)
    W.buffer_set(buf, "short_name", short_name)

    W.nicklist_add_group(buf, '', "000|o", "weechat.color.nicklist_group", 1)
    W.nicklist_add_group(buf, '', "001|h", "weechat.color.nicklist_group", 1)
    W.nicklist_add_group(buf, '', "002|v", "weechat.color.nicklist_group", 1)
    W.nicklist_add_group(buf, '', "999|...", "weechat.color.nicklist_group", 1)

    W.buffer_set(buf, "nicklist", "1")
    W.buffer_set(buf, "nicklist_display_groups", "0")

    server.buffers[room_id] = buf
    server.rooms[room_id] = MatrixRoom(room_id)


def matrix_handle_room_aliases(server, room_id, event):
    # type: (MatrixServer, str, Dict[str, Any]) -> None
    buf = server.buffers[room_id]
    room = server.rooms[room_id]

    alias = event['content']['aliases'][-1]

    if not alias:
        return

    short_name = strip_matrix_server(alias)

    room.alias = alias
    W.buffer_set(buf, "name", alias)
    W.buffer_set(buf, "short_name", short_name)
    W.buffer_set(buf, "localvar_set_channel", alias)


def matrix_handle_room_members(server, room_id, event):
    # type: (MatrixServer, str, Dict[str, Any]) -> None
    buf = server.buffers[room_id]
    room = server.rooms[room_id]

    # TODO print out a informational message
    if event['membership'] == 'join':
        # TODO set the buffer type to a channel if we have more than 2 users
        display_name = event['content']['displayname']
        full_name = event['sender']
        short_name = strip_matrix_server(full_name)[1:]

        if not display_name:
            display_name = short_name

        user = MatrixUser(short_name, display_name)

        if full_name == server.user_id:
            user.nick_color = "weechat.color.chat_nick_self"
            W.buffer_set(
                buf,
                "highlight_words",
                ",".join([full_name, user.name, user.display_name]))
        else:
            user.nick_color = W.info_get("nick_color_name", user.name)

        room.users[full_name] = user

        nick_pointer = W.nicklist_search_nick(buf, "", user.display_name)
        if not nick_pointer:
            add_user_to_nicklist(buf, user)
        else:
            # TODO we can get duplicate display names
            pass

    elif event['membership'] == 'leave':
        full_name = event['sender']
        if full_name in room.users:
            user = room.users[full_name]
            nick_pointer = W.nicklist_search_nick(buf, "", user.display_name)
            if nick_pointer:
                W.nicklist_remove_nick(buf, nick_pointer)

            del room.users[full_name]


def date_from_age(age):
    # type: (float) -> int
    now = time.time()
    date = int(now - (age / 1000))
    return date


def color_for_tags(color):
    if color == "weechat.color.chat_nick_self":
        option = W.config_get(color)
        return W.config_string(option)
    return color


def matrix_handle_room_text_message(server, room_id, event, old=False):
    # type: (MatrixServer, str, Dict[str, Any], bool) -> None
    tag = ""
    msg_author = ""
    nick_color_name = ""

    room = server.rooms[room_id]
    msg = event['content']['body']

    if 'format' in event['content'] and 'formatted_body' in event['content']:
        if event['content']['format'] == "org.matrix.custom.html":
            formatted_data = colors.html_to_formatted(
                event['content']['formatted_body'])
            msg = colors.formatted_to_weechat(W, formatted_data)

    if event['sender'] in room.users:
        user = room.users[event['sender']]
        msg_author = user.display_name
        nick_color_name = user.nick_color
    else:
        msg_author = strip_matrix_server(event['sender'])[1:]
        nick_color_name = W.info_get("nick_color_name", msg_author)

    data = "{author}\t{msg}".format(author=msg_author, msg=msg)

    event_id = event['event_id']

    msg_date = date_from_age(event['unsigned']['age'])

    # TODO if this is an initial sync tag the messages as backlog
    # TODO handle self messages from other devices
    if old:
        tag = ("nick_{a},prefix_nick_{color},matrix_id_{event_id},"
               "matrix_message,notify_message,no_log,no_highlight").format(
                   a=msg_author,
                   color=color_for_tags(nick_color_name),
                   event_id=event_id)
    else:
        tag = ("nick_{a},prefix_nick_{color},matrix_id_{event_id},"
               "matrix_message,notify_message,log1").format(
                   a=msg_author,
                   color=color_for_tags(nick_color_name),
                   event_id=event_id)

    buf = server.buffers[room_id]
    W.prnt_date_tags(buf, msg_date, tag, data)


def matrix_handle_redacted_message(server, room_id, event):
    # type: (MatrixServer, str, Dict[Any, Any]) -> None
    reason = ""
    room = server.rooms[room_id]

    # TODO check if the message is already printed out, in that case we got the
    # message a second time and a redaction event will take care of it.
    censor = event['unsigned']['redacted_because']['sender']
    nick_color_name = ""

    if censor in room.users:
        user = room.users[censor]
        nick_color_name = user.nick_color
        censor = ("{nick_color}{nick}{ncolor} {del_color}"
                  "({host_color}{full_name}{ncolor}{del_color})").format(
                      nick_color=W.color(nick_color_name),
                      nick=user.display_name,
                      ncolor=W.color("reset"),
                      del_color=W.color("chat_delimiters"),
                      host_color=W.color("chat_host"),
                      full_name=censor)
    else:
        censor = strip_matrix_server(censor)[1:]
        nick_color_name = W.info_get("nick_color_name", censor)
        censor = "{color}{censor}{ncolor}".format(
            color=W.color(nick_color_name),
            censor=censor,
            ncolor=W.color("reset"))

    if 'reason' in event['unsigned']['redacted_because']['content']:
        reason = ", reason: \"{reason}\"".format(
            reason=event['unsigned']['redacted_because']['content']['reason'])

    msg = ("{del_color}<{log_color}Message redacted by: "
           "{censor}{log_color}{reason}{del_color}>{ncolor}").format(
               del_color=W.color("chat_delimiters"),
               ncolor=W.color("reset"),
               log_color=W.color("logger.color.backlog_line"),
               censor=censor,
               reason=reason)

    msg_author = strip_matrix_server(event['sender'])[1:]

    data = "{author}\t{msg}".format(author=msg_author, msg=msg)

    event_id = event['event_id']

    msg_date = date_from_age(event['unsigned']['age'])

    tag = ("nick_{a},prefix_nick_{color},matrix_id_{event_id},"
           "matrix_message,matrix_redacted,"
           "notify_message,no_highlight").format(
               a=msg_author,
               color=color_for_tags(nick_color_name),
               event_id=event_id)

    buf = server.buffers[room_id]
    W.prnt_date_tags(buf, msg_date, tag, data)


def matrix_handle_room_messages(server, room_id, event, old=False):
    # type: (MatrixServer, str, Dict[str, Any], bool) -> None
    if event['type'] == 'm.room.message':
        if 'redacted_by' in event['unsigned']:
            matrix_handle_redacted_message(server, room_id, event)
            return

        if event['content']['msgtype'] == 'm.text':
            matrix_handle_room_text_message(server, room_id, event, old)

        # TODO handle different content types here
        else:
            message = ("{prefix}Handling of content type "
                       "{type} not implemented").format(
                           type=event['content']['msgtype'],
                           prefix=W.prefix("error"))
            W.prnt(server.server_buffer, message)


def event_id_from_tags(tags):
    # type: (List[str]) -> str
    for tag in tags:
        if tag.startswith("matrix_id"):
            return tag[10:]

    return ""


def string_strikethrough(string):
    return "".join(["{}\u0336".format(c) for c in string])


def matrix_redact_line(data, tags, event):
    reason = ""

    hdata_line_data = W.hdata_get('line_data')

    message = W.hdata_string(hdata_line_data, data, 'message')
    censor = strip_matrix_server(event['sender'])[1:]

    if 'reason' in event['content']:
        reason = ", reason: \"{reason}\"".format(
            reason=event['content']['reason'])

    redaction_msg = ("{del_color}<{log_color}Message redacted by: "
                     "{censor}{log_color}{reason}{del_color}>{ncolor}").format(
                         del_color=W.color("chat_delimiters"),
                         ncolor=W.color("reset"),
                         log_color=W.color("logger.color.backlog_line"),
                         censor=censor,
                         reason=reason)

    if OPTIONS.redaction_type == RedactType.STRIKETHROUGH:
        message = string_strikethrough(message)
        message = message + " " + redaction_msg
    elif OPTIONS.redaction_type == RedactType.DELETE:
        message = redaction_msg
    elif OPTIONS.redaction_type == RedactType.NOTICE:
        message = message + " " + redaction_msg

    tags.append("matrix_new_redacted")

    new_data = {'tags_array': tags,
                'message': message}

    W.hdata_update(hdata_line_data, data, new_data)

    return W.WEECHAT_RC_OK


def matrix_handle_room_redaction(server, room_id, event):
    buf = server.buffers[room_id]
    event_id = event['redacts']

    own_lines = W.hdata_pointer(W.hdata_get('buffer'), buf, 'own_lines')

    if own_lines:
        hdata_line = W.hdata_get('line')

        line = W.hdata_pointer(
            W.hdata_get('lines'),
            own_lines,
            'last_line'
        )

        while line:
            data = W.hdata_pointer(hdata_line, line, 'data')

            if data:
                tags = tags_from_line_data(data)

                message_id = event_id_from_tags(tags)

                if event_id == message_id:
                    # If the message is already redacted there is nothing to do
                    if ("matrix_redacted" not in tags and
                            "matrix_new_redacted" not in tags):
                        matrix_redact_line(data, tags, event)
                    return W.WEECHAT_RC_OK

            line = W.hdata_move(hdata_line, line, -1)

    return W.WEECHAT_RC_OK


def get_prefix_for_level(level):
    # type: (int) -> str
    if level >= 100:
        return "&"
    elif level >= 50:
        return "@"
    elif level > 0:
        return "+"
    return ""


# TODO make this configurable
def get_prefix_color(prefix):
    # type: (str) -> str
    if prefix == "&":
        return "lightgreen"
    elif prefix == "@":
        return "lightgreen"
    elif prefix == "+":
        return "yellow"
    return ""


def matrix_handle_room_power_levels(server, room_id, event):
    if not event['content']['users']:
        return

    buf = server.buffers[room_id]
    room = server.rooms[room_id]

    for full_name, level in event['content']['users'].items():
        if full_name not in room.users:
            continue

        user = room.users[full_name]
        user.power_level = level
        user.prefix = get_prefix_for_level(level)

        nick_pointer = W.nicklist_search_nick(buf, "", user.display_name)
        W.nicklist_remove_nick(buf, nick_pointer)
        add_user_to_nicklist(buf, user)


def matrix_handle_room_events(server, room_id, room_events):
    # type: (MatrixServer, str, Dict[Any, Any]) -> None
    for event in room_events:
        if event['event_id'] in server.ignore_event_list:
            server.ignore_event_list.remove(event['event_id'])
            continue

        if event['type'] == 'm.room.aliases':
            matrix_handle_room_aliases(server, room_id, event)

        elif event['type'] == 'm.room.member':
            matrix_handle_room_members(server, room_id, event)

        elif event['type'] == 'm.room.message':
            matrix_handle_room_messages(server, room_id, event)

        elif event['type'] == 'm.room.topic':
            buf = server.buffers[room_id]
            room = server.rooms[room_id]
            topic = event['content']['topic']

            room.topic = topic
            room.topic_author = event['sender']

            topic_age = event['unsigned']['age']
            room.topic_date = datetime.datetime.fromtimestamp(
                time.time() - (topic_age / 1000))

            W.buffer_set(buf, "title", topic)

            nick_color = W.info_get("nick_color_name", room.topic_author)
            author = room.topic_author

            if author in room.users:
                user = room.users[author]
                nick_color = user.nick_color
                author = user.display_name

            author = ("{nick_color}{user}{ncolor}").format(
                nick_color=W.color(nick_color),
                user=author,
                ncolor=W.color("reset"))

            # TODO print old topic if configured so
            # TODO nick display name if configured so and found
            message = ("{prefix}{nick} has changed "
                       "the topic for {chan_color}{room}{ncolor} "
                       "to \"{topic}\"").format(
                           prefix=W.prefix("network"),
                           nick=author,
                           chan_color=W.color("chat_channel"),
                           ncolor=W.color("reset"),
                           room=strip_matrix_server(room.alias),
                           topic=topic)

            tags = "matrix_topic,no_highlight,log3,matrix_id_{event_id}".format(
                event_id=event['event_id'])

            date = date_from_age(topic_age)

            W.prnt_date_tags(buf, date, tags, message)

        elif event['type'] == "m.room.redaction":
            matrix_handle_room_redaction(server, room_id, event)

        elif event["type"] == "m.room.power_levels":
            matrix_handle_room_power_levels(server, room_id, event)

        # These events are unimportant for us.
        elif event["type"] in ["m.room.create", "m.room.join_rules",
                               "m.room.history_visibility",
                               "m.room.canonical_alias",
                               "m.room.guest_access",
                               "m.room.third_party_invite"]:
            pass

        elif event["type"] == "m.room.name":
            buf = server.buffers[room_id]
            room = server.rooms[room_id]

            name = event['content']['name']

            if not name:
                return

            room.alias = name
            W.buffer_set(buf, "name", name)
            W.buffer_set(buf, "short_name", name)
            W.buffer_set(buf, "localvar_set_channel", name)

        elif event["type"] == "m.room.encryption":
            buf = server.buffers[room_id]
            room = server.rooms[room_id]
            room.encrypted = True
            message = ("{prefix}This room is encrypted, encryption is "
                       "currently unsuported. Message sending is disabled for "
                       "this room.").format(prefix=W.prefix("error"))
            W.prnt(buf, message)

        # TODO implement message decryption
        elif event["type"] == "m.room.encrypted":
            pass

        else:
            message = ("{prefix}Handling of room event type "
                       "{type} not implemented").format(
                           type=event['type'],
                           prefix=W.prefix("error"))
            W.prnt(server.server_buffer, message)


def matrix_handle_invite_events(server, room_id, events):
    # type: (MatrixServer, str, List[Dict[str, Any]]) -> None
    for event in events:
        if event["type"] != "m.room.member":
            continue

        if 'membership' not in event:
            continue

        if event["membership"] == "invite":
            sender = event["sender"]
            # TODO does this go to the server buffer or to the channel buffer?
            message = ("{prefix}You have been invited to {chan_color}{channel}"
                       "{ncolor} by {nick_color}{nick}{ncolor}").format(
                           prefix=W.prefix("network"),
                           chan_color=W.color("chat_channel"),
                           channel=room_id,
                           ncolor=W.color("reset"),
                           nick_color=W.color("chat_nick"),
                           nick=sender)
            W.prnt(server.server_buffer, message)


def matrix_handle_room_info(server, room_info):
    # type: (MatrixServer, Dict) -> None
    for room_id, room in room_info['join'].items():
        if not room_id:
            continue

        if room_id not in server.buffers:
            matrix_create_room_buffer(server, room_id)

        if not server.rooms[room_id].prev_batch:
            server.rooms[room_id].prev_batch = room['timeline']['prev_batch']

        matrix_handle_room_events(server, room_id, room['state']['events'])
        matrix_handle_room_events(server, room_id, room['timeline']['events'])

    for room_id, room in room_info['invite'].items():
        matrix_handle_invite_events(
            server,
            room_id,
            room['invite_state']['events']
        )


def matrix_sort_old_messages(server, room_id):
    lines = []
    buf = server.buffers[room_id]

    own_lines = W.hdata_pointer(W.hdata_get('buffer'), buf, 'own_lines')

    if own_lines:
        hdata_line = W.hdata_get('line')
        hdata_line_data = W.hdata_get('line_data')
        line = W.hdata_pointer(
            W.hdata_get('lines'),
            own_lines,
            'first_line'
        )

        while line:
            data = W.hdata_pointer(hdata_line, line, 'data')

            line_data = {}

            if data:
                date = W.hdata_time(hdata_line_data, data, 'date')
                print_date = W.hdata_time(hdata_line_data, data,
                                          'date_printed')
                tags = tags_from_line_data(data)
                prefix = W.hdata_string(hdata_line_data, data, 'prefix')
                message = W.hdata_string(hdata_line_data, data,
                                         'message')

                line_data = {'date': date,
                             'date_printed': print_date,
                             'tags_array': ','.join(tags),
                             'prefix': prefix,
                             'message': message}

                lines.append(line_data)

            line = W.hdata_move(hdata_line, line, 1)

        sorted_lines = sorted(lines, key=itemgetter('date'))
        lines = []

        # We need to convert the dates to a string for hdata_update(), this
        # will reverse the list at the same time
        while sorted_lines:
            line = sorted_lines.pop()
            new_line = {k: str(v) for k, v in line.items()}
            lines.append(new_line)

        matrix_update_buffer_lines(lines, own_lines)


def matrix_update_buffer_lines(new_lines, own_lines):
    hdata_line = W.hdata_get('line')
    hdata_line_data = W.hdata_get('line_data')

    line = W.hdata_pointer(
        W.hdata_get('lines'),
        own_lines,
        'first_line'
    )

    while line:
        data = W.hdata_pointer(hdata_line, line, 'data')

        if data:
            W.hdata_update(hdata_line_data, data, new_lines.pop())

        line = W.hdata_move(hdata_line, line, 1)


def matrix_handle_old_messages(server, room_id, events):
    for event in events:
        if event['type'] == 'm.room.message':
            matrix_handle_room_messages(server, room_id, event, old=True)
        # TODO do we wan't to handle topics joins/quits here?
        else:
            pass

    matrix_sort_old_messages(server, room_id)


def matrix_handle_message(
        server,        # type: MatrixServer
        message_type,  # type: MessageType
        response,      # type: Dict[str, Any]
        extra_data     # type: Dict[str, Any]
):
    # type: (...) -> None

    if message_type is MessageType.LOGIN:
        server.access_token = response["access_token"]
        server.user_id = response["user_id"]
        message = MatrixMessage(server, OPTIONS, MessageType.SYNC)
        send_or_queue(server, message)

    elif message_type is MessageType.SYNC:
        next_batch = response['next_batch']

        # we got the same batch again, nothing to do
        if next_batch == server.next_batch:
            matrix_sync(server)
            return

        room_info = response['rooms']
        matrix_handle_room_info(server, room_info)

        server.next_batch = next_batch

        # TODO add a delay to this
        matrix_sync(server)

    elif message_type is MessageType.SEND:
        author = extra_data["author"]
        message = extra_data["message"]
        room_id = extra_data["room_id"]
        date = int(time.time())
        # TODO the event_id can be missing if sending has failed for
        # some reason
        event_id = response["event_id"]

        # This message will be part of the next sync, we already printed it out
        # so ignore it in the sync.
        server.ignore_event_list.append(event_id)

        tag = ("notify_none,no_highlight,self_msg,log1,nick_{a},"
               "prefix_nick_{color},matrix_id_{event_id},"
               "matrix_message").format(
                   a=author,
                   color=color_for_tags("weechat.color.chat_nick_self"),
                   event_id=event_id)

        data = "{author}\t{msg}".format(author=author, msg=message)

        buf = server.buffers[room_id]
        W.prnt_date_tags(buf, date, tag, data)

    elif message_type == MessageType.ROOM_MSG:
        # Response has no messages, that is we already got the oldest message
        # in a previous request, nothing to do
        if not response['chunk']:
            return

        room_id = response['chunk'][0]['room_id']
        room = server.rooms[room_id]

        matrix_handle_old_messages(server, room_id, response['chunk'])

        room.prev_batch = response['end']

    # Nothing to do here, we'll handle state changes and redactions in the sync
    elif (message_type == MessageType.STATE or
          message_type == MessageType.REDACT):
        pass

    else:
        server_buffer_prnt(
            server,
            "Handling of message type {type} not implemented".format(
                type=message_type))


def handle_http_response(server, message):
    # type: (MatrixServer, MatrixMessage) -> None

    assert message.response

    status_code = message.response.status

    def decode_json(server, json_string):
        try:
            return json.loads(json_string, encoding='utf-8')
        except Exception as error:
            message = ("{prefix}matrix: Error decoding json response from "
                       "server: {error}").format(
                           prefix=W.prefix("error"),
                           error=error)

            W.prnt(server.server_buffer, message)
            return None

    if status_code == 200:
        response = decode_json(server, message.response.body)

        # if not response:
        #     # Resend the message
        #     message.response = None
        #     send_or_queue(server, message)
        #     return

        matrix_handle_message(
            server,
            message.type,
            response,
            message.extra_data
        )

    # TODO handle try again response
    elif status_code == 504:
        if message.type == MessageType.SYNC:
            matrix_sync(server)

    elif status_code == 403:
        if message.type == MessageType.LOGIN:
            response = decode_json(server, message.response.body)
            reason = ("." if not response or not response["error"] else
                      ": {r}.".format(r=response["error"]))

            error_message = ("{prefix}Login error{reason}").format(
                prefix=W.prefix("error"),
                reason=reason)
            server_buffer_prnt(server, error_message)

            W.unhook(server.timer_hook)
            server.timer_hook = None

            close_socket(server)
            disconnect(server)
        elif message.type == MessageType.STATE:
            response = decode_json(server, message.response.body)
            reason = ("." if not response or not response["error"] else
                      ": {r}.".format(r=response["error"]))

            error_message = ("{prefix}Can't set state{reason}").format(
                prefix=W.prefix("network"),
                reason=reason)
            server_buffer_prnt(server, error_message)
        else:
            error_message = ("{prefix}Unhandled 403 error, please inform the "
                             "developers about this: {error}").format(
                                 prefix=W.prefix("error"),
                                 error=message.response.body)
            server_buffer_prnt(server, error_message)

    else:
        server_buffer_prnt(
            server,
            ("{prefix}Unhandled {status_code} error, please inform "
             "the developers about this.").format(
                 prefix=W.prefix("error"),
                 status_code=status_code))

        server_buffer_prnt(server, pprint.pformat(message.type))
        server_buffer_prnt(server, pprint.pformat(message.request.payload))
        server_buffer_prnt(server, pprint.pformat(message.response.body))

    creation_date = datetime.datetime.fromtimestamp(message.creation_time)
    done_time = time.time()
    info_message = ("Message of type {t} created at {c}."
                    "\nMessage lifetime information:"
                    "\n    Send delay: {s} ms"
                    "\n    Receive delay: {r} ms"
                    "\n    Handling time: {h} ms"
                    "\n    Total time: {total} ms").format(
                        t=message.type,
                        c=creation_date,
                        s=(message.send_time - message.creation_time) * 1000,
                        r=(message.receive_time - message.send_time) * 1000,
                        h=(done_time - message.receive_time) * 1000,
                        total=(done_time - message.creation_time) * 1000,)
    prnt_debug(DebugType.TIMING, server, info_message)

    return
