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

from matrix.plugin_options import (Option, RedactType, ServerBufferType)

import matrix.globals
from matrix.globals import W, OPTIONS, SERVERS
from matrix.utf import utf8_decode
from matrix.utils import key_from_value, server_buffer_merge
from matrix.commands import hook_page_up


@utf8_decode
def matrix_config_reload_cb(data, config_file):
    return W.WEECHAT_RC_OK


@utf8_decode
def matrix_config_change_cb(data, option):
    option_name = key_from_value(OPTIONS.options, option)

    if option_name == "redactions":
        OPTIONS.redaction_type = RedactType(W.config_integer(option))

    elif option_name == "server_buffer":
        OPTIONS.look_server_buf = ServerBufferType(W.config_integer(option))
        for server in SERVERS.values():
            if server.server_buffer:
                server_buffer_merge(server.server_buffer)

    elif option_name == "max_initial_sync_events":
        OPTIONS.sync_limit = W.config_integer(option)

    elif option_name == "max_backlog_sync_events":
        OPTIONS.backlog_limit = W.config_integer(option)

    elif option_name == "fetch_backlog_on_pgup":
        OPTIONS.enable_backlog = W.config_boolean(option)

        if OPTIONS.enable_backlog:
            if not OPTIONS.page_up_hook:
                hook_page_up(matrix.globals.CONFIG)
        else:
            if OPTIONS.page_up_hook:
                W.unhook(OPTIONS.page_up_hook)
                OPTIONS.page_up_hook = None

    return 1


def matrix_config_init(config_file):
    look_options = [
        Option("redactions", "integer", "strikethrough|notice|delete", 0, 0,
               "strikethrough",
               ("Only notice redactions, strike through or delete "
                "redacted messages")),
        Option("server_buffer", "integer",
               "merge_with_core|merge_without_core|independent", 0, 0,
               "merge_with_core", "Merge server buffers")
    ]

    network_options = [
        Option("max_initial_sync_events", "integer", "", 1, 10000, "30",
               ("How many events to fetch during the initial sync")),
        Option("max_backlog_sync_events", "integer", "", 1, 100, "10",
               ("How many events to fetch during backlog fetching")),
        Option("fetch_backlog_on_pgup", "boolean", "", 0, 0, "on",
               ("Fetch messages in the backlog on a window page up event"))
    ]

    def add_global_options(section, options):
        for option in options:
            OPTIONS.options[option.name] = W.config_new_option(
                config_file, section, option.name, option.type,
                option.description, option.string_values, option.min,
                option.max, option.value, option.value, 0, "", "",
                "matrix_config_change_cb", "", "", "")

    section = W.config_new_section(config_file, "color", 0, 0, "", "", "", "",
                                   "", "", "", "", "", "")

    # TODO color options

    section = W.config_new_section(config_file, "look", 0, 0, "", "", "", "",
                                   "", "", "", "", "", "")

    add_global_options(section, look_options)

    section = W.config_new_section(config_file, "network", 0, 0, "", "", "", "",
                                   "", "", "", "", "", "")

    add_global_options(section, network_options)

    W.config_new_section(
        config_file, "server", 0, 0, "matrix_config_server_read_cb", "",
        "matrix_config_server_write_cb", "", "", "", "", "", "", "")

    return config_file


def matrix_config_read(config):
    # type: (str) -> bool
    return_code = W.config_read(config)
    if return_code == W.WEECHAT_CONFIG_READ_OK:
        return True
    elif return_code == W.WEECHAT_CONFIG_READ_MEMORY_ERROR:
        return False
    elif return_code == W.WEECHAT_CONFIG_READ_FILE_NOT_FOUND:
        return True
    return False


def matrix_config_free(config):
    for section in ["network", "look", "color", "server"]:
        section_pointer = W.config_search_section(config, section)
        W.config_section_free_options(section_pointer)
        W.config_section_free(section_pointer)

    W.config_free(config)
