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

# from __future__ import unicode_literals
from builtins import super
from collections import namedtuple
from enum import Enum, unique

import logbook

import nio
from matrix.globals import SCRIPT_NAME, SERVERS, W
from matrix.utf import utf8_decode

from . import globals as G


@unique
class RedactType(Enum):
    STRIKETHROUGH = 0
    NOTICE = 1
    DELETE = 2


@unique
class ServerBufferType(Enum):
    MERGE_CORE = 0
    MERGE = 1
    INDEPENDENT = 2


class Option(
    namedtuple(
        "Option",
        [
            "name",
            "type",
            "string_values",
            "min",
            "max",
            "value",
            "description",
            "cast_func",
            "change_callback",
        ],
    )
):
    __slots__ = ()

    def __new__(
        cls,
        name,
        type,
        string_values,
        min,
        max,
        value,
        description,
        cast=None,
        change_callback=None,
    ):
        return super().__new__(
            cls,
            name,
            type,
            string_values,
            min,
            max,
            value,
            description,
            cast,
            change_callback,
        )


@utf8_decode
def matrix_config_reload_cb(data, config_file):
    return W.WEECHAT_RC_OK


def change_log_level(category, level):
    if category == "all":
        nio.logger_group.level = level
    elif category == "http":
        nio.http.logger.level = level
    elif category == "client":
        nio.client.logger.level = level
    elif category == "events":
        nio.events.logger.level = level
    elif category == "responses":
        nio.responses.logger.level = level
    elif category == "encryption":
        nio.encryption.logger.level = level


@utf8_decode
def config_server_buffer_cb(data, option):
    for server in SERVERS.values():
        server.buffer_merge()
    return 1


@utf8_decode
def config_log_level_cb(data, option):
    change_log_level(
        G.CONFIG.network.debug_category, G.CONFIG.network.debug_level
    )
    return 1


@utf8_decode
def config_log_category_cb(data, option):
    change_log_level(G.CONFIG.debug_category, logbook.ERROR)
    G.CONFIG.debug_category = G.CONFIG.network.debug_category
    change_log_level(
        G.CONFIG.network.debug_category, G.CONFIG.network.debug_level
    )
    return 1


@utf8_decode
def config_pgup_cb(data, option):
    if G.CONFIG.network.fetch_backlog_on_pgup:
        if not G.CONFIG.page_up_hook:
            G.CONFIG.page_up_hook = W.hook_command_run(
                "/window page_up", "matrix_command_pgup_cb", ""
            )
    else:
        if G.CONFIG.page_up_hook:
            W.unhook(G.CONFIG.page_up_hook)
            G.CONFIG.page_up_hook = None

    return 1


def level_to_logbook(value):
    if value == 0:
        return logbook.ERROR
    if value == 1:
        return logbook.WARNING
    if value == 2:
        return logbook.INFO
    if value == 3:
        return logbook.DEBUG

    return logbook.ERROR


def logbook_category(value):
    if value == 0:
        return "all"
    if value == 1:
        return "http"
    if value == 2:
        return "client"
    if value == 3:
        return "events"
    if value == 4:
        return "responses"
    if value == 5:
        return "encryption"

    return "all"


class WeechatConfig(object):
    def __init__(self, sections):
        self._ptr = W.config_new(
            SCRIPT_NAME, SCRIPT_NAME + "_config_reload_cb", ""
        )

        for section in sections:
            name, options = section
            section_class = ConfigSection.build(name, options)
            setattr(self, name, section_class(name, self._ptr, options))

    def free(self):
        for section in [
            getattr(self, a)
            for a in dir(self)
            if isinstance(getattr(self, a), ConfigSection)
        ]:
            section.free()

        W.config_free(self._ptr)

    def read(self):
        return_code = W.config_read(self._ptr)
        if return_code == W.WEECHAT_CONFIG_READ_OK:
            return True
        if return_code == W.WEECHAT_CONFIG_READ_MEMORY_ERROR:
            return False
        if return_code == W.WEECHAT_CONFIG_READ_FILE_NOT_FOUND:
            return True
        return False


class ConfigSection(object):
    @classmethod
    def build(cls, name, options):
        def constructor(self, name, config_ptr, options):
            self._ptr = W.config_new_section(
                config_ptr, name, 0, 0, "", "", "", "", "", "", "", "", "", ""
            )
            self._config_ptr = config_ptr
            self._option_ptrs = {}

            for option in options:
                self._add_option(option)

        attributes = {
            option.name: cls.option_property(
                option.name, option.type, cast_func=option.cast_func
            )
            for option in options
        }
        attributes["__init__"] = constructor

        section_class = type(name.title() + "Section", (cls,), attributes)
        return section_class

    def free(self):
        W.config_section_free_options(self._ptr)
        W.config_section_free(self._ptr)

    def _add_option(self, option):
        cb = option.change_callback.__name__ if option.change_callback else ""
        option_ptr = W.config_new_option(
            self._config_ptr,
            self._ptr,
            option.name,
            option.type,
            option.description,
            option.string_values,
            option.min,
            option.max,
            option.value,
            option.value,
            0,
            "",
            "",
            cb,
            "",
            "",
            "",
        )

        self._option_ptrs[option.name] = option_ptr

    @staticmethod
    def option_property(name, option_type, evaluate=False, cast_func=None):
        def bool_getter(self):
            return bool(W.config_boolean(self._option_ptrs[name]))

        def str_getter(self):
            return W.config_string(self._option_ptrs[name])

        def str_evaluate_getter(self):
            return W.string_eval_expression(
                W.config_string(self._option_ptrs[name]), {}, {}, {}
            )

        def int_getter(self):
            if cast_func:
                return cast_func(W.config_integer(self._option_ptrs[name]))
            return W.config_integer(self._option_ptrs[name])

        if option_type in ("string", "color"):
            if evaluate:
                return property(str_evaluate_getter)
            return property(str_getter)
        if option_type == "boolean":
            return property(bool_getter)
        if option_type == "integer":
            return property(int_getter)


class MatrixConfig(WeechatConfig):
    def __init__(self):

        self.debug_buffer = ""
        self.debug_category = "all"
        self.page_up_hook = None

        look_options = [
            Option(
                "redactions",
                "integer",
                "strikethrough|notice|delete",
                0,
                0,
                "strikethrough",
                (
                    "Only notice redactions, strike through or delete "
                    "redacted messages"
                ),
                RedactType,
            ),
            Option(
                "server_buffer",
                "integer",
                "merge_with_core|merge_without_core|independent",
                0,
                0,
                "merge_with_core",
                "Merge server buffers",
                ServerBufferType,
                config_server_buffer_cb,
            ),
        ]

        network_options = [
            Option(
                "max_initial_sync_events",
                "integer",
                "",
                1,
                10000,
                "30",
                ("How many events to fetch during the initial sync"),
            ),
            Option(
                "max_backlog_sync_events",
                "integer",
                "",
                1,
                100,
                "10",
                ("How many events to fetch during backlog fetching"),
            ),
            Option(
                "fetch_backlog_on_pgup",
                "boolean",
                "",
                0,
                0,
                "on",
                ("Fetch messages in the backlog on a window page up event"),
                None,
                config_pgup_cb,
            ),
            Option(
                "debug_level",
                "integer",
                "error|warn|info|debug",
                0,
                0,
                "error",
                "Enable network protocol debugging.",
                level_to_logbook,
                config_log_level_cb,
            ),
            Option(
                "debug_category",
                "integer",
                "all|http|client|events|responses|encryption",
                0,
                0,
                "all",
                "Debugging category",
                logbook_category,
            ),
            Option(
                "debug_buffer",
                "boolean",
                "",
                0,
                0,
                "off",
                ("Use a separate buffer for debug logs."),
            ),
        ]

        color_options = [
            Option(
                "quote",
                "color",
                "",
                0,
                0,
                "lightgreen",
                ("Color for matrix style blockquotes"),
            )
        ]

        sections = [
            ("network", network_options),
            ("look", look_options),
            ("color", color_options),
        ]

        super().__init__(sections)

        # The server section is essentially a section with subsections and no
        # options, handle that case independently.
        W.config_new_section(
            self._ptr,
            "server",
            0,
            0,
            "matrix_config_server_read_cb",
            "",
            "matrix_config_server_write_cb",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        )

    def free(self):
        section_ptr = W.config_search_section(self._ptr, "server")
        W.config_section_free(section_ptr)
        super().free()
