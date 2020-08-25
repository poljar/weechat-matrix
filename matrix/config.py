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

"""weechat-matrix Configuration module.

This module contains abstractions on top of weechats configuration files and
the main script configuration class.

To add configuration options refer to MatrixConfig.
Server specific configuration options are handled in server.py
"""

from builtins import super
from collections import namedtuple
from enum import IntEnum, Enum, unique

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


@unique
class NewChannelPosition(IntEnum):
    NONE = 0
    NEXT = 1
    NEAR_SERVER = 2


nio.logger_group.level = logbook.ERROR


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
    """A class representing a new configuration option.

    An option object is consumed by the ConfigSection class adding
    configuration options to weechat.
    """

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
        """
        Parameters:
            name (str): Name of the configuration option
            type (str): Type of the configuration option, can be one of the
                supported weechat types: string, boolean, integer, color
            string_values: (str): A list of string values that the option can
            accept seprated by |
            min (int): Minimal value of the option, only used if the type of
                the option is integer
            max (int): Maximal value of the option, only used if the type of
                the option is integer
            description (str): Description of the configuration option
            cast (callable): A callable function taking a single value and
                returning a modified value. Useful to turn the configuration
                option into an enum while reading it.
            change_callback(callable): A function that will be called
                by weechat every time the configuration option is changed.
        """

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
    """Change the log level of the underlying nio lib

    Called every time the user changes the log level or log category
    configuration option."""

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
        nio.crypto.logger.level = level


@utf8_decode
def config_server_buffer_cb(data, option):
    """Callback for the look.server_buffer option.
    Is called when the option is changed and merges/splits the server
    buffer"""

    for server in SERVERS.values():
        server.buffer_merge()
    return 1


@utf8_decode
def config_log_level_cb(data, option):
    """Callback for the network.debug_level option."""
    change_log_level(
        G.CONFIG.network.debug_category, G.CONFIG.network.debug_level
    )
    return 1


@utf8_decode
def config_log_category_cb(data, option):
    """Callback for the network.debug_category option."""
    change_log_level(G.CONFIG.debug_category, logbook.ERROR)
    G.CONFIG.debug_category = G.CONFIG.network.debug_category
    change_log_level(
        G.CONFIG.network.debug_category, G.CONFIG.network.debug_level
    )
    return 1


@utf8_decode
def config_pgup_cb(data, option):
    """Callback for the network.fetch_backlog_on_pgup option.
    Enables or disables the hook that is run when /window page_up is called"""
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


def parse_nick_prefix_colors(value):
    """Parses the nick prefix color setting string
    ("admin=COLOR1;mod=COLOR2;power=COLOR3") into a prefix -> color dict."""

    def key_to_prefix(key):
        if key == "admin":
            return "&"
        elif key == "mod":
            return "@"
        elif key == "power":
            return "+"
        else:
            return ""

    prefix_colors = {
        "&": "lightgreen",
        "@": "lightgreen",
        "+": "yellow",
    }

    for setting in value.split(";"):
        # skip malformed settings
        if "=" not in setting:
            continue

        key, color = setting.split("=")
        prefix = key_to_prefix(key)

        if prefix:
            prefix_colors[prefix] = color

    return prefix_colors


def eval_cast(string):
    """A function that passes a string to weechat which evaluates it using its
    expression evaluation syntax.
    Can only be used with strings, useful for passwords or options that contain
    a formatted string to e.g. add colors.
    More info here:
        https://weechat.org/files/doc/stable/weechat_plugin_api.en.html#_string_eval_expression"""

    return W.string_eval_expression(string, {}, {}, {})


class WeechatConfig(object):
    """A class representing a weechat configuration file
    Wraps weechats configuration creation functionality"""

    def __init__(self, sections):
        """Create a new weechat configuration file, expects the global
        SCRIPT_NAME to be defined and a reload callback

        Parameters:
            sections (List[Tuple[str, List[Option]]]): List of config sections
                that will be created for the configuration file.
        """
        self._ptr = W.config_new(
            SCRIPT_NAME, SCRIPT_NAME + "_config_reload_cb", ""
        )

        for section in sections:
            name, options = section
            section_class = ConfigSection.build(name, options)
            setattr(self, name, section_class(name, self._ptr, options))

    def free(self):
        """Free all the config sections and their options as well as the
        configuration file. Should be called when the script is unloaded."""
        for section in [
            getattr(self, a)
            for a in dir(self)
            if isinstance(getattr(self, a), ConfigSection)
        ]:
            section.free()

        W.config_free(self._ptr)

    def read(self):
        """Read the config file"""
        return_code = W.config_read(self._ptr)
        if return_code == W.WEECHAT_CONFIG_READ_OK:
            return True
        if return_code == W.WEECHAT_CONFIG_READ_MEMORY_ERROR:
            return False
        if return_code == W.WEECHAT_CONFIG_READ_FILE_NOT_FOUND:
            return True
        return False


class ConfigSection(object):
    """A class representing a weechat config section.
    Should not be used on its own, the WeechatConfig class uses this to build
    config sections."""
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
        """Create a property for this class that makes the reading of config
        option values pythonic. The option will be available as a property with
        the name of the option.
        If a cast function was defined for the option the property will pass
        the option value to the cast function and return its result."""

        def bool_getter(self):
            return bool(W.config_boolean(self._option_ptrs[name]))

        def str_getter(self):
            if cast_func:
                return cast_func(W.config_string(self._option_ptrs[name]))
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
    """Main matrix configuration file.
    This class defines all the global matrix configuration options.
    New global options should be added to the constructor of this class under
    the appropriate section.

    There are three main sections defined:
        Look: This section is for options that change the way matrix messages
            are shown or the way the buffers are shown.
        Color: This section should mainly be for color options, options that
            change color schemes or themes should go to the look section.
        Network: This section is for options that change the way the script
            behaves, e.g. the way it communicates with the server, it handles
            responses or any other behavioural change that doesn't fit in the
            previous sections.

    There is a special section called server defined which contains per server
    configuration options. Server options aren't defined here, they need to be
    added in server.py
    """

    def __init__(self):
        self.debug_buffer = ""
        self.upload_buffer = ""
        self.debug_category = "all"
        self.page_up_hook = None
        self.human_buffer_names = None

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
            Option(
                "new_channel_position",
                "integer",
                "none|next|near_server",
                min(NewChannelPosition),
                max(NewChannelPosition),
                "none",
                "force position of new channel in list of buffers "
                "(none = default position (should be last buffer), "
                "next = current buffer + 1, near_server = after last "
                "channel/pv of server)",
                NewChannelPosition,
            ),
            Option(
                "max_typing_notice_item_length",
                "integer",
                "",
                10,
                1000,
                "50",
                ("Limit the length of the typing notice bar item."),
            ),
            Option(
                "bar_item_typing_notice_prefix",
                "string",
                "",
                0,
                0,
                "Typing: ",
                ("Prefix for the typing notice bar item."),
            ),
            Option(
                "encryption_warning_sign",
                "string",
                "",
                0,
                0,
                "⚠️ ",
                ("A sign that is used to signal trust issues in encrypted "
                 "rooms (note: content is evaluated, see /help eval)"),
                eval_cast,
            ),
            Option(
                "busy_sign",
                "string",
                "",
                0,
                0,
                "⏳",
                ("A sign that is used to signal that the client is busy e.g. "
                 "when the room backlog is fetching"
                 " (note: content is evaluated, see /help eval)"),
                eval_cast,
            ),
            Option(
                "encrypted_room_sign",
                "string",
                "",
                0,
                0,
                "🔐",
                ("A sign that is used to show that the current room is "
                 "encrypted "
                 "(note: content is evaluated, see /help eval)"),
                eval_cast,
            ),
            Option(
                "disconnect_sign",
                "string",
                "",
                0,
                0,
                "❌",
                ("A sign that is used to show that the server is disconnected "
                 "(note: content is evaluated, see /help eval)"),
                eval_cast,
            ),
            Option(
                "pygments_style",
                "string",
                "",
                0,
                0,
                "native",
                "Pygments style to use for highlighting source code blocks",
            ),
            Option(
                "code_blocks",
                "boolean",
                "",
                0,
                0,
                "on",
                ("Display preformatted code blocks as rectangular areas by "
                 "padding them with whitespace up to the length of the longest"
                 " line (with optional margin)"),
            ),
            Option(
                "code_block_margin",
                "integer",
                "",
                0,
                100,
                "2",
                ("Number of spaces to add as a margin around around a code "
                 "block"),
            ),
            Option(
                "quote_wrap",
                "integer",
                "",
                -1,
                1000,
                "67",
                ("After how many characters to soft-wrap lines in a quote "
                 "block (reply message). Set to -1 to disable soft-wrapping."),
            ),
            Option(
                "human_buffer_names",
                "boolean",
                "",
                0,
                0,
                "off",
                ("If turned on the buffer name will consist of the server "
                 "name and the room name instead of the Matrix room ID. Note, "
                 "this requires a change to the logger.file.mask setting "
                 "since conflicts can happen otherwise "
                 "(requires a script reload)."),
            ),
            Option(
                "markdown_input",
                "boolean",
                "",
                0,
                0,
                "on",
                ("If turned on, markdown usage in messages will be converted "
                 "to actual markup (**bold**, *italic*, _italic_, `code`)."),
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
                config_log_category_cb,
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
            Option(
                "lazy_load_room_users",
                "boolean",
                "",
                0,
                0,
                "off",
                ("If on, room users won't be loaded in the background "
                 "proactively, they will be loaded when the user switches to "
                 "the room buffer. This only affects non-encrypted rooms."),
            ),
            Option(
                "max_nicklist_users",
                "integer",
                "",
                100,
                20000,
                "5000",
                ("Limit the number of users that are added to the nicklist. "
                 "Active users and users with a higher power level are always."
                 " Inactive users will be removed from the nicklist after a "
                 "day of inactivity."),
            ),
            Option(
                "lag_reconnect",
                "integer",
                "",
                5,
                604800,
                "90",
                ("Reconnect to the server if the lag is greater than this "
                 "value (in seconds)"),
            ),
            Option(
                "autoreconnect_delay_growing",
                "integer",
                "",
                1,
                100,
                "2",
                ("growing factor for autoreconnect delay to server "
                 "(1 = always same delay, 2 = delay*2 for each retry, etc.)"),
            ),
            Option(
                "autoreconnect_delay_max",
                "integer",
                "",
                0,
                604800,
                "600",
                ("maximum autoreconnect delay to server "
                 "(in seconds, 0 = no maximum)"),
            ),
            Option(
                "print_unconfirmed_messages",
                "boolean",
                "",
                0,
                0,
                "on",
                ("If off, messages are only printed after the server confirms "
                 "their receival. If on, messages are immediately printed but "
                 "colored differently until receival is confirmed."),
            ),
            Option(
                "lag_min_show",
                "integer",
                "",
                1,
                604800,
                "500",
                ("minimum lag to show (in milliseconds)"),
            ),
            Option(
                "typing_notice_conditions",
                "string",
                "",
                0,
                0,
                "${typing_enabled}",
                ("conditions to send typing notifications (note: content is "
                 "evaluated, see /help eval); besides the buffer and window "
                 "variables the typing_enabled variable is also expanded; "
                 "the typing_enabled variable can be manipulated with the "
                 "/room command, see /help room"),
            ),
            Option(
                "read_markers_conditions",
                "string",
                "",
                0,
                0,
                "${markers_enabled}",
                ("conditions to send read markers (note: content is "
                 "evaluated, see /help eval); besides the buffer and window "
                 "variables the markers_enabled variable is also expanded; "
                 "the markers_enabled variable can be manipulated with the "
                 "/room command, see /help room"),
            ),
            Option(
                "resending_ignores_devices",
                "boolean",
                "",
                0,
                0,
                "on",
                ("If on resending the same message to a room that contains "
                 "unverified devices will mark the devices as ignored and "
                 "continue sending the message. If off resending the message "
                 "will again fail and devices need to be marked as verified "
                 "one by one or the /send-anyways command needs to be used to "
                 "ignore them."),
            ),
        ]

        color_options = [
            Option(
                "quote_fg",
                "color",
                "",
                0,
                0,
                "lightgreen",
                "Foreground color for matrix style blockquotes",
            ),
            Option(
                "quote_bg",
                "color",
                "",
                0,
                0,
                "default",
                "Background counterpart of quote_fg",
            ),
            Option(
                "error_message_fg",
                "color",
                "",
                0,
                0,
                "darkgray",
                ("Foreground color for error messages that appear inside a "
                 "room buffer (e.g. when a message errors out when sending or "
                 "when a message is redacted)"),
            ),
            Option(
                "error_message_bg",
                "color",
                "",
                0,
                0,
                "default",
                "Background counterpart of error_message_fg.",
            ),
            Option(
                "unconfirmed_message_fg",
                "color",
                "",
                0,
                0,
                "darkgray",
                ("Foreground color for messages that are printed out but the "
                 "server hasn't confirmed the that he received them."),
            ),
            Option(
                "unconfirmed_message_bg",
                "color",
                "",
                0,
                0,
                "default",
                "Background counterpart of unconfirmed_message_fg."
            ),
            Option(
                "untagged_code_fg",
                "color",
                "",
                0,
                0,
                "blue",
                ("Foreground color for code without a language specifier. "
                 "Also used for `inline code`."),
            ),
            Option(
                "untagged_code_bg",
                "color",
                "",
                0,
                0,
                "default",
                "Background counterpart of untagged_code_fg",
            ),
            Option(
                "nick_prefixes",
                "string",
                "",
                0,
                0,
                "admin=lightgreen;mod=lightgreen;power=yellow",
                ('Colors for nick prefixes indicating power level. '
                 'Format is "admin:color1;mod:color2;power:color3", '
                 'where "admin" stands for admins (power level = 100), '
                 '"mod" stands for moderators (power level >= 50) and '
                 '"power" for any other power user (power level > 0). '
                 'Requires restart to apply changes.'),
                parse_nick_prefix_colors,
            ),
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

    def read(self):
        super().read()
        self.human_buffer_names = self.look.human_buffer_names

    def free(self):
        section_ptr = W.config_search_section(self._ptr, "server")
        W.config_section_free(section_ptr)
        super().free()
