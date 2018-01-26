# pylint: disable=import-error
import sys

from matrix.utf import WeechatWrapper
from matrix.config import PluginOptions, Option

import weechat


def init_matrix_config():
    config_file = W.config_new("matrix", "matrix_config_reload_cb", "")

    look_options = [
        Option(
            "redactions", "integer",
            "strikethrough|notice|delete", 0, 0,
            "strikethrough",
            (
                "Only notice redactions, strike through or delete "
                "redacted messages"
            )
        ),
        Option(
            "server_buffer", "integer",
            "merge_with_core|merge_without_core|independent",
            0, 0, "merge_with_core", "Merge server buffers"
        )
    ]

    network_options = [
        Option(
            "max_initial_sync_events", "integer",
            "", 1, 10000,
            "30",
            (
                "How many events to fetch during the initial sync"
            )
        ),
        Option(
            "max_backlog_sync_events", "integer",
            "", 1, 100,
            "10",
            (
                "How many events to fetch during backlog fetching"
            )
        ),
        Option(
            "fetch_backlog_on_pgup", "boolean",
            "", 0, 0,
            "on",
            (
                "Fetch messages in the backlog on a window page up event"
            )
        )
    ]

    def add_global_options(section, options):
        for option in options:
            OPTIONS.options[option.name] = W.config_new_option(
                config_file, section, option.name,
                option.type, option.description, option.string_values,
                option.min, option.max, option.value, option.value, 0, "",
                "", "matrix_config_change_cb", "", "", "")

    section = W.config_new_section(config_file, "color", 0, 0, "", "", "", "",
                                   "", "", "", "", "", "")

    # TODO color options

    section = W.config_new_section(config_file, "look", 0, 0, "", "", "", "",
                                   "", "", "", "", "", "")

    add_global_options(section, look_options)

    section = W.config_new_section(config_file, "network", 0, 0, "", "", "",
                                   "", "", "", "", "", "", "")

    add_global_options(section, network_options)

    W.config_new_section(
        config_file, "server",
        0, 0,
        "matrix_config_server_read_cb",
        "",
        "matrix_config_server_write_cb",
        "", "", "", "", "", "", ""
    )

    return config_file


W = weechat if sys.hexversion >= 0x3000000 else WeechatWrapper(weechat)

OPTIONS = PluginOptions()                # type: PluginOptions
SERVERS        = dict()                  # type: Dict[str, MatrixServer]
CONFIG         = None                    # type: weechat.config
