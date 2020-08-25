import datetime
import random
import string

WEECHAT_BASE_COLORS = {
    "black":        "0",
    "red":          "1",
    "green":        "2",
    "brown":        "3",
    "blue":         "4",
    "magenta":      "5",
    "cyan":         "6",
    "default":      "7",
    "gray":         "8",
    "lightred":     "9",
    "lightgreen":   "10",
    "yellow":       "11",
    "lightblue":    "12",
    "lightmagenta": "13",
    "lightcyan":    "14",
    "white":        "15"
}


class MockObject(object):
    pass

class MockConfig(object):
    config_template = {
        'debug_buffer': None,
        'debug_category': None,
        '_ptr': None,
        'read': None,
        'free': None,
        'page_up_hook': None,
        'color': {
            'error_message_bg': "",
            'error_message_fg': "",
            'quote_bg': "",
            'quote_fg': "",
            'unconfirmed_message_bg': "",
            'unconfirmed_message_fg': "",
            'untagged_code_bg': "",
            'untagged_code_fg': "",
        },
        'upload_buffer': {
            'display': None,
            'move_line_down': None,
            'move_line_up': None,
            'render': None,
        },
        'look': {
            'bar_item_typing_notice_prefix': None,
            'busy_sign': None,
            'code_block_margin': None,
            'code_blocks': None,
            'disconnect_sign': None,
            'encrypted_room_sign': None,
            'encryption_warning_sign': None,
            'max_typing_notice_item_length': None,
            'pygments_style': None,
            'redactions': None,
            'server_buffer': None,
            'new_channel_position': None,
            'markdown_input': True,
        },
        'network': {
            'debug_buffer': None,
            'debug_category': None,
            'debug_level': None,
            'fetch_backlog_on_pgup': None,
            'lag_min_show': None,
            'lag_reconnect': None,
            'lazy_load_room_users': None,
            'max_initial_sync_events': None,
            'max_nicklist_users': None,
            'print_unconfirmed_messages': None,
            'read_markers_conditions': None,
            'typing_notice_conditions': None,
            'autoreconnect_delay_growing': None,
            'autoreconnect_delay_max': None,
        },
    }

    def __init__(self):
        for category, options in MockConfig.config_template.items():
            if options:
                category_object = MockObject()
                for option, value in options.items():
                    setattr(category_object, option, value)
            else:
                category_object = options

            setattr(self, category, category_object)


def color(color_name):
    # type: (str) -> str
    # yapf: disable
    escape_codes = []
    reset_code = "0"

    def make_fg_color(color_code):
        return "38;5;{}".format(color_code)

    def make_bg_color(color_code):
        return "48;5;{}".format(color_code)

    attributes = {
        "bold":       "1",
        "-bold":      "21",
        "reverse":    "27",
        "-reverse":   "21",
        "italic":     "3",
        "-italic":    "23",
        "underline":  "4",
        "-underline": "24",
        "reset":      "0",
        "resetcolor": "39"
    }

    short_attributes = {
        "*": "1",
        "!": "27",
        "/": "3",
        "_": "4"
    }

    colors = color_name.split(",", 2)

    fg_color = colors.pop(0)

    bg_color = colors.pop(0) if colors else ""

    if fg_color in attributes:
        escape_codes.append(attributes[fg_color])
    else:
        chars = list(fg_color)

        for char in chars:
            if char in short_attributes:
                escape_codes.append(short_attributes[char])
            elif char == "|":
                reset_code = ""
            else:
                break

        stripped_color = fg_color.lstrip("*_|/!")

        if stripped_color in WEECHAT_BASE_COLORS:
            escape_codes.append(
                make_fg_color(WEECHAT_BASE_COLORS[stripped_color]))

        elif stripped_color.isdigit():
            num_color = int(stripped_color)
            if 0 <= num_color < 256:
                escape_codes.append(make_fg_color(stripped_color))

    if bg_color in WEECHAT_BASE_COLORS:
        escape_codes.append(make_bg_color(WEECHAT_BASE_COLORS[bg_color]))
    else:
        if bg_color.isdigit():
            num_color = int(bg_color)
            if 0 <= num_color < 256:
                escape_codes.append(make_bg_color(bg_color))

    escape_string = "\033[{}{}m".format(reset_code, ";".join(escape_codes))

    return escape_string


def prefix(prefix_string):
    prefix_to_symbol = {
        "error":   "=!=",
        "network": "--",
        "action":  "*",
        "join":    "-->",
        "quit":    "<--"
    }

    if prefix_string in prefix_to_symbol:
        return prefix_to_symbol[prefix]

    return ""


def prnt(_, message):
    print(message)


def prnt_date_tags(_, date, tags_string, data):
    message = "{} {} [{}]".format(
        datetime.datetime.fromtimestamp(date),
        data,
        tags_string
    )
    print(message)


def config_search_section(*_, **__):
    pass


def config_new_option(*_, **__):
    pass


def mkdir_home(*_, **__):
    return True


def info_get(info, *_):
    if info == "nick_color_name":
        return random.choice(list(WEECHAT_BASE_COLORS.keys()))

    return ""


def buffer_new(*_, **__):
    return "".join(
        random.choice(string.ascii_uppercase + string.digits) for _ in range(8)
    )


def buffer_set(*_, **__):
    return


def buffer_get_string(_ptr, property):
    if property == "localvar_type":
        return "channel"
    return ""


def buffer_get_integer(_ptr, property):
    return 0


def current_buffer():
    return 1


def nicklist_add_group(*_, **__):
    return


def nicklist_add_nick(*_, **__):
    return


def nicklist_remove_nick(*_, **__):
    return


def nicklist_search_nick(*args, **kwargs):
    return buffer_new(args, kwargs)


def string_remove_color(message, _):
    return message
