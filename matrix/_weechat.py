def color(color_name):
    # type: (str) -> str
    # yapf: disable
    weechat_base_colors = {
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

    escape_codes = []
    reset_code = "0"

    def make_fg_color(color):
        return "38;5;{}".format(color)

    def make_bg_color(color):
        return "48;5;{}".format(color)

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

        if stripped_color in weechat_base_colors:
            escape_codes.append(
                make_fg_color(weechat_base_colors[stripped_color]))

        elif stripped_color.isdigit():
            num_color = int(stripped_color)
            if num_color >= 0 and num_color < 256:
                escape_codes.append(make_fg_color(stripped_color))

    if bg_color in weechat_base_colors:
        escape_codes.append(make_bg_color(weechat_base_colors[bg_color]))
    else:
        if bg_color.isdigit():
            num_color = int(bg_color)
            if num_color >= 0 and num_color < 256:
                escape_codes.append(make_bg_color(bg_color))

    escape_string = "\033[{}{}m".format(reset_code, ";".join(escape_codes))

    return escape_string


def prefix(prefix):
    prefix_to_symbol = {
        "error":   "=!=",
        "network": "--",
        "action":  "*",
        "join":    "-->",
        "quit":    "<--"
    }

    if prefix in prefix_to_symbol:
        return prefix_to_symbol[prefix]

    return ""


def prnt(_, string):
    print(string)


def config_search_section(*args, **kwargs):
    pass


def config_new_option(*args, **kwargs):
    pass


def mkdir_home(*args, **kwargs):
    return True


def info_get(info, *args):
    return ""
