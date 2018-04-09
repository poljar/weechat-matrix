# What is Weechat-Matrix?

[Weechat](https://weechat.org/) is an extensible chat client.

[Matrix](https://matrix.org/blog/home) is an open network for secure, decentralized communication.

[Weechat-Matrix](https://github.com/poljar/weechat-matrix/) is a Python plugin for Weechat that lets Weechat communicate over the Matrix protocol.

# Project Status

Weechat-Matrix already supports large parts of the Matrix protocol.  See our [TODO](https://github.com/poljar/weechat-matrix/blob/master/TODO.md) list for more details.  Encryption support is still in the works.

# Installation

Installation is easy.  As your regular user, just run: `make install` in this repository directory.

The following Python modules must also be available on your system:

- pyOpenSSL
- typing
- webcolors
- http-parser
- future (Python2 users only, see below)

Note that weechat only supports Python2 OR Python3, and that setting is determined at the time that Weechat is compiled.  Weechat-Matrix can work with either Python2 or Python3, but when you install dependencies you will have to take into account which version of Python your Weechat was built to use.  If you are unsure, Python2 is a good first guess.

When encryption is ready, the plugin will also depend on the [Python bindings](https://github.com/poljar/python-olm) for the OLM encryption library.

# Configuration

Configuration is completed primarily through the Weechat interface.  First start Weechat, and then issue the following commands:

1. Start by loading the Weechat-Matrix plugin:

    /script load matrix.py test

1. Now set your username and password:

    /set matrix.server.matrix.org.username johndoe
    /set matrix.server.matrix.org.password jd_is_awesome

1. Now try to connect:

    /matrix connect matrix.org

1. If everything works, save the configuration

    /save

## For using a custom (not matrix.org) matrix server:

1. Add your custom server to the plugin:

    /matrix server add myserver myserver.org

1. Add the appropriate credentials

    /set matrix.server.myserver.username johndoe
    /set matrix.server.myserver.password jd_is_awesome

1. If everything works, save the configuration

    /save

# Helpful Commands

`/help matrix` will print information about the `/matrix` command.

`/matrix help [command]` will print information for subcommands, such as `/matrix help server`

