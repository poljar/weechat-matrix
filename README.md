[![Build Status](https://img.shields.io/travis/poljar/weechat-matrix.svg?style=flat-square)](https://travis-ci.org/poljar/weechat-matrix)
[![#weechat-matrix](https://img.shields.io/badge/matrix-%23weechat--matrix-blue.svg?style=flat-square)](https://matrix.to/#/!twcBhHVdZlQWuuxBhN:termina.org.uk?via=termina.org.uk&via=matrix.org)
[![license](https://img.shields.io/badge/license-ISC-blue.svg?style=flat-square)](https://github.com/poljar/weechat-matrix/blob/master/LICENSE)

# What is Weechat-Matrix?

[Weechat](https://weechat.org/) is an extensible chat client.

[Matrix](https://matrix.org/blog/home) is an open network for secure, decentralized communication.

[Weechat-Matrix](https://github.com/poljar/weechat-matrix/) is a Python plugin for Weechat that lets Weechat communicate over the Matrix protocol.

# Project Status

Weechat-Matrix already supports large parts of the Matrix protocol, end to end encryption
support is still experimental.

# Installation

Installation is easy.  As your regular user, just run: `make install` in this repository directory.

The following Python modules must also be available on your system:

- pyOpenSSL
- typing
- webcolors
- future (Python2 users only, see below)
- atomicwrites
- [matrix-nio](https://github.com/poljar/matrix-nio)
- attrs
- logbook
- pygments

Note that weechat only supports Python2 OR Python3, and that setting is
determined at the time that Weechat is compiled.  Weechat-Matrix can work with
either Python2 or Python3, but when you install dependencies you will have to
take into account which version of Python your Weechat was built to use.

To check the python version that weechat is using, run:

    /python version

## Uploads

Uploads are done using a helper script, the script found under
[contrib/matrix_upload](https://github.com/poljar/weechat-matrix/blob/master/contrib/matrix_upload)
should be installed under your `PATH`.

# Configuration

Configuration is completed primarily through the Weechat interface.  First start Weechat, and then issue the following commands:

1. Start by loading the Weechat-Matrix plugin:

       /script load matrix.py test

1. Now set your username and password:

       /set matrix.server.matrix_org.username johndoe
       /set matrix.server.matrix_org.password jd_is_awesome

1. Now try to connect:

       /matrix connect matrix_org

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


## Bar items

There are two bar items provided by this script:

1. `matrix_typing_notice` - shows the currently typing users

1. `matrix_modes` - shows room and server info (encryption status of the room,
   server connection status)

They can be added to the weechat status bar as usual:
       /set weechat.bar.status.items

The `matrix_modes` bar item is replicated in the already used `buffer_modes` bar
item.

## Typing notices and read receipts

The sending of typing notices and read receipts can be temporarily disabled via
the `/room` command, they can also be permanently configured using standard
weechat conditions settings with the following settings:

1. `matrix.network.read_markers_conditions`
1. `matrix.network.typing_notice_conditions`

# Helpful Commands

`/help matrix` will print information about the `/matrix` command.

`/help olm` will print information about the `/olm` command that is used for
device verification.

`/matrix help [command]` will print information for subcommands, such as `/matrix help server`
