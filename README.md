[![Build Status](https://img.shields.io/travis/poljar/weechat-matrix.svg?style=flat-square)](https://travis-ci.org/poljar/weechat-matrix)
[![#weechat-matrix](https://img.shields.io/badge/matrix-%23weechat--matrix:termina.org.uk-blue.svg?style=flat-square)](https://matrix.to/#/!twcBhHVdZlQWuuxBhN:termina.org.uk?via=termina.org.uk&via=matrix.org)
[![license](https://img.shields.io/badge/license-ISC-blue.svg?style=flat-square)](https://github.com/poljar/weechat-matrix/blob/master/LICENSE)

# What is Weechat-Matrix?

[Weechat](https://weechat.org/) is an extensible chat client.

[Matrix](https://matrix.org/blog/home) is an open network for secure, decentralized communication.

[Weechat-Matrix](https://github.com/poljar/weechat-matrix/) is a Python plugin for Weechat that lets Weechat communicate over the Matrix protocol.

# Project Status

Weechat-Matrix already supports large parts of the Matrix protocol, end to end encryption
support is still experimental.

# Installation

1. Install libolm 3.1+

    - Debian/Ubuntu install libolm-dev if new enough

    - Archlinux based distribution (see https://aur.archlinux.org/packages/libolm/)
      use your favorite pacman frontend with AUR support (yaourt, yay, pikaur, …)

    - Failing any of the above see https://git.matrix.org/git/olm
      for instructions about building it from sources

2. Clone the repo and install dependencies
    ```
    git clone https://github.com/poljar/weechat-matrix.git
    cd weechat-matrix
    pip install -r requirements.txt
    ```

3. As your regular user, just run: `make install` in this repository directory.

    This installs the main python file (`main.py`) into
    `~/.weechat/python/` (renamed to `matrix.py`) along with the other
    python files it needs (from the `matrix` subdir).

    Note that weechat only supports Python2 OR Python3, and that setting is
    determined at the time that Weechat is compiled.  Weechat-Matrix can work with
    either Python2 or Python3, but when you install dependencies you will have to
    take into account which version of Python your Weechat was built to use.

    The minimal supported python2 version is 2.7.10.

    To check the python version that weechat is using, run:

        /python version

## Using virtualenv
If you want to install dependencies inside a virtualenv, rather than
globally for your system or user, you can use a virtualenv.
Weechat-Matrix will automatically use any virtualenv it finds in a
directory called `venv` next to its main Python file (after resolving
symlinks). Typically, this means `~/.weechat/python/venv`.

To create such a virtualenv, you can use something like below. This only
needs to happen once:

```
virtualenv ~/.weechat/python/venv
```

Then, activate the virtualenv:

```
. ~/.weechat/python/venv/bin/activate
```

This needs to be done whenever you want to install packages inside the
virtualenv (so before running the `pip install` command documented
above.


Once the virtualenv is prepared in the right location, Weechat-Matrix
will automatically activate it when the plugin is loaded. This should
not affect other plugins, which seem to have a separate Python
environment.

Note that this only supports virtualenv tools that support the
[`activate_this.py` way of
activation](https://virtualenv.pypa.io/en/latest/userguide/#using-virtualenv-without-bin-python).
This includes the `virtualenv` command, but excludes pyvenv and the
Python3 `venv` module. In particular, this works if (for a typical
installation of `matrix.py`) the file
`~/.weechat/python/venv/bin/activate_this.py` exists.

## Run from git directly

Rather than copying files into `~/.weechat` (step 3 above), it is also
possible to run from a git checkout directly using symlinks.

For this, you need two symlinks:

```
ln -s /path/to/weechat-matrix/main.py ~/.weechat/python/matrix.py
ln -s /path/to/weechat-matrix/matrix ~/.weechat/python/matrix
```

This first link is the main python file, that can be loaded using
`/script load matrix.py`. The second link is to the directory with extra
python files used by the main script. This directory must be linked as
`~/.weechat/python/matrix` so it ends up in the python library path and
its files can be imported using e.g. `import matrix` from the main python
file.

Note that these symlinks are essentially the same as the files that
would have been copied using `make install`.

## Uploads

Uploads are done using a helper script, the script found under
[contrib/matrix_upload](https://github.com/poljar/weechat-matrix/blob/master/contrib/matrix_upload)
should be installed under your `PATH`.

# Configuration

Configuration is completed primarily through the Weechat interface.  First start Weechat, and then issue the following commands:

1. Start by loading the Weechat-Matrix plugin:

       /script load matrix.py

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

## Single sign-on:

Single sign-on is supported using a helper script, the script found under
[contrib/matrix_sso_helper](https://github.com/poljar/weechat-matrix/blob/master/contrib/matrix_sso_helper)
should be installed under your `PATH`.

For single sign-on to be the preferred leave the servers username and password
empty.

After connecting a URL will be presented which needs to be used to perform the
sign on. Please note that the helper script spawns a HTTP server which waits for
the sign-on token to be passed back. This makes it necessary to do the sign on
on the same host as Weechat.

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
