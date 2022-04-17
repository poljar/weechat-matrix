[![Build Status](https://img.shields.io/travis/poljar/weechat-matrix.svg?style=flat-square)](https://travis-ci.org/poljar/weechat-matrix)
[![#weechat-matrix](https://img.shields.io/badge/matrix-%23weechat--matrix:termina.org.uk-blue.svg?style=flat-square)](https://matrix.to/#/!twcBhHVdZlQWuuxBhN:termina.org.uk?via=termina.org.uk&via=matrix.org)
[![license](https://img.shields.io/badge/license-ISC-blue.svg?style=flat-square)](https://github.com/poljar/weechat-matrix/blob/master/LICENSE)

# What is Weechat-Matrix?

[Weechat](https://weechat.org/) is an extensible chat client.

[Matrix](https://matrix.org/blog/home) is an open network for secure,
decentralized communication.

[weechat-matrix](https://github.com/poljar/weechat-matrix/) is a Python script
for Weechat that lets Weechat communicate over the Matrix protocol.

# Project Status

weechat-matrix is stable and quite usable as a daily driver. It already
supports large parts of the Matrix protocol, including end-to-end encryption
(though some features like cross-signing and session unwedging are
unimplemented).

However, due to some inherent limitations of Weechat *scripts*, development has
moved to [weechat-matrix-rs](https://github.com/poljar/weechat-matrix-rs),
a Weechat *plugin* written in Rust. As such, weechat-matrix is in maintenance
mode and will likely not be receiving substantial new features. PRs are still
accepted and welcome.

# Installation

## Arch Linux

Packaged as `community/weechat-matrix`.

    pacman -S weechat-matrix

## Alpine Linux

    apk add weechat-matrix

Then follow the instructions printed during installation to make the script
available to weechat.

## Other platforms

1. Install libolm 3.1+

    - Debian 11+ (testing/sid) or Ubuntu 19.10+ install libolm-dev

    - FreeBSD `pkg install olm`

    - macOS `brew install libolm`

    - Failing any of the above see https://gitlab.matrix.org/matrix-org/olm
      for instructions about building it from sources

2. Clone the repo and install dependencies
    ```
    git clone https://github.com/poljar/weechat-matrix.git
    cd weechat-matrix
    pip install --user -r requirements.txt
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

    The minimal supported python3 version is 3.5.4 or 3.6.1.

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
will automatically activate it when the script is loaded. This should
not affect other script, which seem to have a separate Python
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

## Uploading files

Uploads are done using a helper script, which is found under
[contrib/matrix_upload](https://github.com/poljar/weechat-matrix/blob/master/contrib/matrix_upload.py).
We recommend you install this under your `PATH` as `matrix_upload` (without the `.py` suffix).
Uploads can be done from Weechat with: `/upload <file>`.

## Downloading encrypted files

Encrypted files are displayed as an `emxc://` URI which cannot be directly
opened. They can be opened in two different ways:

- **In the CLI** by running the
[contrib/matrix_decrypt](https://github.com/poljar/weechat-matrix/blob/master/contrib/matrix_decrypt.py)
helper script.

- **In the browser** by using
  [matrix-decryptapp](https://github.com/seirl/matrix-decryptapp). This is a
  static website which cannot see your data, all the decryption happens
  on the client side. You can either host it yourself or directly use the
  instance hosted on `seirl.github.io`. This weechat trigger will convert all
  your `emxc://` URLs into clickable https links:

  ```
  /trigger addreplace emxc_decrypt modifier weechat_print "" ";($|[^\w/#:\[])(emxc://([^ ]+));${re:1}https://seirl.github.io/matrix-decryptapp/#${re:2};"
  ```

# Configuration

Configuration is completed primarily through the Weechat interface.  First start Weechat, and then issue the following commands:

1. Start by loading the Weechat-Matrix script:

       /script load matrix.py

2. Now set your username and password:

       /set matrix.server.matrix_org.username johndoe
       /set matrix.server.matrix_org.password jd_is_awesome

3. Now try to connect:

       /matrix connect matrix_org

4. Automatically load the script

       $ ln -s ../matrix.py ~/.weechat/python/autoload

5. Automatically connect to the server

       /set matrix.server.matrix_org.autoconnect on

6. If everything works, save the configuration

       /save

## For using a custom (not matrix.org) matrix server:

1. Add your custom server to the script:

       /matrix server add myserver myserver.org

1. Add the appropriate credentials

       /set matrix.server.myserver.username johndoe
       /set matrix.server.myserver.password jd_is_awesome

1. If everything works, save the configuration

       /save

## Single sign-on:

Single sign-on is supported using a helper script, the script found under
[contrib/matrix_sso_helper](https://github.com/poljar/weechat-matrix/blob/master/contrib/matrix_sso_helper.py)
should be installed under your `PATH` as `matrix_sso_helper` (without the `.py` suffix).

For single sign-on to be the preferred leave the servers username and password
empty.

After connecting a URL will be presented which needs to be used to perform the
sign on. Please note that the helper script spawns a HTTP server which waits for
the sign-on token to be passed back. This makes it necessary to do the sign on
on the same host as Weechat.

A hsignal is sent out when the SSO helper spawns as well, the name of the
hsignal is `matrix_sso_login` and it will contain the name of the server in the
`server` variable and the full URL that can be used to log in in the `url`
variable.

To open the login URL automatically in a browser a trigger can be added:

        /trigger add sso_browser hsignal matrix_sso_login "" "" "/exec -bg firefox ${url}"

If signing on on the same host as Weechat is undesirable the listening port of
the SSO helper should be set to a static value using the
`sso_helper_listening_port` setting:

       /set matrix.server.myserver.sso_helper_listening_port 8443

After setting the listening port the same port on the local machine can be
forwarded using ssh to the remote host:

        ssh -L 8443:localhost:8443 example.org

This forwards the local port 8443 to the localhost:8443 address on example.org.
Note that it is necessary to forward the port to the localhost address on the
remote host because the helper only listens on localhost.

## Bar items

There are two bar items provided by this script:

1. `matrix_typing_notice` - shows the currently typing users

1. `matrix_modes` - shows room and server info (encryption status of the room,
   server connection status)

They can be added to the weechat status bar as usual:
       /set weechat.bar.status.items

The `matrix_modes` bar item is replicated in the already used `buffer_modes` bar
item.

## Typing notifications and read receipts

The sending of typing notifications and read receipts can be temporarily
disabled for a given room via the `/room` command. They can also be permanently
configured using standard weechat conditions settings with the following
settings:

1. `matrix.network.read_markers_conditions`
1. `matrix.network.typing_notice_conditions`

## Cursor bindings

While you can reply on a matrix message using the `/reply-matrix` command (see
its help in weechat), weechat-matrix also adds a binding in `/cursor` mode to
easily reply to a particular message. This mode can be triggered either by
running `/cursor`, or by middle-clicking somewhere on the screen. See weechat's
help for `/cursor`.

The default binding is:

    /key bindctxt cursor @chat(python.matrix.*):r hsignal:matrix_cursor_reply

This means that you can reply to a message in a Matrix buffer using the middle
mouse button, then `r`.

This binding is automatically set when the script is loaded and there is no
such binding yet. If you want to use a different key than `r`, you can execute
the above command with a different key in place of `r`. To use modifier keys
like control and alt, use alt-k, then your wanted binding key combo, to enter
weechat's representation of that key combo in the input bar.

## Navigating room buffers using go.py

If you try to use the `go.py` script to navigate buffers created by
weechat-matrix, `go.py` will by default use the full buffer name which does not
contain a human-readable room display name but only the Matrix room ID. This is
necessary so that the logger file is able to produce unique, permanent
filenames for a room.

However, buffers also have human-readable short names. To make `go.py` use the
short names for navigation, you can run the following command:

```
/set plugins.var.python.go.short_name "on"
```

As an alternative, you can also force weechat-matrix to use human-readable
names as the full buffer names by running

```
/set matrix.look.human_buffer_names on
```

Beware that you will then also need to adjust your logger setup to prevent room
name conflicts from causing logger file conflicts.

# Helpful Commands

`/help matrix` will print information about the `/matrix` command.

`/help olm` will print information about the `/olm` command that is used for
device verification.

`/matrix help [command]` will print information for subcommands, such as `/matrix help server`
