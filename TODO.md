# Weechat Matrix Scrip

# TODO
- [O] Handle disconnects seamlessly
    - [X] Handle send errors
    - [X] Handle receive errors
    - [X] Handle the disconnect properly
    - [X] Reconnect if there is stuff to do and we're disconnected
    - [X] Message queue timer.
- [O] Server buffer
    - [X] Create server buffer
    - [X] Merge with the core buffer if configured to do so
    - [ ] Informational messages
    - [X] Debugging
    - [X] Profiling
- [O] Matrix
    - [X] Login
    - [ ] Logout
    - [X] Sync
        - [X] Send sync request after login
        - [X] Parse sync response and store important data
        - [X] Create Buffers for rooms
        - [X] Populate nicklist
        - [X] Print out received messages
    - [O] Message Error handling
        - [X] Login
        - [X] Send messages
        - [X] Sync
        - [X] Redact
        - [X] Kick
        - [X] Redact
        - [X] Topic
        - [X] Join
        - [X] Part
        - [X] Invite
        - [X] Backlog messages
        - [ ] Try again
    - [o] Send messages
        - [X] Text
        - [o] Html
            - [X] Attributes
            - [ ] Color
        - [o] Parsing html to formated text
            - [X] Attributes
            - [X] Color
            - [ ] Lists
            - [X] Quotes
            - [ ] Code
    - [X] Topic
    - [X] Print sent messages without waiting for a sync
    - [X] Old message sync (rooms/{roomid}/messages)
    - [X] Handle calculation of room display names
    - [ ] Handle invited users that haven't yet joined
        - treat them as semi-joined
        - keep them in the nicklist (but appropriately stylized)
        - take them into account when calculating room display names
    - [X] Redactions
    - [X] Power levels
    - [X] Invite
    - [X] Join room
    - [X] Leave room
    - [ ] Upload
- [ ] Presence
    - [ ] Presence sending
    - [ ] Presence setting
- [ ] Read marker
    - [ ] Setting
    - [ ] Sending
- [ ] Typing notifications
    - [ ] Input change callback
    - [ ] Sending out the notification
    - [ ] Timer for the notification reset
    - [ ] Sending out the reset of the notification
- [X] Process the HTTP messages and put them into a queue
- [X] Parse the json response
- [O] Configuration
    - [X] Create default configuration
    - [X] Read configuration from file
    - [X] Save configuration
    - [X] Server address
    - [X] Auto connect
    - [X] SSL verify on/off
    - [ ] Presence sending
    - [X] Sync max backlog
    - [ ] Encrypt by default
    - [ ] Typing notification enable/disable
    - [X] Device name
    - [X] Default matrix.org server config
    - [X] Per server config
    - [X] Look - merge server buffer with core
    - [X] Global options
- [O] Core
    - [X] Don't use sendall in the send() function
    - [X] Create a default server if there doesn't exist one
    - [X] matrix help command
    - [X] Server add command
    - [X] Server list command
    - [X] Server listfull command
    - [X] Server delete command
    - [X] Server completion
    - [X] Create server classes based from the config
    - [X] Refactor out connection functions for multiple server support
    - [X] Refactor the server command function
    - [X] Nicklist groups
    - [ ] Smart filters
    - [X] Clear message queue on disconnect
    - [X] Fix Reconnect handling
    - [X] Fetch messages if we scroll to the top (hook_signal window_scroll)
    - [X] Status bar element if we're fetching old messages
    - [ ] Prevent self-highlighting when mentioning yourself from another client.
    - [O] Color and attributes.
        - [X] Parsing the input line
        - [X] Converting the input to weechat output
        - [o] Converting the input to html
            - [X] Attributes
            - [ ] Colors
- [.] Commands
    - [X] Topic
    - [X] Redact
    - [o] Join
        - [X] Join public rooms
        - [X] Join private rooms
        - [ ] Create rooms if they don't exist
        - [ ] Completion
    - [X] Kick
        - [X] Completion
    - [ ] Query
        - [ ] Completion
    - [ ] Part
        - [ ] Completion
    - [ ] Invite
        - [ ] Completion
    - [ ] Whois
        - [ ] Completion
    - [ ] OP
    - [ ] Voice
    - [ ] Password
    - [ ] Room
        - [ ] Rename
        - [ ] Info
        - [ ] Join rules
- [O] Refactoring
    - [X] Server
    - [X] API
    - [ ] Message handling
    - [X] Colors
- [ ] Separate weechat IO from message handling/parsing
- [o] Input sanitization
    - [ ] Rooms ID
    - [ ] Room aliases
    - [X] Event ID
    - [X] User ID
    - [X] Age
    - [ ] Display names
    - [X] Messages
    - [ ] Topics
- [ ] Tests
    - [ ] Commands
    - [ ] Message handling
    - [ ] Utils

# OLM
- [ ] Encrypted messaging
    - [ ] Generate keys
    - [ ] Store keys
    - [ ] Load keys
    - [ ] Upload keys
    - [ ] Rotate keys
    - [ ] Encrypt messages
    - [ ] Decrypt messages
    - [ ] Group message encryption
    - [ ] Device ID storing
    - [ ] Device ID loading
- [ ] Olm command
    - [ ] info
    - [ ] verify

- Keys should be transparently encrypted with your login password. (The lib
  already does that for us.)
- More info [here](https://matrix.org/docs/guides/e2e_implementation.html).

- Keys are bound to a user and a device.
- Ids to store:
    - user name (same as login user) -> weechat stores this for us
    - device_id -> store it in a separate data file
    - server-name -> folder
- OLM things to store:
    - Account info (holds the Identity keypair)
    - Session info
    - Group session info

## Olm weechat data format
- Create a matrix folder under the weechat home folder
- Create a server folder in the matrix folder
- Filenames in this folder should have the form of
  user_device.extension
- Store the device id in <user>.device_id
- Example:
  .weechat
  └── matrix
      └── matrix.org
          ├── poljar.device_id
          ├── poljar_<device_id>.account
          ├── poljar_<device_id>.session
          ├── poljar_<device_id>.group_session
          └── poljar_<device_id>.known_devices

- File formats:
    - .device_id -> single line containing the device id
    - .account -> pickle with the olm lib, encrypt using the user password
    - .session -> pickle with the olm lib, encrypt using the user password
    - .group_session -> pickle with the olm lib, encrypt using the user password
    - .known_devices -> pickle using the pickle module or json, a dict containing a
      user_id and a device_id

# DONE Color sending and recieving
- [SGR to/from RGB](https://github.com/chadj2/bash-ui/blob/master/COLORS.md#xterm-colorspaces)
- [RGB to from HTML/Hex](https://pypi.python.org/pypi/webcolors/1.3)
- [Fix broken HTML with Beautiful soup](https://stackoverflow.com/questions/293482/how-do-i-fix-wrongly-nested-unclosed-html-tags)

# DONE Message Redaction
- Store the event id somewhere with the message (the slack plugin replaces the
  date_printed variable for the message hdata, we can use a custom tag while
  printing lines)
- If we get a redaction event use hdata_pointer to get a list of all printed
  messages
- Strike through or completely delete the message

# DONE Old message fetching
- We can fetch old messages if we have less lines than max buffer lines or lines
  only younger than max buffer minutes
- To print out the messages we need to sort the line_data by date (see hdata)

# Room command
- Create room
- Set room join rules
- Room power levels
- Alias
- Encrypt room
