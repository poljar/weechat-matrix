import asyncio
import json
import os
import socket
import time
import traceback
import sys
import concurrent.futures

import attr
from .globals import W

from uuid import uuid4


@attr.s
class WeechatFuture:
    inner = attr.ib()
    uuid = attr.ib()
    hook = attr.ib()


@attr.s
class WeechatFdData:
    hook = attr.ib()
    callback = attr.ib()


@attr.s
class HookConnectResponse:
    socket = attr.ib()
    return_value = attr.ib()

    @property
    def error_message(self):
        if self.return_value == W.WEECHAT_HOOK_CONNECT_OK:
            return "Connection ok"

        return "Connection failed"

def getaddrinfo_func(data):
    data = json.loads(data)
    data.pop("uuid")
    ret = socket.getaddrinfo(**data)
    return json.dumps(ret)


def gettaddrinfo_cb(data, command, return_code, out, err):
    loop = asyncio.get_event_loop()

    if return_code == W.WEECHAT_HOOK_PROCESS_ERROR:
        return W.WEECHAT_RC_OK

    if return_code == 0:
        if out != "":
            data = json.loads(data)
            queue = loop._process_queues.pop(data["uuid"])
            queue.put_nowait(out)

    return W.WEECHAT_RC_OK


def asyncio_reader_cb(_, fd):
    loop = asyncio.get_event_loop()

    try:
        fd_data = loop._readers[fd]
        fd_data.callback()
    except KeyError:
        return W.WEECHAT_RC_OK

    return W.WEECHAT_RC_OK


def asyncio_writer_cb(_, fd):
    loop = asyncio.get_event_loop()

    try:
        fd_data = loop._writers[fd]
        fd_data.callback()
    except KeyError:
        return W.WEECHAT_RC_OK

    return W.WEECHAT_RC_OK


def asyncio_loop_cb(uuid, remaining_calls):
    loop = asyncio.get_event_loop()

    try:
        future = loop._futures.pop(uuid)
        handle = future.inner

        if not handle._cancelled:
            handle._run()

    except KeyError:
        return W.WEECHAT_RC_OK

    return W.WEECHAT_RC_OK


def asyncio_connect_cb(uuid, status, gnutls_rc, sock, error, ip_address):
    loop = asyncio.get_event_loop()

    try:
        queue = loop._socket_queues.pop(uuid)
        message = HookConnectResponse(sock, status)
        queue.put_nowait(message)

    except KeyError:
        return W.WEECHAT_RC_OK

    return W.WEECHAT_RC_OK


class WeechatTransport(asyncio.Transport):
    max_size = 256 * 1024  # Buffer size passed to recv().
    _sock = None

    _start_tls_compatible = True

    def __init__(self, loop, sock, protocol, extra=None, server=None):
        super().__init__(extra, loop)
        self._extra['socket'] = asyncio.trsock.TransportSocket(sock)

        try:
            self._extra['sockname'] = sock.getsockname()
        except OSError:
            self._extra['sockname'] = None
        if 'peername' not in self._extra:
            try:
                self._extra['peername'] = sock.getpeername()
            except socket.error:
                self._extra['peername'] = None

        self._sock = sock
        self._sock_fd = sock.fileno()
        self._protocol_connected = False
        self.set_protocol(protocol)

        self._server = server
        self._buffer = bytearray()

        self._conn_lost = 0  # Set when call to connection_lost scheduled.
        self._closing = False  # Set when close() called.
        self._read_ready_cb = None

        self._eof = False
        self._paused = False
        self._empty_waiter = None

        if self._server is not None:
            self._server._attach()

        loop._transports[self._sock_fd] = self

        self._loop.call_soon(self._protocol.connection_made, self)
        # only start reading when connection_made() has been called
        self._loop.call_soon(self._add_reader, self._sock_fd, self._read_ready)


class WeechatLoop(asyncio.AbstractEventLoop):
    def __init__(self):
        self._exc = None
        self._debug = False
        self._default_executor = None

        self._csock = None
        self._ssock = None

        self._running = True

        self._threadsafe_futures = list()

        self._futures = dict()

        self._readers = dict()
        self._writers = dict()

        self._transports = dict()
        self._socket_queues = dict()
        self._process_queues = dict()

        # self._make_self_pipe()

    def get_debug(self):
        return False

    def time(self):
        return time.monotonic()

    def run_forever(self):
        pass

    def run_until_complete(self, future):
        raise NotImplementedError("Run until complete is not implemented.")

    def is_running(self):
        return self._running

    def is_closed(self):
        return not self._running

    def stop(self):
        return

    def close(self):
        self.stop()

    def get_debug(self):
        return self._debug

    def set_debug(self, enabled):
        self._debug = enabled

    def shutdown_asyncgens(self):
        pass

    def call_exception_handler(self, context):
        self._exc = context.get('exception', None)

    def _check_callback(self, callback, method):
        if (coroutines.iscoroutine(callback) or
                coroutines.iscoroutinefunction(callback)):
            raise TypeError(
                f"coroutines cannot be used with {method}()")
        if not callable(callback):
            raise TypeError(
                f'a callable object was expected by {method}(), '
                f'got {callback!r}')

    def call_soon_threadsafe(self, callback, *args, context=None):
        raise NotImplementedError("Threadsafe calling is not implemented.")
        if self._debug:
            self._check_callback(callback, 'call_soon_threadsafe')

        handle = asyncio.Handle(callback, args, self)

        self._threadsafe_futures.append(handle)

        self._write_to_self()
        return handle

    def _write_to_self(self):
        csock = self._csock

        if csock is not None:
            try:
                csock.send(b'\0\n')
            except OSError:
                pass

    def _make_self_pipe(self):
        self._ssock, self._csock = socket.socketpair()
        self._ssock.setblocking(False)
        self._csock.setblocking(False)
        self._add_reader(self._ssock.fileno(), self._read_from_self)

    def _process_self_data(self, data):
        for handle in self._thradsafe_futures:
            self._call_soon(handle)

        self._thradsafe_futures = list()

    def _read_from_self(self):
        while True:
            try:
                data = self._ssock.recv(4096)
                if not data:
                    break
                self._process_self_data(data)
            except InterruptedError:
                continue
            except BlockingIOError:
                break

    def _call_soon(self, handle):
        uuid = str(uuid4())
        hook = W.hook_timer(1, 0, 1, "asyncio_loop_cb", uuid)

        future = WeechatFuture(handle, uuid, hook)
        self._futures[uuid] = future


    def call_soon(self, callback, *args, context=None):
        handle = asyncio.Handle(callback, args, self)
        self._call_soon(handle)

        return handle

    def call_later(self, delay, callback, *args, context=None):
        delay = int(delay * 1000)
        if delay < 0:
            raise RuntimeError("Can't schedule in the past")

        now = self.time()
        when = now + delay

        handle = asyncio.TimerHandle(when, callback, args, self)
        uuid = str(uuid4())
        hook = W.hook_timer(delay, 0, 1, "asyncio_loop_cb", uuid)

        future = WeechatFuture(handle, uuid, hook)
        self._futures[uuid] = future
        handle._scheduled = True

        return handle

    def call_at(self, when, callback, *args, context=None):
        now = self.time()

        if when < now:
            raise RuntimeError("Can't schedule in the past")

        delay = max(when - now, 1)

        return self.call_later(delay, callback, *args, context)

    def create_task(self, coro, *, name=None):
        async def wrapper():
            try:
                return await coro
            except Exception as e:
                print(f"Coroutine failed with exception of type {type(e)} {e}")
                traceback.print_exc(file=sys.stdout)
                self._exc = e

        return asyncio.Task(wrapper(), loop=self)

    def create_future(self):
        return asyncio.Future(loop=self)

    def _timer_handle_cancelled(self, handle):
        pass

    # This function is from the cpython implementation for the
    # BaseSelectorEventLoop
    # https://github.com/python/cpython/blob/3f43ceff186da09978d0aff257bb18b8ac7611f7/Lib/asyncio/selector_events.py
    def _ensure_fd_no_transport(self, fd):
        fileno = fd

        if not isinstance(fileno, int):
            try:
                fileno = int(fileno.fileno())
            except (AttributeError, TypeError, ValueError):
                # This code matches selectors._fileobj_to_fd function.
                raise ValueError(f"Invalid file object: {fd!r}") from None
        try:
            transport = self._transports[fileno]
        except KeyError:
            pass
        else:
            if not transport.is_closing():
                raise RuntimeError(
                    f'File descriptor {fd!r} is used by transport '
                    f'{transport!r}')

    def _add_reader(self, fd, callback, *args):
        if not isinstance(fd, int):
            fd = int(fd.fileno())

        hook = W.hook_fd(fd, 1, 0, 0, "asyncio_reader_cb", "")
        fd_data = WeechatFdData(hook, callback)
        self._readers[fd] = fd_data

    def add_reader(self, fd, callback, *args):
        self._ensure_fd_no_transport(fd)
        self._add_reader(fd, callback, *args)

    def _remove_reader(self, fd):
        self.remove_reader(fd)

    def remove_reader(self, fd):
        if not isinstance(fd, int):
            fd = int(fd.fileno())

        try:
            fd_data = self._readers.pop(fd)
            W.unhook(fd_data.hook)
            return True
        except KeyError:
            return False

    def _add_writer(self, fd, callback, *args):
        if not isinstance(fd, int):
            fd = int(fd.fileno())

        hook = W.hook_fd(fd, 0, 1, 0, "asyncio_writer_cb", "")
        fd_data = WeechatFdData(hook, callback)
        self._writers[fd] = fd_data

    def add_writer(self, fd, callback, *args):
        self._ensure_fd_no_transport(fd)
        self._add_writer(fd, callback, *args)

    def _remove_writer(self, fd):
        self.remove_writer(fd)

    def remove_writer(self, fd):
        if not isinstance(fd, int):
            fd = int(fd.fileno())

        try:
            fd_data = self._writers.pop(fd)
            W.unhook(fd_data.hook)
            return True
        except KeyError:
            return False

    async def getaddrinfo(self, host, port, *, family=0, type=0, proto=0,
            flags=0):
        uuid = str(uuid4())
        queue = asyncio.Queue()
        self._process_queues[uuid] = queue

        data = json.dumps({
            "uuid": uuid,
            "host": host,
            "port": port,
            "family": family,
            "type": type,
            "proto": proto
        })

        hook = W.hook_process(
            "func:getaddrinfo_func",
            0,
            "gettaddrinfo_cb",
            data
        )

        return json.loads(await queue.get())

    def run_in_executor(self, executor, func, *args):
        # raise NotImplementedError("Executor isn't implemented")
        if executor is None:
            executor = self._default_executor
            if executor is None:
                executor = concurrent.futures.ThreadPoolExecutor()
                self._default_executor = executor
        return asyncio.wrap_future(
            executor.submit(func, *args), loop=self)

    async def create_connection(
        self,
        protocol_factory,
        host=None,
        port=None,
        *,
        ssl=None,
        family=0,
        proto=0,
        flags=0,
        sock=None,
        local_addr=None,
        server_hostname=None,
        ssl_handshake_timeout=None,
        happy_eyeballs_delay=None,
        interleave=None
    ):
        local_addr = local_addr or ""

        if server_hostname is not None and not ssl:
                raise ValueError('server_hostname is only meaningful with ssl')

        if server_hostname is None and ssl:
            if not host:
                raise ValueError('You must set server_hostname '
                                     'when using ssl without a host')
            server_hostname = host

        if ssl_handshake_timeout is not None and not ssl:
            raise ValueError('ssl_handshake_timeout is only meaningful with ssl')

        if host is not None or port is not None:
            if sock is not None:
                raise ValueError(
                    'host/port and sock can not be specified at the same time')

            uuid = str(uuid4())
            queue = asyncio.Queue()

            self._socket_queues[uuid] = queue

            hook = W.hook_connect("", host, port, 1, 0, local_addr,
            "asyncio_connect_cb", uuid)

            message = await queue.get()

            if message.return_value != W.WEECHAT_HOOK_CONNECT_OK:
                raise OSError(message.error_message)

            sock = socket.fromfd(message.socket, socket.AF_INET, socket.SOCK_STREAM)

            # fromfd() duplicates the file descriptor, we can close the one we got
            # from weechat now since we use the one from our socket when calling
            # hook_fd()
            os.close(message.socket)

        else:
            if sock is None:
                raise ValueError(
                    'host and port was not specified and no sock specified')
            if sock.type != socket.SOCK_STREAM:
                raise ValueError(
                    f'A Stream Socket was expected, got {sock!r}')

        transport, protocol = await self._create_connection_transport(
            sock,
            protocol_factory,
            ssl,
            server_hostname,
            ssl_handshake_timeout=ssl_handshake_timeout
        )

        return transport, protocol

    async def _create_connection_transport(
        self,
        sock,
        protocol_factory,
        ssl,
        server_hostname,
        server_side=False,
        ssl_handshake_timeout=None
    ):
        sock.setblocking(False)

        protocol = protocol_factory()
        waiter = self.create_future()

        if ssl:
            sslcontext = None if isinstance(ssl, bool) else ssl
            transport = self._make_ssl_transport(
                sock, protocol, sslcontext, waiter,
                server_side=server_side, server_hostname=server_hostname,
                ssl_handshake_timeout=ssl_handshake_timeout)
        else:
            transport = self._make_socket_transport(sock, protocol, waiter)

        try:
            await waiter
        except:
            transport.close()
            raise

        return transport, protocol

    def _make_socket_transport(self, sock, protocol, waiter=None, *, extra=None,
            server = None):
        return asyncio.selector_events._SelectorSocketTransport(self, sock,
                protocol, waiter, extra, server)

    def _make_ssl_transport(
            self, rawsock, protocol, sslcontext, waiter=None,
            *, server_side=False, server_hostname=None,
            extra=None, server=None,
            ssl_handshake_timeout=asyncio.constants.SSL_HANDSHAKE_TIMEOUT):
        ssl_protocol = asyncio.sslproto.SSLProtocol(
                self, protocol, sslcontext, waiter,
                server_side, server_hostname,
                ssl_handshake_timeout=ssl_handshake_timeout)
        asyncio.selector_events._SelectorSocketTransport(self, rawsock,
                ssl_protocol, extra=extra, server=server)
        return ssl_protocol._app_transport
