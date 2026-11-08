"""The TCP session with one eD2k server: login, search, sources, callbacks and offered files.

The login packet follows ``CServerConnect::ConnectionEstablished`` in aMule. After login a background task reads
every packet the server sends and routes it: search pages and source lists to the call waiting for them, callback
requests to the client, and messages and status to the session's attributes. Every packet passes the size limits
of :class:`PacketStream` and the parsers of :mod:`ed2k_client.search`, so a hostile server can only fail the
session.
"""

import asyncio
import logging
import re
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Self

from ed2k_client.constants import (
    EDONKEY_VERSION,
    LARGE_FILE_THRESHOLD,
    SOFTWARE_ID,
    SOFTWARE_VERSION,
    ClientTag,
    CryptOption,
    FileTag,
    LoginFlag,
    Protocol,
    ServerOp,
    ServerTcpFlag,
)
from ed2k_client.errors import ConnectionFailedError, ProtocolError
from ed2k_client.hashing import Ed2kHash
from ed2k_client.search import encode_query, is_low_id, parse_server_results
from ed2k_client.settings import DEFAULT_TIMEOUTS
from ed2k_client.sources import Source
from ed2k_client.tags import Tag, write_tags
from ed2k_client.transport import SERVER_STREAM, PacketStream
from ed2k_client.wire import U32, Writer

if TYPE_CHECKING:
    from collections.abc import Sequence
    from types import TracebackType

    from ed2k_client.identity import Identity
    from ed2k_client.search import SearchQuery, SearchResult
    from ed2k_client.servermet import ServerEntry
    from ed2k_client.settings import Limits, Timeouts
    from ed2k_client.transport import StreamOptions
    from ed2k_client.wire import Packet, Reader

logger = logging.getLogger(__name__)

type CallbackHandler = Callable[[str, int], Coroutine[Any, Any, None]]

# The capabilities aMule announces in its login: https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/ServerConnect.cpp#L188
LOGIN_FLAGS: LoginFlag = (
    LoginFlag.ZLIB
    | LoginFlag.AUXPORT
    | LoginFlag.NEWTAGS
    | LoginFlag.UNICODE
    | LoginFlag.LARGEFILES
    | LoginFlag.SUPPORTCRYPT
    | LoginFlag.REQUESTCRYPT
)
NO_SERVER_FLAGS: ServerTcpFlag = ServerTcpFlag(0)

# An offered file with this address and port marks the file as complete instead of naming a source:
# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/KnownFile.cpp#L1173
COMPLETE_FILE_ID: int = 0xFBFB_FBFB
COMPLETE_FILE_PORT: int = 0xFBFB

# Control characters in a server message could rewrite the terminal line it is logged to
CONTROL_CHARACTERS = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')


def emule_version_tag() -> int:
    """Pack the software id and version as eMule's ``CT_EMULE_VERSION`` does.

    :returns: ``software << 24 | major << 17 | minor << 10 | update << 7``.
    :rtype: int
    """
    # The layout of aMule's own tag: https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/ServerConnect.cpp#L253
    major, minor, update = SOFTWARE_VERSION
    return SOFTWARE_ID << 24 | major << 17 | minor << 10 | update << 7


@dataclass(frozen=True, slots=True)
class OfferedFile:
    """A complete file published to the server.

    :ivar file_hash: the eD2k hash.
    :ivar name: the published name.
    :ivar size: the size in bytes.
    :ivar file_type: the eD2k type string, ``Doc`` for documents.
    """

    file_hash: Ed2kHash
    name: str
    size: int
    file_type: str = ''


@dataclass(frozen=True, slots=True)
class LoginDetails:
    """What the client tells a server about itself when it logs in.

    :ivar identity: the user hash the session belongs to.
    :ivar tcp_port: the port this client listens on.
    :ivar nickname: the user name shown to the server.
    """

    identity: Identity
    tcp_port: int
    nickname: str


@dataclass(slots=True)
class ServerState:
    """What the server told the client.

    :ivar client_id: the assigned ID.
    :ivar tcp_flags: the server's capabilities.
    :ivar users: the reported number of users.
    :ivar files: the reported number of files.
    :ivar messages: the server's messages, cleaned of control characters.
    """

    client_id: int = 0
    tcp_flags: ServerTcpFlag = NO_SERVER_FLAGS
    users: int = 0
    files: int = 0
    messages: list[str] = field(default_factory=list)


def _clean_message(text: str, *, limits: Limits) -> str:
    """Strip control characters from a server message and cut it to length.

    :param text: the message.
    :type text: str
    :param limits: the cap on the kept length.
    :type limits: Limits
    :returns: the cleaned message.
    :rtype: str
    """
    return CONTROL_CHARACTERS.sub(' ', text)[: limits.server_message_length]


def _parse_sources(reader: Reader, *, obfuscated: bool) -> tuple[Ed2kHash, list[Source]]:
    """Parse a source list, with the obfuscation settings and user hashes when present.

    :param reader: the payload reader.
    :type reader: Reader
    :param obfuscated: whether it is ``OP_FOUNDSOURCES_OBFU``.
    :type obfuscated: bool
    :returns: the file hash and its sources.
    :rtype: tuple[Ed2kHash, list[Source]]
    """
    file_hash = Ed2kHash(reader.hash16())
    sources = []

    # <hash 16><count 1> then per source <id 4><port 2>, plus <crypt 1>[<user hash 16>] in the _OBFU variant:
    # https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/PartFile.cpp#L1800
    for _ in range(reader.u8()):
        client_id, port = reader.u32(), reader.u16()
        crypt, user_hash = CryptOption(0), None
        if obfuscated:
            crypt = CryptOption(reader.u8())
            if crypt & CryptOption.HAS_USER_HASH:
                user_hash = reader.hash16()
        sources.append(Source(client_id=client_id, port=port, user_hash=user_hash, crypt=crypt))

    return file_hash, sources[: reader.limits.sources_per_file]


class ServerSession:
    """A logged-in session with one server.

    :ivar entry: the server.
    :ivar state: what the server reported.
    """

    def __init__(
        self,
        *,
        stream: PacketStream,
        entry: ServerEntry,
        on_callback: CallbackHandler | None,
        timeouts: Timeouts = DEFAULT_TIMEOUTS,
        limits: Limits,
    ) -> None:
        """Wrap an open stream; use :meth:`login` to create a session.

        :param stream: the connection.
        :type stream: PacketStream
        :param entry: the server.
        :type entry: ServerEntry
        :param on_callback: called with the address of a peer that asked the server to reach this client.
        :type on_callback: CallbackHandler | None
        :param timeouts: how long searches and source requests wait.
        :type timeouts: Timeouts
        :param limits: the caps on server packets, messages and result pages.
        :type limits: Limits
        """
        self._stream = stream
        self.entry = entry
        self.state = ServerState()
        self._on_callback = on_callback
        self._timeouts = timeouts
        self._limits = limits
        self._search_pages: asyncio.Queue[Packet] = asyncio.Queue(maxsize=limits.server_result_pages)
        self._source_waiters: dict[Ed2kHash, asyncio.Future[list[Source]]] = {}
        self._search_lock = asyncio.Lock()
        self._login_done = asyncio.Event()
        self._reader_task: asyncio.Task[None] | None = None
        self._background: set[asyncio.Task[None]] = set()

        # Packets of the eDonkey namespace by opcode. Anything else a server sends is ignored, as aMule ignores it
        self._handlers: dict[int, Callable[[Packet], None]] = {
            ServerOp.IDCHANGE: self._on_id_change,
            ServerOp.SERVERMESSAGE: self._on_message,
            ServerOp.SERVERSTATUS: self._on_status,
            ServerOp.SEARCHRESULT: self._on_search_page,
            ServerOp.FOUNDSOURCES: self._on_sources,
            ServerOp.FOUNDSOURCES_OBFU: self._on_sources,
            ServerOp.CALLBACKREQUESTED: self._on_callback_requested,
        }

    @classmethod
    async def login(
        cls,
        *,
        entry: ServerEntry,
        details: LoginDetails,
        on_callback: CallbackHandler | None = None,
        timeouts: Timeouts = DEFAULT_TIMEOUTS,
        options: StreamOptions = SERVER_STREAM,
    ) -> Self:
        """Connect to a server and log in.

        :param entry: the server.
        :type entry: ServerEntry
        :param details: the identity, port and name this client announces.
        :type details: LoginDetails
        :param on_callback: called when a peer asks the server to reach this client.
        :type on_callback: CallbackHandler | None
        :param timeouts: how long the login, searches and source requests wait.
        :type timeouts: Timeouts
        :param options: how the connection connects and reads, with the eDonkey namespace for packed packets.
        :type options: StreamOptions
        :returns: the logged-in session.
        :rtype: Self
        :raises ConnectionFailedError: when the server does not assign an ID in time.
        """
        stream = await PacketStream.connect(host=entry.host, port=entry.port, options=options)
        session = cls(stream=stream, entry=entry, on_callback=on_callback, timeouts=timeouts, limits=options.limits)

        # <user hash 16><client id 4><port 2><tags>, where id 0 lets the server assign one
        payload = Writer().raw(details.identity.user_hash).u32(0).u16(details.tcp_port)
        write_tags(
            payload,
            [
                Tag(ClientTag.NAME, details.nickname),
                Tag(ClientTag.VERSION, EDONKEY_VERSION),
                Tag(ClientTag.SERVER_FLAGS, int(LOGIN_FLAGS)),
                Tag(ClientTag.EMULE_VERSION, emule_version_tag()),
            ],
        )
        await stream.send(protocol=Protocol.EDONKEY, opcode=ServerOp.LOGINREQUEST, payload=payload.getvalue())

        # The reader starts before the wait, because the ID arrives as an ordinary packet after messages and status
        session._reader_task = asyncio.create_task(session._read_loop())

        # The reader ends when the server hangs up, which settles the login as failed without waiting out the timeout
        assigned = asyncio.ensure_future(session._login_done.wait())
        await asyncio.wait(
            {assigned, session._reader_task}, timeout=timeouts.server_login, return_when=asyncio.FIRST_COMPLETED
        )
        assigned.cancel()
        if session._login_done.is_set():
            return session

        hung_up = session._reader_task.done()
        await session.close()
        if hung_up:
            err_msg = f'{entry.address} closed the connection before assigning an ID'
        else:
            err_msg = f'{entry.address} assigned no ID within {timeouts.server_login} s'
        raise ConnectionFailedError(err_msg)

    @property
    def is_low_id(self) -> bool:
        """Whether the server could not reach this client and gave it a Low ID."""
        return is_low_id(self.state.client_id)

    @property
    def connected(self) -> bool:
        """Whether the session's reader is still running."""
        return self._reader_task is not None and not self._reader_task.done()

    async def _read_loop(self) -> None:
        """Read and dispatch server packets until the session ends, then release waiting calls."""
        try:
            while True:
                self._dispatch(await self._stream.read_packet(limit=self._limits.server_packet))
        except (ConnectionFailedError, ProtocolError) as error:
            logger.warning('Session with %s ended: %s', self.entry.address, error)
        finally:
            # A source request still waiting would otherwise wait for its full timeout on a dead session
            for waiter in self._source_waiters.values():
                if not waiter.done():
                    waiter.set_result([])

    def _dispatch(self, packet: Packet) -> None:
        """Hand an eDonkey packet to its handler.

        :param packet: the packet.
        :type packet: Packet
        """
        logger.debug('Server packet 0x%02X/0x%02X, %d bytes', packet.protocol, packet.opcode, len(packet.payload))
        handler = self._handlers.get(packet.opcode) if packet.protocol == Protocol.EDONKEY else None
        if handler is not None:
            handler(packet)

    def _on_id_change(self, packet: Packet) -> None:
        """Record the assigned ID and the server flags and finish the login.

        :param packet: the packet.
        :type packet: Packet
        """
        reader = packet.reader()
        self.state.client_id = reader.u32()

        # The flags are optional, and aMule reads them only when four more bytes follow the ID:
        # https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/ServerSocket.cpp#L248
        if reader.remaining >= U32.size:
            self.state.tcp_flags = ServerTcpFlag(reader.u32())
        self._login_done.set()

    def _on_message(self, packet: Packet) -> None:
        """Keep a server message.

        :param packet: the packet.
        :type packet: Packet
        """
        message = _clean_message(packet.reader().string(), limits=self._limits)
        self.state.messages = [*self.state.messages, message][-self._limits.server_messages :]
        logger.info('Server %s says %s', self.entry.address, message)

    def _on_status(self, packet: Packet) -> None:
        """Record the user and file counts.

        :param packet: the packet.
        :type packet: Packet
        """
        reader = packet.reader()
        self.state.users, self.state.files = reader.u32(), reader.u32()

    def _on_search_page(self, packet: Packet) -> None:
        """Keep a search result page while a search waits for it and has room for it.

        :param packet: the packet.
        :type packet: Packet
        """
        # A page nobody asked for, or one beyond the pages a search reads, would only grow memory, as a hostile
        # server could keep sending them for the whole session
        if self._search_lock.locked() and not self._search_pages.full():
            self._search_pages.put_nowait(packet)

    def _on_sources(self, packet: Packet) -> None:
        """Hand a source list to the call waiting for it.

        :param packet: the packet.
        :type packet: Packet
        """
        obfuscated = packet.opcode == ServerOp.FOUNDSOURCES_OBFU
        file_hash, sources = _parse_sources(packet.reader(), obfuscated=obfuscated)
        waiter = self._source_waiters.get(file_hash)
        if waiter is not None and not waiter.done():
            waiter.set_result(sources)

    def _on_callback_requested(self, packet: Packet) -> None:
        """Start the callback handler for a peer that asked to be called.

        :param packet: the packet.
        :type packet: Packet
        """
        if self._on_callback is None:
            return

        # The handler dials the peer, which may take seconds, so it runs as a task beside the reader loop
        reader = packet.reader()
        task = asyncio.create_task(self._on_callback(reader.ed2k_ip(), reader.u16()))
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    async def search(self, query: SearchQuery, *, max_results: int = 300) -> list[SearchResult]:
        """Run a search on this server.

        :param query: the query.
        :type query: SearchQuery
        :param max_results: stop asking for more pages after this many results.
        :type max_results: int
        :returns: the results that match the query's extensions, in server order.
        :rtype: list[SearchResult]
        """
        # A size term above 4 GiB needs the 64-bit operand, which only servers with the LARGEFILES flag parse
        allow_64bit = bool(self.state.tcp_flags & ServerTcpFlag.LARGEFILES)
        tree = encode_query(query, allow_64bit=allow_64bit)
        results: list[SearchResult] = []

        # Result pages carry no search id, so one search at a time, and pages left from a timed-out search are dropped
        async with self._search_lock:
            while not self._search_pages.empty():
                self._search_pages.get_nowait()
            await self._stream.send(protocol=Protocol.EDONKEY, opcode=ServerOp.SEARCHREQUEST, payload=tree)

            for _ in range(self._limits.server_result_pages):
                try:
                    packet = await asyncio.wait_for(self._search_pages.get(), self._timeouts.server_search)
                except TimeoutError:
                    break
                page = parse_server_results(packet.reader())
                results.extend(page.results)
                if not page.more_available or len(results) >= max_results:
                    break
                await self._stream.send(protocol=Protocol.EDONKEY, opcode=ServerOp.QUERY_MORE_RESULT)

        return [result for result in results if query.accepts(result)][:max_results]

    async def get_sources(self, *, file_hash: Ed2kHash, size: int) -> list[Source]:
        """Ask the server which of its users share a file.

        :param file_hash: the file hash.
        :type file_hash: Ed2kHash
        :param size: the file size, which servers since 17.8 require.
        :type size: int
        :returns: the sources, empty when the server knows none or does not answer in time.
        :rtype: list[Source]
        """
        # A large file sends a zero 32-bit size and then the 64-bit size, as servers accept since 17.9:
        # https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/DownloadQueue.cpp#L1104
        payload = Writer().raw(file_hash.digest)
        if size > LARGE_FILE_THRESHOLD:
            payload.u32(0).u64(size)
        else:
            payload.u32(size)

        waiter = asyncio.get_running_loop().create_future()
        self._source_waiters[file_hash] = waiter
        try:
            await self._stream.send(protocol=Protocol.EDONKEY, opcode=ServerOp.GETSOURCES, payload=payload.getvalue())
            sources: list[Source] = await asyncio.wait_for(waiter, self._timeouts.server_sources)
        except TimeoutError:
            return []
        finally:
            self._source_waiters.pop(file_hash, None)
        return sources

    async def request_callback(self, client_id: int) -> None:
        """Ask the server to make a Low ID peer connect to this client, which only works from a High ID.

        :param client_id: the peer's Low ID.
        :type client_id: int
        """
        payload = Writer().u32(client_id).getvalue()
        await self._stream.send(protocol=Protocol.EDONKEY, opcode=ServerOp.CALLBACKREQUEST, payload=payload)

    async def offer_files(self, files: Sequence[OfferedFile]) -> None:
        """Publish complete files on the server so that it lists this client as their source.

        :param files: the files.
        :type files: Sequence[OfferedFile]
        """
        # Each entry is <hash 16><id 4><port 2><tags>, and the 64-bit size is split into SIZE and SIZE_HI
        payload = Writer().u32(len(files))
        for offered in files:
            payload.raw(offered.file_hash.digest).u32(COMPLETE_FILE_ID).u16(COMPLETE_FILE_PORT)
            tags = [Tag(FileTag.NAME, offered.name), Tag(FileTag.SIZE, offered.size & LARGE_FILE_THRESHOLD)]
            if offered.size > LARGE_FILE_THRESHOLD:
                tags.append(Tag(FileTag.SIZE_HI, offered.size >> 32))
            if offered.file_type:
                tags.append(Tag(FileTag.TYPE, offered.file_type))
            write_tags(payload, tags)

        await self._stream.send(protocol=Protocol.EDONKEY, opcode=ServerOp.OFFERFILES, payload=payload.getvalue())

    async def close(self) -> None:
        """Stop the reader and close the connection."""
        if self._reader_task is not None:
            self._reader_task.cancel()
            await asyncio.gather(self._reader_task, return_exceptions=True)
        await self._stream.close()

    async def __aenter__(self) -> Self:
        """Enter the context.

        :returns: the session itself.
        :rtype: Self
        """
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None
    ) -> None:
        """Close the session on leaving the context.

        :param exc_type: the exception type, if any.
        :type exc_type: type[BaseException] | None
        :param exc: the exception, if any.
        :type exc: BaseException | None
        :param traceback: the traceback, if any.
        :type traceback: TracebackType | None
        """
        await self.close()
