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
    MAX_SERVER_PACKET,
    MAX_SOURCES_PER_FILE,
    SEARCH_TIMEOUT,
    SERVER_LOGIN_TIMEOUT,
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
    from ed2k_client.wire import Packet, Reader

logger = logging.getLogger(__name__)

type CallbackHandler = Callable[[str, int], Coroutine[Any, Any, None]]

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
COMPLETE_FILE_ID: int = 0xFBFB_FBFB
COMPLETE_FILE_PORT: int = 0xFBFB
MAX_MESSAGES: int = 50
MAX_MESSAGE_LENGTH: int = 1000
MAX_PAGES: int = 3
SOURCES_TIMEOUT: float = 20.0
CONTROL_CHARACTERS = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')


def emule_version_tag() -> int:
    """Pack the software id and version as eMule's ``CT_EMULE_VERSION`` does.

    :returns: ``software << 24 | major << 17 | minor << 10 | update << 7``.
    :rtype: int
    """
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


def _clean_message(text: str) -> str:
    """Strip control characters from a server message and cut it to length.

    :param text: the message.
    :type text: str
    :returns: the cleaned message.
    :rtype: str
    """
    return CONTROL_CHARACTERS.sub(' ', text)[:MAX_MESSAGE_LENGTH]


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
    for _ in range(reader.u8()):
        client_id, port = reader.u32(), reader.u16()
        crypt, user_hash = CryptOption(0), None
        if obfuscated:
            crypt = CryptOption(reader.u8())
            if crypt & CryptOption.HAS_USER_HASH:
                user_hash = reader.hash16()
        sources.append(Source(client_id=client_id, port=port, user_hash=user_hash, crypt=crypt))
    return file_hash, sources[:MAX_SOURCES_PER_FILE]


class ServerSession:
    """A logged-in session with one server.

    :ivar entry: the server.
    :ivar state: what the server reported.
    """

    def __init__(self, *, stream: PacketStream, entry: ServerEntry, on_callback: CallbackHandler | None) -> None:
        """Wrap an open stream; use :meth:`login` to create a session.

        :param stream: the connection.
        :type stream: PacketStream
        :param entry: the server.
        :type entry: ServerEntry
        :param on_callback: called with the address of a peer that asked the server to reach this client.
        :type on_callback: CallbackHandler | None
        """
        self._stream = stream
        self.entry = entry
        self.state = ServerState()
        self._on_callback = on_callback
        self._search_pages: asyncio.Queue[Packet] = asyncio.Queue()
        self._source_waiters: dict[Ed2kHash, asyncio.Future[list[Source]]] = {}
        self._search_lock = asyncio.Lock()
        self._login_done = asyncio.Event()
        self._reader_task: asyncio.Task[None] | None = None
        self._background: set[asyncio.Task[None]] = set()
        self._handlers: dict[int, Callable[[Packet], None]] = {
            ServerOp.IDCHANGE: self._on_id_change,
            ServerOp.SERVERMESSAGE: self._on_message,
            ServerOp.SERVERSTATUS: self._on_status,
            ServerOp.SEARCHRESULT: self._search_pages.put_nowait,
            ServerOp.FOUNDSOURCES: self._on_sources,
            ServerOp.FOUNDSOURCES_OBFU: self._on_sources,
            ServerOp.CALLBACKREQUESTED: self._on_callback_requested,
        }

    @classmethod
    async def login(
        cls,
        *,
        entry: ServerEntry,
        identity: Identity,
        tcp_port: int,
        nickname: str,
        on_callback: CallbackHandler | None = None,
    ) -> Self:
        """Connect to a server and log in.

        :param entry: the server.
        :type entry: ServerEntry
        :param identity: this client's identity.
        :type identity: Identity
        :param tcp_port: the port this client listens on.
        :type tcp_port: int
        :param nickname: the user name shown to the server.
        :type nickname: str
        :param on_callback: called when a peer asks the server to reach this client.
        :type on_callback: CallbackHandler | None
        :returns: the logged-in session.
        :rtype: Self
        :raises ConnectionFailedError: when the server does not assign an ID in time.
        """
        stream = await PacketStream.connect(host=entry.host, port=entry.port, options=SERVER_STREAM)
        session = cls(stream=stream, entry=entry, on_callback=on_callback)
        payload = Writer().raw(identity.user_hash).u32(0).u16(tcp_port)
        write_tags(
            payload,
            [
                Tag(ClientTag.NAME, nickname),
                Tag(ClientTag.VERSION, EDONKEY_VERSION),
                Tag(ClientTag.SERVER_FLAGS, int(LOGIN_FLAGS)),
                Tag(ClientTag.EMULE_VERSION, emule_version_tag()),
            ],
        )
        await stream.send(protocol=Protocol.EDONKEY, opcode=ServerOp.LOGINREQUEST, payload=payload.getvalue())
        session._reader_task = asyncio.create_task(session._read_loop())
        try:
            await asyncio.wait_for(session._login_done.wait(), SERVER_LOGIN_TIMEOUT)
        except TimeoutError as error:
            await session.close()
            err_msg = f'{entry.address} assigned no ID within {SERVER_LOGIN_TIMEOUT} s'
            raise ConnectionFailedError(err_msg) from error
        return session

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
                self._dispatch(await self._stream.read_packet(limit=MAX_SERVER_PACKET))
        except (ConnectionFailedError, ProtocolError) as error:
            logger.warning('Session with %s ended: %s', self.entry.address, error)
        finally:
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
        if reader.remaining >= U32.size:
            self.state.tcp_flags = ServerTcpFlag(reader.u32())
        self._login_done.set()

    def _on_message(self, packet: Packet) -> None:
        """Keep a server message.

        :param packet: the packet.
        :type packet: Packet
        """
        message = _clean_message(packet.reader().string())
        self.state.messages = [*self.state.messages, message][-MAX_MESSAGES:]
        logger.info('Server %s says %s', self.entry.address, message)

    def _on_status(self, packet: Packet) -> None:
        """Record the user and file counts.

        :param packet: the packet.
        :type packet: Packet
        """
        reader = packet.reader()
        self.state.users, self.state.files = reader.u32(), reader.u32()

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
        allow_64bit = bool(self.state.tcp_flags & ServerTcpFlag.LARGEFILES)
        tree = encode_query(query, allow_64bit=allow_64bit)
        results: list[SearchResult] = []
        async with self._search_lock:
            while not self._search_pages.empty():
                self._search_pages.get_nowait()
            await self._stream.send(protocol=Protocol.EDONKEY, opcode=ServerOp.SEARCHREQUEST, payload=tree)
            for _ in range(MAX_PAGES):
                try:
                    packet = await asyncio.wait_for(self._search_pages.get(), SEARCH_TIMEOUT)
                except TimeoutError:
                    break
                page = parse_server_results(packet.reader())
                results.extend(page.results)
                if not page.more_available or len(results) >= max_results:
                    break
                await self._stream.send(protocol=Protocol.EDONKEY, opcode=ServerOp.QUERY_MORE_RESULT)
        return [result for result in results if query.matches_extension(result.name)][:max_results]

    async def get_sources(self, *, file_hash: Ed2kHash, size: int) -> list[Source]:
        """Ask the server which of its users share a file.

        :param file_hash: the file hash.
        :type file_hash: Ed2kHash
        :param size: the file size, which servers since 17.8 require.
        :type size: int
        :returns: the sources, empty when the server knows none or does not answer in time.
        :rtype: list[Source]
        """
        payload = Writer().raw(file_hash.digest)
        if size > LARGE_FILE_THRESHOLD:
            payload.u32(0).u64(size)
        else:
            payload.u32(size)
        waiter = asyncio.get_running_loop().create_future()
        self._source_waiters[file_hash] = waiter
        try:
            await self._stream.send(protocol=Protocol.EDONKEY, opcode=ServerOp.GETSOURCES, payload=payload.getvalue())
            sources: list[Source] = await asyncio.wait_for(waiter, SOURCES_TIMEOUT)
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
