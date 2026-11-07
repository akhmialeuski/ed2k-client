"""In-process stand-ins for an eD2k server, a seeding peer and a Kad network that speak the real wire format.

The fake server evaluates the binary search tree it receives against its index, so a search test also checks the
semantics of the encoded query, and it sends its result pages zlib-packed the way Lugdunum servers do. The fake Kad
nodes answer only when the receiver ID in ``KADEMLIA2_REQ`` is theirs and search only inside the 2^120 tolerance
zone, the two checks a real aMule node makes. The fake peer answers AICH requests, which the client's own serving side
does not, so it stands in for an eMule seeder in the AICH tests.

The scripted stream stands in for one :class:`PacketStream` in unit tests. ``create_autospec`` cannot read the
signatures of :class:`PacketStream`, because its annotations name imports that exist only for type checkers.
"""

import asyncio
import ipaddress
import operator
import random
import struct
import zlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Self

from ed2k_client.constants import (
    AICH_HASH_LENGTH,
    ClientTag,
    CryptOption,
    EmuleOp,
    FileTag,
    KadOp,
    PeerOp,
    Protocol,
    SearchOperator,
    ServerOp,
    ServerTcpFlag,
)
from ed2k_client.errors import ConnectionFailedError, ProtocolError
from ed2k_client.hashing import Ed2kHash, md4
from ed2k_client.kad.contacts import KadId
from ed2k_client.peer import AICH_SHIFT, PartRequest
from ed2k_client.search import BooleanOperator, SearchNodeKind
from ed2k_client.servermet import ServerEntry
from ed2k_client.settings import DEFAULT_LIMITS
from ed2k_client.sources import Source, SourceOrigin, client_id_from_host
from ed2k_client.tags import Tag, int_value, read_tags, str_value, tag_map, write_tags
from ed2k_client.transport import PacketStream, StreamOptions
from ed2k_client.wire import Reader, Writer, decode_udp, encode_udp
from tests.helpers import recovery_data

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path
    from types import TracebackType

    from ed2k_client.errors import Ed2kError
    from ed2k_client.hashing import FileHashes
    from ed2k_client.wire import Packet

LOOPBACK = '127.0.0.1'
LOOPBACK_IP = int(ipaddress.IPv4Address(LOOPBACK))
SERVER_FLAGS = ServerTcpFlag.COMPRESSION | ServerTcpFlag.NEWTAGS | ServerTcpFlag.UNICODE | ServerTcpFlag.LARGEFILES
WELCOME = 'Welcome to the fake server'
TOLERANCE = 1 << 120
KAD_VERSION = 8
MAX_BOOTSTRAP_CONTACTS = 20
TYPE_MASK = 0x1F
DOCUMENT_TYPE = 'Doc'
DOCUMENT_EXTENSIONS = ('.pdf', '.djvu')
SERVER_SIDE = StreamOptions(idle_timeout=None)
PEER_NAME = 'fake peer'
PEER_USER_HASH = bytes(range(16))
COMPARATORS = {
    SearchOperator.EQUAL: operator.eq,
    SearchOperator.GREATER: operator.gt,
    SearchOperator.LESS: operator.lt,
    SearchOperator.GREATER_EQUAL: operator.ge,
    SearchOperator.LESS_EQUAL: operator.le,
    SearchOperator.NOT_EQUAL: operator.ne,
}


@dataclass(slots=True)
class IndexedFile:
    """A file the fake server knows.

    :ivar file_hash: the eD2k hash.
    :ivar name: the published name.
    :ivar size: the size.
    :ivar sources: user hashes by ``(client_id, port)`` of the clients that offered it.
    """

    file_hash: Ed2kHash
    name: str
    size: int
    sources: dict[tuple[int, int], bytes] = field(default_factory=dict)

    @property
    def file_type(self) -> str:
        """The server-side type, ``Doc`` for books."""
        return DOCUMENT_TYPE if self.name.lower().endswith(DOCUMENT_EXTENSIONS) else ''


def _boolean(reader: Reader, item: IndexedFile) -> bool:
    """Evaluate a boolean node: its operator, then both of its operands.

    :param reader: the tree reader, positioned at the node.
    :type reader: Reader
    :param item: the indexed file.
    :type item: IndexedFile
    :returns: whether the node matches.
    :rtype: bool
    """
    operator = reader.u8()
    left, right = evaluate(reader, item), evaluate(reader, item)
    if operator == BooleanOperator.AND:
        return left and right
    return left or right if operator == BooleanOperator.OR else left and not right


def _keyword(reader: Reader, item: IndexedFile) -> bool:
    """Match a keyword node against the file name, ignoring case.

    :param reader: the tree reader, positioned at the node.
    :type reader: Reader
    :param item: the indexed file.
    :type item: IndexedFile
    :returns: whether the name contains the keyword.
    :rtype: bool
    """
    return reader.string().lower() in item.name.lower()


def _string_tag(reader: Reader, item: IndexedFile) -> bool:
    """Match a string tag node: the extension against the name, or the server-side file type.

    :param reader: the tree reader, positioned at the node.
    :type reader: Reader
    :param item: the indexed file.
    :type item: IndexedFile
    :returns: whether the tag matches.
    :rtype: bool
    """
    value, tag = reader.string(), reader.take(reader.u16())[0]
    if tag == FileTag.FORMAT:
        return item.name.lower().endswith('.' + value.lower())
    return tag == FileTag.TYPE and item.file_type == value


def _number(reader: Reader, item: IndexedFile, *, wide: bool) -> bool:
    """Compare the size or the source count of a file with a numeric node.

    :param reader: the tree reader, positioned at the node.
    :type reader: Reader
    :param item: the indexed file.
    :type item: IndexedFile
    :param wide: whether the bound is a 64-bit number.
    :type wide: bool
    :returns: whether the comparison holds.
    :rtype: bool
    """
    value = reader.u64() if wide else reader.u32()
    operator, tag = reader.u8(), reader.take(reader.u16())[0]
    actual = item.size if tag == FileTag.SIZE else len(item.sources)
    return COMPARATORS[SearchOperator(operator)](actual, value)


NODE_EVALUATORS: dict[int, Callable[[Reader, IndexedFile], bool]] = {
    SearchNodeKind.BOOLEAN: _boolean,
    SearchNodeKind.KEYWORD: _keyword,
    SearchNodeKind.STRING_TAG: _string_tag,
    SearchNodeKind.NUMBER32: lambda reader, item: _number(reader, item, wide=False),
    SearchNodeKind.NUMBER64: lambda reader, item: _number(reader, item, wide=True),
}


def evaluate(reader: Reader, item: IndexedFile) -> bool:
    """Evaluate one node of a search tree, consuming exactly its bytes, both operands always.

    :param reader: the tree reader, positioned at the node.
    :type reader: Reader
    :param item: the indexed file.
    :type item: IndexedFile
    :returns: whether the file matches the node.
    :rtype: bool
    """
    return NODE_EVALUATORS[reader.u8()](reader, item)


@dataclass(slots=True)
class Session:
    """A client logged in to the fake server.

    :ivar stream: its connection.
    :ivar client_id: the ID it was given.
    :ivar port: the TCP port it announced.
    :ivar user_hash: its user hash.
    """

    stream: PacketStream
    client_id: int
    port: int
    user_hash: bytes


class FakeServer:
    """An eD2k server on loopback.

    :ivar files: the index.
    :ivar sessions: logged-in clients by ID.
    :ivar searches: the number of searches answered.
    :ivar port: the TCP port it listens on, 0 until it starts.
    """

    def __init__(self, *, low_id: bool = False) -> None:
        """Prepare the server; ``low_id`` gives every client a Low ID, as when the server cannot reach it.

        :param low_id: whether every client gets a Low ID, as when the server cannot reach it.
        :type low_id: bool
        """
        self._low_id = low_id
        self._next_low_id = 1000
        self.files: dict[Ed2kHash, IndexedFile] = {}
        self.sessions: dict[int, Session] = {}
        self.searches = 0
        self._changed = asyncio.Condition()
        self._server: asyncio.Server | None = None
        self.port = 0

    async def __aenter__(self) -> Self:
        """Start listening on a free loopback port.

        :returns: the server.
        :rtype: Self
        """
        self._server = await asyncio.start_server(self._handle, LOOPBACK, 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None
    ) -> None:
        """Stop listening and drop every client.

        :param exc_type: the exception type, if any.
        :type exc_type: type[BaseException] | None
        :param exc: the exception, if any.
        :type exc: BaseException | None
        :param traceback: the traceback, if any.
        :type traceback: TracebackType | None
        """
        if self._server is not None:
            self._server.close()
            self._server.close_clients()
            await self._server.wait_closed()

    @property
    def entry(self) -> ServerEntry:
        """The server as a client configures it."""
        return ServerEntry(host=LOOPBACK, port=self.port, name='fake')

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Serve one client connection until it closes or breaks the protocol.

        :param reader: the connection reader.
        :type reader: asyncio.StreamReader
        :param writer: the connection writer.
        :type writer: asyncio.StreamWriter
        """
        stream = PacketStream(reader=reader, writer=writer, options=SERVER_SIDE)
        logged_in: list[Session] = []
        try:
            await self._converse(stream, logged_in)
        except ConnectionFailedError, ProtocolError:
            pass
        finally:
            for session in logged_in:
                self.sessions.pop(session.client_id, None)
            await stream.close()

    async def _converse(self, stream: PacketStream, logged_in: list[Session]) -> None:
        """Read packets, logging the client in first and serving its requests afterwards.

        :param stream: the connection.
        :type stream: PacketStream
        :param logged_in: the sessions of this connection, extended by a login.
        :type logged_in: list[Session]
        """
        while True:
            packet = await stream.read_packet()
            if packet.opcode == ServerOp.LOGINREQUEST:
                logged_in.append(await self._login(stream, packet.reader()))
            elif logged_in:
                await self._serve(logged_in[-1], packet.opcode, packet.reader())

    async def wait_for_files(self, count: int) -> None:
        """Wait until clients have offered ``count`` files.

        :param count: the number of files to wait for.
        :type count: int
        """
        async with self._changed:
            await self._changed.wait_for(lambda: len(self.files) >= count)

    async def _login(self, stream: PacketStream, reader: Reader) -> Session:
        """Assign an ID and answer with the welcome message, the ID and the status.

        :param stream: the connection.
        :type stream: PacketStream
        :param reader: the login request body.
        :type reader: Reader
        :returns: the new session.
        :rtype: Session
        """
        user_hash, _, port = reader.hash16(), reader.u32(), reader.u16()
        read_tags(reader)
        if self._low_id:
            client_id = self._next_low_id
            self._next_low_id += 1
        else:
            client_id = client_id_from_host(stream.peer[0])
        session = Session(stream=stream, client_id=client_id, port=port, user_hash=user_hash)
        self.sessions[client_id] = session
        replies = [
            (ServerOp.SERVERMESSAGE, Writer().string(WELCOME)),
            (ServerOp.IDCHANGE, Writer().u32(client_id).u32(SERVER_FLAGS)),
            (ServerOp.SERVERSTATUS, Writer().u32(len(self.sessions)).u32(len(self.files))),
        ]
        for opcode, payload in replies:
            await stream.send(protocol=Protocol.EDONKEY, opcode=opcode, payload=payload.getvalue())
        return session

    async def _serve(self, session: Session, opcode: int, reader: Reader) -> None:
        """Answer one request of a logged-in client.

        :param session: the client that asked.
        :type session: Session
        :param opcode: the request opcode.
        :type opcode: int
        :param reader: the request body.
        :type reader: Reader
        """
        match opcode:
            case ServerOp.OFFERFILES:
                for _ in range(reader.u32()):
                    file_hash = Ed2kHash(reader.hash16())
                    reader.take(6)
                    tags = tag_map(read_tags(reader))
                    size = int_value(tags, FileTag.SIZE) | int_value(tags, FileTag.SIZE_HI) << 32
                    item = self.files.setdefault(file_hash, IndexedFile(file_hash, str_value(tags, FileTag.NAME), size))
                    item.sources[session.client_id, session.port] = session.user_hash
                async with self._changed:
                    self._changed.notify_all()
            case ServerOp.SEARCHREQUEST:
                await self._search(session, reader.rest())
            case ServerOp.GETSOURCES:
                await self._sources(session, Ed2kHash(reader.hash16()))
            case ServerOp.CALLBACKREQUEST:
                target = self.sessions.get(reader.u32())
                if target is not None:
                    payload = Writer().ed2k_ip(session.stream.peer[0]).u16(session.port).getvalue()
                    await target.stream.send(
                        protocol=Protocol.EDONKEY, opcode=ServerOp.CALLBACKREQUESTED, payload=payload
                    )
            case _:
                pass

    async def _search(self, session: Session, tree: bytes) -> None:
        """Answer a search with one zlib-packed page of every matching file.

        :param session: the client that asked.
        :type session: Session
        :param tree: the binary search tree.
        :type tree: bytes
        """
        self.searches += 1
        matches = [item for item in self.files.values() if evaluate(Reader(tree), item)]
        page = Writer().u32(len(matches))
        for item in matches:
            page.raw(item.file_hash.digest).u32(0).u16(0)
            tags = [Tag(FileTag.NAME, item.name), Tag(FileTag.SIZE, item.size), Tag(FileTag.TYPE, item.file_type)]
            tags += [Tag(FileTag.SOURCES, len(item.sources)), Tag(FileTag.COMPLETE_SOURCES, len(item.sources))]
            write_tags(page, tags)
        payload = zlib.compress(page.getvalue())
        await session.stream.send(protocol=Protocol.PACKED, opcode=ServerOp.SEARCHRESULT, payload=payload)

    async def _sources(self, session: Session, file_hash: Ed2kHash) -> None:
        """Answer a source request with every client that offered the file.

        :param session: the client that asked.
        :type session: Session
        :param file_hash: the file.
        :type file_hash: Ed2kHash
        """
        item = self.files.get(file_hash)
        if item is None:
            return
        payload = Writer().raw(file_hash.digest).u8(len(item.sources))
        crypt = CryptOption.SUPPORTED | CryptOption.HAS_USER_HASH
        for (client_id, port), user_hash in item.sources.items():
            payload.u32(client_id).u16(port).u8(crypt).raw(user_hash)
        await session.stream.send(
            protocol=Protocol.EDONKEY, opcode=ServerOp.FOUNDSOURCES_OBFU, payload=payload.getvalue()
        )


class FakePeer:
    """A High ID seeder of one file on loopback that answers AICH requests from a tree it is given.

    It speaks the part of the client to client protocol the downloader uses, with 32-bit offsets only.

    :ivar data: the content it serves.
    :ivar hashes: the eD2k hashes it announces for the content.
    :ivar aich: the AICH tree it serves for whatever root it is asked about, or ``None`` for a peer that neither
        announces nor answers AICH.
    :ivar corrupt: whether it flips every byte it sends.
    :ivar aich_requests: the parts it was asked AICH hashes for, in order.
    :ivar served: bytes of data sent.
    :ivar port: the TCP port it listens on, 0 until it starts.
    """

    def __init__(
        self, data: bytes, *, hashes: FileHashes, aich: dict[int, bytes] | None, corrupt: bool = False
    ) -> None:
        """Prepare the peer.

        :param data: the content it serves.
        :type data: bytes
        :param hashes: the eD2k hashes it announces for the content.
        :type hashes: FileHashes
        :param aich: the AICH tree it serves, or ``None`` for a peer without AICH.
        :type aich: dict[int, bytes] | None
        :param corrupt: whether it flips every byte it sends.
        :type corrupt: bool
        """
        self.data = data
        self.hashes = hashes
        self.aich = aich
        self.corrupt = corrupt
        self.aich_requests: list[int] = []
        self.served = 0
        self._server: asyncio.Server | None = None
        self.port = 0

    async def __aenter__(self) -> Self:
        """Start listening on a free loopback port.

        :returns: the peer.
        :rtype: Self
        """
        self._server = await asyncio.start_server(self._handle, LOOPBACK, 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None
    ) -> None:
        """Stop listening and drop every connection.

        :param exc_type: the exception type, if any.
        :type exc_type: type[BaseException] | None
        :param exc: the exception, if any.
        :type exc: BaseException | None
        :param traceback: the traceback, if any.
        :type traceback: TracebackType | None
        """
        if self._server is not None:
            self._server.close()
            self._server.close_clients()
            await self._server.wait_closed()

    @property
    def source(self) -> Source:
        """The peer as a source a link names."""
        return Source(
            client_id=client_id_from_host(LOOPBACK), port=self.port, crypt=CryptOption(0), origin=SourceOrigin.LINK
        )

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Answer one downloader until it disconnects.

        :param reader: the connection reader.
        :type reader: asyncio.StreamReader
        :param writer: the connection writer.
        :type writer: asyncio.StreamWriter
        """
        stream = PacketStream(reader=reader, writer=writer, options=SERVER_SIDE)
        try:
            while True:
                await self._answer(stream, await stream.read_packet())
        except ConnectionFailedError, ProtocolError:
            pass
        finally:
            await stream.close()

    async def _answer(self, stream: PacketStream, packet: Packet) -> None:
        """Answer one request.

        :param stream: the connection.
        :type stream: PacketStream
        :param packet: the request.
        :type packet: Packet
        """
        reader = packet.reader()
        match (packet.protocol, packet.opcode):
            case (Protocol.EDONKEY, PeerOp.HELLO):
                await stream.send(protocol=Protocol.EDONKEY, opcode=PeerOp.HELLOANSWER, payload=self._hello())
            case (Protocol.EDONKEY, PeerOp.REQUESTFILENAME | PeerOp.SETREQFILEID | PeerOp.HASHSETREQUEST):
                await self._answer_file_query(stream, packet.opcode)
            case (Protocol.EDONKEY, PeerOp.STARTUPLOADREQ):
                await stream.send(protocol=Protocol.EDONKEY, opcode=PeerOp.ACCEPTUPLOADREQ)
            case (Protocol.EDONKEY, PeerOp.REQUESTPARTS):
                await self._send_parts(stream, PartRequest.parse(reader, large=False))
            case (Protocol.EMULE, EmuleOp.AICHREQUEST):
                await self._answer_aich(stream, reader)
            case _:
                pass

    def _hello(self) -> bytes:
        """Build the hello answer, announcing AICH when the peer has a tree.

        :returns: the payload.
        :rtype: bytes
        """
        options = int(self.aich is not None) << AICH_SHIFT
        hello = Writer().raw(PEER_USER_HASH).u32(client_id_from_host(LOOPBACK)).u16(self.port)
        write_tags(hello, [Tag(ClientTag.NAME, PEER_NAME), Tag(ClientTag.EMULE_MISCOPTIONS1, options)])
        return hello.u32(0).u16(0).getvalue()

    async def _answer_file_query(self, stream: PacketStream, opcode: int) -> None:
        """Answer a file name, file status or hashset request for the one file the peer has.

        :param stream: the connection.
        :type stream: PacketStream
        :param opcode: the request opcode.
        :type opcode: int
        """
        answer = Writer().raw(self.hashes.file_hash.digest)
        if opcode == PeerOp.REQUESTFILENAME:
            reply = PeerOp.REQFILENAMEANSWER
            answer.string(PEER_NAME)
        elif opcode == PeerOp.SETREQFILEID:
            reply = PeerOp.FILESTATUS
            answer.u16(0)
        else:
            reply = PeerOp.HASHSETANSWER
            answer.u16(len(self.hashes.part_hashes)).raw(b''.join(self.hashes.part_hashes))
        await stream.send(protocol=Protocol.EDONKEY, opcode=reply, payload=answer.getvalue())

    async def _send_parts(self, stream: PacketStream, request: PartRequest) -> None:
        """Send the requested ranges as raw data packets, spoiled when the peer corrupts.

        :param stream: the connection.
        :type stream: PacketStream
        :param request: the block request.
        :type request: PartRequest
        """
        for start, end in request.ranges:
            chunk = self.data[start:end]
            if self.corrupt:
                chunk = bytes(byte ^ 0xFF for byte in chunk)
            self.served += len(chunk)
            payload = Writer().raw(self.hashes.file_hash.digest).u32(start).u32(end).raw(chunk).getvalue()
            await stream.send(protocol=Protocol.EDONKEY, opcode=PeerOp.SENDINGPART, payload=payload)

    async def _answer_aich(self, stream: PacketStream, reader: Reader) -> None:
        """Answer an AICH request with the recovery hashes of the part, or refuse it without a tree.

        :param stream: the connection.
        :type stream: PacketStream
        :param reader: the request payload.
        :type reader: Reader
        """
        # The root asked about is echoed, so a peer given another tree forges hashes for the right root
        reader.hash16()
        part, root = reader.u16(), reader.take(AICH_HASH_LENGTH)
        self.aich_requests.append(part)
        answer = Writer().raw(self.hashes.file_hash.digest)
        if self.aich is not None:
            answer.u16(part).raw(root).raw(recovery_data(self.aich, size=len(self.data), part=part))
        await stream.send(protocol=Protocol.EMULE, opcode=EmuleOp.AICHANSWER, payload=answer.getvalue())


def write_contact(writer: Writer, *, kad_id: KadId, host: str, udp_port: int) -> None:
    """Append the 25-byte Kad contact record.

    :param writer: the payload writer.
    :type writer: Writer
    :param kad_id: the node ID.
    :type kad_id: KadId
    :param host: the IPv4 address.
    :type host: str
    :param udp_port: the UDP port.
    :type udp_port: int
    """
    kad_id.write(writer).u32(int(ipaddress.IPv4Address(host))).u16(udp_port).u16(0).u8(KAD_VERSION)


@dataclass(slots=True)
class FakeKadNode(asyncio.DatagramProtocol):
    """One Kad node on loopback.

    :ivar kad_id: its ID.
    :ivar network: every node of the fake network.
    :ivar keywords: keyword target to ``(file hash, tags)`` entries.
    :ivar sources: file target to ``(user hash, tags)`` entries.
    :ivar received: the number of datagrams it got.
    :ivar port: its UDP port.
    :ivar transport: its socket, once open.
    """

    kad_id: KadId
    network: list[FakeKadNode]
    keywords: dict[KadId, list[tuple[bytes, list[Tag]]]] = field(default_factory=dict)
    sources: dict[KadId, list[tuple[bytes, list[Tag]]]] = field(default_factory=dict)
    received: int = 0
    port: int = 0
    transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Remember the socket.

        :param transport: the socket.
        :type transport: asyncio.BaseTransport
        """
        assert isinstance(transport, asyncio.DatagramTransport)
        self.transport = transport
        self.port = transport.get_extra_info('sockname')[1]

    def _with_contacts(self, writer: Writer, nodes: list[FakeKadNode]) -> bytes:
        """Append the contact records of some nodes to an answer.

        :param writer: the answer being built.
        :type writer: Writer
        :param nodes: the nodes to list.
        :type nodes: list[FakeKadNode]
        :returns: the answer body.
        :rtype: bytes
        """
        for node in nodes:
            write_contact(writer, kad_id=node.kad_id, host=LOOPBACK, udp_port=node.port)
        return writer.getvalue()

    def _answer(self, opcode: int, reader: Reader) -> tuple[int, bytes] | None:
        """Answer a bootstrap, a lookup or a search the way a Kad 2 node does, or not at all.

        :param opcode: the request opcode.
        :type opcode: int
        :param reader: the request body.
        :type reader: Reader
        :returns: the answer opcode and body, or ``None`` to stay silent.
        :rtype: tuple[int, bytes] | None
        """
        if opcode == KadOp.BOOTSTRAP_REQ:
            others = [node for node in self.network if node is not self][:MAX_BOOTSTRAP_CONTACTS]
            return KadOp.BOOTSTRAP_RES, self._with_contacts(
                self.kad_id.write(Writer()).u16(0).u8(KAD_VERSION).u16(len(others)), others
            )
        if opcode == KadOp.REQ:
            wanted, target, receiver = reader.u8() & TYPE_MASK, KadId.read(reader), KadId.read(reader)
            if receiver != self.kad_id:
                return None
            nodes = sorted(self.network, key=lambda node: node.kad_id.distance(target))[:wanted]
            return KadOp.RES, self._with_contacts(target.write(Writer()).u8(len(nodes)), nodes)
        target = KadId.read(reader)
        entries = (self.keywords if opcode == KadOp.SEARCH_KEY_REQ else self.sources).get(target, [])
        if self.kad_id.distance(target) >= TOLERANCE or not entries:
            return None
        writer = target.write(self.kad_id.write(Writer())).u16(len(entries))
        for key, tags in entries:
            KadId.from_digest(key).write(writer)
            write_tags(writer, tags, count_size=1)
        return KadOp.SEARCH_RES, writer.getvalue()

    def datagram_received(self, data: bytes, addr: tuple[str | int, int]) -> None:
        """Answer the Kad 2 requests a searching client sends.

        :param data: the datagram.
        :type data: bytes
        :param addr: the sender.
        :type addr: tuple[str | int, int]
        """
        self.received += 1
        packet = decode_udp(data)
        answer = self._answer(packet.opcode, packet.reader())
        if answer is not None and self.transport is not None:
            self.transport.sendto(encode_udp(protocol=Protocol.KAD, opcode=answer[0], payload=answer[1]), addr)


class MalformingKadNode(FakeKadNode):
    """A Kad node that answers every request with the right opcode and a body one byte or one entry short."""

    def _answer(self, opcode: int, reader: Reader) -> tuple[int, bytes] | None:
        """Answer a search with a count of one and no entry, and anything else with its last byte cut off.

        :param opcode: the request opcode.
        :type opcode: int
        :param reader: the request body.
        :type reader: Reader
        :returns: the answer opcode and its truncated body, or ``None``.
        :rtype: tuple[int, bytes] | None
        """
        if opcode in {KadOp.SEARCH_KEY_REQ, KadOp.SEARCH_SOURCE_REQ}:
            target = KadId.read(reader)
            return KadOp.SEARCH_RES, target.write(self.kad_id.write(Writer())).u16(1).getvalue()
        answer = super()._answer(opcode, reader)
        return None if answer is None else (answer[0], answer[1][:-1])


class FakeKadNetwork:
    """A handful of Kad nodes on loopback, with a node inside the tolerance zone of every published target.

    :ivar nodes: the nodes.
    """

    def __init__(self, *, size: int = 10, seed: int = 3) -> None:
        """Prepare ``size`` random node IDs from ``seed``.

        :param size: the number of nodes.
        :type size: int
        :param seed: the seed of the random node IDs.
        :type seed: int
        """
        self._random = random.Random(seed)
        self.nodes: list[FakeKadNode] = []
        self._ids = [KadId(self._random.getrandbits(128)) for _ in range(size)]

    async def _add(self, kad_id: KadId, *, kind: type[FakeKadNode] = FakeKadNode) -> FakeKadNode:
        """Open a node socket on loopback and add the node to the network.

        :param kad_id: the node ID.
        :type kad_id: KadId
        :param kind: the class of the node.
        :type kind: type[FakeKadNode]
        :returns: the node.
        :rtype: FakeKadNode
        """
        node = kind(kad_id=kad_id, network=self.nodes)
        await asyncio.get_running_loop().create_datagram_endpoint(lambda: node, local_addr=(LOOPBACK, 0))
        self.nodes.append(node)
        return node

    async def add_malforming_node(self, target: KadId) -> FakeKadNode:
        """Add a node next to a target that answers every request malformed.

        :param target: the target whose tolerance zone the node joins.
        :type target: KadId
        :returns: the node.
        :rtype: FakeKadNode
        """
        return await self._add(KadId(target.value ^ 1), kind=MalformingKadNode)

    async def __aenter__(self) -> Self:
        """Open every node's socket.

        :returns: the network.
        :rtype: Self
        """
        for kad_id in self._ids:
            await self._add(kad_id)
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None
    ) -> None:
        """Close every node's socket.

        :param exc_type: the exception type, if any.
        :type exc_type: type[BaseException] | None
        :param exc: the exception, if any.
        :type exc: BaseException | None
        :param traceback: the traceback, if any.
        :type traceback: TracebackType | None
        """
        for node in self.nodes:
            if node.transport is not None:
                node.transport.close()

    async def _responsible(self, target: KadId) -> list[FakeKadNode]:
        """Find the nodes in the tolerance zone of a target, adding one when none is.

        :param target: the target.
        :type target: KadId
        :returns: the responsible nodes.
        :rtype: list[FakeKadNode]
        """
        inside = [node for node in self.nodes if node.kad_id.distance(target) < TOLERANCE]
        return inside or [await self._add(KadId(target.value ^ self._random.getrandbits(100)))]

    async def publish_keyword(self, word: str, *, file_hash: Ed2kHash, name: str, size: int) -> None:
        """Index a file under a keyword on the nodes responsible for the keyword.

        :param word: the keyword.
        :type word: str
        :param file_hash: the file.
        :type file_hash: Ed2kHash
        :param name: the published file name.
        :type name: str
        :param size: the file size in bytes.
        :type size: int
        """
        target = KadId.from_digest(md4(word.lower().encode()))
        tags = [Tag(FileTag.NAME, name), Tag(FileTag.SIZE, size), Tag(FileTag.SOURCES, 1)]
        for node in await self._responsible(target):
            node.keywords.setdefault(target, []).append((file_hash.digest, tags))

    async def publish_source(
        self, file_hash: Ed2kHash, *, port: int, user_hash: bytes, source_type: int = 1, source_ip: int = LOOPBACK_IP
    ) -> None:
        """Index a peer as a source of a file, on loopback unless ``source_ip`` says otherwise.

        :param file_hash: the file.
        :type file_hash: Ed2kHash
        :param port: the TCP port of the source.
        :type port: int
        :param user_hash: the user hash of the source.
        :type user_hash: bytes
        :param source_type: the Kad source type, 1 for a directly reachable peer.
        :type source_type: int
        :param source_ip: the address of the source as a number.
        :type source_ip: int
        """
        target = KadId.from_digest(file_hash.digest)
        tags = [
            Tag(FileTag.SOURCE_TYPE, source_type),
            Tag(FileTag.SOURCE_IP, source_ip),
            Tag(FileTag.SOURCE_PORT, port),
            Tag(FileTag.SOURCE_UDP_PORT, 0),
        ]
        for node in await self._responsible(target):
            node.sources.setdefault(target, []).append((user_hash, tags))

    def write_nodes_dat(self, path: Path, *, count: int = 3) -> Path:
        """Write a version 2 ``nodes.dat`` that lists the first ``count`` nodes.

        :param path: the file to write.
        :type path: Path
        :param count: how many of the first nodes to list.
        :type count: int
        :returns: the path written.
        :rtype: Path
        """
        writer = Writer().raw(struct.pack('<III', 0, 2, count))
        for node in self.nodes[:count]:
            write_contact(writer, kad_id=node.kad_id, host=LOOPBACK, udp_port=node.port)
            writer.raw(bytes(9))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(writer.getvalue())
        return path


class ScriptedStream:
    """A peer connection that hands out prepared packets and then reports itself closed.

    :ivar peer: the remote address.
    :ivar limits: the caps of the connection.
    :ivar closed: whether the connection was closed through its context.
    :ivar sent: the ``(protocol, opcode, payload)`` of every packet the stream accepted.
    """

    def __init__(
        self, packets: Sequence[Packet], *, peer: tuple[str, int], send_error: Ed2kError | None = None
    ) -> None:
        """Queue the packets the peer sends.

        :param packets: the packets in the order the peer sends them.
        :type packets: Sequence[Packet]
        :param peer: the remote address.
        :type peer: tuple[str, int]
        :param send_error: raised by every send, as on a connection the peer reset, or ``None`` to accept sends.
        :type send_error: Ed2kError | None
        """
        self.peer = peer
        self.limits = DEFAULT_LIMITS
        self.closed = False
        self.sent: list[tuple[int, int, bytes]] = []
        self._packets = list(packets)
        self._send_error = send_error

    async def read_packet(self, *, limit: int | None = None) -> Packet:
        """Return the next packet, or fail once none is left.

        :param limit: the largest accepted packet length, unused.
        :type limit: int | None
        :returns: the packet.
        :rtype: Packet
        :raises ConnectionFailedError: once every packet was read.
        """
        del limit
        if self._packets:
            return self._packets.pop(0)
        err_msg = 'closed'
        raise ConnectionFailedError(err_msg)

    async def send(self, *, protocol: int, opcode: int, payload: bytes = b'') -> None:
        """Record a packet, or fail as the stream was told to.

        :param protocol: the namespace byte.
        :type protocol: int
        :param opcode: the operation code.
        :type opcode: int
        :param payload: the body.
        :type payload: bytes
        :raises Ed2kError: the send error the stream was given.
        """
        if self._send_error is not None:
            raise self._send_error
        self.sent.append((protocol, opcode, payload))

    async def __aenter__(self) -> Self:
        """Enter the context.

        :returns: the stream itself.
        :rtype: Self
        """
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None
    ) -> None:
        """Record that the connection was closed.

        :param exc_type: the exception type, if any.
        :type exc_type: type[BaseException] | None
        :param exc: the exception, if any.
        :type exc: BaseException | None
        :param traceback: the traceback, if any.
        :type traceback: TracebackType | None
        """
        del exc_type, exc, traceback
        self.closed = True
