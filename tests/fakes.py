"""In-process stand-ins for an eD2k server and a Kad network that speak the real wire format over loopback.

The fake server evaluates the binary search tree it receives against its index, so a search test also checks the
semantics of the encoded query, and it sends its result pages zlib-packed the way Lugdunum servers do. The fake Kad
nodes answer only when the receiver ID in ``KADEMLIA2_REQ`` is theirs and search only inside the 2^120 tolerance
zone, the two checks a real aMule node makes.
"""

import asyncio
import ipaddress
import operator
import random
import struct
import zlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Self

from ed2k_client.constants import CryptOption, FileTag, KadOp, Protocol, SearchOperator, ServerOp, ServerTcpFlag
from ed2k_client.errors import ConnectionFailedError, ProtocolError
from ed2k_client.hashing import Ed2kHash, md4
from ed2k_client.kad.contacts import KadId
from ed2k_client.search import BooleanOperator, SearchNodeKind
from ed2k_client.servermet import ServerEntry
from ed2k_client.sources import client_id_from_host
from ed2k_client.tags import Tag, int_value, read_tags, str_value, tag_map, write_tags
from ed2k_client.transport import PacketStream, StreamOptions
from ed2k_client.wire import Reader, Writer, decode_udp, encode_udp

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path
    from types import TracebackType

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
    operator = reader.u8()
    left, right = evaluate(reader, item), evaluate(reader, item)
    if operator == BooleanOperator.AND:
        return left and right
    return left or right if operator == BooleanOperator.OR else left and not right


def _keyword(reader: Reader, item: IndexedFile) -> bool:
    return reader.string().lower() in item.name.lower()


def _string_tag(reader: Reader, item: IndexedFile) -> bool:
    value, tag = reader.string(), reader.take(reader.u16())[0]
    if tag == FileTag.FORMAT:
        return item.name.lower().endswith('.' + value.lower())
    return tag == FileTag.TYPE and item.file_type == value


def _number(reader: Reader, item: IndexedFile, *, wide: bool) -> bool:
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
    """Evaluate one node of a search tree, consuming exactly its bytes, both operands always."""
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
    """

    def __init__(self, *, low_id: bool = False) -> None:
        """Prepare the server; ``low_id`` gives every client a Low ID, as when the server cannot reach it."""
        self._low_id = low_id
        self._next_low_id = 1000
        self.files: dict[Ed2kHash, IndexedFile] = {}
        self.sessions: dict[int, Session] = {}
        self.searches = 0
        self._changed = asyncio.Condition()
        self._server: asyncio.Server | None = None
        self.port = 0

    async def __aenter__(self) -> Self:
        """Start listening on a free loopback port."""
        self._server = await asyncio.start_server(self._handle, LOOPBACK, 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None
    ) -> None:
        """Stop listening and drop every client."""
        if self._server is not None:
            self._server.close()
            self._server.close_clients()
            await self._server.wait_closed()

    @property
    def entry(self) -> ServerEntry:
        """The server as a client configures it."""
        return ServerEntry(host=LOOPBACK, port=self.port, name='fake')

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
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
        while True:
            packet = await stream.read_packet()
            if packet.opcode == ServerOp.LOGINREQUEST:
                logged_in.append(await self._login(stream, packet.reader()))
            elif logged_in:
                await self._serve(logged_in[-1], packet.opcode, packet.reader())

    async def wait_for_files(self, count: int) -> None:
        """Wait until clients have offered ``count`` files."""
        async with self._changed:
            await self._changed.wait_for(lambda: len(self.files) >= count)

    async def _login(self, stream: PacketStream, reader: Reader) -> Session:
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


def write_contact(writer: Writer, *, kad_id: KadId, host: str, udp_port: int) -> None:
    """Append the 25-byte Kad contact record."""
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
    """

    kad_id: KadId
    network: list[FakeKadNode]
    keywords: dict[KadId, list[tuple[bytes, list[Tag]]]] = field(default_factory=dict)
    sources: dict[KadId, list[tuple[bytes, list[Tag]]]] = field(default_factory=dict)
    received: int = 0
    port: int = 0
    transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Remember the socket."""
        assert isinstance(transport, asyncio.DatagramTransport)
        self.transport = transport
        self.port = transport.get_extra_info('sockname')[1]

    def _with_contacts(self, writer: Writer, nodes: list[FakeKadNode]) -> bytes:
        for node in nodes:
            write_contact(writer, kad_id=node.kad_id, host=LOOPBACK, udp_port=node.port)
        return writer.getvalue()

    def _answer(self, opcode: int, reader: Reader) -> tuple[int, bytes] | None:
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
        """Answer the Kad 2 requests a searching client sends."""
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
        """Prepare ``size`` random node IDs from ``seed``."""
        self._random = random.Random(seed)
        self.nodes: list[FakeKadNode] = []
        self._ids = [KadId(self._random.getrandbits(128)) for _ in range(size)]

    async def _add(self, kad_id: KadId, *, kind: type[FakeKadNode] = FakeKadNode) -> FakeKadNode:
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
        """Open every node's socket."""
        for kad_id in self._ids:
            await self._add(kad_id)
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None
    ) -> None:
        """Close every node's socket."""
        for node in self.nodes:
            if node.transport is not None:
                node.transport.close()

    async def _responsible(self, target: KadId) -> list[FakeKadNode]:
        inside = [node for node in self.nodes if node.kad_id.distance(target) < TOLERANCE]
        return inside or [await self._add(KadId(target.value ^ self._random.getrandbits(100)))]

    async def publish_keyword(self, word: str, *, file_hash: Ed2kHash, name: str, size: int) -> None:
        """Index a file under a keyword on the nodes responsible for the keyword."""
        target = KadId.from_digest(md4(word.lower().encode()))
        tags = [Tag(FileTag.NAME, name), Tag(FileTag.SIZE, size), Tag(FileTag.SOURCES, 1)]
        for node in await self._responsible(target):
            node.keywords.setdefault(target, []).append((file_hash.digest, tags))

    async def publish_source(
        self, file_hash: Ed2kHash, *, port: int, user_hash: bytes, source_type: int = 1, source_ip: int = LOOPBACK_IP
    ) -> None:
        """Index a peer as a source of a file, on loopback unless ``source_ip`` says otherwise."""
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
        """Write a version 2 ``nodes.dat`` that lists the first ``count`` nodes."""
        writer = Writer().raw(struct.pack('<III', 0, 2, count))
        for node in self.nodes[:count]:
            write_contact(writer, kad_id=node.kad_id, host=LOOPBACK, udp_port=node.port)
            writer.raw(bytes(9))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(writer.getvalue())
        return path
