"""The client to client protocol: hello, file requests, upload slots and data transfer, in both roles.

The downloading side follows ``CUpDownClient`` in aMule (``BaseClient.cpp`` and ``DownloadClient.cpp``): hello,
file name and status, hashset, upload request, then block requests of up to three ranges answered by raw
``SENDINGPART`` or zlib-compressed ``COMPRESSEDPART`` packets. The serving side answers the same requests for files
in the :class:`SharedLibrary` only, checks every requested range against the file size and the 3-block limit aMule
enforces, and hands out a bounded number of upload slots.
"""

import asyncio
import logging
import zlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Self

from ed2k_client.constants import (
    BLOCK_SIZE,
    EDONKEY_VERSION,
    HASH_LENGTH,
    LARGE_FILE_THRESHOLD,
    MAX_DATA_PACKET,
    MAX_HASHSET_PARTS,
    MAX_REQUEST_RANGES,
    ClientTag,
    EmuleOp,
    PeerOp,
    Protocol,
)
from ed2k_client.errors import ConnectionFailedError, ProtocolError, SecurityError
from ed2k_client.hashing import Ed2kHash, part_count
from ed2k_client.partfile import Block
from ed2k_client.server import emule_version_tag
from ed2k_client.settings import DEFAULT_PEER
from ed2k_client.tags import Tag, int_value, read_tags, str_value, tag_map, write_tags
from ed2k_client.wire import Writer

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Collection, Sequence

    from ed2k_client.identity import Identity
    from ed2k_client.settings import PeerSettings
    from ed2k_client.share import SharedLibrary
    from ed2k_client.transport import PacketStream
    from ed2k_client.wire import Packet, Reader

logger = logging.getLogger(__name__)

# OP_QUEUERANKING carries a 16-bit rank and ten reserved bytes: https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/UploadClient.cpp#L590
QUEUE_RANK_PADDING: bytes = bytes(10)
NO_SERVER: tuple[str, int] = ('0.0.0.0', 0)

# The two option tags of the hello, laid out as aMule's SendHelloTypePacket packs them:
# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/BaseClient.cpp#L1096
# The first announces version 1 of data compression and Unicode support with shared files hidden, and no UDP, AICH
# or source exchange. The second announces large files and support for obfuscation.
MISC_OPTIONS_1: int = 1 << 28 | 1 << 20 | 1 << 2
COMPRESSION_SHIFT: int = 20
VERSION_MASK: int = 0xF
MISC_OPTIONS_2: int = 1 << 4 | 1 << 7

DATA_OPCODES: frozenset[tuple[int, int]] = frozenset(
    {
        (Protocol.EDONKEY, PeerOp.SENDINGPART),
        (Protocol.EMULE, EmuleOp.SENDINGPART_I64),
        (Protocol.EMULE, EmuleOp.COMPRESSEDPART),
        (Protocol.EMULE, EmuleOp.COMPRESSEDPART_I64),
    }
)
SLOT_END_OPCODES: frozenset[tuple[int, int]] = frozenset(
    {(Protocol.EDONKEY, PeerOp.OUTOFPARTREQS), (Protocol.EDONKEY, PeerOp.CANCELTRANSFER)}
)
WIDE_OPCODES: frozenset[int] = frozenset({EmuleOp.SENDINGPART_I64, EmuleOp.COMPRESSEDPART_I64})
COMPRESSED_OPCODES: frozenset[int] = frozenset({EmuleOp.COMPRESSEDPART, EmuleOp.COMPRESSEDPART_I64})


@dataclass(frozen=True, slots=True)
class HelloInfo:
    """What a peer said about itself.

    :ivar user_hash: its user hash.
    :ivar client_id: its eD2k ID.
    :ivar port: its TCP port.
    :ivar name: its user name, untrusted.
    :ivar compression: whether it accepts zlib-compressed blocks.
    """

    user_hash: bytes
    client_id: int
    port: int
    name: str
    compression: bool = False


@dataclass(frozen=True, slots=True)
class FileStatus:
    """The parts a peer has of a file.

    :ivar parts: indexes of the parts it has.
    """

    parts: frozenset[int]


class QueuedError(ConnectionFailedError):
    """The peer put this client in its upload queue instead of granting a slot, or again after ending one.

    :ivar rank: the position the peer reported, 0 when it reported none.
    """

    def __init__(self, rank: int) -> None:
        """Record the queue rank.

        :param rank: the position the peer reported, 0 when it reported none.
        :type rank: int
        """
        super().__init__(f'queued at rank {rank}')
        self.rank = rank


@dataclass(frozen=True, slots=True)
class LocalPeer:
    """What this client tells peers about itself.

    :ivar identity: the user hash.
    :ivar client_id: the ID the server assigned, 0 without a server.
    :ivar tcp_port: the listening port.
    :ivar nickname: the user name.
    :ivar server: the address of the connected server, or ``None``.
    """

    identity: Identity
    client_id: int
    tcp_port: int
    nickname: str
    server: tuple[str, int] | None = None


class BlockInflater:
    """Inflate the zlib stream of one compressed block, which arrives split over several packets.

    :ivar produced: bytes inflated so far.
    """

    def __init__(self, block: Block) -> None:
        """Start an empty stream for a block.

        :param block: the block the stream fills.
        :type block: Block
        """
        self._decompressor = zlib.decompressobj()
        self._room = block.end - block.start
        self.produced = 0

    def feed(self, data: bytes) -> bytes:
        """Inflate the next piece and refuse output beyond the block.

        :param data: compressed bytes.
        :type data: bytes
        :returns: the newly inflated bytes.
        :rtype: bytes
        :raises ProtocolError: when the stream is corrupt or inflates beyond the block size.
        """
        # One byte more than the block can take is enough to tell an honest stream from one that overflows it
        try:
            output = self._decompressor.decompress(data, self._room - self.produced + 1)
        except zlib.error as error:
            err_msg = f'corrupt compressed block ({error})'
            raise ProtocolError(err_msg) from error

        self.produced += len(output)
        if self._decompressor.unconsumed_tail or self.produced > self._room:
            err_msg = 'compressed block inflates beyond its size'
            raise ProtocolError(err_msg)
        return output


def build_hello(local: LocalPeer, *, answer: bool) -> bytes:
    """Build the payload of ``OP_HELLO`` or ``OP_HELLOANSWER``.

    :param local: this client's description.
    :type local: LocalPeer
    :param answer: whether it is the answer, which has no leading hash length byte.
    :type answer: bool
    :returns: the payload.
    :rtype: bytes
    """
    # [<16 1>]<user hash 16><id 4><port 2><tags><server ip 4><server port 2>: https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/BaseClient.cpp#L1020
    writer = Writer()
    if not answer:
        writer.u8(HASH_LENGTH)
    writer.raw(local.identity.user_hash).u32(local.client_id).u16(local.tcp_port)
    write_tags(
        writer,
        [
            Tag(ClientTag.NAME, local.nickname),
            Tag(ClientTag.VERSION, EDONKEY_VERSION),
            Tag(ClientTag.EMULE_VERSION, emule_version_tag()),
            Tag(ClientTag.EMULE_MISCOPTIONS1, MISC_OPTIONS_1),
            Tag(ClientTag.EMULE_MISCOPTIONS2, MISC_OPTIONS_2),
        ],
    )

    host, port = local.server or NO_SERVER
    return writer.ed2k_ip(host).u16(port).getvalue()


def parse_hello(reader: Reader, *, answer: bool) -> HelloInfo:
    """Parse a hello or hello answer.

    :param reader: the payload reader.
    :type reader: Reader
    :param answer: whether it is the answer, which has no leading hash length byte.
    :type answer: bool
    :returns: the peer's description.
    :rtype: HelloInfo
    :raises ProtocolError: when the hash length byte is wrong.
    """
    if not answer and reader.u8() != HASH_LENGTH:
        err_msg = 'hello with a wrong hash length'
        raise ProtocolError(err_msg)
    user_hash, client_id, port = reader.hash16(), reader.u32(), reader.u16()
    tags = tag_map(read_tags(reader))

    # The compression version sits in bits 20 to 23 of the first option tag: https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/BaseClient.cpp#L547
    compression_version = int_value(tags, ClientTag.EMULE_MISCOPTIONS1) >> COMPRESSION_SHIFT & VERSION_MASK
    return HelloInfo(
        user_hash=user_hash,
        client_id=client_id,
        port=port,
        name=str_value(tags, ClientTag.NAME),
        compression=compression_version > 0,
    )


def parse_file_status(reader: Reader, *, size: int) -> FileStatus:
    """Parse ``<count 2><bits>`` after the hash, where a count of 0 means the peer has the whole file.

    :param reader: the payload reader positioned after the hash.
    :type reader: Reader
    :param size: the file size.
    :type size: int
    :returns: the parts the peer has.
    :rtype: FileStatus
    :raises ProtocolError: when the part count does not fit the file.
    """
    # https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/DownloadClient.cpp#L386
    count = reader.u16()
    total = part_count(size)
    if count == 0:
        return FileStatus(parts=frozenset(range(total)))
    if count != total:
        err_msg = f'file status with {count} parts for a file of {total}'
        raise ProtocolError(err_msg)

    # One bit per part, least significant bit first within each byte
    bits = reader.take((count + 7) // 8)
    return FileStatus(parts=frozenset(index for index in range(count) if bits[index // 8] >> (index % 8) & 1))


def encode_part_request(*, file_hash: Ed2kHash, blocks: Sequence[Block], large: bool) -> tuple[int, int, bytes]:
    """Build a block request of up to three ranges, unused ranges being zero.

    :param file_hash: the file.
    :type file_hash: Ed2kHash
    :param blocks: one to three blocks.
    :type blocks: Sequence[Block]
    :param large: whether to use 64-bit offsets for a file above 4 GiB.
    :type large: bool
    :returns: protocol, opcode and payload.
    :rtype: tuple[int, int, bytes]
    """
    # <hash 16><three starts><three ends>, where all starts come before all ends and an empty range is 0 to 0
    padded = [*blocks, *[Block(0, 0)] * (MAX_REQUEST_RANGES - len(blocks))]
    writer = Writer().raw(file_hash.digest)
    put = writer.u64 if large else writer.u32
    for block in padded:
        put(block.start)
    for block in padded:
        put(block.end)

    if large:
        return Protocol.EMULE, EmuleOp.REQUESTPARTS_I64, writer.getvalue()
    return Protocol.EDONKEY, PeerOp.REQUESTPARTS, writer.getvalue()


@dataclass(frozen=True, slots=True)
class PartRequest:
    """A block request as the serving side reads it.

    :ivar file_hash: the requested file.
    :ivar ranges: the non-empty ``(start, end)`` ranges.
    """

    file_hash: Ed2kHash
    ranges: tuple[tuple[int, int], ...]

    @classmethod
    def parse(cls, reader: Reader, *, large: bool) -> Self:
        """Parse a 32- or 64-bit block request.

        :param reader: the payload reader.
        :type reader: Reader
        :param large: whether the offsets are 64-bit.
        :type large: bool
        :returns: the request.
        :rtype: Self
        """
        file_hash = Ed2kHash(reader.hash16())
        read = reader.u64 if large else reader.u32
        starts = [read() for _ in range(MAX_REQUEST_RANGES)]
        ends = [read() for _ in range(MAX_REQUEST_RANGES)]
        return cls(file_hash=file_hash, ranges=tuple((s, e) for s, e in zip(starts, ends, strict=True) if e > s))


class PeerConnection:
    """One TCP connection with another client.

    :ivar stream: the packet stream.
    :ivar remote: what the peer said in its hello, once known.
    """

    def __init__(self, *, stream: PacketStream, local: LocalPeer, settings: PeerSettings = DEFAULT_PEER) -> None:
        """Wrap an open stream.

        :param stream: the connection.
        :type stream: PacketStream
        :param local: this client's description.
        :type local: LocalPeer
        :param settings: how data is sent while serving.
        :type settings: PeerSettings
        """
        self.stream = stream
        self._local = local
        self._settings = settings
        self.remote: HelloInfo | None = None
        self._holding_slot = False

    async def _next(self, wanted: Collection[tuple[int, int]]) -> Packet:
        """Read packets until one of the wanted kinds arrives.

        :param wanted: accepted ``(protocol, opcode)`` pairs.
        :type wanted: Collection[tuple[int, int]]
        :returns: the packet.
        :rtype: Packet
        :raises ProtocolError: when the peer floods unexpected packets.
        """
        # A peer may send packets this client has no use for, so a few unknown packets are normal and only a long
        # run of them is a flood. A data packet is bounded by the protocol, while a hashset answer grows by 16 bytes a
        # part and is bounded by the configured cap of control packets
        limit = max(MAX_DATA_PACKET, self.stream.limits.control_packet)
        for _ in range(self.stream.limits.ignored_packets):
            packet = await self.stream.read_packet(limit=limit)
            if (packet.protocol, packet.opcode) in wanted:
                return packet
            logger.debug('Ignoring 0x%02X/0x%02X from %s', packet.protocol, packet.opcode, self.stream.peer)
        err_msg = f'too many unexpected packets from {self.stream.peer}'
        raise ProtocolError(err_msg)

    async def hello(self) -> HelloInfo:
        """Greet the peer as the side that opened the connection.

        :returns: the peer's description.
        :rtype: HelloInfo
        """
        await self.stream.send(
            protocol=Protocol.EDONKEY, opcode=PeerOp.HELLO, payload=build_hello(self._local, answer=False)
        )
        packet = await self._next({(Protocol.EDONKEY, PeerOp.HELLOANSWER)})
        self.remote = parse_hello(packet.reader(), answer=True)
        return self.remote

    async def request_file(self, *, file_hash: Ed2kHash, size: int) -> FileStatus:
        """Ask the peer for a file and learn which parts it has.

        :param file_hash: the file.
        :type file_hash: Ed2kHash
        :param size: the file size.
        :type size: int
        :returns: the peer's parts.
        :rtype: FileStatus
        :raises ConnectionFailedError: when the peer does not have the file.
        """
        # The name request comes first and the status request second, in the order aMule sends them:
        # https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/DownloadClient.cpp#L232
        for opcode in (PeerOp.REQUESTFILENAME, PeerOp.SETREQFILEID):
            await self.stream.send(protocol=Protocol.EDONKEY, opcode=opcode, payload=file_hash.digest)

        wanted = {
            (Protocol.EDONKEY, PeerOp.FILESTATUS),
            (Protocol.EDONKEY, PeerOp.FILEREQANSNOFIL),
            (Protocol.EDONKEY, PeerOp.REQFILENAMEANSWER),
        }
        while True:
            packet = await self._next(wanted)
            reader = packet.reader()

            # An answer about another file belongs to an earlier request on a reused connection
            if Ed2kHash(reader.hash16()) != file_hash:
                continue
            if packet.opcode == PeerOp.FILEREQANSNOFIL:
                err_msg = f'{self.stream.peer} does not have {file_hash}'
                raise ConnectionFailedError(err_msg)
            if packet.opcode == PeerOp.FILESTATUS:
                return parse_file_status(reader, size=size)

    async def request_hashset(self, file_hash: Ed2kHash) -> list[bytes]:
        """Ask the peer for the part hashes of a file.

        :param file_hash: the file.
        :type file_hash: Ed2kHash
        :returns: the part hashes, unverified.
        :rtype: list[bytes]
        :raises ProtocolError: when the count is implausible.
        """
        await self.stream.send(protocol=Protocol.EDONKEY, opcode=PeerOp.HASHSETREQUEST, payload=file_hash.digest)
        reader = (await self._next({(Protocol.EDONKEY, PeerOp.HASHSETANSWER)})).reader()
        reader.hash16()

        # The hashes are checked against the file hash by the caller, here only the count is bounded
        count = reader.u16()
        if count > MAX_HASHSET_PARTS:
            err_msg = f'hashset of {count} parts'
            raise ProtocolError(err_msg)
        return [reader.hash16() for _ in range(count)]

    async def request_upload(self, file_hash: Ed2kHash, *, queue_wait: float) -> None:
        """Ask for an upload slot and wait on the connection while queued.

        :param file_hash: the file.
        :type file_hash: Ed2kHash
        :param queue_wait: seconds to wait in the queue for the slot on this connection.
        :type queue_wait: float
        :raises QueuedError: when no slot arrives within the wait.
        """
        await self.stream.send(protocol=Protocol.EDONKEY, opcode=PeerOp.STARTUPLOADREQ, payload=file_hash.digest)

        # eMule reports the rank as OP_QUEUERANKING with 16 bits, older clients as OP_QUEUERANK with 32:
        # https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/ClientTCPSocket.cpp#L1367
        rank = 0
        wanted = {
            (Protocol.EDONKEY, PeerOp.ACCEPTUPLOADREQ),
            (Protocol.EMULE, EmuleOp.QUEUERANKING),
            (Protocol.EDONKEY, PeerOp.QUEUERANK),
        }
        # The stream's idle timeout must be at least queue_wait, which the downloader arranges when it dials
        try:
            async with asyncio.timeout(queue_wait):
                while (packet := await self._next(wanted)).opcode != PeerOp.ACCEPTUPLOADREQ:
                    reader = packet.reader()
                    rank = reader.u16() if packet.protocol == Protocol.EMULE else reader.u32()
                    logger.info('Queued by %s at rank %d', self.stream.peer, rank)
        except (TimeoutError, ConnectionFailedError) as error:
            raise QueuedError(rank) from error

    async def download_blocks(
        self, *, file_hash: Ed2kHash, blocks: Sequence[Block], large: bool
    ) -> AsyncIterator[tuple[Block, int, bytes]]:
        """Request up to three blocks and yield their data as it arrives.

        :param file_hash: the file.
        :type file_hash: Ed2kHash
        :param blocks: one to three blocks.
        :type blocks: Sequence[Block]
        :param large: whether the file needs 64-bit offsets.
        :type large: bool
        :returns: ``(block, start offset, data)`` for every piece received.
        :rtype: AsyncIterator[tuple[Block, int, bytes]]
        :raises ProtocolError: on data outside the requested blocks.
        :raises QueuedError: when the peer ends the upload slot and puts this client back in its queue.
        :raises ConnectionFailedError: when the connection is lost.
        """
        protocol, opcode, payload = encode_part_request(file_hash=file_hash, blocks=blocks, large=large)
        await self.stream.send(protocol=protocol, opcode=opcode, payload=payload)
        remaining = {block: block.end - block.start for block in blocks}
        inflaters: dict[Block, BlockInflater] = {}

        while any(remaining.values()):
            # aMule ends every session after 10 MiB or an hour while others wait, and queues the client again, so the
            # end of a slot is a place in the queue rather than a failure of the source:
            # https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/UploadQueue.cpp#L599
            # https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/UploadClient.cpp#L495
            packet = await self._next(DATA_OPCODES | SLOT_END_OPCODES)
            if (packet.protocol, packet.opcode) in SLOT_END_OPCODES:
                raise QueuedError(0)

            reader = packet.reader()
            if Ed2kHash(reader.hash16()) != file_hash:
                continue

            # Every data packet names its own offset, so it is placed by that offset and never by arrival order
            start = reader.u64() if packet.opcode in WIDE_OPCODES else reader.u32()
            block = next((b for b in blocks if b.start <= start < b.end), None)
            if block is None:
                err_msg = f'data at offset {start} from {self.stream.peer} lies outside the request'
                raise ProtocolError(err_msg)

            # A compressed block is one zlib stream split over packets that all repeat the block start, so the
            # write offset is where the inflated output has reached: https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/DownloadClient.cpp#L864
            if packet.opcode in COMPRESSED_OPCODES:
                reader.u32()  # total compressed size of the block, not needed with a streaming inflater
                inflater = inflaters.setdefault(block, BlockInflater(block))
                offset = block.start + inflater.produced
                data = inflater.feed(reader.rest())
            else:
                end = reader.u64() if packet.opcode in WIDE_OPCODES else reader.u32()
                data, offset = reader.rest(), start
                if end - start != len(data):
                    err_msg = f'{len(data)} data bytes from {self.stream.peer} do not span {start} to {end}'
                    raise ProtocolError(err_msg)

            if data:
                remaining[block] = max(0, remaining[block] - len(data))
                yield block, offset, data

    async def serve(self, *, library: SharedLibrary, slots: asyncio.Semaphore) -> None:
        """Answer a peer's requests for shared files until it disconnects.

        :param library: the shared files.
        :type library: SharedLibrary
        :param slots: the upload slots shared by all connections.
        :type slots: asyncio.Semaphore
        """
        # The slot is released in finally, so a peer that disconnects while holding one frees it for the next
        try:
            while True:
                packet = await self.stream.read_packet()
                await self._answer(packet, library=library, slots=slots)
        except (ConnectionFailedError, ProtocolError, SecurityError) as error:
            logger.info('Serving %s ended: %s', self.stream.peer, error)
        finally:
            if self._holding_slot:
                slots.release()
                self._holding_slot = False

    async def _answer(self, packet: Packet, *, library: SharedLibrary, slots: asyncio.Semaphore) -> None:
        """Answer one request of a downloading peer.

        :param packet: the request.
        :type packet: Packet
        :param library: the shared files.
        :type library: SharedLibrary
        :param slots: the upload slots.
        :type slots: asyncio.Semaphore
        """
        reader = packet.reader()
        match (packet.protocol, packet.opcode):
            case (Protocol.EDONKEY, PeerOp.HELLO):
                self.remote = parse_hello(reader, answer=False)
                payload = build_hello(self._local, answer=True)
                await self.stream.send(protocol=Protocol.EDONKEY, opcode=PeerOp.HELLOANSWER, payload=payload)
            case (Protocol.EDONKEY, PeerOp.REQUESTFILENAME | PeerOp.SETREQFILEID | PeerOp.HASHSETREQUEST):
                await self._answer_file_query(packet.opcode, Ed2kHash(reader.hash16()), library=library)
            case (Protocol.EDONKEY, PeerOp.STARTUPLOADREQ):
                # A peer that finds the slots taken learns it is queued and then waits on this connection. The slot
                # is recorded as held the moment it is taken, so serve() gives it back whatever fails after that
                if not self._holding_slot:
                    if slots.locked():
                        payload = Writer().u16(1).raw(QUEUE_RANK_PADDING).getvalue()
                        await self.stream.send(protocol=Protocol.EMULE, opcode=EmuleOp.QUEUERANKING, payload=payload)
                    await slots.acquire()
                    self._holding_slot = True
                await self.stream.send(protocol=Protocol.EDONKEY, opcode=PeerOp.ACCEPTUPLOADREQ)
            case (Protocol.EDONKEY, PeerOp.REQUESTPARTS) | (Protocol.EMULE, EmuleOp.REQUESTPARTS_I64) if (
                self._holding_slot
            ):
                large = packet.protocol == Protocol.EMULE
                await self._send_parts(PartRequest.parse(reader, large=large), library=library, large=large)
            case (Protocol.EDONKEY, PeerOp.CANCELTRANSFER | PeerOp.END_OF_DOWNLOAD) if self._holding_slot:
                slots.release()
                self._holding_slot = False
            case _:
                logger.debug('Not answering 0x%02X/0x%02X', packet.protocol, packet.opcode)

    async def _answer_file_query(self, opcode: int, file_hash: Ed2kHash, *, library: SharedLibrary) -> None:
        """Answer a file name, file status or hashset request.

        :param opcode: the request opcode.
        :type opcode: int
        :param file_hash: the requested file.
        :type file_hash: Ed2kHash
        :param library: the shared files.
        :type library: SharedLibrary
        """
        shared = library.get(file_hash)
        payload = Writer().raw(file_hash.digest)

        # A complete file answers its status with a part count of 0, which means every part
        if shared is None:
            answer = PeerOp.FILEREQANSNOFIL
        elif opcode == PeerOp.REQUESTFILENAME:
            answer = PeerOp.REQFILENAMEANSWER
            payload.string(shared.name)
        elif opcode == PeerOp.SETREQFILEID:
            answer = PeerOp.FILESTATUS
            payload.u16(0)
        else:
            answer = PeerOp.HASHSETANSWER
            payload.u16(len(shared.part_hashes)).raw(b''.join(shared.part_hashes))

        await self.stream.send(protocol=Protocol.EDONKEY, opcode=answer, payload=payload.getvalue())

    async def _send_parts(self, request: PartRequest, *, library: SharedLibrary, large: bool) -> None:
        """Send the requested ranges, compressed when the peer accepts it and it helps.

        :param request: the block request.
        :type request: PartRequest
        :param library: the shared files.
        :type library: SharedLibrary
        :param large: whether the peer asked with 64-bit offsets.
        :type large: bool
        :raises SecurityError: when a range exceeds three blocks.
        """
        shared = library.get(request.file_hash)
        if shared is None:
            return

        wide = large or shared.size > LARGE_FILE_THRESHOLD
        for start, end in request.ranges:
            # aMule refuses a range longer than three blocks the same way: https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/UploadDiskIOThread.cpp#L248
            if end - start > MAX_REQUEST_RANGES * BLOCK_SIZE:
                err_msg = f'{self.stream.peer} asked for {end - start} bytes in one range'
                raise SecurityError(err_msg)
            data = library.read(shared=shared, start=start, end=end)

            # Compressed only when the peer announced compression version 1 and the data actually shrinks, the two
            # checks aMule makes: https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/UploadDiskIOThread.cpp#L385
            packed = zlib.compress(data) if self.remote is not None and self.remote.compression else data
            if len(packed) < len(data):
                await self._send_compressed(request.file_hash, start=start, packed=packed, wide=wide)
            else:
                await self._send_raw(request.file_hash, start=start, data=data, wide=wide)

    async def _send_raw(self, file_hash: Ed2kHash, *, start: int, data: bytes, wide: bool) -> None:
        """Send a range as raw data packets.

        :param file_hash: the file.
        :type file_hash: Ed2kHash
        :param start: the range start.
        :type start: int
        :param data: the bytes.
        :type data: bytes
        :param wide: whether to use 64-bit offsets.
        :type wide: bool
        """
        # aMule cuts a range into packets of at least 10 KiB: https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/UploadDiskIOThread.cpp#L468
        protocol, opcode = (Protocol.EMULE, EmuleOp.SENDINGPART_I64) if wide else (Protocol.EDONKEY, PeerOp.SENDINGPART)
        for offset in range(0, len(data), self._settings.send_chunk):
            chunk = data[offset : offset + self._settings.send_chunk]
            payload = Writer().raw(file_hash.digest)
            (payload.u64 if wide else payload.u32)(start + offset)
            (payload.u64 if wide else payload.u32)(start + offset + len(chunk))
            await self.stream.send(protocol=protocol, opcode=opcode, payload=payload.raw(chunk).getvalue())

    async def _send_compressed(self, file_hash: Ed2kHash, *, start: int, packed: bytes, wide: bool) -> None:
        """Send a zlib-compressed range as compressed data packets.

        :param file_hash: the file.
        :type file_hash: Ed2kHash
        :param start: the range start.
        :type start: int
        :param packed: the compressed bytes.
        :type packed: bytes
        :param wide: whether to use 64-bit offsets.
        :type wide: bool
        """
        # As eMule does, every packet of one block repeats the block start and the total compressed size
        opcode = EmuleOp.COMPRESSEDPART_I64 if wide else EmuleOp.COMPRESSEDPART
        chunk = self._settings.send_chunk
        for offset in range(0, len(packed), chunk):
            payload = Writer().raw(file_hash.digest)
            (payload.u64 if wide else payload.u32)(start)
            payload.u32(len(packed)).raw(packed[offset : offset + chunk])
            await self.stream.send(protocol=Protocol.EMULE, opcode=opcode, payload=payload.getvalue())
