"""Binary encoding of eD2k and Kad packets.

Every multi-byte number is little-endian. :class:`Reader` refuses to read past the end of its buffer and refuses any
length larger than the caller's limit, so a hostile length field turns into a :class:`ProtocolError` before any
memory is allocated. zlib payloads are inflated through :func:`inflate`, which stops at a fixed output size and
therefore defeats compression bombs.
"""

import ipaddress
import struct
import zlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, Self

from ed2k_client.constants import HASH_LENGTH, Protocol
from ed2k_client.errors import ProtocolError
from ed2k_client.settings import DEFAULT_LIMITS

if TYPE_CHECKING:
    from ed2k_client.settings import Limits

# <protocol 1><length 4><opcode 1>, where the length counts the opcode and the payload:
# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/Packet.cpp#L80
HEADER = struct.Struct('<BIB')
UDP_HEADER = struct.Struct('<BB')
U8 = struct.Struct('<B')
U16 = struct.Struct('<H')
U32 = struct.Struct('<I')
U64 = struct.Struct('<Q')
F32 = struct.Struct('<f')
LENGTH_PREFIXES: dict[int, struct.Struct] = {1: U8, 2: U16, 4: U32}
BYTE_ORDER: Literal['little'] = 'little'


def decode_text(raw: bytes) -> str:
    """Decode network text as UTF-8, replacing invalid bytes because old clients still send Latin-1 names.

    :param raw: the bytes.
    :type raw: bytes
    :returns: the text.
    :rtype: str
    """
    return raw.decode('utf-8', errors='replace')


class Reader:
    """Read typed values from a bytes buffer without ever passing its end.

    :ivar position: offset of the next byte to read.
    :ivar limits: the caps applied to lengths read from the buffer.
    """

    def __init__(self, data: bytes, *, limits: Limits = DEFAULT_LIMITS) -> None:
        """Wrap a buffer.

        :param data: the bytes to read.
        :type data: bytes
        :param limits: the caps applied to lengths read from the buffer.
        :type limits: Limits
        """
        # A memoryview slices without copying, so reading a large packet field by field stays linear
        self._data = memoryview(data)
        self.position = 0
        self.limits = limits

    @property
    def remaining(self) -> int:
        """Number of unread bytes."""
        return len(self._data) - self.position

    def take(self, size: int) -> bytes:
        """Read exactly ``size`` bytes.

        :param size: number of bytes.
        :type size: int
        :returns: the bytes.
        :rtype: bytes
        :raises ProtocolError: when fewer bytes are left or the size is negative.
        """
        if size < 0 or size > self.remaining:
            err_msg = f'need {size} bytes at offset {self.position}, have {self.remaining}'
            raise ProtocolError(err_msg)

        chunk = bytes(self._data[self.position : self.position + size])
        self.position += size
        return chunk

    def rest(self) -> bytes:
        """Read every remaining byte.

        :returns: the unread tail of the buffer.
        :rtype: bytes
        """
        return self.take(self.remaining)

    def number(self, layout: struct.Struct) -> int:
        """Read one little-endian unsigned integer as wide as the given layout.

        :param layout: a single-field integer struct such as :data:`U32`, which gives the width.
        :type layout: struct.Struct
        :returns: the value.
        :rtype: int
        """
        return int.from_bytes(self.take(layout.size), BYTE_ORDER)

    def u8(self) -> int:
        """Read an unsigned byte.

        :returns: the value.
        :rtype: int
        """
        return self.number(U8)

    def u16(self) -> int:
        """Read an unsigned 16-bit integer.

        :returns: the value.
        :rtype: int
        """
        return self.number(U16)

    def u32(self) -> int:
        """Read an unsigned 32-bit integer.

        :returns: the value.
        :rtype: int
        """
        return self.number(U32)

    def u64(self) -> int:
        """Read an unsigned 64-bit integer.

        :returns: the value.
        :rtype: int
        """
        return self.number(U64)

    def f32(self) -> float:
        """Read a 32-bit float.

        :returns: the value.
        :rtype: float
        """
        return float(F32.unpack(self.take(F32.size))[0])

    def hash16(self) -> bytes:
        """Read a 16-byte MD4 hash.

        :returns: the hash bytes.
        :rtype: bytes
        """
        return self.take(HASH_LENGTH)

    def ed2k_ip(self) -> str:
        """Read an IPv4 address stored in network byte order, as eD2k does, while Kad stores it little-endian.

        :returns: the dotted address.
        :rtype: str
        """
        return str(ipaddress.IPv4Address(self.take(4)))

    def string(self, *, length_size: int = 2, limit: int | None = None) -> str:
        """Read a length-prefixed UTF-8 string.

        Invalid UTF-8 is replaced instead of rejected, because old clients still send Latin-1 file names.

        :param length_size: width of the length prefix, 1, 2 or 4 bytes.
        :type length_size: int
        :param limit: largest accepted length in bytes, the reader's ``string_bytes`` limit when ``None``.
        :type limit: int | None
        :returns: the decoded text.
        :rtype: str
        :raises ProtocolError: when the length exceeds the limit or the buffer.
        """
        if limit is None:
            limit = self.limits.string_bytes

        size = self.number(LENGTH_PREFIXES[length_size])
        if size > limit:
            err_msg = f'string of {size} bytes exceeds the limit of {limit}'
            raise ProtocolError(err_msg)
        return decode_text(self.take(size))

    def expect_end(self) -> Self:
        """Check that nothing is left unread.

        :returns: the reader itself.
        :rtype: Self
        :raises ProtocolError: when bytes are left.
        """
        if self.remaining:
            err_msg = f'{self.remaining} trailing bytes'
            raise ProtocolError(err_msg)
        return self


class Writer:
    """Build a little-endian binary payload."""

    def __init__(self) -> None:
        """Start an empty buffer."""
        self._parts: list[bytes] = []

    def raw(self, data: bytes) -> Self:
        """Append bytes as they are.

        :param data: the bytes.
        :type data: bytes
        :returns: the writer itself.
        :rtype: Self
        """
        self._parts.append(bytes(data))
        return self

    def u8(self, value: int) -> Self:
        """Append an unsigned byte.

        :param value: the value.
        :type value: int
        :returns: the writer itself.
        :rtype: Self
        """
        return self.raw(U8.pack(value))

    def u16(self, value: int) -> Self:
        """Append an unsigned 16-bit integer.

        :param value: the value.
        :type value: int
        :returns: the writer itself.
        :rtype: Self
        """
        return self.raw(U16.pack(value))

    def u32(self, value: int) -> Self:
        """Append an unsigned 32-bit integer.

        :param value: the value.
        :type value: int
        :returns: the writer itself.
        :rtype: Self
        """
        return self.raw(U32.pack(value))

    def u64(self, value: int) -> Self:
        """Append an unsigned 64-bit integer.

        :param value: the value.
        :type value: int
        :returns: the writer itself.
        :rtype: Self
        """
        return self.raw(U64.pack(value))

    def f32(self, value: float) -> Self:
        """Append a 32-bit float.

        :param value: the value.
        :type value: float
        :returns: the writer itself.
        :rtype: Self
        """
        return self.raw(F32.pack(value))

    def ed2k_ip(self, address: str) -> Self:
        """Append an IPv4 address in network byte order.

        :param address: the dotted address.
        :type address: str
        :returns: the writer itself.
        :rtype: Self
        """
        return self.raw(ipaddress.IPv4Address(address).packed)

    def string(self, text: str, *, length_size: int = 2) -> Self:
        """Append a length-prefixed UTF-8 string.

        :param text: the text.
        :type text: str
        :param length_size: width of the length prefix, 1, 2 or 4 bytes.
        :type length_size: int
        :returns: the writer itself.
        :rtype: Self
        """
        encoded = text.encode()
        self.raw(LENGTH_PREFIXES[length_size].pack(len(encoded)))
        return self.raw(encoded)

    def getvalue(self) -> bytes:
        """Return everything written so far.

        :returns: the payload.
        :rtype: bytes
        """
        return b''.join(self._parts)


@dataclass(frozen=True, slots=True)
class Packet:
    """One decoded packet with an unpacked payload.

    :ivar protocol: the namespace byte, never ``PACKED`` or ``KAD_PACKED`` after decoding.
    :ivar opcode: the operation code.
    :ivar payload: the body after the opcode.
    :ivar limits: the caps the packet's readers apply.
    """

    protocol: int
    opcode: int
    payload: bytes
    limits: Limits = field(default=DEFAULT_LIMITS, compare=False, repr=False)

    def reader(self) -> Reader:
        """Open a reader over the payload.

        :returns: a reader positioned at the first payload byte.
        :rtype: Reader
        """
        return Reader(self.payload, limits=self.limits)


def inflate(data: bytes, *, limit: int = DEFAULT_LIMITS.unpacked_size) -> bytes:
    """Decompress a zlib stream and refuse output larger than ``limit``.

    :param data: the compressed bytes.
    :type data: bytes
    :param limit: largest accepted output size.
    :type limit: int
    :returns: the decompressed bytes.
    :rtype: bytes
    :raises ProtocolError: when the stream is corrupt, truncated or inflates beyond the limit.
    """
    # max_length stops the inflater at the limit and leaves the rest of the input in unconsumed_tail, so a bomb
    # never reaches its full size in memory
    decompressor = zlib.decompressobj()
    try:
        output = decompressor.decompress(data, limit)
    except zlib.error as error:
        err_msg = f'corrupt zlib payload: {error}'
        raise ProtocolError(err_msg) from error

    if decompressor.unconsumed_tail:
        err_msg = f'zlib payload inflates beyond {limit} bytes'
        raise ProtocolError(err_msg)
    if not decompressor.eof:
        err_msg = 'truncated zlib payload'
        raise ProtocolError(err_msg)
    return output


def encode_tcp(*, protocol: int, opcode: int, payload: bytes = b'') -> bytes:
    """Frame a TCP packet as ``<protocol 1><length 4><opcode 1><payload>``.

    :param protocol: the namespace byte.
    :type protocol: int
    :param opcode: the operation code.
    :type opcode: int
    :param payload: the body.
    :type payload: bytes
    :returns: the framed packet.
    :rtype: bytes
    """
    return HEADER.pack(protocol, len(payload) + 1, opcode) + payload


def unpack_payload(
    *, protocol: int, opcode: int, payload: bytes, packed_as: int = Protocol.EMULE, limits: Limits = DEFAULT_LIMITS
) -> Packet:
    """Turn a received body into a :class:`Packet`, inflating it when the protocol byte says it is packed.

    The namespace of an inflated packet depends on who sent it, exactly as in aMule: a server's packed packet is an
    eDonkey packet (``CServerSocket::PacketReceived``), a client's is an eMule packet (``CPacket::UnPackPacket``)
    and a Kad packet stays Kad.

    :param protocol: the namespace byte as received.
    :type protocol: int
    :param opcode: the operation code.
    :type opcode: int
    :param payload: the body as received.
    :type payload: bytes
    :param packed_as: the namespace of a packed TCP packet from this sender.
    :type packed_as: int
    :param limits: the caps on the inflated size and on the packet's readers.
    :type limits: Limits
    :returns: the decoded packet.
    :rtype: Packet
    :raises ProtocolError: when the protocol byte is unknown.
    """
    # https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/ServerSocket.cpp#L631
    # https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/Packet.cpp#L301
    match protocol:
        case Protocol.PACKED:
            body = inflate(payload, limit=limits.unpacked_size)
            return Packet(protocol=packed_as, opcode=opcode, payload=body, limits=limits)
        case Protocol.KAD_PACKED:
            body = inflate(payload, limit=limits.unpacked_size)
            return Packet(protocol=Protocol.KAD, opcode=opcode, payload=body, limits=limits)
        case Protocol.EDONKEY | Protocol.EMULE | Protocol.KAD:
            return Packet(protocol=protocol, opcode=opcode, payload=payload, limits=limits)
        case _:
            err_msg = f'unknown protocol byte 0x{protocol:02X}'
            raise ProtocolError(err_msg)


def encode_udp(*, protocol: int, opcode: int, payload: bytes = b'') -> bytes:
    """Frame a UDP datagram as ``<protocol 1><opcode 1><payload>``.

    :param protocol: the namespace byte.
    :type protocol: int
    :param opcode: the operation code.
    :type opcode: int
    :param payload: the body.
    :type payload: bytes
    :returns: the datagram.
    :rtype: bytes
    """
    return UDP_HEADER.pack(protocol, opcode) + payload


def decode_udp(datagram: bytes, *, limits: Limits = DEFAULT_LIMITS) -> Packet:
    """Decode a UDP datagram into a :class:`Packet`.

    :param datagram: the received datagram.
    :type datagram: bytes
    :param limits: the caps on the inflated size and on the packet's readers.
    :type limits: Limits
    :returns: the decoded packet.
    :rtype: Packet
    :raises ProtocolError: when the datagram is too short or its protocol byte is unknown.
    """
    if len(datagram) < UDP_HEADER.size:
        err_msg = f'datagram of {len(datagram)} bytes is too short'
        raise ProtocolError(err_msg)

    protocol, opcode = UDP_HEADER.unpack_from(datagram)
    return unpack_payload(protocol=protocol, opcode=opcode, payload=datagram[UDP_HEADER.size :], limits=limits)
