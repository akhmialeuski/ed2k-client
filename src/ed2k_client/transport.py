"""A TCP connection that exchanges eD2k packets, optionally inside eMule obfuscation.

:class:`PacketStream` frames, limits and times out every read, so a peer that sends a huge length field, trickles
bytes or never answers costs a bounded amount of memory and time. It is an async context manager and always closes
its socket.
"""

import asyncio
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Self

from ed2k_client.constants import CONNECT_TIMEOUT, MAX_CONTROL_PACKET, READ_TIMEOUT, Protocol
from ed2k_client.errors import ConnectionFailedError, ProtocolError
from ed2k_client.obfuscation import PROTOCOL_BYTES, accept_obfuscated, open_obfuscated
from ed2k_client.wire import HEADER, encode_tcp, unpack_payload

if TYPE_CHECKING:
    from types import TracebackType

    from ed2k_client.obfuscation import CipherPair
    from ed2k_client.wire import Packet

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class StreamOptions:
    """How one connection reads its packets.

    :ivar packed_as: the namespace of packed packets, eMule for a client and eDonkey for a server, as in aMule.
    :ivar idle_timeout: seconds a read may wait for the next packet, ``None`` to wait forever.
    """

    packed_as: int = Protocol.EMULE
    idle_timeout: float | None = READ_TIMEOUT


PEER_STREAM = StreamOptions()
SERVER_STREAM = StreamOptions(packed_as=Protocol.EDONKEY, idle_timeout=None)


class PacketStream:
    """Send and receive framed packets over one TCP connection.

    :ivar peer: the remote ``(host, port)``.
    """

    def __init__(
        self,
        *,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        ciphers: CipherPair | None = None,
        first_byte: bytes = b'',
        options: StreamOptions = PEER_STREAM,
    ) -> None:
        """Wrap an open connection.

        :param reader: the connection's reader.
        :type reader: asyncio.StreamReader
        :param writer: the connection's writer.
        :type writer: asyncio.StreamWriter
        :param ciphers: the obfuscation streams, or ``None`` for an open connection.
        :type ciphers: CipherPair | None
        :param first_byte: the plain protocol byte already read while detecting obfuscation.
        :type first_byte: bytes
        :param options: how packets are read on this connection.
        :type options: StreamOptions
        """
        self._reader = reader
        self._writer = writer
        self._ciphers = ciphers
        self._pending = first_byte
        self._options = options
        host, port = writer.get_extra_info('peername')[:2]
        self.peer: tuple[str, int] = (host, port)

    @classmethod
    async def connect(
        cls, *, host: str, port: int, obfuscate_for: bytes | None = None, options: StreamOptions = PEER_STREAM
    ) -> Self:
        """Dial a peer or a server.

        :param host: the IPv4 address.
        :type host: str
        :param port: the TCP port.
        :type port: int
        :param obfuscate_for: the receiver's user hash to obfuscate the connection, or ``None``.
        :type obfuscate_for: bytes | None
        :param options: how packets are read on this connection.
        :type options: StreamOptions
        :returns: the open stream.
        :rtype: Self
        :raises ConnectionFailedError: when the connection or the handshake fails.
        """
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), CONNECT_TIMEOUT)
        except (OSError, TimeoutError) as error:
            err_msg = f'cannot connect to {host}:{port}, {error!r}'
            raise ConnectionFailedError(err_msg) from error
        if obfuscate_for is None:
            return cls(reader=reader, writer=writer, options=options)
        try:
            ciphers = await asyncio.wait_for(
                open_obfuscated(reader, writer, receiver_hash=obfuscate_for), CONNECT_TIMEOUT
            )
        except (OSError, TimeoutError, asyncio.IncompleteReadError, ProtocolError) as error:
            writer.close()
            err_msg = f'obfuscation handshake with {host}:{port} failed ({error!r})'
            raise ConnectionFailedError(err_msg) from error
        return cls(reader=reader, writer=writer, ciphers=ciphers, options=options)

    @classmethod
    async def accept(cls, *, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, own_hash: bytes) -> Self:
        """Wrap an incoming connection, answering the obfuscation handshake when the peer starts one.

        :param reader: the connection's reader.
        :type reader: asyncio.StreamReader
        :param writer: the connection's writer.
        :type writer: asyncio.StreamWriter
        :param own_hash: this client's user hash, the key of incoming obfuscation.
        :type own_hash: bytes
        :returns: the stream.
        :rtype: Self
        """
        first = await asyncio.wait_for(reader.readexactly(1), READ_TIMEOUT)
        if first[0] in PROTOCOL_BYTES:
            return cls(reader=reader, writer=writer, first_byte=first)
        ciphers = await asyncio.wait_for(accept_obfuscated(reader, writer, own_hash=own_hash), READ_TIMEOUT)
        return cls(reader=reader, writer=writer, ciphers=ciphers)

    @property
    def obfuscated(self) -> bool:
        """Whether the connection runs inside obfuscation."""
        return self._ciphers is not None

    async def _read_exactly(self, size: int) -> bytes:
        # The pending byte exists only on an open connection, so it never needs decrypting.
        """Read bytes, decrypting them on an obfuscated connection.

        :param size: the number of bytes.
        :type size: int
        :returns: the plain bytes.
        :rtype: bytes
        """
        data, self._pending = self._pending[:size], self._pending[size:]
        if len(data) < size:
            received = await self._reader.readexactly(size - len(data))
            data += received if self._ciphers is None else self._ciphers.receive.apply(received)
        return data

    async def _read_frame(self, limit: int) -> Packet:
        """Read one framed packet and check its length.

        :param limit: the largest accepted length.
        :type limit: int
        :returns: the packet.
        :rtype: Packet
        :raises ProtocolError: when the length is out of range.
        """
        protocol, length, opcode = HEADER.unpack(await self._read_exactly(HEADER.size))
        if not 1 <= length <= limit:
            err_msg = f'packet length {length} outside 1..{limit} from {self.peer}'
            raise ProtocolError(err_msg)
        payload = await self._read_exactly(length - 1)
        return unpack_payload(protocol=protocol, opcode=opcode, payload=payload, packed_as=self._options.packed_as)

    async def read_packet(self, *, limit: int = MAX_CONTROL_PACKET) -> Packet:
        """Read one packet within the stream's idle timeout.

        :param limit: largest accepted packet length.
        :type limit: int
        :returns: the decoded packet.
        :rtype: Packet
        :raises ProtocolError: when the length exceeds the limit or the packet is malformed.
        :raises ConnectionFailedError: when the connection closes or the idle timeout expires.
        """
        try:
            async with asyncio.timeout(self._options.idle_timeout):
                return await self._read_frame(limit)
        except (asyncio.IncompleteReadError, OSError, TimeoutError) as error:
            err_msg = f'connection to {self.peer} lost ({error!r})'
            raise ConnectionFailedError(err_msg) from error

    async def send(self, *, protocol: int, opcode: int, payload: bytes = b'') -> None:
        """Send one packet.

        :param protocol: the namespace byte.
        :type protocol: int
        :param opcode: the operation code.
        :type opcode: int
        :param payload: the body.
        :type payload: bytes
        :raises ConnectionFailedError: when the connection is gone.
        """
        frame = encode_tcp(protocol=protocol, opcode=opcode, payload=payload)
        if self._ciphers is not None:
            frame = self._ciphers.send.apply(frame)
        try:
            self._writer.write(frame)
            await asyncio.wait_for(self._writer.drain(), READ_TIMEOUT)
        except (OSError, TimeoutError) as error:
            err_msg = f'sending to {self.peer} failed with {error!r}'
            raise ConnectionFailedError(err_msg) from error

    async def close(self) -> None:
        """Close the connection, ignoring a peer that already went away."""
        self._writer.close()
        try:
            await self._writer.wait_closed()
        except OSError as error:
            logger.debug('Closing %s gave %r', self.peer, error)

    async def __aenter__(self) -> Self:
        """Enter the context.

        :returns: the stream itself.
        :rtype: Self
        """
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None
    ) -> None:
        """Close the connection on leaving the context.

        :param exc_type: the exception type, if any.
        :type exc_type: type[BaseException] | None
        :param exc: the exception, if any.
        :type exc: BaseException | None
        :param traceback: the traceback, if any.
        :type traceback: TracebackType | None
        """
        await self.close()
