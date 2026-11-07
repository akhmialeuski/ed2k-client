"""Unit tests of how the client treats peers that reach it, on an in-memory file system."""

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING, Self
from unittest.mock import AsyncMock, PropertyMock, create_autospec, patch, sentinel

import pytest

from ed2k_client.client import Client, ClientConfig
from ed2k_client.constants import PeerOp, Protocol
from ed2k_client.settings import DEFAULT_LIMITS
from ed2k_client.share import SharedLibrary
from ed2k_client.transport import PacketStream
from ed2k_client.wire import Packet

if TYPE_CHECKING:
    from types import TracebackType

pytestmark = pytest.mark.usefixtures('fs')

CONFIG = ClientConfig(state_dir=Path('/state'), download_dir=Path('/downloads'))
PUBLIC_PEER = ('8.8.8.8', 4662)

# A first byte that is no protocol byte starts an obfuscation handshake, and zeros never carry its sync value
NOT_A_HANDSHAKE = b'\x01' + bytes(64)

# A hello answer one byte long, far short of the user hash it must start with
SHORT_HELLO_ANSWER = Packet(protocol=Protocol.EDONKEY, opcode=PeerOp.HELLOANSWER, payload=b'\x00')


class HelloBreakingStream:
    """A dialled peer that answers the hello with a packet too short to parse.

    It stands in for :class:`PacketStream`, whose annotations name imports that exist only for type checkers, so
    ``create_autospec`` cannot read its signature.

    :ivar peer: the remote address.
    :ivar limits: the caps of the connection.
    :ivar closed: whether the connection was closed.
    """

    def __init__(self) -> None:
        """Start an open connection."""
        self.peer = PUBLIC_PEER
        self.limits = DEFAULT_LIMITS
        self.closed = False

    async def read_packet(self, *, limit: int | None = None) -> Packet:
        """Return the short hello answer.

        :param limit: the largest accepted packet length, unused.
        :type limit: int | None
        :returns: the packet.
        :rtype: Packet
        """
        del limit
        return SHORT_HELLO_ANSWER

    async def send(self, *, protocol: int, opcode: int, payload: bytes = b'') -> None:
        """Accept a packet and drop it.

        :param protocol: the namespace byte.
        :type protocol: int
        :param opcode: the operation code.
        :type opcode: int
        :param payload: the body.
        :type payload: bytes
        """
        del protocol, opcode, payload

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


class TestOnIncoming:
    """Tests of how :class:`Client` takes an incoming connection."""

    async def test_broken_handshake_is_dropped_quietly(self) -> None:
        """A connection that opens with neither a protocol byte nor a valid handshake is closed without an error.

        Any scanner that reaches the shared port sends such bytes, and an exception leaving the handler would log a
        traceback for every one of them.
        """
        client = Client(CONFIG)
        reader = asyncio.StreamReader()
        reader.feed_data(NOT_A_HANDSHAKE)
        reader.feed_eof()
        writer = create_autospec(asyncio.StreamWriter, instance=True)
        writer.get_extra_info.return_value = PUBLIC_PEER

        await client._on_incoming(reader, writer)

        writer.close.assert_called_once_with()


class TestOnCallback:
    """Tests of how :class:`Client` serves a peer that asked the server for a callback."""

    @patch.object(SharedLibrary, 'files', new_callable=PropertyMock, return_value=[sentinel.shared])
    async def test_malformed_hello_answer_ends_the_callback_quietly(self, files: PropertyMock) -> None:
        """A called-back peer whose hello answer does not parse costs only its connection.

        The callback runs as a background task, so an exception leaving it is never retrieved and shows up only as a
        warning about a lost task.

        :param files: the mocked shared files, one of them so that the callback is served.
        :type files: PropertyMock
        """
        del files
        client = Client(CONFIG)
        stream = HelloBreakingStream()

        with patch.object(PacketStream, 'connect', new=AsyncMock(return_value=stream)):
            await client._on_callback(*PUBLIC_PEER)

        assert stream.closed
