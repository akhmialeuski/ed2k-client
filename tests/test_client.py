"""Unit tests of how the client treats peers that reach it, on an in-memory file system."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, PropertyMock, create_autospec, patch, sentinel

import pytest

from ed2k_client.client import Client, ClientConfig
from ed2k_client.constants import PeerOp, Protocol
from ed2k_client.share import SharedLibrary
from ed2k_client.transport import PacketStream
from ed2k_client.wire import Packet
from tests.fakes import ScriptedStream

pytestmark = pytest.mark.usefixtures('fs')

CONFIG = ClientConfig(state_dir=Path('/state'), download_dir=Path('/downloads'))
PUBLIC_PEER = ('8.8.8.8', 4662)

# A first byte that is no protocol byte starts an obfuscation handshake, and zeros never carry its sync value
NOT_A_HANDSHAKE = b'\x01' + bytes(64)

# A hello answer one byte long, far short of the user hash it must start with
SHORT_HELLO_ANSWER = Packet(protocol=Protocol.EDONKEY, opcode=PeerOp.HELLOANSWER, payload=b'\x00')


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
        stream = ScriptedStream([SHORT_HELLO_ANSWER], peer=PUBLIC_PEER)

        with patch.object(PacketStream, 'connect', new=AsyncMock(return_value=stream)):
            await client._on_callback(*PUBLIC_PEER)

        assert stream.closed
