"""Unit tests of the downloader: how the end of a session with a source decides its next try."""

from pathlib import Path
from typing import TYPE_CHECKING, Self
from unittest.mock import AsyncMock, patch

import pytest

from ed2k_client.constants import PeerOp, Protocol
from ed2k_client.download import Downloader, DownloadSettings
from ed2k_client.hashing import Ed2kHash, md4
from ed2k_client.identity import Identity
from ed2k_client.partfile import PartFile
from ed2k_client.peer import LocalPeer, build_hello
from ed2k_client.security import AddressPolicy
from ed2k_client.settings import DEFAULT_LIMITS
from ed2k_client.sources import Source, client_id_from_host
from ed2k_client.wire import Packet

if TYPE_CHECKING:
    from types import TracebackType

CONNECT = 'ed2k_client.download.PacketStream.connect'
QUARANTINE = Path('/q')
BOOK = 'book.pdf'
FILE_HASH = Ed2kHash(md4(b'book'))

# Below one part, so the peer is never asked for a hashset
SIZE = 5_000_000
PUBLIC_PEER = ('8.8.8.8', 4662)
SOURCE = Source(client_id=client_id_from_host(PUBLIC_PEER[0]), port=PUBLIC_PEER[1])
LOCAL = LocalPeer(identity=Identity.generate(), client_id=0, tcp_port=0, nickname='leecher')
UPLOADER = LocalPeer(identity=Identity.generate(), client_id=0, tcp_port=0, nickname='uploader')
SETTINGS = DownloadSettings(max_connect_failures=3)


class SessionEndingStream:
    """A busy uploader that greets, has the whole file, grants a slot and ends the session at once.

    aMule ends an upload session this way after 10 MiB or an hour while others wait in its queue. It stands in for
    :class:`PacketStream`, whose annotations name imports that exist only for type checkers, so ``create_autospec``
    cannot read its signature.

    :ivar peer: the remote address.
    :ivar limits: the caps of the connection.
    """

    def __init__(self) -> None:
        """Queue the packets of one session."""
        self.peer = PUBLIC_PEER
        self.limits = DEFAULT_LIMITS
        self._packets = [
            Packet(protocol=Protocol.EDONKEY, opcode=PeerOp.HELLOANSWER, payload=build_hello(UPLOADER, answer=True)),
            Packet(protocol=Protocol.EDONKEY, opcode=PeerOp.FILESTATUS, payload=FILE_HASH.digest + bytes(2)),
            Packet(protocol=Protocol.EDONKEY, opcode=PeerOp.ACCEPTUPLOADREQ, payload=b''),
            Packet(protocol=Protocol.EDONKEY, opcode=PeerOp.OUTOFPARTREQS, payload=b''),
        ]

    async def read_packet(self, *, limit: int | None = None) -> Packet:
        """Return the next packet of the session.

        :param limit: the largest accepted packet length, unused.
        :type limit: int | None
        :returns: the packet.
        :rtype: Packet
        """
        del limit
        return self._packets.pop(0)

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
        """Leave the context.

        :param exc_type: the exception type, if any.
        :type exc_type: type[BaseException] | None
        :param exc: the exception, if any.
        :type exc: BaseException | None
        :param traceback: the traceback, if any.
        :type traceback: TracebackType | None
        """
        del exc_type, exc, traceback


class TestWork:
    """Tests of how :class:`Downloader` schedules a source after one session with it."""

    @pytest.mark.usefixtures('fs')
    @patch(CONNECT, new_callable=AsyncMock)
    async def test_session_ended_by_the_uploader_keeps_the_source(self, connect: AsyncMock) -> None:
        """A source whose sessions end with ``OP_OUTOFPARTREQS`` is asked again later and never banned.

        The uploader puts this client back in its queue with that packet, so it is a place in the queue rather than a
        failed connection. Counted as a failure, every busy source would be banned after its third session, and a
        file larger than three sessions could never finish from it.

        :param connect: the mocked dial, which opens a session that the uploader ends.
        :type connect: AsyncMock
        """
        connect.side_effect = lambda **_: SessionEndingStream()
        part_file = PartFile.open(directory=QUARANTINE, name=BOOK, size=SIZE, file_hash=FILE_HASH)
        downloader = Downloader(part_file=part_file, local=LOCAL, policy=AddressPolicy(), settings=SETTINGS)
        downloader.add_sources([SOURCE])
        state = downloader._sources[SOURCE.client_id, SOURCE.port]

        for _ in range(SETTINGS.max_connect_failures):
            await downloader._work(state)

        assert (state.banned, state.failures) == (False, 0)
