"""Unit tests of the downloader: how the end of a session with a source decides its next try, and what ends a run."""

import errno
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

import pytest

from ed2k_client.constants import PeerOp, Protocol
from ed2k_client.download import Downloader, DownloadSettings
from ed2k_client.errors import DownloadError
from ed2k_client.hashing import Ed2kHash, md4
from ed2k_client.identity import Identity
from ed2k_client.partfile import PartFile
from ed2k_client.peer import LocalPeer, build_hello
from ed2k_client.security import AddressPolicy
from ed2k_client.sources import Source, client_id_from_host
from ed2k_client.wire import Packet, Writer
from tests.fakes import ScriptedStream

if TYPE_CHECKING:
    from unittest.mock import MagicMock

CONNECT = 'ed2k_client.download.PacketStream.connect'
WRITE = 'ed2k_client.partfile.PartFile.write'
QUARANTINE = Path('/q')
DOWNLOADS = Path('/downloads')
BOOK = 'book.pdf'
FILE_HASH = Ed2kHash(md4(b'book'))

# Below one part, so the peer is never asked for a hashset
SIZE = 5_000_000
PUBLIC_PEER = ('8.8.8.8', 4662)
SOURCE = Source(client_id=client_id_from_host(PUBLIC_PEER[0]), port=PUBLIC_PEER[1])
LOCAL = LocalPeer(identity=Identity.generate(), client_id=0, tcp_port=0, nickname='leecher')
UPLOADER = LocalPeer(identity=Identity.generate(), client_id=0, tcp_port=0, nickname='uploader')
SETTINGS = DownloadSettings(max_connect_failures=3)
FAST_POLL = DownloadSettings(poll_interval=0.001, deadline=0.5)
DISK_FULL = OSError(errno.ENOSPC, 'No space left on device')
DATA_BYTES = 1000

# A busy uploader greets, has the whole file and grants a slot
SESSION_START = (
    Packet(protocol=Protocol.EDONKEY, opcode=PeerOp.HELLOANSWER, payload=build_hello(UPLOADER, answer=True)),
    Packet(protocol=Protocol.EDONKEY, opcode=PeerOp.FILESTATUS, payload=FILE_HASH.digest + bytes(2)),
    Packet(protocol=Protocol.EDONKEY, opcode=PeerOp.ACCEPTUPLOADREQ, payload=b''),
)

# aMule ends an upload session this way after 10 MiB or an hour while others wait in its queue
SESSION_END = Packet(protocol=Protocol.EDONKEY, opcode=PeerOp.OUTOFPARTREQS, payload=b'')
FIRST_DATA = Packet(
    protocol=Protocol.EDONKEY,
    opcode=PeerOp.SENDINGPART,
    payload=Writer().raw(FILE_HASH.digest).u32(0).u32(DATA_BYTES).raw(bytes(DATA_BYTES)).getvalue(),
)


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
        connect.side_effect = lambda **_: ScriptedStream([*SESSION_START, SESSION_END], peer=PUBLIC_PEER)
        part_file = PartFile.open(directory=QUARANTINE, name=BOOK, size=SIZE, file_hash=FILE_HASH)
        downloader = Downloader(part_file=part_file, local=LOCAL, policy=AddressPolicy(), settings=SETTINGS)
        downloader.add_sources([SOURCE])
        state = downloader._sources[SOURCE.client_id, SOURCE.port]

        for _ in range(SETTINGS.max_connect_failures):
            await downloader._work(state)

        assert (state.banned, state.failures) == (False, 0)


class TestRun:
    """Tests of :meth:`Downloader.run`."""

    @pytest.mark.usefixtures('fs')
    @patch(WRITE, autospec=True, side_effect=DISK_FULL)
    @patch(CONNECT, new_callable=AsyncMock)
    async def test_disk_error_fails_the_download_after_one_session(self, connect: AsyncMock, write: MagicMock) -> None:
        """A write that fails on the local disk ends the download with its cause after the one session it hit.

        A peer cannot cause such an error, so asking the peer again only repeats it. Left to the scheduler, the
        source would be dialled again at every poll until the deadline, while aMule bans a client that asks again
        within 590 seconds, and the download would report the deadline instead of the disk.

        :param connect: the mocked dial, which opens a session that delivers one piece of data.
        :type connect: AsyncMock
        :param write: the mocked part file write, which fails as on a full disk.
        :type write: MagicMock
        """
        del write
        connect.side_effect = lambda **_: ScriptedStream([*SESSION_START, FIRST_DATA], peer=PUBLIC_PEER)
        part_file = PartFile.open(directory=QUARANTINE, name=BOOK, size=SIZE, file_hash=FILE_HASH)
        downloader = Downloader(part_file=part_file, local=LOCAL, policy=AddressPolicy(), settings=FAST_POLL)

        with pytest.raises(DownloadError, match='No space left'):
            await downloader.run(feed=AsyncMock(return_value=[SOURCE]), download_dir=DOWNLOADS)
        assert connect.await_count == 1
