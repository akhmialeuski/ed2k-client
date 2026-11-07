"""Unit tests of the client on an in-memory file system: peers that reach it and where it takes its server list."""

import asyncio
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, PropertyMock, create_autospec, patch, sentinel

import pytest

from ed2k_client.client import IP_FILTER_CACHE, SERVER_MET_CACHE, Client, ClientConfig
from ed2k_client.constants import PeerOp, Protocol
from ed2k_client.security import IpFilter
from ed2k_client.servermet import ServerEntry, ServerList
from ed2k_client.share import SharedLibrary
from ed2k_client.transport import PacketStream
from ed2k_client.wire import Packet
from tests.fakes import ScriptedStream
from tests.helpers import server_met

if TYPE_CHECKING:
    from unittest.mock import MagicMock

    from pyfakefs.fake_filesystem import FakeFilesystem

pytestmark = pytest.mark.usefixtures('fs')

CONFIG = ClientConfig(state_dir=Path('/state'), download_dir=Path('/downloads'))
PUBLIC_PEER = ('8.8.8.8', 4662)
CACHED_LIST = CONFIG.state_dir / SERVER_MET_CACHE
LOCAL_LIST = Path('/lists/server.met')
OFFLINE = 'offline'
BUSY = ServerEntry(host='203.0.113.10', port=4661, name='busy', users=900)
QUIET = ServerEntry(host='203.0.113.20', port=4242, name='quiet', users=10)
FILTER_CACHE = CONFIG.state_dir / IP_FILTER_CACHE
FILTER_TEXT = b'001.002.003.000 - 001.002.003.255 , 000 , fakes\n'
BLOCKED = '1.2.3.4'
# A modification time at the epoch is older than any refresh interval
EPOCH = 0

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


class TestServerCandidates:
    """Tests of where :meth:`Client.connect` takes the servers it tries."""

    @patch.object(ServerList, 'download', side_effect=OSError(OFFLINE))
    async def test_cached_list_stands_in_when_the_download_fails(self, download: MagicMock, fs: FakeFilesystem) -> None:
        """A list saved by an earlier download is used when the download fails, ordered by users as always.

        :param download: the mocked download, which fails as an unreachable host does.
        :type download: MagicMock
        :param fs: the in-memory file system that holds the cached list.
        :type fs: FakeFilesystem
        """
        del download
        client = Client(CONFIG)
        fs.create_file(CACHED_LIST, contents=server_met([QUIET, BUSY]))

        assert await client._server_candidates() == [BUSY, QUIET]

    @patch.object(ServerList, 'download', side_effect=OSError(OFFLINE))
    async def test_failed_download_without_a_cache_is_raised(self, download: MagicMock) -> None:
        """A failed download with nothing cached is reported, since no server is known.

        :param download: the mocked download, which fails as an unreachable host does.
        :type download: MagicMock
        """
        del download
        client = Client(CONFIG)

        with pytest.raises(OSError, match=OFFLINE):
            await client._server_candidates()

    @patch.object(ServerList, 'download', return_value=ServerList(servers=(BUSY,)))
    async def test_download_is_cached_in_the_state_directory(self, download: MagicMock) -> None:
        """A successful download is asked to save itself in the state directory, where a failed one looks.

        :param download: the mocked download, which returns one server.
        :type download: MagicMock
        """
        client = Client(CONFIG)

        assert await client._server_candidates() == [BUSY]
        assert download.call_args.kwargs['save_to'] == CACHED_LIST

    @patch.object(ServerList, 'download')
    async def test_local_server_met_replaces_the_download(self, download: MagicMock, fs: FakeFilesystem) -> None:
        """A configured local server.met is read instead of downloading one.

        :param download: the mocked download, which must not be called.
        :type download: MagicMock
        :param fs: the in-memory file system that holds the local list.
        :type fs: FakeFilesystem
        """
        fs.create_file(LOCAL_LIST, contents=server_met([BUSY]))
        client = Client(replace(CONFIG, server_met=LOCAL_LIST))

        assert await client._server_candidates() == [BUSY]
        download.assert_not_called()


class TestAutomaticIpFilter:
    """Tests of how :class:`Client` keeps the automatic IP filter in its state directory."""

    @patch.object(IpFilter, 'download')
    async def test_fresh_copy_is_used_without_a_download(self, download: MagicMock, fs: FakeFilesystem) -> None:
        """A copy younger than the refresh interval is read, and nothing is downloaded.

        :param download: the mocked download, which must not be called.
        :type download: MagicMock
        :param fs: the in-memory file system that holds the copy.
        :type fs: FakeFilesystem
        """
        client = Client(CONFIG)
        fs.create_file(FILTER_CACHE, contents=FILTER_TEXT)

        assert (await client._automatic_ip_filter()).blocks(BLOCKED)
        download.assert_not_called()

    @patch.object(IpFilter, 'download', return_value=IpFilter())
    async def test_old_copy_is_downloaded_again(self, download: MagicMock, fs: FakeFilesystem) -> None:
        """A copy older than the refresh interval is replaced by a download saved in its place.

        :param download: the mocked download, which returns an empty filter.
        :type download: MagicMock
        :param fs: the in-memory file system that holds the old copy.
        :type fs: FakeFilesystem
        """
        client = Client(CONFIG)
        fs.create_file(FILTER_CACHE, contents=FILTER_TEXT).st_mtime = EPOCH

        await client._automatic_ip_filter()

        assert download.call_args.kwargs['save_to'] == FILTER_CACHE

    @patch.object(IpFilter, 'download', side_effect=OSError(OFFLINE))
    async def test_failed_download_falls_back_to_the_old_copy(self, download: MagicMock, fs: FakeFilesystem) -> None:
        """An old copy still filters when the download that should replace it fails.

        :param download: the mocked download, which fails as an unreachable host does.
        :type download: MagicMock
        :param fs: the in-memory file system that holds the old copy.
        :type fs: FakeFilesystem
        """
        del download
        client = Client(CONFIG)
        fs.create_file(FILTER_CACHE, contents=FILTER_TEXT).st_mtime = EPOCH

        assert (await client._automatic_ip_filter()).blocks(BLOCKED)

    @patch.object(IpFilter, 'download', side_effect=OSError(OFFLINE))
    async def test_failed_download_without_a_copy_runs_unfiltered(
        self, download: MagicMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Without a copy a failed download leaves the client unfiltered, as it was before the setting, and says so.

        :param download: the mocked download, which fails as an unreachable host does.
        :type download: MagicMock
        :param caplog: the captured log records.
        :type caplog: pytest.LogCaptureFixture
        """
        del download
        client = Client(CONFIG)

        assert not (await client._automatic_ip_filter()).blocks(BLOCKED)
        assert 'without an IP filter' in caplog.text
