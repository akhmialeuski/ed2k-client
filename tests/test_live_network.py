"""Checks against the live eD2k and Kad networks.

They run only with ``-m network``, on a host that may reach the live network. The assertions are deliberately loose
about counts, since the live network changes from hour to hour, and strict about what must hold for any answer:
types, extensions and the safety filters.
"""

import asyncio
from typing import TYPE_CHECKING

import pytest

from ed2k_client import Client, ServerEntry, ServerList
from ed2k_client.client import ClientConfig
from ed2k_client.constants import LOW_ID_LIMIT
from ed2k_client.download import DownloadSettings

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.network

# ed2k-rust answered searches on 2026-11-06, while eMule Sunrise accepted logins but ignored searches.
SEARCHING_SERVER = ServerEntry(host='85.17.116.222', port=6082, name='ed2k-rust')
KEYWORD = 'springer'
BOOK_EXTENSIONS = ('.pdf', '.djvu')


def live_config(root: Path) -> ClientConfig:
    """Build a config with the server that answers searches and a private state directory.

    :param root: the directory the client keeps its files in.
    :type root: Path
    :returns: the config.
    :rtype: ClientConfig
    """
    return ClientConfig(
        state_dir=root / 'state',
        download_dir=root / 'downloads',
        servers=(SEARCHING_SERVER,),
        udp_port=0,
        download=DownloadSettings(deadline=60.0),
    )


class TestServerListDownload:
    """Tests of :meth:`ServerList.download`."""

    async def test_server_list_lists_live_servers(self) -> None:
        """The eMule Security server list downloads over HTTPS and names several servers with users."""
        servers = await asyncio.to_thread(ServerList.download)

        assert len(servers.servers) >= 5
        assert any(server.users > 1000 for server in servers.servers)


class TestSearch:
    """Tests of :meth:`Client.search` on the live networks."""

    async def test_live_server_search_returns_books(self, tmp_path: Path) -> None:
        """A real server returns PDF and DjVu books for a common word, and only those.

        :param tmp_path: the directory the clients keep their files in.
        :type tmp_path: Path
        """
        async with Client(live_config(tmp_path)) as client:
            status = await client.connect()
            results = await client.search(KEYWORD)

        assert all(session.client_id > 0 for session in status.servers)
        assert len(results) >= 10
        assert all(result.name.lower().endswith(BOOK_EXTENSIONS) for result in results)
        assert all(result.size > 0 for result in results)

    async def test_live_kad_search_returns_books(self, tmp_path: Path) -> None:
        """Kad bootstraps from the public nodes.dat and finds books without any server.

        :param tmp_path: the directory the clients keep their files in.
        :type tmp_path: Path
        """
        async with Client(live_config(tmp_path)) as client:
            contacts = await client.connect_kad()
            results = await client.search(KEYWORD)

        assert contacts >= 50
        assert results
        assert all(result.name.lower().endswith(BOOK_EXTENSIONS) for result in results)


class TestFindSources:
    """Tests of :meth:`Client.find_sources` on the live networks."""

    async def test_live_sources_are_reachable_addresses(self, tmp_path: Path) -> None:
        """Sources of a well-sourced book are High ID peers on public addresses.

        :param tmp_path: the directory the clients keep their files in.
        :type tmp_path: Path
        """
        async with Client(live_config(tmp_path)) as client:
            await client.connect()
            await client.connect_kad()
            results = await client.search(KEYWORD)
            best = max(results, key=lambda result: result.sources)
            sources = await client.find_sources(file_hash=best.file_hash, size=best.size)

        assert all(
            client.policy.permits(source.host, source.port) for source in sources if source.client_id >= LOW_ID_LIMIT
        )
