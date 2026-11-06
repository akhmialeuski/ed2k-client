"""The Kad path end to end against in-process Kad nodes, and both networks together.

The client bootstraps from a ``nodes.dat`` that lists fake nodes, walks to the node responsible for a keyword or a
file, searches there, and downloads from a source it learned only from Kad.
"""

import asyncio
import socket
from contextlib import AsyncExitStack
from typing import TYPE_CHECKING

import pytest

from ed2k_client import Client, Ed2kHash, hash_file
from ed2k_client.constants import KadOp, Protocol
from ed2k_client.hashing import md4
from ed2k_client.kad.contacts import KadId
from ed2k_client.search import SearchOrigin
from ed2k_client.sources import SourceOrigin
from ed2k_client.tags import Tag, write_tags
from ed2k_client.wire import Writer, encode_udp
from tests.fakes import FakeKadNetwork, FakeServer
from tests.helpers import LOOPBACK, ServeSpy, compressible, free_port, incompressible, make_config, write_file

if TYPE_CHECKING:
    from pathlib import Path

    from ed2k_client import ClientConfig

pytestmark = pytest.mark.integration

KEYWORD = 'kademlia'
BOOK = 'Kademlia in Practice.pdf'
LEECHER = 'leecher'
SEEDER = 'seeder'
SOURCE_DIR = 'src'
NODES_DAT = 'nodes.dat'
FORGED_NAME = 'forged.pdf'


def kad_config(root: Path, name: str, network: FakeKadNetwork, **overrides: object) -> ClientConfig:
    """Build a client config that bootstraps from the fake network."""
    return make_config(root, name, nodes_dat=network.write_nodes_dat(root / name / NODES_DAT), **overrides)


async def test_bootstrap_learns_the_whole_network(tmp_path: Path) -> None:
    """Three seed contacts lead to every node of the network."""
    async with FakeKadNetwork(size=12) as network, Client(kad_config(tmp_path, LEECHER, network)) as client:
        contacts = await client.connect_kad()

    assert contacts == 12


async def test_keyword_search_reaches_the_responsible_node(tmp_path: Path) -> None:
    """The search walks to the node in the keyword's tolerance zone and filters its answer by extension."""
    async with FakeKadNetwork() as network:
        await network.publish_keyword(KEYWORD, file_hash=Ed2kHash(md4(b'a')), name=BOOK, size=5_000_000)
        await network.publish_keyword(KEYWORD, file_hash=Ed2kHash(md4(b'b')), name='kademlia.mp3', size=3_000_000)
        responsible = network.nodes[-1]
        async with Client(kad_config(tmp_path, LEECHER, network)) as client:
            await client.connect_kad()
            results = await client.search(KEYWORD)

    assert [(result.name, result.size, result.origin) for result in results] == [(BOOK, 5_000_000, SearchOrigin.KAD)]
    assert responsible.received >= 2


async def test_source_search_keeps_only_reachable_sources(tmp_path: Path) -> None:
    """Directly reachable sources (types 1 and 4) are kept, firewalled ones (type 3) are not dialled."""
    file_hash = Ed2kHash(md4(b'book'))
    async with FakeKadNetwork() as network:
        await network.publish_source(file_hash, port=4662, user_hash=md4(b'open'))
        await network.publish_source(file_hash, port=4663, user_hash=md4(b'crypt'), source_type=4)
        await network.publish_source(file_hash, port=4664, user_hash=md4(b'firewalled'), source_type=3)
        async with Client(kad_config(tmp_path, LEECHER, network)) as client:
            await client.connect_kad()
            sources = await client.find_sources(file_hash=file_hash, size=1000)

    assert sorted(source.port for source in sources) == [4662, 4663]
    assert {source.host for source in sources} == {LOOPBACK}


async def test_unsolicited_answers_are_dropped(tmp_path: Path) -> None:
    """A forged search answer from an address the client never asked is ignored."""
    target = KadId.from_digest(md4(KEYWORD.encode()))
    async with FakeKadNetwork() as network, Client(kad_config(tmp_path, LEECHER, network)) as client:
        await client.connect_kad()
        node = client._kad
        assert node is not None
        assert node._transport is not None
        client_port = node._transport.get_extra_info('sockname')[1]
        forged = target.write(target.write(Writer())).u16(1)
        KadId.from_digest(md4(b'forged')).write(forged)
        write_tags(forged, [Tag(0x01, FORGED_NAME), Tag(0x02, 1000)], count_size=1)
        datagram = encode_udp(protocol=Protocol.KAD, opcode=KadOp.SEARCH_RES, payload=forged.getvalue())
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rogue:
            search = asyncio.create_task(client.search(KEYWORD))
            for _ in range(20):
                rogue.sendto(datagram, (LOOPBACK, client_port))
                await asyncio.sleep(0.05)
            results = await search

    assert all(result.name != FORGED_NAME for result in results)


async def test_download_found_only_through_kad(tmp_path: Path) -> None:
    """A book indexed in Kad is found, its source comes from Kad, and the download completes without a server."""
    payload = write_file(tmp_path / SOURCE_DIR / BOOK, incompressible(3_000_000))
    hashes = hash_file(payload)
    async with AsyncExitStack() as stack:
        network = await stack.enter_async_context(FakeKadNetwork())
        seeder = await stack.enter_async_context(Client(make_config(tmp_path, SEEDER)))
        await seeder.share(payload)
        spy = ServeSpy()
        spy.install(seeder.library)
        assert seeder.listening_port is not None
        await network.publish_keyword(KEYWORD, file_hash=hashes.file_hash, name=BOOK, size=hashes.size)
        await network.publish_source(hashes.file_hash, port=seeder.listening_port, user_hash=seeder.identity.user_hash)
        leecher = await stack.enter_async_context(Client(kad_config(tmp_path, LEECHER, network)))
        await leecher.connect_kad()

        found = await leecher.search(KEYWORD)
        finished = await leecher.download(found[0])

    assert finished.path.read_bytes() == payload.read_bytes()
    assert spy.served >= hashes.size


async def test_both_networks_merge_into_one_result_and_download(tmp_path: Path) -> None:
    """A book known to the server and to Kad appears once, and its sources from both networks are merged."""
    payload = write_file(tmp_path / SOURCE_DIR / BOOK, compressible(2_500_000))
    hashes = hash_file(payload)
    async with AsyncExitStack() as stack:
        server = await stack.enter_async_context(FakeServer())
        network = await stack.enter_async_context(FakeKadNetwork())
        seeder = await stack.enter_async_context(
            Client(make_config(tmp_path, SEEDER, servers=(server.entry,), tcp_port=free_port()))
        )
        await seeder.connect()
        await seeder.share(payload)
        assert seeder.listening_port is not None
        await network.publish_keyword(KEYWORD, file_hash=hashes.file_hash, name=BOOK, size=hashes.size)
        await network.publish_source(hashes.file_hash, port=seeder.listening_port, user_hash=seeder.identity.user_hash)
        leecher = await stack.enter_async_context(
            Client(kad_config(tmp_path, LEECHER, network, servers=(server.entry,)))
        )
        await leecher.connect()
        await leecher.connect_kad()
        async with asyncio.timeout(10):
            await server.wait_for_files(1)

        results = await leecher.search(KEYWORD)
        sources = await leecher.find_sources(file_hash=hashes.file_hash, size=hashes.size)
        finished = await leecher.download(results[0])

    assert [result.file_hash for result in results] == [hashes.file_hash]
    assert len(sources) == 1
    assert sources[0].origin in {SourceOrigin.SERVER, SourceOrigin.KAD}
    assert finished.path.read_bytes() == payload.read_bytes()
