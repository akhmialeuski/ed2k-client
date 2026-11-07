"""The Kad path end to end against in-process Kad nodes, and both networks together.

The client bootstraps from a ``nodes.dat`` that lists fake nodes, walks to the node responsible for a keyword or a
file, searches there, and downloads from a source it learned only from Kad.
"""

import asyncio
import socket
from contextlib import AsyncExitStack
from operator import attrgetter
from typing import TYPE_CHECKING

import pytest

from ed2k_client import Client, Ed2kHash, hash_file
from ed2k_client.constants import KadOp, Protocol
from ed2k_client.hashing import md4
from ed2k_client.kad.contacts import KadId
from ed2k_client.kad.node import BOOTSTRAP_REQUEST
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
OPCODE_OF = attrgetter('opcode')
FORGED_NAME = 'forged.pdf'


def kad_config(root: Path, name: str, network: FakeKadNetwork, **overrides: object) -> ClientConfig:
    """Build a client config that bootstraps from the fake network.

    :param root: the directory under which every client keeps its files.
    :type root: Path
    :param name: the client, which names its directory.
    :type name: str
    :param network: the fake Kad network the nodes.dat lists.
    :type network: FakeKadNetwork
    :param overrides: fields of ClientConfig that replace the defaults.
    :type overrides: object
    :returns: the config.
    :rtype: ClientConfig
    """
    return make_config(root, name, nodes_dat=network.write_nodes_dat(root / name / NODES_DAT), **overrides)


class TestConnectKad:
    """Tests of :meth:`Client.connect_kad`."""

    async def test_bootstrap_learns_the_whole_network(self, tmp_path: Path) -> None:
        """Three seed contacts lead to every node of the network.

        :param tmp_path: the directory the clients keep their files in.
        :type tmp_path: Path
        """
        async with FakeKadNetwork(size=12) as network, Client(kad_config(tmp_path, LEECHER, network)) as client:
            contacts = await client.connect_kad()

        assert contacts == 12

    async def test_malformed_bootstrap_answer_costs_only_its_seed(self, tmp_path: Path) -> None:
        """A seed whose bootstrap answer is cut short is skipped, and the other seeds still lead to the whole network.

        :param tmp_path: the directory of the client's files.
        :type tmp_path: Path
        """
        async with FakeKadNetwork() as network:
            await network.add_malforming_node(KadId.from_digest(md4(KEYWORD.encode())))
            nodes_dat = network.write_nodes_dat(tmp_path / NODES_DAT, count=len(network.nodes))
            async with Client(make_config(tmp_path, LEECHER, nodes_dat=nodes_dat)) as client:
                contacts = await client.connect_kad()

        assert contacts == len(network.nodes)


class TestSearch:
    """Tests of :meth:`Client.search` through Kad."""

    async def test_keyword_search_reaches_the_responsible_node(self, tmp_path: Path) -> None:
        """The search walks to the node in the keyword's tolerance zone and filters its answer by extension.

        :param tmp_path: the directory the clients keep their files in.
        :type tmp_path: Path
        """
        async with FakeKadNetwork() as network:
            await network.publish_keyword(KEYWORD, file_hash=Ed2kHash(md4(b'a')), name=BOOK, size=5_000_000)
            await network.publish_keyword(KEYWORD, file_hash=Ed2kHash(md4(b'b')), name='kademlia.mp3', size=3_000_000)
            responsible = network.nodes[-1]
            async with Client(kad_config(tmp_path, LEECHER, network)) as client:
                await client.connect_kad()
                results = await client.search(KEYWORD)

        assert [(result.name, result.size, result.origin) for result in results] == [
            (BOOK, 5_000_000, SearchOrigin.KAD)
        ]
        assert responsible.received >= 2

    async def test_unsolicited_answers_are_dropped(self, tmp_path: Path) -> None:
        """A forged search answer from an address the client never asked is ignored.

        :param tmp_path: the directory the clients keep their files in.
        :type tmp_path: Path
        """
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

    async def test_malformed_answers_do_not_hide_the_honest_ones(self, tmp_path: Path) -> None:
        """A node in the keyword's zone that answers lookups and searches malformed loses only its own answers.

        :param tmp_path: the directory of the client's files.
        :type tmp_path: Path
        """
        async with FakeKadNetwork() as network:
            await network.publish_keyword(KEYWORD, file_hash=Ed2kHash(md4(b'a')), name=BOOK, size=5_000_000)
            await network.add_malforming_node(KadId.from_digest(md4(KEYWORD.encode())))
            async with Client(kad_config(tmp_path, LEECHER, network)) as client:
                await client.connect_kad()
                results = await client.search(KEYWORD)

        assert [result.name for result in results] == [BOOK]

    async def test_both_networks_merge_into_one_result_and_download(self, tmp_path: Path) -> None:
        """A book known to the server and to Kad appears once, and its sources from both networks are merged.

        :param tmp_path: the directory the clients keep their files in.
        :type tmp_path: Path
        """
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
            await network.publish_source(
                hashes.file_hash, port=seeder.listening_port, user_hash=seeder.identity.user_hash
            )
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


class TestFindSources:
    """Tests of :meth:`Client.find_sources` through Kad."""

    async def test_source_search_keeps_only_reachable_sources(self, tmp_path: Path) -> None:
        """Directly reachable sources (types 1 and 4) are kept, firewalled ones (type 3) are not dialled.

        :param tmp_path: the directory the clients keep their files in.
        :type tmp_path: Path
        """
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

    async def test_source_with_an_address_beyond_32_bits_is_skipped(self, tmp_path: Path) -> None:
        """A source entry whose address tag does not fit IPv4 is skipped, and the other entries of the answer are kept.

        :param tmp_path: the directory of the client's files.
        :type tmp_path: Path
        """
        file_hash = Ed2kHash(md4(b'book'))
        async with FakeKadNetwork() as network:
            await network.publish_source(file_hash, port=4662, user_hash=md4(b'open'))
            await network.publish_source(file_hash, port=4663, user_hash=md4(b'wide'), source_ip=1 << 40)
            async with Client(kad_config(tmp_path, LEECHER, network)) as client:
                await client.connect_kad()
                sources = await client.find_sources(file_hash=file_hash, size=1000)

        assert [source.port for source in sources] == [4662]


class TestAsk:
    """Tests of how a Kad node routes the answers of the requests it has in flight."""

    async def test_concurrent_requests_to_one_node_each_get_their_answer(self, tmp_path: Path) -> None:
        """Two requests in flight to the same node for the same kind of answer each receive one.

        Concurrent downloads refresh their sources through Kad at the same time and reach the same close nodes.

        :param tmp_path: the directory of the client's files.
        :type tmp_path: Path
        """
        async with FakeKadNetwork() as network, Client(kad_config(tmp_path, LEECHER, network)) as client:
            await client.connect_kad()
            node = client._kad
            assert node is not None
            contact = next(iter(node.contacts.values()))
            replies = await asyncio.gather(*(node._ask(contact, BOOTSTRAP_REQUEST, parse=OPCODE_OF) for _ in range(2)))

        assert all(replies)


class TestDownload:
    """Tests of :meth:`Client.download` with sources from Kad only."""

    async def test_download_found_only_through_kad(self, tmp_path: Path) -> None:
        """A book indexed in Kad is found, its source comes from Kad, and the download completes without a server.

        :param tmp_path: the directory the clients keep their files in.
        :type tmp_path: Path
        """
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
            await network.publish_source(
                hashes.file_hash, port=seeder.listening_port, user_hash=seeder.identity.user_hash
            )
            leecher = await stack.enter_async_context(Client(kad_config(tmp_path, LEECHER, network)))
            await leecher.connect_kad()

            found = await leecher.search(KEYWORD)
            finished = await leecher.download(found[0])

        assert finished.path.read_bytes() == payload.read_bytes()
        assert spy.served >= hashes.size
