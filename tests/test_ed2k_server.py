"""The eD2k server path end to end against an in-process server that speaks the real protocol.

Seeders log in and publish their files with ``OP_OFFERFILES``, leechers search with the binary query tree, ask for
sources and download, and a Low ID seeder serves a peer that reached it through a server callback.
"""

import asyncio
from contextlib import AsyncExitStack
from typing import TYPE_CHECKING

import pytest

from ed2k_client import Client, ConnectionFailedError, FileLink, SearchQuery, ServerEntry, hash_file
from ed2k_client.constants import PART_SIZE, PeerOp, Protocol
from ed2k_client.identity import Identity
from ed2k_client.partfile import blocks_of_part
from ed2k_client.peer import LocalPeer, PeerConnection, build_hello, parse_hello
from ed2k_client.server import LoginDetails, ServerSession
from ed2k_client.servermet import ServerMemory
from ed2k_client.transport import PacketStream
from tests.fakes import WELCOME, FakeServer
from tests.helpers import (
    DJVU_HEADER,
    LOOPBACK,
    ServeSpy,
    compressible,
    free_port,
    incompressible,
    make_config,
    write_file,
)

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.integration

SEEDER = 'seeder'
LEECHER = 'leecher'
REMOTE = 'remote'
LIBRARY = 'library'
KEYWORD = 'kademlia'
BOOK = 'Kademlia Explained.pdf'
ATLAS = 'Kademlia Atlas.djvu'
LEAFLET = 'Small Kademlia Leaflet.pdf'
SHELF_SIZE = 4
WAIT_LIMIT = 10.0
FIRST_BOOK = 'Kademlia First Steps.pdf'
SECOND_BOOK = 'Kademlia Second Thoughts.pdf'
SMALL_BOOK = 5_000


def library(root: Path) -> Path:
    """Write the seeder's shelf: two matching books, a text file and an unrelated small book.

    :param root: the directory under which every client keeps its files.
    :type root: Path
    :returns: the shelf directory.
    :rtype: Path
    """
    write_file(root / LIBRARY / BOOK, incompressible(PART_SIZE + 4321))
    write_file(root / LIBRARY / ATLAS, compressible(600_000, header=DJVU_HEADER))
    write_file(root / LIBRARY / 'kademlia notes.txt', b'plain text')
    write_file(root / LIBRARY / LEAFLET, compressible(2_000))
    return root / LIBRARY


async def publishing_seeder(stack: AsyncExitStack, root: Path, server: FakeServer, shelf: Path) -> Client:
    """Start a seeder that logs in to the server and publishes the shelf there.

    :param stack: the exit stack that closes the client.
    :type stack: AsyncExitStack
    :param root: the directory under which every client keeps its files.
    :type root: Path
    :param server: the fake server.
    :type server: FakeServer
    :param shelf: the directory to share.
    :type shelf: Path
    :returns: the seeder.
    :rtype: Client
    """
    seeder = await stack.enter_async_context(
        Client(make_config(root, SEEDER, servers=(server.entry,), tcp_port=free_port()))
    )
    await seeder.connect()
    await seeder.share(shelf)
    async with asyncio.timeout(WAIT_LIMIT):
        await server.wait_for_files(SHELF_SIZE)
    return seeder


async def connected_leecher(stack: AsyncExitStack, root: Path, server: FakeServer) -> Client:
    """Start a leecher logged in to the server.

    :param stack: the exit stack that closes the client.
    :type stack: AsyncExitStack
    :param root: the directory under which every client keeps its files.
    :type root: Path
    :param server: the fake server.
    :type server: FakeServer
    :returns: the leecher.
    :rtype: Client
    """
    leecher = await stack.enter_async_context(Client(make_config(root, LEECHER, servers=(server.entry,))))
    await leecher.connect()
    return leecher


class TestConnect:
    """Tests of :meth:`Client.connect` and of the session it keeps."""

    @pytest.mark.parametrize('low_id', [False, True], ids=['high-id', 'low-id'])
    async def test_login_reports_id(self, tmp_path: Path, low_id: bool) -> None:
        """A client logs in and tells a High ID from a Low ID.

        :param tmp_path: the directory the clients keep their files in.
        :type tmp_path: Path
        :param low_id: whether the server gives the client a Low ID.
        :type low_id: bool
        """
        async with FakeServer(low_id=low_id) as server, Client(make_config(tmp_path, SEEDER)) as client:
            (session,) = (await client.connect(server.entry)).servers

            assert session.low_id is low_id
            assert session.server == server.entry
            assert session.client_id == next(iter(server.sessions))

    async def test_port_zero_announces_the_bound_port(self, tmp_path: Path) -> None:
        """A client configured with port 0 tells the server the port its listener got, never 0.

        The server dials the announced port to tell a High ID from a Low ID and lists it as the port of every file the
        client offers, so port 0 makes the client unreachable whatever the network allows.

        :param tmp_path: the directory the clients keep their files in.
        :type tmp_path: Path
        """
        async with FakeServer() as server, Client(make_config(tmp_path, SEEDER)) as client:
            await client.connect(server.entry)
            listening = client.listening_port
            announced = next(iter(server.sessions.values())).port

        assert listening is not None
        assert announced == listening

    async def test_welcome_message_is_recorded(self, tmp_path: Path) -> None:
        """Server messages are kept for the caller to show.

        :param tmp_path: the directory the clients keep their files in.
        :type tmp_path: Path
        """
        async with FakeServer() as server, Client(make_config(tmp_path, LEECHER)) as client:
            await client.connect(server.entry)
            (session,) = client._servers
            assert WELCOME in session.state.messages

    async def test_login_fails_at_once_when_the_server_hangs_up(self) -> None:
        """A server that closes the connection after the login request fails the login at once, not after the timeout."""

        async def hang_up(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            """Read the start of the login request, then close the connection.

            :param reader: the connection reader.
            :type reader: asyncio.StreamReader
            :param writer: the connection writer.
            :type writer: asyncio.StreamWriter
            """
            await reader.read(1)
            writer.close()

        listener = await asyncio.start_server(hang_up, LOOPBACK, 0)
        entry = ServerEntry(host=LOOPBACK, port=listener.sockets[0].getsockname()[1])
        details = LoginDetails(identity=Identity.generate(), tcp_port=4662, nickname=REMOTE)
        loop = asyncio.get_running_loop()
        started = loop.time()
        try:
            with pytest.raises(ConnectionFailedError, match='closed the connection'):
                await ServerSession.login(entry=entry, details=details)
        finally:
            listener.close()
            await listener.wait_closed()

        assert loop.time() - started < WAIT_LIMIT

    async def test_server_going_away_leaves_the_client_usable(self, tmp_path: Path) -> None:
        """When the server drops the session, a search returns nothing instead of raising.

        :param tmp_path: the directory the clients keep their files in.
        :type tmp_path: Path
        """
        async with Client(make_config(tmp_path, LEECHER)) as client:
            async with FakeServer() as server:
                await client.connect(server.entry)
            await asyncio.sleep(0.2)

            assert await client.search(KEYWORD) == []

    async def test_sessions_open_on_several_servers_up_to_the_setting(self, tmp_path: Path) -> None:
        """Logins run in parallel until the configured number of sessions is open, past a server that refuses.

        Only the servers that accepted are remembered, the one that answered last first.

        :param tmp_path: the directory the clients keep their files in.
        :type tmp_path: Path
        """
        async with AsyncExitStack() as stack:
            first, second, third = [await stack.enter_async_context(FakeServer()) for _ in range(3)]
            refusing = ServerEntry(host=LOOPBACK, port=free_port())
            servers = (refusing, first.entry, second.entry, third.entry)
            config = make_config(tmp_path, LEECHER, servers=servers, server_sessions=2)
            client = await stack.enter_async_context(Client(config))
            status = await client.connect()

        assert [session.server for session in status.servers] == [first.entry, second.entry]
        assert ServerMemory.load(config.state_dir).addresses == [second.entry.address, first.entry.address]

    async def test_remembered_server_is_tried_first(self, tmp_path: Path) -> None:
        """A server that accepted a login before is tried ahead of the configured order.

        :param tmp_path: the directory the clients keep their files in.
        :type tmp_path: Path
        """
        async with AsyncExitStack() as stack:
            first, second = [await stack.enter_async_context(FakeServer()) for _ in range(2)]
            config = make_config(tmp_path, LEECHER, servers=(first.entry, second.entry), server_sessions=1)
            config.state_dir.mkdir(parents=True)
            ServerMemory.load(config.state_dir).remember(second.entry)
            client = await stack.enter_async_context(Client(config))
            status = await client.connect()

        assert [session.server for session in status.servers] == [second.entry]


class TestSearch:
    """Tests of :meth:`Client.search` through a server."""

    async def test_search_filters_by_extension_and_size(self, tmp_path: Path) -> None:
        """A book search finds the PDFs and the DjVu, skips the text file, and a size floor drops the leaflet.

        :param tmp_path: the directory the clients keep their files in.
        :type tmp_path: Path
        """
        shelf = library(tmp_path)
        async with AsyncExitStack() as stack:
            server = await stack.enter_async_context(FakeServer())
            await publishing_seeder(stack, tmp_path, server, shelf)
            leecher = await connected_leecher(stack, tmp_path, server)

            books = await leecher.search(KEYWORD)
            large = await leecher.search(SearchQuery(text=KEYWORD, extensions=('pdf', 'djvu'), min_size=10_000))

        assert sorted(result.name for result in books) == sorted([BOOK, ATLAS, LEAFLET])
        assert sorted(result.name for result in large) == sorted([BOOK, ATLAS])
        assert all(result.sources == 1 for result in books)
        assert server.searches == 2

    async def test_every_server_is_searched_and_asked_for_sources(self, tmp_path: Path) -> None:
        """A book known to one server and a book known to another are both found, each with its own source.

        :param tmp_path: the directory the clients keep their files in.
        :type tmp_path: Path
        """
        # Sizes differ, because equal content would give both books one hash and so one merged result
        books = [
            write_file(tmp_path / name / name, compressible(SMALL_BOOK + index))
            for index, name in enumerate((FIRST_BOOK, SECOND_BOOK))
        ]
        async with AsyncExitStack() as stack:
            servers = [await stack.enter_async_context(FakeServer()) for _ in books]
            for server, book in zip(servers, books, strict=True):
                config = make_config(tmp_path, book.stem, servers=(server.entry,), tcp_port=free_port())
                seeder = await stack.enter_async_context(Client(config))
                await seeder.connect()
                await seeder.share(book)
                async with asyncio.timeout(WAIT_LIMIT):
                    await server.wait_for_files(1)
            entries = tuple(server.entry for server in servers)
            leecher = await stack.enter_async_context(Client(make_config(tmp_path, LEECHER, servers=entries)))
            await leecher.connect()
            results = await leecher.search(KEYWORD)
            sources = [await leecher.find_sources(file_hash=result.file_hash, size=result.size) for result in results]

        assert sorted(result.name for result in results) == [FIRST_BOOK, SECOND_BOOK]
        assert [len(found) for found in sources] == [1, 1]


class TestDownload:
    """Tests of :meth:`Client.download` with sources from a server."""

    async def test_search_sources_and_download_through_the_server(self, tmp_path: Path) -> None:
        """A leecher finds a book, gets its source from the server with the user hash, and downloads it obfuscated.

        :param tmp_path: the directory the clients keep their files in.
        :type tmp_path: Path
        """
        shelf = library(tmp_path)
        async with AsyncExitStack() as stack:
            server = await stack.enter_async_context(FakeServer())
            seeder = await publishing_seeder(stack, tmp_path, server, shelf)
            spy = ServeSpy()
            spy.install(seeder.library)
            leecher = await connected_leecher(stack, tmp_path, server)

            found = next(result for result in await leecher.search(KEYWORD) if result.name == BOOK)
            sources = await leecher.find_sources(file_hash=found.file_hash, size=found.size)
            finished = await leecher.download(found)

        assert [source.user_hash for source in sources] == [seeder.identity.user_hash]
        assert sources[0].wants_obfuscation
        assert finished.path.read_bytes() == (shelf / BOOK).read_bytes()
        assert spy.served >= found.size

    async def test_link_download_needs_no_search(self, tmp_path: Path) -> None:
        """A known ed2k link is enough: the client asks the server for sources and downloads.

        :param tmp_path: the directory the clients keep their files in.
        :type tmp_path: Path
        """
        shelf = library(tmp_path)
        hashes = hash_file(shelf / ATLAS)
        link = FileLink(name=ATLAS, size=hashes.size, file_hash=hashes.file_hash)
        async with AsyncExitStack() as stack:
            server = await stack.enter_async_context(FakeServer())
            await publishing_seeder(stack, tmp_path, server, shelf)
            leecher = await connected_leecher(stack, tmp_path, server)

            finished = await leecher.download(str(link))

        assert finished.path.read_bytes() == (shelf / ATLAS).read_bytes()


class TestShare:
    """Tests of :meth:`Client.share` through a server callback."""

    async def test_low_id_seeder_serves_through_a_callback(self, tmp_path: Path) -> None:
        """A server callback makes a Low ID seeder dial the requesting peer and serve it a block.

        :param tmp_path: the directory the clients keep their files in.
        :type tmp_path: Path
        """
        shelf = library(tmp_path)
        hashes = hash_file(shelf / BOOK)
        first_block = blocks_of_part(size=hashes.size, part=0)[0]
        received: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()
        remote = LocalPeer(identity=Identity.generate(), client_id=0, tcp_port=0, nickname=REMOTE)

        async def act_as_remote_peer(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            """Answer the seeder that called back as a downloading peer and fetch one block.

            :param reader: the connection reader.
            :type reader: asyncio.StreamReader
            :param writer: the connection writer.
            :type writer: asyncio.StreamWriter
            """
            async with await PacketStream.accept(
                reader=reader, writer=writer, own_hash=remote.identity.user_hash
            ) as stream:
                parse_hello((await stream.read_packet()).reader(), answer=False)
                answer = build_hello(remote, answer=True)
                await stream.send(protocol=Protocol.EDONKEY, opcode=PeerOp.HELLOANSWER, payload=answer)
                connection = PeerConnection(stream=stream, local=remote)
                await connection.request_file(file_hash=hashes.file_hash, size=hashes.size)
                await connection.request_upload(hashes.file_hash, queue_wait=5)
                pieces = connection.download_blocks(file_hash=hashes.file_hash, blocks=[first_block], large=False)
                received.set_result(b''.join([piece async for _, _, piece in pieces]))

        async with AsyncExitStack() as stack:
            server = await stack.enter_async_context(FakeServer(low_id=True))
            seeder = await stack.enter_async_context(Client(make_config(tmp_path, SEEDER, servers=(server.entry,))))
            (seeder_session,) = (await seeder.connect()).servers
            await seeder.share(shelf)
            listener = await asyncio.start_server(act_as_remote_peer, LOOPBACK, 0)
            stack.push_async_callback(listener.wait_closed)
            stack.callback(listener.close)
            requester = await stack.enter_async_context(
                await ServerSession.login(
                    entry=server.entry,
                    details=LoginDetails(
                        identity=remote.identity, tcp_port=listener.sockets[0].getsockname()[1], nickname=REMOTE
                    ),
                )
            )
            await requester.request_callback(seeder_session.client_id)
            data = await asyncio.wait_for(received, WAIT_LIMIT)

        assert seeder_session.low_id
        assert data == (shelf / BOOK).read_bytes()[first_block.start : first_block.end]

    async def test_shared_files_are_published_on_every_server(self, tmp_path: Path) -> None:
        """A seeder logged in to two servers offers its files to both, so leechers of either server find it.

        :param tmp_path: the directory the clients keep their files in.
        :type tmp_path: Path
        """
        shelf = write_file(tmp_path / LIBRARY / FIRST_BOOK, compressible(SMALL_BOOK)).parent
        async with AsyncExitStack() as stack:
            servers = [await stack.enter_async_context(FakeServer()) for _ in range(2)]
            entries = tuple(server.entry for server in servers)
            seeder = await stack.enter_async_context(
                Client(make_config(tmp_path, SEEDER, servers=entries, tcp_port=free_port()))
            )
            await seeder.connect()
            await seeder.share(shelf)
            async with asyncio.timeout(WAIT_LIMIT):
                await asyncio.gather(*(server.wait_for_files(1) for server in servers))

        assert [len(server.files) for server in servers] == [1, 1]
