"""The public entry point: one :class:`Client` that connects, searches, downloads and optionally shares.

Typical use::

    async with Client(ClientConfig()) as client:
        await client.connect()
        results = await client.search('kademlia')
        finished = await client.download(results[0])

The client owns every socket it opens and closes them on leaving the ``async with`` block. Sharing is off until
:meth:`Client.share` is called, and the listener for incoming connections runs only while something is shared.
"""

import asyncio
import contextlib
import fcntl
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Self

from ed2k_client.constants import DEFAULT_TCP_PORT, DEFAULT_UDP_PORT
from ed2k_client.download import Downloader, DownloadSettings
from ed2k_client.errors import ConnectionFailedError, NotConnectedError, SecurityError, StateInUseError
from ed2k_client.identity import Identity
from ed2k_client.kad.contacts import NODES_DAT_URL, download_nodes_dat, parse_nodes_dat
from ed2k_client.kad.node import KadNode
from ed2k_client.links import FileLink
from ed2k_client.partfile import PartFile
from ed2k_client.peer import LocalPeer, PeerConnection
from ed2k_client.search import FileType, SearchQuery, SearchResult, SearchResults
from ed2k_client.security import AddressPolicy, IpFilter, sanitize_filename
from ed2k_client.server import OfferedFile, ServerSession
from ed2k_client.servermet import DEFAULT_SERVER_MET_URL, ServerList
from ed2k_client.share import SharedLibrary
from ed2k_client.transport import PacketStream

if TYPE_CHECKING:
    from collections.abc import Sequence
    from types import TracebackType

    from ed2k_client.download import DownloadResult, ProgressCallback
    from ed2k_client.hashing import Ed2kHash
    from ed2k_client.servermet import ServerEntry
    from ed2k_client.share import SharedFile
    from ed2k_client.sources import Source

logger = logging.getLogger(__name__)

DEFAULT_STATE_DIR: Path = Path.home() / '.local' / 'state' / 'ed2k-client'
DEFAULT_DOWNLOAD_DIR: Path = Path.home() / 'Downloads' / 'ed2k'
QUARANTINE_DIR: str = '.incoming'
LOCK_FILE: str = 'client.lock'
DEFAULT_NICKNAME: str = 'ed2k-client'
MAX_INCOMING: int = 16
DOCUMENT_EXTENSIONS: frozenset[str] = frozenset({'pdf', 'djvu', 'djv'})
BOOK_EXTENSIONS: tuple[str, ...] = ('pdf', 'djvu')


@dataclass(frozen=True, slots=True)
class ClientConfig:
    """Settings of a client.

    :ivar state_dir: identity, hash cache and other private state.
    :ivar download_dir: finished files; unfinished ones stay in its ``.incoming`` quarantine.
    :ivar nickname: the user name shown to servers and peers.
    :ivar tcp_port: the port announced to servers and used for incoming connections while sharing.
    :ivar listen_host: the IPv4 address the listener binds while sharing.
    :ivar udp_port: the local Kad port.
    :ivar servers: servers to use; empty means the list at ``server_met_url``.
    :ivar server_met_url: HTTPS URL of a ``server.met``.
    :ivar nodes_dat: a local ``nodes.dat``; ``None`` means the file at ``nodes_dat_url``.
    :ivar nodes_dat_url: HTTPS URL of a ``nodes.dat``.
    :ivar ip_filter: a local ``ipfilter.dat`` with ranges never to contact.
    :ivar upload_slots: peers served at the same time while sharing.
    :ivar allow_private_peers: dial loopback and private addresses, for tests on one machine only.
    :ivar download: limits of each download.
    """

    state_dir: Path = DEFAULT_STATE_DIR
    download_dir: Path = DEFAULT_DOWNLOAD_DIR
    nickname: str = DEFAULT_NICKNAME
    tcp_port: int = DEFAULT_TCP_PORT
    listen_host: str = '0.0.0.0'
    udp_port: int = DEFAULT_UDP_PORT
    servers: tuple[ServerEntry, ...] = ()
    server_met_url: str = DEFAULT_SERVER_MET_URL
    nodes_dat: Path | None = None
    nodes_dat_url: str = NODES_DAT_URL
    ip_filter: Path | None = None
    upload_slots: int = 2
    allow_private_peers: bool = False
    download: DownloadSettings = field(default_factory=DownloadSettings)


@dataclass(frozen=True, slots=True)
class ClientStatus:
    """What the client is connected to.

    :ivar server: the connected server, or ``None``.
    :ivar client_id: the ID it assigned.
    :ivar low_id: whether the ID is a Low ID.
    :ivar kad_contacts: live Kad contacts.
    :ivar shared_files: files offered to others.
    """

    server: ServerEntry | None
    client_id: int
    low_id: bool
    kad_contacts: int
    shared_files: int


class Client:
    """An eD2k and Kad client.

    :ivar config: the settings.
    :ivar identity: the persistent user hash and Kad ID.
    :ivar policy: which network addresses may be contacted.
    :ivar library: the shared files.
    """

    def __init__(self, config: ClientConfig | None = None) -> None:
        """Prepare the client without touching the network.

        :param config: the settings, defaults when ``None``.
        :type config: ClientConfig | None
        """
        self.config = config or ClientConfig()
        self.identity = Identity.load_or_create(self.config.state_dir)
        ip_filter = IpFilter()
        if self.config.ip_filter is not None:
            ip_filter = IpFilter.parse(self.config.ip_filter.read_text(encoding='latin-1').splitlines())
        self.policy = AddressPolicy(ip_filter=ip_filter, allow_private=self.config.allow_private_peers)
        self.library = SharedLibrary(state_dir=self.config.state_dir)
        self._server: ServerSession | None = None
        self._kad: KadNode | None = None
        self._listener: asyncio.Server | None = None
        self._slots = asyncio.Semaphore(self.config.upload_slots)
        self._incoming = asyncio.Semaphore(MAX_INCOMING)
        self._exits = contextlib.AsyncExitStack()

    async def __aenter__(self) -> Self:
        """Enter the context.

        :returns: the client.
        :rtype: Self
        """
        await self._exits.__aenter__()
        # A server keeps one session per user hash and drops the older one, so two processes sharing an identity
        # would keep disconnecting each other; the lock makes the second one fail at once instead.
        lock = self._exits.enter_context((self.config.state_dir / LOCK_FILE).open('w', encoding='utf-8'))
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            await self._exits.aclose()
            err_msg = f'{self.config.state_dir} is used by another client process'
            raise StateInUseError(err_msg) from error
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None
    ) -> None:
        """Close the server session, the Kad socket, the listener and every peer connection.

        :param exc_type: the exception type, if any.
        :type exc_type: type[BaseException] | None
        :param exc: the exception, if any.
        :type exc: BaseException | None
        :param traceback: the traceback, if any.
        :type traceback: TracebackType | None
        """
        await self._exits.__aexit__(exc_type, exc, traceback)

    @property
    def status(self) -> ClientStatus:
        """A snapshot of the connections."""
        state = self._server.state if self._server else None
        return ClientStatus(
            server=self._server.entry if self._server else None,
            client_id=state.client_id if state else 0,
            low_id=self._server.is_low_id if self._server else True,
            kad_contacts=len(self._kad.contacts) if self._kad else 0,
            shared_files=len(self.library.files),
        )

    @property
    def listening_port(self) -> int | None:
        """The TCP port incoming peers connect to while something is shared, ``None`` before sharing."""
        if self._listener is None or not self._listener.sockets:
            return None
        return int(self._listener.sockets[0].getsockname()[1])

    @property
    def _local(self) -> LocalPeer:
        """Describe this client for hellos with the current server and ID.

        :returns: the description.
        :rtype: LocalPeer
        """
        server = (self._server.entry.host, self._server.entry.port) if self._server else None
        client_id = self._server.state.client_id if self._server else 0
        return LocalPeer(
            identity=self.identity,
            client_id=client_id,
            tcp_port=self.config.tcp_port,
            nickname=self.config.nickname,
            server=server,
        )

    async def connect(self, server: ServerEntry | None = None) -> ClientStatus:
        """Log in to a server: the given one, or the first of the configured list that accepts the client.

        :param server: a specific server, or ``None`` to try the list ordered by users.
        :type server: ServerEntry | None
        :returns: the status after login.
        :rtype: ClientStatus
        :raises ConnectionFailedError: when no server accepts the login.
        """
        if server is not None:
            candidates: Sequence[ServerEntry] = [server]
        elif self.config.servers:
            candidates = self.config.servers
        else:
            server_list = await asyncio.to_thread(ServerList.download, self.config.server_met_url)
            candidates = server_list.by_users()
        for entry in candidates:
            if not self.policy.permits(entry.host, entry.port):
                continue
            try:
                session = await ServerSession.login(
                    entry=entry,
                    identity=self.identity,
                    tcp_port=self.config.tcp_port,
                    nickname=self.config.nickname,
                    on_callback=self._on_callback,
                )
            except ConnectionFailedError as error:
                logger.warning('Server %s refused: %s', entry.address, error)
                continue
            self._server = await self._exits.enter_async_context(session)
            logger.info('Logged in to %s with ID %d', entry.address, session.state.client_id)
            return self.status
        err_msg = 'no server accepted the login'
        raise ConnectionFailedError(err_msg)

    async def connect_kad(self) -> int:
        """Join Kad from ``nodes.dat``.

        :returns: the number of live contacts.
        :rtype: int
        """
        if self.config.nodes_dat is not None:
            seeds = parse_nodes_dat(self.config.nodes_dat.read_bytes())
        else:
            seeds = await asyncio.to_thread(download_nodes_dat, self.config.nodes_dat_url)
        node = KadNode(kad_id=self.identity.kad_id, policy=self.policy, udp_port=self.config.udp_port)
        self._kad = await self._exits.enter_async_context(node)
        return await self._kad.bootstrap(seeds)

    async def search(self, query: SearchQuery | str, *, max_results: int = 200) -> list[SearchResult]:
        """Search the connected server and Kad, merge the answers by hash and rank them by sources.

        A plain string searches for books: its words in PDF or DjVu files. A :class:`SearchQuery` sets the
        extensions, the file type and the size limits explicitly.

        :param query: the words, or a full query.
        :type query: SearchQuery | str
        :param max_results: the most results to return.
        :type max_results: int
        :returns: the results, most sources first.
        :rtype: list[SearchResult]
        :raises NotConnectedError: when neither a server nor Kad is connected.
        """
        if self._server is None and self._kad is None:
            err_msg = 'connect to a server or to Kad before searching'
            raise NotConnectedError(err_msg)
        if isinstance(query, str):
            query = SearchQuery(text=query, extensions=BOOK_EXTENSIONS)
        merged = SearchResults()
        searches = []
        if self._server is not None:
            searches.append(self._server.search(query, max_results=max_results))
        if self._kad is not None:
            searches.append(self._kad.search_keyword(query))
        for outcome in await asyncio.gather(*searches, return_exceptions=True):
            if isinstance(outcome, BaseException):
                logger.warning('A search failed: %r', outcome)
                continue
            for result in outcome:
                merged.add(result)
        return merged.ranked()[:max_results]

    async def find_sources(self, *, file_hash: Ed2kHash, size: int) -> list[Source]:
        """Ask the server and Kad which peers share a file.

        :param file_hash: the file.
        :type file_hash: Ed2kHash
        :param size: its size.
        :type size: int
        :returns: the sources from both, duplicates removed.
        :rtype: list[Source]
        """
        lookups = []
        if self._server is not None:
            lookups.append(self._server.get_sources(file_hash=file_hash, size=size))
        if self._kad is not None:
            lookups.append(self._kad.search_sources(file_hash=file_hash, size=size))
        found: dict[tuple[int, int], Source] = {}
        for outcome in await asyncio.gather(*lookups, return_exceptions=True):
            if isinstance(outcome, BaseException):
                logger.warning('A source lookup failed: %r', outcome)
                continue
            for source in outcome:
                found.setdefault((source.client_id, source.port), source)
        return list(found.values())

    async def download(
        self,
        item: SearchResult | FileLink | str,
        *,
        progress: ProgressCallback | None = None,
        settings: DownloadSettings | None = None,
        extra_sources: Sequence[Source] = (),
    ) -> DownloadResult:
        """Download a file found by a search or named by an ``ed2k://`` link.

        :param item: a search result, a parsed link or link text.
        :type item: SearchResult | FileLink | str
        :param progress: called with ``DownloadProgress`` snapshots.
        :type progress: ProgressCallback | None
        :param settings: limits of this download, the configured ones when ``None``.
        :type settings: DownloadSettings | None
        :param extra_sources: sources known beforehand, such as a peer named by the user.
        :type extra_sources: Sequence[Source]
        :returns: the verified file outside quarantine.
        :rtype: DownloadResult
        """
        match item:
            case str():
                link = FileLink.parse(item)
            case SearchResult():
                link = item.link
            case FileLink():
                link = item
        name = sanitize_filename(link.name, fallback=f'{link.file_hash.hex}.bin')
        part_file = PartFile.open(
            directory=self.config.download_dir / QUARANTINE_DIR, name=name, size=link.size, file_hash=link.file_hash
        )
        downloader = Downloader(
            part_file=part_file,
            local=self._local,
            policy=self.policy,
            settings=settings or self.config.download,
            on_progress=progress,
        )
        downloader.add_sources(extra_sources)

        async def feed() -> list[Source]:
            """Ask the server and Kad for the current sources of the file.

            :returns: the sources.
            :rtype: list[Source]
            """
            return await self.find_sources(file_hash=link.file_hash, size=link.size)

        return await downloader.run(feed=feed, download_dir=self.config.download_dir)

    async def share(self, path: Path) -> list[SharedFile]:
        """Offer a file or the files of a directory, start the listener and publish them on the server.

        :param path: a file or a directory.
        :type path: Path
        :returns: the files now shared.
        :rtype: list[SharedFile]
        """
        added = await asyncio.to_thread(self.library.add, path)
        if self._listener is None:
            # eD2k addresses are IPv4 only; binding all families would give each its own port when the port is 0.
            self._listener = await asyncio.start_server(
                self._on_incoming, host=self.config.listen_host, port=self.config.tcp_port
            )
            self._exits.push_async_callback(self._close_listener)
        if self._server is not None:
            await self._server.offer_files(
                [
                    OfferedFile(file_hash=f.file_hash, name=f.name, size=f.size, file_type=_file_type(f.name))
                    for f in added
                ]
            )
        return added

    async def _close_listener(self) -> None:
        """Stop accepting peers and cut off the ones being served."""
        if self._listener is not None:
            self._listener.close()
            # close() stops accepting only; peers already being served are cut off too.
            self._listener.close_clients()
            await self._listener.wait_closed()

    async def _on_incoming(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Serve one incoming peer after the address policy and the connection limit allow it.

        :param reader: the connection reader.
        :type reader: asyncio.StreamReader
        :param writer: the connection writer.
        :type writer: asyncio.StreamWriter
        """
        host, port = writer.get_extra_info('peername')[:2]
        if self._incoming.locked() or not self.policy.permits(host, port):
            writer.close()
            return
        async with self._incoming:
            try:
                stream = await PacketStream.accept(reader=reader, writer=writer, own_hash=self.identity.user_hash)
            except (TimeoutError, OSError, asyncio.IncompleteReadError, SecurityError) as error:
                logger.info('Incoming %s:%d dropped: %r', host, port, error)
                writer.close()
                return
            async with stream:
                await PeerConnection(stream=stream, local=self._local).serve(library=self.library, slots=self._slots)

    async def _on_callback(self, host: str, port: int) -> None:
        """Dial a peer that asked the server for a callback and serve it, when something is shared.

        :param host: the peer address.
        :type host: str
        :param port: the peer port.
        :type port: int
        """
        if not self.library.files or not self.policy.permits(host, port):
            return
        try:
            async with await PacketStream.connect(host=host, port=port) as stream:
                connection = PeerConnection(stream=stream, local=self._local)
                await connection.hello()
                await connection.serve(library=self.library, slots=self._slots)
        except ConnectionFailedError as error:
            logger.info('Callback to %s:%d failed: %s', host, port, error)


def _file_type(name: str) -> str:
    """Pick the server-side file type of a published name.

    :param name: the file name.
    :type name: str
    :returns: ``Doc`` for documents, empty otherwise.
    :rtype: str
    """
    return FileType.DOCUMENT if name.lower().rpartition('.')[2] in DOCUMENT_EXTENSIONS else ''
