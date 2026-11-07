"""The public entry point: one :class:`Client` that connects, searches, downloads and optionally shares.

Typical use::

    async with Client(ClientConfig()) as client:
        await client.connect()
        results = await client.search('kademlia')
        finished = await client.download(results[0])

The client owns every socket it opens and closes them on leaving the ``async with`` block. Sharing is off until
:meth:`Client.share` is called. The listener for incoming connections starts with the first share, or with the login
when the configured TCP port is 0, so that the servers learn the port the listener got.
"""

import asyncio
import contextlib
import fcntl
import logging
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Self

from ed2k_client.constants import DEFAULT_TCP_PORT, DEFAULT_UDP_PORT, Protocol
from ed2k_client.download import Downloader, DownloadSettings
from ed2k_client.errors import (
    ConnectionFailedError,
    NotConnectedError,
    ProtocolError,
    SecurityError,
    StateInUseError,
)
from ed2k_client.identity import Identity
from ed2k_client.kad.contacts import NODES_DAT_URL, download_nodes_dat, parse_nodes_dat
from ed2k_client.kad.node import KadNode
from ed2k_client.links import FileLink, ServerLink
from ed2k_client.partfile import PartFile
from ed2k_client.peer import LocalPeer, PeerConnection
from ed2k_client.search import FileType, SearchQuery, SearchResult, SearchResults
from ed2k_client.security import AddressPolicy, IpFilter, sanitize_filename
from ed2k_client.server import LoginDetails, OfferedFile, ServerSession
from ed2k_client.servermet import DEFAULT_SERVER_MET_URL, ServerEntry, ServerList, ServerMemory
from ed2k_client.settings import (
    IoSettings,
    KadSettings,
    Limits,
    PeerSettings,
    ShareSettings,
    Timeouts,
    settings_from_mapping,
)
from ed2k_client.share import SharedLibrary
from ed2k_client.transport import PacketStream, StreamOptions

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from types import TracebackType

    from ed2k_client.download import DownloadResult, ProgressCallback
    from ed2k_client.hashing import Ed2kHash
    from ed2k_client.share import SharedFile
    from ed2k_client.sources import Source

logger = logging.getLogger(__name__)

DEFAULT_STATE_DIR: Path = Path.home() / '.local' / 'state' / 'ed2k-client'
DEFAULT_DOWNLOAD_DIR: Path = Path.home() / 'Downloads' / 'ed2k'
QUARANTINE_DIR: str = '.incoming'
LOCK_FILE: str = 'client.lock'
ANY_PORT: int = 0
SERVER_MET_CACHE: str = 'server.met'
DEFAULT_NICKNAME: str = 'ed2k-client'
SERVERS_KEY: str = 'servers'
DOCUMENT_EXTENSIONS: frozenset[str] = frozenset({'pdf', 'djvu', 'djv'})
BOOK_EXTENSIONS: tuple[str, ...] = ('pdf', 'djvu')


@dataclass(frozen=True, slots=True)
class ClientConfig:
    """Settings of a client.

    :ivar state_dir: identity, hash cache and other private state.
    :ivar download_dir: finished files; unfinished ones stay in its ``.incoming`` quarantine.
    :ivar nickname: the user name shown to servers and peers.
    :ivar tcp_port: the port announced to servers and used for incoming connections while sharing, 0 for any free
        port, which the listener then takes before the login so that the port it got is the one announced.
    :ivar listen_host: the IPv4 address the listener binds while sharing.
    :ivar udp_port: the local Kad port.
    :ivar servers: servers to use; empty means the list of ``server_met`` or at ``server_met_url``.
    :ivar server_met_url: HTTPS URL of a ``server.met``.
    :ivar server_met: a local ``server.met``; ``None`` means the file at ``server_met_url``.
    :ivar server_sessions: servers the client stays logged in to at the same time, each searched and asked for sources.
    :ivar nodes_dat: a local ``nodes.dat``; ``None`` means the file at ``nodes_dat_url``.
    :ivar nodes_dat_url: HTTPS URL of a ``nodes.dat``.
    :ivar ip_filter: a local ``ipfilter.dat`` with ranges never to contact.
    :ivar allow_private_peers: dial loopback and private addresses, for tests on one machine only.
    :ivar download: limits of each download.
    :ivar timeouts: how long the client waits on servers, peers and Kad.
    :ivar limits: caps on everything that arrives from the network.
    :ivar kad: how Kad lookups and searches spread.
    :ivar peer: how the client talks to one peer.
    :ivar share: limits of sharing.
    :ivar io: buffer sizes of local file work.
    """

    state_dir: Path = DEFAULT_STATE_DIR
    download_dir: Path = DEFAULT_DOWNLOAD_DIR
    nickname: str = DEFAULT_NICKNAME
    tcp_port: int = DEFAULT_TCP_PORT
    listen_host: str = '0.0.0.0'
    udp_port: int = DEFAULT_UDP_PORT
    servers: tuple[ServerEntry, ...] = ()
    server_met_url: str = DEFAULT_SERVER_MET_URL
    server_met: Path | None = None
    server_sessions: int = 4
    nodes_dat: Path | None = None
    nodes_dat_url: str = NODES_DAT_URL
    ip_filter: Path | None = None
    allow_private_peers: bool = False
    download: DownloadSettings = field(default_factory=DownloadSettings)
    timeouts: Timeouts = field(default_factory=Timeouts)
    limits: Limits = field(default_factory=Limits)
    kad: KadSettings = field(default_factory=KadSettings)
    peer: PeerSettings = field(default_factory=PeerSettings)
    share: ShareSettings = field(default_factory=ShareSettings)
    io: IoSettings = field(default_factory=IoSettings)

    def __post_init__(self) -> None:
        """Check the values that cannot be zero.

        :raises ValueError: when no server session is allowed.
        """
        # Ports here may be 0, which picks a free one, so the check of the settings groups does not apply
        if self.server_sessions < 1:
            err_msg = f'ClientConfig.server_sessions must be positive, not {self.server_sessions}'
            raise ValueError(err_msg)

    @classmethod
    def from_toml(cls, path: Path, *, base: Self | None = None) -> Self:
        """Read a configuration file whose keys and tables are named like the fields of this class.

        :param path: the TOML file.
        :type path: Path
        :param base: the configuration the file overrides, the defaults when ``None``.
        :type base: Self | None
        :returns: the configuration.
        :rtype: Self
        """
        with path.open('rb') as stream:
            return cls.from_mapping(tomllib.load(stream), base=base)

    @classmethod
    def from_mapping(cls, table: Mapping[str, object], *, base: Self | None = None) -> Self:
        """Build a configuration from a parsed TOML table.

        Values missing from the table keep those of ``base``. ``servers`` is a list of ``ed2k://|server|...|/``
        links, and every other key is checked against the type of its field.

        :param table: the parsed table.
        :type table: Mapping[str, object]
        :param base: the configuration the table overrides, the defaults when ``None``.
        :type base: Self | None
        :returns: the configuration.
        :rtype: Self
        :raises TypeError: when a value has the wrong type.
        :raises ValueError: on an unknown key or a value the settings refuse.
        :raises ProtocolError: on a malformed server link.
        """
        data = dict(table)

        # The server links are the one value whose type needs parsing, so they are taken out before the generic check
        links = data.pop(SERVERS_KEY, None)
        config = settings_from_mapping(cls, data, base=base if base is not None else cls())
        if links is None:
            return config
        if not isinstance(links, list) or not all(isinstance(link, str) for link in links):
            err_msg = f'{SERVERS_KEY} must be a list of ed2k server links'
            raise TypeError(err_msg)

        servers = tuple(ServerEntry(host=link.host, port=link.port) for link in map(ServerLink.parse, links))
        return replace(config, servers=servers)


@dataclass(frozen=True, slots=True)
class ServerStatus:
    """One live server session.

    :ivar server: the server.
    :ivar client_id: the ID it assigned.
    :ivar low_id: whether the ID is a Low ID.
    """

    server: ServerEntry
    client_id: int
    low_id: bool


@dataclass(frozen=True, slots=True)
class ClientStatus:
    """What the client is connected to.

    :ivar servers: the live server sessions, the first of which this client names to peers.
    :ivar kad_contacts: live Kad contacts.
    :ivar shared_files: files offered to others.
    """

    servers: tuple[ServerStatus, ...]
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

        # ipfilter.dat files are Latin-1 text, and only their addresses and levels are read
        ip_filter = IpFilter()
        if self.config.ip_filter is not None:
            ip_filter = IpFilter.parse(self.config.ip_filter.read_text(encoding='latin-1').splitlines())
        self.policy = AddressPolicy(ip_filter=ip_filter, allow_private=self.config.allow_private_peers)
        self.library = SharedLibrary(state_dir=self.config.state_dir, read_chunk=self.config.io.read_chunk)

        # One set of stream options per kind of connection, built once from the configuration
        timeouts = self.config.timeouts
        self._peer_stream = StreamOptions(
            idle_timeout=timeouts.read,
            connect_timeout=timeouts.connect,
            write_timeout=timeouts.read,
            limits=self.config.limits,
            obfuscation_padding=self.config.peer.obfuscation_padding,
        )
        self._server_stream = replace(self._peer_stream, packed_as=Protocol.EDONKEY, idle_timeout=None)

        self._servers: list[ServerSession] = []
        self._server_memory = ServerMemory.load(self.config.state_dir)
        self._kad: KadNode | None = None
        self._listener: asyncio.Server | None = None
        self._slots = asyncio.Semaphore(self.config.share.upload_slots)
        self._incoming = asyncio.Semaphore(self.config.share.max_incoming)
        self._exits = contextlib.AsyncExitStack()

    async def __aenter__(self) -> Self:
        """Enter the context.

        :returns: the client.
        :rtype: Self
        """
        await self._exits.__aenter__()

        # A server keeps one session per user hash and drops the older one, so two processes sharing an identity
        # would keep disconnecting each other, and the lock makes the second one fail at once instead
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
        """Close the server sessions, the Kad socket, the listener and every peer connection.

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
        return ClientStatus(
            servers=tuple(
                ServerStatus(server=session.entry, client_id=session.state.client_id, low_id=session.is_low_id)
                for session in self._live_servers
            ),
            kad_contacts=len(self._kad.contacts) if self._kad else 0,
            shared_files=len(self.library.files),
        )

    @property
    def _live_servers(self) -> list[ServerSession]:
        """The server sessions whose connection is still open, in the order they were preferred."""
        return [session for session in self._servers if session.connected]

    @property
    def listening_port(self) -> int | None:
        """The TCP port incoming peers connect to while something is shared, ``None`` before sharing."""
        if self._listener is None or not self._listener.sockets:
            return None
        return int(self._listener.sockets[0].getsockname()[1])

    @property
    def _announced_port(self) -> int:
        """The TCP port the server and peers are told: the listener's port once it runs, the configured one before."""
        return self.listening_port or self.config.tcp_port

    @property
    def _local(self) -> LocalPeer:
        """Describe this client for hellos with the first live server and the ID it assigned.

        :returns: the description.
        :rtype: LocalPeer
        """
        # A hello names one server, through which a peer may ask for a callback, so it names the most preferred one
        primary = next(iter(self._live_servers), None)
        server = (primary.entry.host, primary.entry.port) if primary else None
        client_id = primary.state.client_id if primary else 0

        return LocalPeer(
            identity=self.identity,
            client_id=client_id,
            tcp_port=self._announced_port,
            nickname=self.config.nickname,
            server=server,
        )

    async def connect(self, server: ServerEntry | None = None) -> ClientStatus:
        """Log in to servers until ``server_sessions`` sessions are open, or to the one given server.

        The candidates are the configured servers, the local ``server.met`` or the downloaded one, with the servers
        that accepted a login before tried first and the rest by users. Logins run in parallel, as many as sessions
        are still missing, and a refused one makes room for the next candidate.

        :param server: a specific server, or ``None`` to try the list.
        :type server: ServerEntry | None
        :returns: the status after login.
        :rtype: ClientStatus
        :raises ConnectionFailedError: when no server accepts the login.
        """
        candidates = [server] if server is not None else await self._server_candidates()
        wanted = 1 if server is not None else self.config.server_sessions - len(self._live_servers)
        open_addresses = {session.entry.address for session in self._live_servers}
        pending = [
            entry
            for entry in self._server_memory.prefer(candidates)
            if entry.address not in open_addresses and self.policy.permits(entry.host, entry.port)
        ]

        # The server dials the announced port to tell a High ID from a Low ID, so a free port is taken before the login
        if self.config.tcp_port == ANY_PORT:
            await self._listen()

        while wanted > 0 and pending:
            batch, pending = pending[:wanted], pending[wanted:]
            sessions = [session for session in await asyncio.gather(*map(self._login, batch)) if session is not None]
            self._servers.extend(sessions)
            wanted -= len(sessions)

        if not self._live_servers:
            err_msg = 'no server accepted the login'
            raise ConnectionFailedError(err_msg)
        return self.status

    async def _server_candidates(self) -> list[ServerEntry]:
        """List the servers to log in to: the configured ones, the local ``server.met`` or the downloaded one.

        A downloaded list is cached in the state directory, and the cache stands in for the download when it fails.

        :returns: the servers, the configured ones in their order and those of a list by users.
        :rtype: list[ServerEntry]
        :raises OSError: when the download fails and no cached list exists.
        :raises ProtocolError: when the list is malformed or the download fails and no cached list exists.
        """
        if self.config.servers:
            return list(self.config.servers)
        if self.config.server_met is not None:
            return ServerList.load(self.config.server_met, limits=self.config.limits).by_users()

        # urllib blocks, so the download runs in a thread and the event loop stays responsive
        cache = self.config.state_dir / SERVER_MET_CACHE
        try:
            server_list = await asyncio.to_thread(
                ServerList.download,
                self.config.server_met_url,
                limits=self.config.limits,
                timeout=self.config.timeouts.bootstrap_fetch,
                save_to=cache,
            )
        except (OSError, ProtocolError) as error:
            if not cache.exists():
                raise
            logger.warning('Using the cached server list, because the download failed: %s', error)
            server_list = ServerList.load(cache, limits=self.config.limits)
        return server_list.by_users()

    async def _login(self, entry: ServerEntry) -> ServerSession | None:
        """Log in to one server, remember it when it accepts and forget it when it refuses.

        :param entry: the server.
        :type entry: ServerEntry
        :returns: the open session, or ``None`` when the server refused.
        :rtype: ServerSession | None
        """
        try:
            session = await ServerSession.login(
                entry=entry,
                details=LoginDetails(
                    identity=self.identity, tcp_port=self._announced_port, nickname=self.config.nickname
                ),
                on_callback=self._on_callback,
                timeouts=self.config.timeouts,
                options=self._server_stream,
            )
        except ConnectionFailedError as error:
            logger.warning('Server %s refused: %s', entry.address, error)
            self._server_memory.forget(entry)
            return None

        self._server_memory.remember(entry)
        logger.info('Logged in to %s with ID %d', entry.address, session.state.client_id)
        return await self._exits.enter_async_context(session)

    async def connect_kad(self) -> int:
        """Join Kad from ``nodes.dat``.

        :returns: the number of live contacts.
        :rtype: int
        """
        if self.config.nodes_dat is not None:
            seeds = parse_nodes_dat(self.config.nodes_dat.read_bytes(), limits=self.config.limits)
        else:
            seeds = await asyncio.to_thread(
                download_nodes_dat,
                self.config.nodes_dat_url,
                limits=self.config.limits,
                timeout=self.config.timeouts.bootstrap_fetch,
            )

        node = KadNode(
            kad_id=self.identity.kad_id,
            policy=self.policy,
            udp_port=self.config.udp_port,
            settings=self.config.kad,
            limits=self.config.limits,
        )
        self._kad = await self._exits.enter_async_context(node)
        return await self._kad.bootstrap(seeds)

    async def search(self, query: SearchQuery | str, *, max_results: int = 200) -> list[SearchResult]:
        """Search every live server session and Kad, merge the answers by hash and rank them by sources.

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
        if not self._servers and self._kad is None:
            err_msg = 'connect to a server or to Kad before searching'
            raise NotConnectedError(err_msg)
        if isinstance(query, str):
            query = SearchQuery(text=query, extensions=BOOK_EXTENSIONS)

        # Every server and Kad are asked at once, and one that fails costs only its own results
        merged = SearchResults()
        searches = [session.search(query, max_results=max_results) for session in self._live_servers]
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
        """Ask every live server session and Kad which peers share a file.

        :param file_hash: the file.
        :type file_hash: Ed2kHash
        :param size: its size.
        :type size: int
        :returns: the sources from all of them, duplicates removed.
        :rtype: list[Source]
        """
        lookups = [session.get_sources(file_hash=file_hash, size=size) for session in self._live_servers]
        if self._kad is not None:
            lookups.append(self._kad.search_sources(file_hash=file_hash, size=size))

        # A peer known to several servers or to Kad as well counts once, keyed by its ID and port
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

        # The final name is decided now, but the file carries it only after it leaves quarantine
        name = sanitize_filename(
            link.name, fallback=f'{link.file_hash.hex}.bin', max_bytes=self.config.limits.filename_bytes
        )
        part_file = PartFile.open(
            directory=self.config.download_dir / QUARANTINE_DIR,
            name=name,
            size=link.size,
            file_hash=link.file_hash,
            read_chunk=self.config.io.read_chunk,
        )
        downloader = Downloader(
            part_file=part_file,
            local=self._local,
            policy=self.policy,
            settings=settings or self.config.download,
            stream_options=self._peer_stream,
            peer_settings=self.config.peer,
            io_settings=self.config.io,
            on_progress=progress,
        )
        downloader.add_sources(extra_sources)

        async def feed() -> list[Source]:
            """Ask the servers and Kad for the current sources of the file.

            :returns: the sources.
            :rtype: list[Source]
            """
            return await self.find_sources(file_hash=link.file_hash, size=link.size)

        return await downloader.run(feed=feed, download_dir=self.config.download_dir)

    async def share(self, path: Path) -> list[SharedFile]:
        """Offer a file or the files of a directory, start the listener and publish them on every live server.

        :param path: a file or a directory.
        :type path: Path
        :returns: the files now shared.
        :rtype: list[SharedFile]
        """
        # Hashing a library of books takes minutes, so it runs in a thread
        added = await asyncio.to_thread(self.library.add, path)
        await self._listen()

        # Peers find a source only through the servers it is published on, and a server that fails costs only itself
        offered = [
            OfferedFile(file_hash=f.file_hash, name=f.name, size=f.size, file_type=_file_type(f.name)) for f in added
        ]
        sessions = self._live_servers
        outcomes = await asyncio.gather(*(session.offer_files(offered) for session in sessions), return_exceptions=True)
        for session, outcome in zip(sessions, outcomes, strict=True):
            if isinstance(outcome, ConnectionFailedError):
                logger.warning('Offering files to %s failed: %s', session.entry.address, outcome)
            elif isinstance(outcome, BaseException):
                raise outcome
        return added

    async def _listen(self) -> None:
        """Start accepting peers, unless the listener already runs."""
        if self._listener is not None:
            return

        # eD2k addresses are IPv4 only, and binding all families would give each its own port when the port is 0
        self._listener = await asyncio.start_server(
            self._on_incoming, host=self.config.listen_host, port=self.config.tcp_port
        )
        self._exits.push_async_callback(self._close_listener)

    async def _close_listener(self) -> None:
        """Stop accepting peers and cut off the ones being served."""
        if self._listener is not None:
            self._listener.close()

            # close() stops accepting only, so the peers already being served are cut off separately
            self._listener.close_clients()
            await self._listener.wait_closed()

    async def _on_incoming(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Serve one incoming peer after the address policy and the connection limit allow it.

        :param reader: the connection reader.
        :type reader: asyncio.StreamReader
        :param writer: the connection writer.
        :type writer: asyncio.StreamWriter
        """
        # A full house or a refused address is closed before a single byte is read
        host, port = writer.get_extra_info('peername')[:2]
        if self._incoming.locked() or not self.policy.permits(host, port):
            writer.close()
            return

        async with self._incoming:
            try:
                stream = await PacketStream.accept(
                    reader=reader, writer=writer, own_hash=self.identity.user_hash, options=self._peer_stream
                )
            # A first byte that is no protocol byte starts a handshake, which a peer sending anything else fails
            except (TimeoutError, OSError, asyncio.IncompleteReadError, ProtocolError, SecurityError) as error:
                logger.info('Incoming %s:%d dropped: %r', host, port, error)
                writer.close()
                return

            async with stream:
                connection = PeerConnection(stream=stream, local=self._local, settings=self.config.peer)
                await connection.serve(library=self.library, slots=self._slots)

    async def _on_callback(self, host: str, port: int) -> None:
        """Dial a peer that asked the server for a callback and serve it, when something is shared.

        :param host: the peer address.
        :type host: str
        :param port: the peer port.
        :type port: int
        """
        if not self.library.files or not self.policy.permits(host, port):
            return

        # After a callback this client dials, but the peer is the one that downloads, so the roles of the hello and
        # of the transfer are swapped
        try:
            async with await PacketStream.connect(host=host, port=port, options=self._peer_stream) as stream:
                connection = PeerConnection(stream=stream, local=self._local, settings=self.config.peer)
                await connection.hello()
                await connection.serve(library=self.library, slots=self._slots)
        except (ConnectionFailedError, ProtocolError) as error:
            logger.info('Callback to %s:%d failed: %s', host, port, error)


def _file_type(name: str) -> str:
    """Pick the server-side file type of a published name.

    :param name: the file name.
    :type name: str
    :returns: ``Doc`` for documents, empty otherwise.
    :rtype: str
    """
    return FileType.DOCUMENT if name.lower().rpartition('.')[2] in DOCUMENT_EXTENSIONS else ''
