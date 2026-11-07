"""Download one file from many sources into quarantine, verify it and release it.

Each source gets a worker that runs the peer protocol of :mod:`ed2k_client.peer`. A shared set of blocks in flight
keeps two peers from fetching the same block. A peer that queues this client is asked again after the reask
interval only, because aMule bans a client that asks again within ``MIN_REQUESTTIME``, 590 seconds, four times.
A peer whose data fails a part hash or the protocol is banned for the rest of the download. When every part is
verified, the content is inspected by :func:`check_document` and only a safe document of an expected kind leaves
quarantine.

A Low ID source cannot be dialled. This client reaches only High ID sources, which is the whole network a Low ID
client can use without a server callback or a Kad buddy.
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING

from ed2k_client.constants import LARGE_FILE_THRESHOLD
from ed2k_client.errors import ConnectionFailedError, DownloadError, HashMismatchError, ProtocolError
from ed2k_client.peer import PeerConnection, QueuedError
from ed2k_client.security import (
    DocumentKind,
    check_document,
    inspect_document,
    resolve_inside,
    unique_path,
)
from ed2k_client.settings import DEFAULT_IO, DEFAULT_PEER, SECONDS_PER_HOUR, check_positive
from ed2k_client.sources import Source
from ed2k_client.transport import PEER_STREAM, PacketStream

if TYPE_CHECKING:
    from ed2k_client.partfile import Block, PartFile
    from ed2k_client.peer import LocalPeer
    from ed2k_client.security import (
        AddressPolicy,
        Inspection,
    )
    from ed2k_client.settings import IoSettings, PeerSettings
    from ed2k_client.transport import StreamOptions

logger = logging.getLogger(__name__)

type SourceKey = tuple[int, int]
type SourceFeed = Callable[[], Awaitable[Sequence[Source]]]
type ProgressCallback = Callable[[DownloadProgress], None]

FINAL_FILE_MODE: int = 0o600


class ContentPolicy(StrEnum):
    """Which finished files may leave quarantine.

    ``DOCUMENTS`` releases PDF and DjVu files without active content. ``SAFE`` releases files of any kind except
    programs, scripts, documents that may carry macros and PDF files with active content. ``ANY`` releases every
    file and only records what the inspection found.
    """

    DOCUMENTS = 'documents'
    SAFE = 'safe'
    ANY = 'any'


@dataclass(frozen=True, slots=True)
class DownloadSettings:
    """Limits of one download.

    :ivar max_peers: sources downloaded from at the same time.
    :ivar queue_wait: seconds to wait on a connection while queued.
    :ivar reask_interval: seconds before asking a queueing peer again. aMule bans a client that asks again within
        590 seconds four times, and the default is aMule's own ``FILEREASKTIME``.
    :ivar source_refresh: seconds between two refreshes of the source list.
    :ivar deadline: seconds after which the download gives up.
    :ivar content_policy: which finished files may leave quarantine.
    :ivar poll_interval: seconds between two rounds of starting workers and reporting progress.
    :ivar max_connect_failures: failed connections in a row after which a source is dropped.
    """

    max_peers: int = 4
    queue_wait: float = 120.0
    # https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/include/protocol/ed2k/Constants.h#L35
    reask_interval: float = 1300.0
    source_refresh: float = 900.0
    deadline: float = 6 * SECONDS_PER_HOUR
    content_policy: ContentPolicy = ContentPolicy.DOCUMENTS
    poll_interval: float = 1.0
    max_connect_failures: int = 3

    def __post_init__(self) -> None:
        """Check the values."""
        check_positive(self)


@dataclass(frozen=True, slots=True)
class DownloadProgress:
    """A snapshot of a running download.

    :ivar name: the file name.
    :ivar size: the size in bytes.
    :ivar verified_bytes: bytes in verified parts.
    :ivar active_peers: peers currently sending or connecting.
    :ivar known_sources: sources known so far.
    """

    name: str
    size: int
    verified_bytes: int
    active_peers: int
    known_sources: int


@dataclass(frozen=True, slots=True)
class DownloadResult:
    """A finished download.

    :ivar path: where the verified file now lives.
    :ivar inspection: what the content check found.
    """

    path: Path
    inspection: Inspection


@dataclass(slots=True)
class SourceState:
    """What the downloader knows about one source.

    :ivar source: the source.
    :ivar next_try: loop time before which the source is not dialled.
    :ivar failures: consecutive connection failures.
    :ivar banned: whether the source sent bad data.
    """

    source: Source
    next_try: float = 0.0
    failures: int = 0
    banned: bool = False


@dataclass(slots=True)
class Downloader:
    """Run the download of one :class:`PartFile`.

    :ivar part_file: the file being downloaded.
    :ivar local: this client's description for hellos.
    :ivar policy: which addresses may be dialled.
    :ivar settings: the limits.
    :ivar stream_options: how connections to sources connect and read, before the queue wait is applied.
    :ivar peer_settings: how many blocks one request asks for.
    :ivar io_settings: buffer sizes of the content check.
    :ivar on_progress: called after every verified part and every change of peers.
    """

    part_file: PartFile
    local: LocalPeer
    policy: AddressPolicy
    settings: DownloadSettings = field(default_factory=DownloadSettings)
    stream_options: StreamOptions = PEER_STREAM
    peer_settings: PeerSettings = DEFAULT_PEER
    io_settings: IoSettings = DEFAULT_IO
    on_progress: ProgressCallback | None = None
    _sources: dict[SourceKey, SourceState] = field(default_factory=dict)
    _in_flight: set[Block] = field(default_factory=set)
    _workers: dict[SourceKey, asyncio.Task[None]] = field(default_factory=dict)
    _contributors: dict[int, set[SourceKey]] = field(default_factory=dict)
    _exclusive: dict[int, SourceKey | None] = field(default_factory=dict)

    def add_sources(self, sources: Sequence[Source]) -> int:
        """Remember new sources that this client can dial.

        :param sources: sources from a server, Kad or a link.
        :type sources: Sequence[Source]
        :returns: how many were new and usable.
        :rtype: int
        """
        added = 0
        for source in sources:
            # A Low ID is a server-local number rather than an address, so there is nothing to dial
            key = (source.client_id, source.port)
            if key in self._sources or source.is_low_id or not self.policy.permits(source.host, source.port):
                continue
            self._sources[key] = SourceState(source=source)
            added += 1
        return added

    def _report(self) -> None:
        """Send a progress snapshot to the callback, if there is one."""
        if self.on_progress is not None:
            self.on_progress(
                DownloadProgress(
                    name=self.part_file.name,
                    size=self.part_file.size,
                    verified_bytes=self.part_file.verified_bytes,
                    active_peers=len(self._workers),
                    known_sources=len(self._sources),
                )
            )

    async def run(self, *, feed: SourceFeed, download_dir: Path) -> DownloadResult:
        """Download until every part is verified, then release the file from quarantine.

        :param feed: returns fresh sources, called at the start and every ``source_refresh`` seconds.
        :type feed: SourceFeed
        :param download_dir: the directory the finished file goes to.
        :type download_dir: Path
        :returns: the finished file.
        :rtype: DownloadResult
        :raises DownloadError: when the deadline passes first.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.settings.deadline
        next_refresh = 0.0

        # One loop schedules everything: it refreshes sources, starts workers for sources that are due and reports,
        # while the workers themselves write blocks as they arrive
        try:
            while not self.part_file.complete:
                now = loop.time()
                if now >= deadline:
                    err_msg = f'{self.part_file.name}: deadline passed with {self.part_file.verified_bytes} bytes'
                    raise DownloadError(err_msg)

                if now >= next_refresh:
                    logger.info('%d new sources', self.add_sources(await feed()))
                    next_refresh = now + self.settings.source_refresh

                self._start_workers(now)
                self._report()
                await asyncio.sleep(self.settings.poll_interval)
        finally:
            for task in self._workers.values():
                task.cancel()
            await asyncio.gather(*self._workers.values(), return_exceptions=True)

        return self._release(download_dir)

    def _start_workers(self, now: float) -> None:
        """Start workers for sources that are due, up to the peer limit.

        :param now: the loop time.
        :type now: float
        """
        for key, state in self._sources.items():
            if len(self._workers) >= self.settings.max_peers:
                return
            if key in self._workers or state.banned or state.next_try > now:
                continue

            task = asyncio.create_task(self._work(state))
            self._workers[key] = task

            def forget(_: asyncio.Task[None], key: SourceKey = key) -> None:
                """Drop a finished worker from the table.

                :param _: the finished task.
                :type _: asyncio.Task[None]
                :param key: the source the worker served.
                :type key: SourceKey
                """
                self._workers.pop(key, None)

            task.add_done_callback(forget)

    async def _work(self, state: SourceState) -> None:
        """Run one session with a source and schedule, ban or retry it by the outcome.

        :param state: the source state.
        :type state: SourceState
        """
        source = state.source
        key = (source.client_id, source.port)
        loop = asyncio.get_running_loop()
        obfuscate_for = source.user_hash if source.wants_obfuscation else None

        # A queued connection stays silent until the slot arrives, so its idle timeout must cover the queue wait
        idle = max(self.stream_options.idle_timeout or 0.0, self.settings.queue_wait)
        try:
            async with await PacketStream.connect(
                host=source.host,
                port=source.port,
                obfuscate_for=obfuscate_for,
                options=replace(self.stream_options, idle_timeout=idle),
            ) as stream:
                connection = PeerConnection(stream=stream, local=self.local, settings=self.peer_settings)
                await self._transfer(connection, key=key)
            state.failures = 0
            state.next_try = loop.time() + self.settings.reask_interval
        except QueuedError as queued:
            logger.info('%s queued us at %d; asking again later', source.host, queued.rank)
            state.next_try = loop.time() + self.settings.reask_interval
        except (HashMismatchError, ProtocolError) as error:
            logger.warning('Banning %s:%d for this file: %s', source.host, source.port, error)
            state.banned = True
        except ConnectionFailedError as error:
            state.failures += 1
            state.banned = state.failures >= self.settings.max_connect_failures
            state.next_try = loop.time() + self.settings.reask_interval
            logger.info('%s:%d failed (%s)', source.host, source.port, error)
        finally:
            # A part pinned to this peer becomes free for anyone once the peer is gone
            for part, owner in self._exclusive.items():
                if owner == key:
                    self._exclusive[part] = None

        self._report()

    async def _transfer(self, connection: PeerConnection, *, key: SourceKey) -> None:
        """Run the peer protocol with one connection and download the blocks it offers.

        :param connection: the open connection.
        :type connection: PeerConnection
        :param key: the source key.
        :type key: SourceKey
        """
        part_file = self.part_file
        await connection.hello()
        status = await connection.request_file(file_hash=part_file.file_hash, size=part_file.size)

        # A file of one part has no hashset, because its file hash is the part hash
        if part_file.needs_hashset:
            part_file.set_hashset(await connection.request_hashset(part_file.file_hash))

        # A peer with nothing new is not asked for a slot, so it does not count the request against this client
        if not any(True for _ in part_file.missing_blocks(parts=set(status.parts))):
            return

        await connection.request_upload(part_file.file_hash, queue_wait=self.settings.queue_wait)
        large = part_file.size > LARGE_FILE_THRESHOLD
        while blocks := self._claim(set(status.parts), key=key):
            try:
                async for block, offset, data in connection.download_blocks(
                    file_hash=part_file.file_hash, blocks=blocks, large=large
                ):
                    self._store(block=block, offset=offset, data=data, key=key)
            finally:
                self._in_flight.difference_update(blocks)

    def _store(self, *, block: Block, offset: int, data: bytes, key: SourceKey) -> None:
        """Write data and decide who is to blame when its part fails the hash check.

        Without AICH the client cannot tell which block of a failed part was bad. A part that came from one peer
        convicts that peer. A part with several contributors convicts nobody: it is wiped and handed to a single
        peer, so that a second failure has exactly one suspect.

        :param block: the block the data belongs to.
        :type block: Block
        :param offset: file offset of the data.
        :type offset: int
        :param data: the bytes.
        :type data: bytes
        :param key: the peer that sent them.
        :type key: SourceKey
        :raises HashMismatchError: when this peer alone delivered a corrupt part.
        """
        self._contributors.setdefault(block.part, set()).add(key)
        try:
            verified = self.part_file.write(block=block, start=offset, data=data)
        except HashMismatchError as error:
            # The writer is always among the suspects, because it was added above. Alone it is banned by raising,
            # which ends its worker, and among others the part is handed to the next single peer instead
            suspects = self._contributors.pop(error.part, set())
            if suspects == {key}:
                raise
            self._exclusive[error.part] = None
            logger.warning('Part %d failed its hash with %d contributors', error.part, len(suspects))
            return

        if verified is not None:
            self._contributors.pop(verified, None)
            self._exclusive.pop(verified, None)
            self._report()

    def _claim(self, parts: set[int], *, key: SourceKey) -> list[Block]:
        """Reserve up to three missing blocks this peer has and nobody else is fetching.

        :param parts: the parts the peer has.
        :type parts: set[int]
        :param key: the source key.
        :type key: SourceKey
        :returns: the reserved blocks, empty when nothing is left for this peer.
        :rtype: list[Block]
        """
        if self._sources[key].banned:
            return []

        claimed = []
        for block in self.part_file.missing_blocks(parts=parts):
            # A part in _exclusive is free while its owner is None and pinned to one peer otherwise
            if block in self._in_flight or self._exclusive.get(block.part, key) not in {key, None}:
                continue
            if block.part in self._exclusive:
                self._exclusive[block.part] = key
            claimed.append(block)
            if len(claimed) == self.peer_settings.blocks_per_request:
                break

        self._in_flight.update(claimed)
        return claimed

    def _release(self, download_dir: Path) -> DownloadResult:
        """Inspect the finished file and move it from quarantine to the download directory.

        :param download_dir: the destination.
        :type download_dir: Path
        :returns: the released file.
        :rtype: DownloadResult
        :raises SecurityError: when the content policy refuses the file.
        """
        part_file = self.part_file

        # check_document raises SecurityError on a refused file, which leaves it in quarantine, while the ANY policy
        # only records what the inspection found. The quarantined data is named by its hash, so the checks get the
        # name the file is released under, which decides what opening it runs
        data, name, io = part_file.data_path, part_file.name, self.io_settings
        match self.settings.content_policy:
            case ContentPolicy.DOCUMENTS:
                expected = (DocumentKind.PDF, DocumentKind.DJVU)
                inspection = check_document(data, expected=expected, name=name, io=io)
            case ContentPolicy.SAFE:
                inspection = check_document(data, expected=None, name=name, io=io)
            case ContentPolicy.ANY:
                inspection = inspect_document(data, name=name, io=io)

        target = unique_path(resolve_inside(download_dir, part_file.name))
        part_file.data_path.replace(target)
        Path(target).chmod(FINAL_FILE_MODE)
        part_file.discard_metadata()
        logger.info('Released %s from quarantine', target)
        return DownloadResult(path=target, inspection=inspection)
