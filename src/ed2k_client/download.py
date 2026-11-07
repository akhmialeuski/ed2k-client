"""Download one file from many sources into quarantine, verify it and release it.

Each source gets a worker that runs the peer protocol of :mod:`ed2k_client.peer`. A shared set of blocks in flight
keeps two peers from fetching the same block. A peer that queues this client is asked again after the reask
interval only, because aMule bans a client that asks again within ``MIN_REQUESTTIME``, 590 seconds, four times.
A peer whose data fails a part hash or the protocol is banned for the rest of the download. When the link carries an
AICH root, complete sources are asked for the AICH hashes of the parts, which pin a failed part on the blocks and the
peer that broke it. When every part is verified, the content is inspected by :func:`check_document` and only a safe
document of an expected kind leaves quarantine.

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
from ed2k_client.errors import (
    ConnectionFailedError,
    DownloadError,
    HashMismatchError,
    LinkMismatchError,
    ProtocolError,
)
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
    from ed2k_client.peer import FileStatus, HelloInfo, LocalPeer
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

    ``SAFE``, the default, releases files of any kind except programs, scripts, documents that may carry macros and
    PDF files with active content. ``DOCUMENTS`` releases only PDF and DjVu files without active content. ``ANY``
    releases every file and only records what the inspection found.
    """

    DOCUMENTS = 'documents'
    SAFE = 'safe'
    ANY = 'any'


class AichPolicy(StrEnum):
    """What the AICH root of a link demands before a part is accepted.

    ``REQUIRE``, the default, fetches a part only once a peer has served the AICH hashes that prove its blocks, so a
    part whose MD4 collides with the original cannot pass, and a file no complete AICH source serves runs into the
    deadline. ``PREFER`` fetches every part and accepts one on its MD4 alone, with a warning, when no peer served its
    AICH hashes. A link without a root is checked by MD4 under either policy.
    """

    REQUIRE = 'require'
    PREFER = 'prefer'


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
    :ivar aich: what the AICH root of a link demands before a part is accepted.
    :ivar poll_interval: seconds between two rounds of starting workers and reporting progress.
    :ivar max_connect_failures: failed connections in a row after which a source is dropped.
    """

    max_peers: int = 4
    queue_wait: float = 120.0
    # https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/include/protocol/ed2k/Constants.h#L35
    reask_interval: float = 1300.0
    source_refresh: float = 900.0
    deadline: float = 6 * SECONDS_PER_HOUR
    content_policy: ContentPolicy = ContentPolicy.SAFE
    aich: AichPolicy = AichPolicy.REQUIRE
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
    _senders: dict[int, dict[int, set[SourceKey]]] = field(default_factory=dict)
    _exclusive: dict[int, SourceKey | None] = field(default_factory=dict)
    _failure: BaseException | None = None

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
        :raises DownloadError: when the deadline passes first, or a worker fails for a reason no peer causes.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.settings.deadline
        next_refresh = 0.0

        # One loop schedules everything: it refreshes sources, starts workers for sources that are due and reports,
        # while the workers themselves write blocks as they arrive
        try:
            while not self.part_file.complete:
                # A link no source can satisfy, or a local failure such as a full disk, hits every peer the same
                # way, so it ends the download
                if isinstance(self._failure, LinkMismatchError):
                    raise self._failure
                if self._failure is not None:
                    err_msg = f'{self.part_file.name}: {self._failure}'
                    raise DownloadError(err_msg) from self._failure

                now = loop.time()
                if now >= deadline:
                    raise DownloadError(self._deadline_message())

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

    def _deadline_message(self) -> str:
        """Describe a download that ran out of time, naming the parts still waiting for AICH hashes.

        :returns: the message.
        :rtype: str
        """
        part_file = self.part_file
        message = f'{part_file.name}: deadline passed with {part_file.verified_bytes} bytes'
        if waiting := self._waiting_for_aich(set(range(part_file.part_count)) - part_file.verified_parts):
            message += f', and parts {sorted(waiting)} still wait for AICH hashes that only a complete source serves'
        return message

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

            def forget(finished: asyncio.Task[None], key: SourceKey = key) -> None:
                """Drop a finished worker from the table and keep the error that ended it, which no peer caused.

                :param finished: the finished task.
                :type finished: asyncio.Task[None]
                :param key: the source the worker served.
                :type key: SourceKey
                """
                self._workers.pop(key, None)

                # _work settles every peer outcome itself, so an exception that leaves it is local
                if not finished.cancelled() and (error := finished.exception()) is not None:
                    self._failure = error

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
        except LinkMismatchError as error:
            self._failure = error
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
        remote = await connection.hello()
        status = await connection.request_file(file_hash=part_file.file_hash, size=part_file.size)

        # A file of one part has no hashset, because its file hash is the part hash
        if part_file.needs_hashset:
            part_file.set_hashset(await connection.request_hashset(part_file.file_hash))
        await self._fetch_aich(connection, remote=remote, status=status)

        # A peer with nothing new is not asked for a slot, so it does not count the request against this client
        parts = set(status.parts)
        if not any(True for _ in part_file.missing_blocks(parts=parts - self._waiting_for_aich(parts))):
            return

        await connection.request_upload(part_file.file_hash, queue_wait=self.settings.queue_wait)
        large = part_file.size > LARGE_FILE_THRESHOLD
        while blocks := self._claim(parts, key=key):
            try:
                async for block, offset, data in connection.download_blocks(
                    file_hash=part_file.file_hash, blocks=blocks, large=large
                ):
                    self._store(block=block, offset=offset, data=data, key=key)
            finally:
                self._in_flight.difference_update(blocks)

    async def _fetch_aich(self, connection: PeerConnection, *, remote: HelloInfo, status: FileStatus) -> None:
        """Ask a complete source for the AICH hashes of every unverified part that still lacks them.

        Only a source with the whole file can answer. A source that does not announce AICH is not asked, because an
        older client leaves the request unanswered until the connection times out.

        :param connection: the open connection.
        :type connection: PeerConnection
        :param remote: what the peer said in its hello.
        :type remote: HelloInfo
        :param status: the parts the peer has.
        :type status: FileStatus
        :raises ProtocolError: when an answer does not prove itself against the root, which bans the peer.
        """
        part_file = self.part_file
        aich = part_file.aich
        if aich is None or not remote.aich or len(status.parts) < part_file.part_count:
            return

        for part in range(part_file.part_count):
            if part in part_file.verified_parts or aich.ready(part):
                continue
            asked = aich.source_part(part)
            hashes = await connection.request_aich(
                file_hash=part_file.file_hash, part=asked, root=aich.root, count=aich.hash_count(asked)
            )
            if hashes is None:
                logger.info('%s serves no AICH hashes for %s', connection.stream.peer, part_file.name)
                return
            aich.accept(part=asked, hashes=hashes)

    def _waiting_for_aich(self, parts: set[int]) -> set[int]:
        """Pick the parts that may not be fetched yet, because their AICH hashes are required and still missing.

        :param parts: the parts to look at.
        :type parts: set[int]
        :returns: the parts that wait.
        :rtype: set[int]
        """
        aich = self.part_file.aich
        if aich is None or self.settings.aich != AichPolicy.REQUIRE:
            return set()
        return {part for part in parts if not aich.ready(part)}

    def _store(self, *, block: Block, offset: int, data: bytes, key: SourceKey) -> None:
        """Write data, remembering which peer wrote into which block in case its part fails.

        :param block: the block the data belongs to.
        :type block: Block
        :param offset: file offset of the data.
        :type offset: int
        :param data: the bytes.
        :type data: bytes
        :param key: the peer that sent them.
        :type key: SourceKey
        :raises HashMismatchError: when the failed part convicts this peer.
        """
        self._senders.setdefault(block.part, {}).setdefault(block.start, set()).add(key)
        try:
            verified = self.part_file.write(block=block, start=offset, data=data)
        except HashMismatchError as error:
            self._blame(error, key=key)
            return

        if verified is not None:
            self._senders.pop(verified, None)
            self._exclusive.pop(verified, None)
            self._report()

    def _blame(self, error: HashMismatchError, *, key: SourceKey) -> None:
        """Ban the peers a failed part convicts and free the part for the next attempt.

        With AICH the failed blocks are known, so the only peer that wrote into a failed block is banned and the good
        blocks stay. A failed block that several peers wrote into convicts nobody and is fetched again. Without AICH a
        part that came from one peer convicts that peer, and a part with several contributors convicts nobody: it is
        handed to a single peer, so that a second failure has exactly one suspect.

        :param error: the failure.
        :type error: HashMismatchError
        :param key: the peer whose data completed the part.
        :type key: SourceKey
        :raises HashMismatchError: when this peer is convicted, which ends its worker.
        """
        if error.bad_blocks:
            senders = self._senders.get(error.part, {})
            writers = [senders.pop(start, set()) for start in error.bad_blocks]
            guilty = {peer for peers in writers if len(peers) == 1 for peer in peers}
        else:
            suspects = set().union(*self._senders.pop(error.part, {}).values())
            guilty = suspects if len(suspects) == 1 else set()
            if not guilty:
                self._exclusive[error.part] = None

        # Another convicted peer stops at its next claim, which hands out nothing to a banned source
        for peer in guilty - {key}:
            source = self._sources[peer].source
            logger.warning('Banning %s:%d for this file: %s', source.host, source.port, error)
            self._sources[peer].banned = True
        if key in guilty:
            raise error
        if not guilty:
            logger.warning('%s, and no single peer is to blame', error)

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
        for block in self.part_file.missing_blocks(parts=parts - self._waiting_for_aich(parts)):
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
