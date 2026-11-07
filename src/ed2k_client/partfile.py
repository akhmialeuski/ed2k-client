"""A file being downloaded: sparse data in quarantine, resumable progress and per-part MD4 verification.

The data lives in ``<incoming>/<hash>.part`` and the progress in ``<hash>.part.json`` beside it, both readable by
the owner only. Parts are split into blocks of 180 KiB that never cross a part boundary, the unit in which peers
are asked for data. A block counts as received only when the union of the byte ranges written into it covers it,
so overlapping or repeated data from a hostile peer cannot complete it early. A part that is complete is hashed
and either marked verified or wiped and downloaded again.
"""

import json
import os
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Literal, Self

from Crypto.Hash import MD4

from ed2k_client.constants import BLOCK_SIZE, PART_SIZE
from ed2k_client.errors import HashMismatchError, ProtocolError
from ed2k_client.hashing import data_part_count, expected_part_hash, hash_from_parts, hashset_length
from ed2k_client.settings import DEFAULT_IO

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence
    from pathlib import Path

    from ed2k_client.hashing import Ed2kHash

FILE_MODE: int = 0o600
DIRECTORY_MODE: int = 0o700
METADATA_SUFFIX: str = '.part.json'
DATA_SUFFIX: str = '.part'
ENCODING: str = 'utf-8'
READ_BINARY: Literal['rb'] = 'rb'
UPDATE_BINARY: Literal['r+b'] = 'r+b'


@dataclass(frozen=True, slots=True, order=True)
class Block:
    """A request unit inside one part.

    :ivar start: first byte offset in the file.
    :ivar end: offset after the last byte.
    """

    start: int
    end: int

    @property
    def part(self) -> int:
        """Index of the part that holds the block."""
        return self.start // PART_SIZE


@dataclass(frozen=True, slots=True)
class PartState:
    """The persisted progress of a download.

    :ivar size: the file size.
    :ivar part_hashes: the verified hashset in hex.
    :ivar verified_parts: indexes of verified parts.
    """

    size: int
    part_hashes: list[str]
    verified_parts: list[int]


def blocks_of_part(*, size: int, part: int) -> list[Block]:
    """Split one part into request blocks.

    :param size: the file size.
    :type size: int
    :param part: the part index.
    :type part: int
    :returns: the blocks in order.
    :rtype: list[Block]
    """
    # The last block of a part is shorter when PART_SIZE is not a multiple of BLOCK_SIZE, which it is not:
    # 9,728,000 = 52 * 184,320 + 143,360, so a block never reaches into the next part
    part_start = part * PART_SIZE
    part_end = min(part_start + PART_SIZE, size)
    return [Block(start, min(start + BLOCK_SIZE, part_end)) for start in range(part_start, part_end, BLOCK_SIZE)]


@dataclass(slots=True)
class Coverage:
    """Merged byte ranges received inside one block.

    :ivar ranges: disjoint sorted ``(start, end)`` pairs.
    """

    ranges: list[tuple[int, int]] = field(default_factory=list)

    def add(self, start: int, end: int) -> None:
        """Record a received range and merge it with its neighbours.

        :param start: first offset.
        :type start: int
        :param end: offset after the last byte.
        :type end: int
        """
        # Touching ranges merge too, so two halves of a block become one range that covers it
        merged: list[tuple[int, int]] = []
        for low, high in sorted([*self.ranges, (start, end)]):
            if merged and low <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], high))
            else:
                merged.append((low, high))
        self.ranges = merged

    def covers(self, block: Block) -> bool:
        """Check whether the ranges cover the whole block.

        :param block: the block.
        :type block: Block
        :returns: whether every byte of the block was received.
        :rtype: bool
        """
        return any(low <= block.start and high >= block.end for low, high in self.ranges)


class PartFile:
    """Download state of one file.

    :ivar name: the sanitised name the finished file will get.
    :ivar size: the file size.
    :ivar file_hash: the eD2k hash.
    :ivar part_hashes: the verified hashset, empty until known for a multi-part file.
    :ivar verified_parts: parts whose MD4 matched.
    :ivar data_path: the quarantined data file.
    :ivar metadata_path: the progress file.
    """

    def __init__(
        self, *, directory: Path, name: str, size: int, file_hash: Ed2kHash, read_chunk: int = DEFAULT_IO.read_chunk
    ) -> None:
        """Create the in-memory state; use :meth:`open` to attach it to disk.

        :param directory: the quarantine directory.
        :type directory: Path
        :param name: the sanitised final name.
        :type name: str
        :param size: the file size.
        :type size: int
        :param file_hash: the eD2k hash.
        :type file_hash: Ed2kHash
        :param read_chunk: bytes read at a time while a part is hashed.
        :type read_chunk: int
        """
        self.name = name
        self.size = size
        self.file_hash = file_hash
        self.part_hashes: tuple[bytes, ...] = ()
        self.verified_parts: set[int] = set()
        self._coverage: dict[Block, Coverage] = {}
        self._read_chunk = read_chunk

        # Named by hash rather than by the untrusted file name, so no peer can choose a path in quarantine
        self.data_path = directory / f'{file_hash.hex}{DATA_SUFFIX}'
        self.metadata_path = directory / f'{file_hash.hex}{METADATA_SUFFIX}'

    @classmethod
    def open(
        cls, *, directory: Path, name: str, size: int, file_hash: Ed2kHash, read_chunk: int = DEFAULT_IO.read_chunk
    ) -> Self:
        """Open or create the part file of a download, resuming verified parts from an earlier run.

        :param directory: the quarantine directory.
        :type directory: Path
        :param name: the sanitised final name.
        :type name: str
        :param size: the file size.
        :type size: int
        :param file_hash: the eD2k hash.
        :type file_hash: Ed2kHash
        :param read_chunk: bytes read at a time while a part is hashed.
        :type read_chunk: int
        :returns: the part file.
        :rtype: Self
        """
        directory.mkdir(mode=DIRECTORY_MODE, parents=True, exist_ok=True)
        part_file = cls(directory=directory, name=name, size=size, file_hash=file_hash, read_chunk=read_chunk)

        # Only verified parts survive a restart. Blocks of an unfinished part are fetched again, because nothing
        # proves that bytes written before a crash are the bytes a peer sent
        resumed = False
        if part_file.metadata_path.exists() and part_file.data_path.exists():
            state = PartState(**json.loads(part_file.metadata_path.read_text(encoding=ENCODING)))
            resumed = state.size == size
            if resumed:
                part_file.part_hashes = tuple(bytes.fromhex(item) for item in state.part_hashes)
                part_file.verified_parts = set(state.verified_parts)

        # Progress under another size cannot be resumed, and its data file may be longer than this size, so it starts
        # over too: a stale tail would otherwise leave quarantine with the verified parts
        if not resumed:
            # os.open sets mode 0600 at creation, and ftruncate makes a sparse file that takes no space yet
            descriptor = os.open(part_file.data_path, os.O_RDWR | os.O_CREAT | os.O_TRUNC, FILE_MODE)
            os.ftruncate(descriptor, size)
            os.close(descriptor)

        part_file.save()
        return part_file

    @property
    def part_count(self) -> int:
        """Number of parts that hold data."""
        return data_part_count(self.size)

    @property
    def needs_hashset(self) -> bool:
        """Whether part hashes are still missing for a multi-part file."""
        return hashset_length(self.size) > 0 and not self.part_hashes

    @property
    def complete(self) -> bool:
        """Whether every part is verified."""
        return len(self.verified_parts) == self.part_count

    @property
    def verified_bytes(self) -> int:
        """Bytes in verified parts."""
        return sum(min(PART_SIZE, self.size - part * PART_SIZE) for part in self.verified_parts)

    def set_hashset(self, part_hashes: Sequence[bytes]) -> None:
        """Accept the part hashes of a multi-part file after checking them against the file hash.

        :param part_hashes: the hashset a peer sent.
        :type part_hashes: Sequence[bytes]
        :raises ProtocolError: when the hashset does not belong to the file.
        """
        # The file hash is the MD4 of the part hashes, so a forged hashset cannot pass this check
        if len(part_hashes) != hashset_length(self.size) or hash_from_parts(part_hashes) != self.file_hash:
            err_msg = f'hashset does not match {self.file_hash}'
            raise ProtocolError(err_msg)
        self.part_hashes = tuple(part_hashes)
        self.save()

    def missing_blocks(self, *, parts: set[int] | None = None) -> Iterator[Block]:
        """Yield blocks not yet received, in file order.

        :param parts: restrict to these parts, typically those a peer has, or ``None`` for all.
        :type parts: set[int] | None
        :returns: the blocks.
        :rtype: Iterator[Block]
        """
        for part in range(self.part_count):
            if part in self.verified_parts or (parts is not None and part not in parts):
                continue
            for block in blocks_of_part(size=self.size, part=part):
                coverage = self._coverage.get(block)
                if coverage is None or not coverage.covers(block):
                    yield block

    def write(self, *, block: Block, start: int, data: bytes) -> int | None:
        """Write received data inside a requested block and verify its part once the part is complete.

        :param block: the block the data belongs to.
        :type block: Block
        :param start: file offset of the first data byte.
        :type start: int
        :param data: the bytes.
        :type data: bytes
        :returns: the index of a part that just verified, or ``None``.
        :rtype: int | None
        :raises ProtocolError: when the data falls outside the block or into a part that is already verified.
        :raises HashMismatchError: when a completed part fails its hash; the part is then wiped.
        """
        end = start + len(data)
        if not data or start < block.start or end > block.end:
            err_msg = f'data from {start} to {end} lies outside block {block}'
            raise ProtocolError(err_msg)

        # A verified part is never hashed again before the file leaves quarantine, so a write into it would replace
        # checked bytes for good. Each block goes to one peer only, so only a peer repeating data sends such a write
        if block.part in self.verified_parts:
            err_msg = f'{len(data)} bytes at {start} land in part number {block.part}, which is already verified'
            raise ProtocolError(err_msg)

        with self.data_path.open(UPDATE_BINARY) as stream:
            stream.seek(start)
            stream.write(data)

        # The part is hashed once, when its last block is covered
        self._coverage.setdefault(block, Coverage()).add(start, end)
        part_blocks = blocks_of_part(size=self.size, part=block.part)
        if not all(b in self._coverage and self._coverage[b].covers(b) for b in part_blocks):
            return None
        return self._verify_part(block.part)

    def _verify_part(self, part: int) -> int:
        """Hash a completed part and mark it verified or wipe it.

        :param part: the part index.
        :type part: int
        :returns: the part index.
        :rtype: int
        :raises HashMismatchError: when the part does not match its hash.
        """
        start = part * PART_SIZE
        digest = MD4.new()
        with self.data_path.open(READ_BINARY) as stream:
            stream.seek(start)
            remaining = min(PART_SIZE, self.size - start)
            while remaining and (chunk := stream.read(min(self._read_chunk, remaining))):
                digest.update(chunk)
                remaining -= len(chunk)

        expected = expected_part_hash(
            file_hash=self.file_hash, size=self.size, part_hashes=self.part_hashes, index=part
        )

        # The coverage goes either way: a verified part needs it no more, and a failed part must be fetched again,
        # which an empty coverage makes every one of its blocks missing for
        for block in blocks_of_part(size=self.size, part=part):
            self._coverage.pop(block, None)
        if digest.digest() != expected:
            err_msg = f'part {part} of {self.file_hash} failed its MD4 check'
            raise HashMismatchError(err_msg, part=part)

        self.verified_parts.add(part)
        self.save()
        return part

    def save(self) -> None:
        """Persist the progress atomically so that a later run resumes from the verified parts."""
        state = PartState(
            size=self.size,
            part_hashes=[item.hex() for item in self.part_hashes],
            verified_parts=sorted(self.verified_parts),
        )

        # Written beside the target and renamed over it, so a crash leaves either the old or the new progress
        temporary = self.metadata_path.with_suffix('.tmp')
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
        with os.fdopen(descriptor, 'w', encoding=ENCODING) as stream:
            json.dump(asdict(state), stream)
        temporary.replace(self.metadata_path)

    def read(self, *, start: int, length: int) -> bytes:
        """Read bytes back.

        :param start: file offset.
        :type start: int
        :param length: number of bytes.
        :type length: int
        :returns: the bytes.
        :rtype: bytes
        """
        with self.data_path.open(READ_BINARY) as stream:
            stream.seek(start)
            return stream.read(length)

    def discard_metadata(self) -> None:
        """Remove the progress file after the data has been moved out of quarantine."""
        self.metadata_path.unlink(missing_ok=True)
