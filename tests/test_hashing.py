"""Tests of the eD2k hash against vectors produced by RHash 1.4.3, an independent implementation."""

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from ed2k_client.constants import EMPTY_MD4, PART_SIZE
from ed2k_client.errors import ProtocolError
from ed2k_client.hashing import (
    Ed2kHash,
    expected_part_hash,
    hash_file,
    hashset_length,
    part_count,
    verify_hashset,
)

if TYPE_CHECKING:
    from pyfakefs.fake_filesystem import FakeFilesystem

PATTERN = bytes(range(251))

# Computed with `rhash --ed2k` over files filled with PATTERN repeated, on 2026-11-06.
RHASH_VECTORS = [
    (0, '31d6cfe0d16ae931b73c59d7e0c089c0'),
    (3, 'e9a4db2923faf634cbb12cc1f8ac5c66'),
    (PART_SIZE - 1, '8bc46f92ea3ad078998cc7baf97c31c3'),
    (PART_SIZE, '22155255a2ed92712ccd01ad0eb9e8cb'),
    (PART_SIZE + 1, '07149b89efa248c03d7e2c5e734d2d88'),
    (2 * PART_SIZE, 'b22937d7a5bb74050fb54037fe573649'),
    (2 * PART_SIZE + 1, '2bd1f2c5e81ab3f0fe4410ffe9658859'),
]


def pattern_file(fs: FakeFilesystem, size: int) -> Path:
    """Create an in-memory file of the given size filled with the repeating test pattern.

    :param fs: the in-memory file system.
    :type fs: FakeFilesystem
    :param size: the file size in bytes.
    :type size: int
    :returns: the file.
    :rtype: Path
    """
    path = Path(f'/data/pattern_{size}.bin')
    fs.create_file(path, contents=(PATTERN * (size // len(PATTERN) + 1))[:size])
    return path


class TestHashFile:
    """Tests of :func:`hash_file`."""

    @pytest.mark.parametrize(('size', 'expected'), RHASH_VECTORS)
    def test_hash_file_matches_rhash(self, fs: FakeFilesystem, size: int, expected: str) -> None:
        """Every size class of the eD2k rules hashes to what RHash computes.

        :param fs: the in-memory file system.
        :type fs: FakeFilesystem
        :param size: the file size in bytes.
        :type size: int
        :param expected: the eD2k hash RHash computes for the file, in lower-case hex.
        :type expected: str
        """
        hashes = hash_file(pattern_file(fs, size))

        assert hashes.file_hash.hex.lower() == expected
        assert len(hashes.part_hashes) == hashset_length(size)
        assert verify_hashset(file_hash=hashes.file_hash, size=size, part_hashes=hashes.part_hashes)

    def test_exact_multiple_ends_with_empty_part_hash(self, fs: FakeFilesystem) -> None:
        """A file of exactly one part carries the MD4 of the empty string as its second part hash.

        :param fs: the in-memory file system.
        :type fs: FakeFilesystem
        """
        hashes = hash_file(pattern_file(fs, PART_SIZE))

        assert hashes.part_hashes[-1] == EMPTY_MD4
        assert part_count(PART_SIZE) == 2


class TestVerifyHashset:
    """Tests of :func:`verify_hashset`."""

    def test_tampered_hashset_is_rejected(self, fs: FakeFilesystem) -> None:
        """A hashset with one changed part hash does not verify against the file hash.

        :param fs: the in-memory file system.
        :type fs: FakeFilesystem
        """
        hashes = hash_file(pattern_file(fs, PART_SIZE + 1))
        forged = (bytes(16), *hashes.part_hashes[1:])

        assert not verify_hashset(file_hash=hashes.file_hash, size=hashes.size, part_hashes=forged)
        assert not verify_hashset(file_hash=hashes.file_hash, size=hashes.size, part_hashes=hashes.part_hashes[:1])


class TestExpectedPartHash:
    """Tests of :func:`expected_part_hash`."""

    def test_single_part_file_is_checked_against_file_hash(self, fs: FakeFilesystem) -> None:
        """The expected hash of the only part of a small file is the file hash itself.

        :param fs: the in-memory file system.
        :type fs: FakeFilesystem
        """
        hashes = hash_file(pattern_file(fs, 3))

        assert (
            expected_part_hash(file_hash=hashes.file_hash, size=3, part_hashes=(), index=0) == hashes.file_hash.digest
        )


class TestEd2kHash:
    """Tests of :class:`Ed2kHash`."""

    def test_hash_round_trips_through_hex(self) -> None:
        """The hex form parses back to the same hash and malformed text is refused."""
        digest = Ed2kHash.from_hex('22155255A2ED92712CCD01AD0EB9E8CB')

        assert Ed2kHash.from_hex(digest.hex) == digest
        with pytest.raises(ProtocolError, match='hex'):
            Ed2kHash.from_hex('xyz')
