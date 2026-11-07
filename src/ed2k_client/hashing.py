"""The eD2k file hash: MD4 over 9,728,000-byte parts and MD4 over the list of part hashes.

The rules follow ``CKnownFile::SetFileSize`` in aMule. A file shorter than one part has no part hashes and its hash
is the MD4 of the content. A longer file has one hash per part, and a file whose size is an exact multiple of the
part size gets one more hash, the MD4 of the empty string, which takes part in the file hash too.

MD4 comes from pycryptodome because OpenSSL 3, and therefore ``hashlib``, no longer offers it by default.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Self, override

from Crypto.Hash import MD4

from ed2k_client.constants import HASH_LENGTH, PART_SIZE
from ed2k_client.errors import ProtocolError
from ed2k_client.settings import DEFAULT_IO

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


@dataclass(frozen=True, slots=True, order=True)
class Ed2kHash:
    """A 16-byte eD2k file hash.

    :ivar digest: the raw hash bytes.
    """

    digest: bytes

    def __post_init__(self) -> None:
        """Reject a digest of the wrong length.

        :raises ProtocolError: when the digest is not 16 bytes long.
        """
        if len(self.digest) != HASH_LENGTH:
            err_msg = f'eD2k hash must be {HASH_LENGTH} bytes, got {len(self.digest)}'
            raise ProtocolError(err_msg)

    @classmethod
    def from_hex(cls, text: str) -> Self:
        """Parse 32 hexadecimal digits.

        :param text: the hex text, in any case.
        :type text: str
        :returns: the hash.
        :rtype: Self
        :raises ProtocolError: when the text is not 32 hex digits.
        """
        try:
            return cls(bytes.fromhex(text))
        except ValueError as error:
            err_msg = f'not a hex hash: {text!r}'
            raise ProtocolError(err_msg) from error

    @property
    def hex(self) -> str:
        """Upper-case hex form used in ed2k links."""
        return self.digest.hex().upper()

    @override
    def __str__(self) -> str:
        """Return the upper-case hex form.

        :returns: the hex text.
        :rtype: str
        """
        return self.hex


@dataclass(frozen=True, slots=True)
class FileHashes:
    """The eD2k hash of a file with the hashes of its parts.

    :ivar file_hash: the eD2k hash.
    :ivar part_hashes: the hashset, empty for a file shorter than one part.
    :ivar size: the file size in bytes.
    """

    file_hash: Ed2kHash
    part_hashes: tuple[bytes, ...]
    size: int


def md4(data: bytes) -> bytes:
    """Hash bytes with MD4.

    :param data: the input.
    :type data: bytes
    :returns: the 16-byte digest.
    :rtype: bytes
    """
    return MD4.new(data).digest()


def part_count(size: int) -> int:
    """Count the parts that ``OP_FILESTATUS`` reports for a file, which is one more for an exact multiple.

    :param size: file size in bytes.
    :type size: int
    :returns: the number of eD2k parts.
    :rtype: int
    """
    # aMule's table of sizes and counts: https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/KnownFile.cpp#L446
    return size // PART_SIZE + 1


def data_part_count(size: int) -> int:
    """Count the parts that actually hold data.

    :param size: file size in bytes.
    :type size: int
    :returns: the number of parts with at least one byte.
    :rtype: int
    """
    # Ceiling division, and an empty file still has one empty part
    return max(1, -(-size // PART_SIZE))


def hashset_length(size: int) -> int:
    """Count the part hashes the hashset of a file must contain.

    :param size: file size in bytes.
    :type size: int
    :returns: zero for a single-part file, otherwise the number of eD2k parts.
    :rtype: int
    """
    return 0 if size < PART_SIZE else part_count(size)


def hash_from_parts(part_hashes: Sequence[bytes]) -> Ed2kHash:
    """Combine a hashset into the file hash.

    :param part_hashes: the part hashes in order, at least two.
    :type part_hashes: Sequence[bytes]
    :returns: the file hash.
    :rtype: Ed2kHash
    """
    return Ed2kHash(md4(b''.join(part_hashes)))


def verify_hashset(*, file_hash: Ed2kHash, size: int, part_hashes: Sequence[bytes]) -> bool:
    """Check that a hashset received from a peer belongs to the file.

    :param file_hash: the expected file hash.
    :type file_hash: Ed2kHash
    :param size: the file size.
    :type size: int
    :param part_hashes: the hashset to check.
    :type part_hashes: Sequence[bytes]
    :returns: whether the hashset has the right length and combines into the file hash.
    :rtype: bool
    """
    if len(part_hashes) != hashset_length(size):
        return False
    return not part_hashes or hash_from_parts(part_hashes) == file_hash


def expected_part_hash(*, file_hash: Ed2kHash, size: int, part_hashes: Sequence[bytes], index: int) -> bytes:
    """Return the hash a downloaded part must have.

    :param file_hash: the file hash, which is the part hash of a single-part file.
    :type file_hash: Ed2kHash
    :param size: the file size.
    :type size: int
    :param part_hashes: the verified hashset.
    :type part_hashes: Sequence[bytes]
    :param index: the zero-based part index.
    :type index: int
    :returns: the expected MD4 of the part.
    :rtype: bytes
    """
    return file_hash.digest if hashset_length(size) == 0 else part_hashes[index]


def hash_file(path: Path, *, read_chunk: int = DEFAULT_IO.read_chunk) -> FileHashes:
    """Compute the eD2k hash and hashset of a file on disk.

    :param path: the file.
    :type path: Path
    :param read_chunk: bytes read at a time.
    :type read_chunk: int
    :returns: the hashes and the size.
    :rtype: FileHashes
    """
    part_hashes: list[bytes] = []
    size = 0
    part_size = PART_SIZE
    with path.open('rb') as stream:
        # A full part is always followed by one more round, so an exact multiple ends with the empty-part hash
        while part_size == PART_SIZE:
            part = MD4.new()
            part_size = 0
            while part_size < PART_SIZE and (chunk := stream.read(min(read_chunk, PART_SIZE - part_size))):
                part.update(chunk)
                part_size += len(chunk)
            size += part_size
            part_hashes.append(part.digest())

    # Below one part the single part hash is the file hash and no hashset exists
    if size < PART_SIZE:
        return FileHashes(file_hash=Ed2kHash(part_hashes[0]), part_hashes=(), size=size)
    return FileHashes(file_hash=hash_from_parts(part_hashes), part_hashes=tuple(part_hashes), size=size)
