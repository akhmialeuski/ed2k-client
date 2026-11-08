"""The files this client offers to others, served strictly by hash.

A peer names a file only by its eD2k hash, and the library maps the hash to a path the user added. Paths are
resolved once, symbolic links are refused, and a read checks that the file still has the size and modification time
it had when it was hashed, so a file swapped or truncated on disk is withdrawn instead of being served wrong.
Hashes are cached in the state directory, because hashing a library of books takes minutes.
"""

import json
import logging
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Literal

from ed2k_client.errors import SecurityError
from ed2k_client.files import write_private
from ed2k_client.hashing import Ed2kHash, hash_file
from ed2k_client.settings import DEFAULT_IO

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

logger = logging.getLogger(__name__)

CACHE_FILE: str = 'known_files.json'
ENCODING: str = 'utf-8'
READ_BINARY: Literal['rb'] = 'rb'


@dataclass(frozen=True, slots=True)
class SharedFile:
    """A file offered to the network.

    :ivar path: the resolved path.
    :ivar name: the published name.
    :ivar size: the size when hashed.
    :ivar mtime_ns: the modification time when hashed.
    :ivar file_hash: the eD2k hash.
    :ivar part_hashes: the hashset.
    """

    path: Path
    name: str
    size: int
    mtime_ns: int
    file_hash: Ed2kHash
    part_hashes: tuple[bytes, ...]


@dataclass(frozen=True, slots=True)
class CachedHash:
    """A cache record of one hashed file.

    :ivar size: the size when hashed.
    :ivar mtime_ns: the modification time when hashed.
    :ivar file_hash: the eD2k hash in hex.
    :ivar part_hashes: the hashset in hex.
    """

    size: int
    mtime_ns: int
    file_hash: str
    part_hashes: list[str]


class SharedLibrary:
    """Files offered by hash, with a persistent hash cache."""

    def __init__(self, *, state_dir: Path, read_chunk: int = DEFAULT_IO.read_chunk) -> None:
        """Load the hash cache.

        :param state_dir: the client's state directory.
        :type state_dir: Path
        :param read_chunk: bytes read at a time while hashing.
        :type read_chunk: int
        """
        self._cache_path = state_dir / CACHE_FILE
        self._read_chunk = read_chunk
        self._cache: dict[str, CachedHash] = {}
        if self._cache_path.exists():
            raw = json.loads(self._cache_path.read_text(encoding=ENCODING))
            self._cache = {path: CachedHash(**record) for path, record in raw.items()}

        self._files: dict[Ed2kHash, SharedFile] = {}

    @property
    def files(self) -> list[SharedFile]:
        """The shared files."""
        return list(self._files.values())

    def get(self, file_hash: Ed2kHash) -> SharedFile | None:
        """Find a shared file by hash.

        :param file_hash: the hash a peer asked for.
        :type file_hash: Ed2kHash
        :returns: the file, or ``None`` when it is not shared.
        :rtype: SharedFile | None
        """
        return self._files.get(file_hash)

    def add(self, path: Path) -> list[SharedFile]:
        """Share a file or every regular file directly inside a directory.

        :param path: a file or a directory.
        :type path: Path
        :returns: the files added.
        :rtype: list[SharedFile]
        :raises SecurityError: when the path is a symbolic link.
        """
        if path.is_symlink():
            err_msg = f'refusing to share the symbolic link {path}'
            raise SecurityError(err_msg)

        # One level only, and links inside the directory are skipped too, so sharing a folder never reaches
        # files outside it
        candidates: Iterable[Path] = sorted(path.iterdir()) if path.is_dir() else [path]
        added = [self._add_file(item.resolve()) for item in candidates if item.is_file() and not item.is_symlink()]
        self._save_cache()
        return added

    def _add_file(self, path: Path) -> SharedFile:
        """Hash a file, or take its hash from the cache, and index it.

        :param path: the resolved file.
        :type path: Path
        :returns: the shared file.
        :rtype: SharedFile
        """
        # Size and modification time decide whether a cached hash is still valid, as aMule matches its known files:
        # https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/KnownFileList.cpp#L75
        stat = path.stat()
        cached = self._cache.get(str(path))
        if cached is None or (cached.size, cached.mtime_ns) != (stat.st_size, stat.st_mtime_ns):
            logger.info('Hashing %s', path)
            hashes = hash_file(path, read_chunk=self._read_chunk)
            cached = CachedHash(
                size=stat.st_size,
                mtime_ns=stat.st_mtime_ns,
                file_hash=hashes.file_hash.hex,
                part_hashes=[item.hex() for item in hashes.part_hashes],
            )
            self._cache[str(path)] = cached

        shared = SharedFile(
            path=path,
            name=path.name,
            size=cached.size,
            mtime_ns=cached.mtime_ns,
            file_hash=Ed2kHash.from_hex(cached.file_hash),
            part_hashes=tuple(bytes.fromhex(item) for item in cached.part_hashes),
        )
        self._files[shared.file_hash] = shared
        return shared

    def _save_cache(self) -> None:
        """Write the hash cache atomically with owner-only permissions."""
        cache = {path: asdict(record) for path, record in self._cache.items()}
        write_private(self._cache_path, json.dumps(cache).encode(ENCODING))

    def read(self, *, shared: SharedFile, start: int, end: int) -> bytes:
        """Read a range of a shared file after checking it was not changed on disk.

        :param shared: the file.
        :type shared: SharedFile
        :param start: first offset.
        :type start: int
        :param end: offset after the last byte.
        :type end: int
        :returns: the bytes.
        :rtype: bytes
        :raises SecurityError: when the range is invalid, or the file changed or vanished since it was hashed.
        """
        if not 0 <= start < end <= shared.size:
            err_msg = f'range {start}-{end} is invalid for {shared.size} bytes'
            raise SecurityError(err_msg)

        # A changed file would be served under a hash it no longer has, and a deleted one under no file at all, so
        # either is withdrawn instead
        try:
            stat = shared.path.stat()
        except OSError as error:
            self._files.pop(shared.file_hash, None)
            err_msg = f'{shared.path} can no longer be read and is no longer shared'
            raise SecurityError(err_msg) from error
        if (stat.st_size, stat.st_mtime_ns) != (shared.size, shared.mtime_ns):
            self._files.pop(shared.file_hash, None)
            err_msg = f'{shared.path} changed since it was hashed and is no longer shared'
            raise SecurityError(err_msg)

        with shared.path.open(READ_BINARY) as stream:
            stream.seek(start)
            return stream.read(end - start)
