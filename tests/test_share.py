"""Unit tests of the shared library: what it withdraws instead of serving, on an in-memory file system."""

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from ed2k_client.errors import SecurityError
from ed2k_client.share import SharedLibrary

if TYPE_CHECKING:
    from pyfakefs.fake_filesystem import FakeFilesystem

STATE_DIR = Path('/state')
BOOK = Path('/books/book.pdf')
CONTENT = b'%PDF-1.7\n' + bytes(1000)


class TestRead:
    """Tests of :meth:`SharedLibrary.read`."""

    def test_deleted_file_is_withdrawn(self, fs: FakeFilesystem) -> None:
        """A shared file deleted from disk is refused as a security error and is no longer shared.

        The serving loop ends a session cleanly only on the package's own errors, so a plain file error would escape
        it for every request, and the file would stay offered under a hash nobody can be served.

        :param fs: the in-memory file system that holds the shared file.
        :type fs: FakeFilesystem
        """
        fs.create_dir(STATE_DIR)
        fs.create_file(BOOK, contents=CONTENT)
        library = SharedLibrary(state_dir=STATE_DIR)
        shared = library.add(BOOK)[0]
        BOOK.unlink()

        with pytest.raises(SecurityError, match='no longer shared'):
            library.read(shared=shared, start=0, end=len(CONTENT))
        assert library.get(shared.file_hash) is None
