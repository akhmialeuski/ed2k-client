"""Unit tests of the owner-only atomic file write that every state file of the client goes through."""

import stat
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from ed2k_client.files import FILE_MODE, write_private

if TYPE_CHECKING:
    from pyfakefs.fake_filesystem import FakeFilesystem

pytestmark = pytest.mark.usefixtures('fs')

STATE_FILE = Path('/state/servers.json')
OLD_CONTENT = b'["203.0.113.10:4661"]'
NEW_CONTENT = b'["203.0.113.20:4242", "203.0.113.10:4661"]'


class TestWritePrivate:
    """Tests of :func:`write_private`."""

    def test_content_replaces_the_file_readable_by_its_owner_only(self, fs: FakeFilesystem) -> None:
        """The new content replaces the old one, and the file stays private whatever mode it had.

        :param fs: the in-memory file system that holds the old file.
        :type fs: FakeFilesystem
        """
        fs.create_file(STATE_FILE, contents=OLD_CONTENT, st_mode=stat.S_IFREG | 0o644)

        write_private(STATE_FILE, NEW_CONTENT)

        assert (STATE_FILE.read_bytes(), stat.S_IMODE(STATE_FILE.stat().st_mode)) == (NEW_CONTENT, FILE_MODE)

    def test_failed_write_leaves_the_old_content(self, fs: FakeFilesystem) -> None:
        """A write that fails midway, here on a full disk, never leaves a half-written file in place of the old one.

        :param fs: the in-memory file system, filled up to the old file.
        :type fs: FakeFilesystem
        """
        fs.create_file(STATE_FILE, contents=OLD_CONTENT)
        fs.set_disk_usage(total_size=len(OLD_CONTENT))

        with pytest.raises(OSError, match='No space left'):
            write_private(STATE_FILE, NEW_CONTENT)

        assert STATE_FILE.read_bytes() == OLD_CONTENT
