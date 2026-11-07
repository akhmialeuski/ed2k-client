"""Unit tests of the server lists: saving and reading a ``server.met`` and remembering servers that accepted a login."""

import stat
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from ed2k_client.errors import ProtocolError
from ed2k_client.servermet import ServerEntry, ServerList, ServerMemory
from tests.helpers import server_met

if TYPE_CHECKING:
    from unittest.mock import MagicMock

pytestmark = pytest.mark.usefixtures('fs')

FETCH = 'ed2k_client.servermet.fetch_https'
STATE_DIR = Path('/state')
SAVED_LIST = Path('/lists/server.met')
BUSY = ServerEntry(host='203.0.113.10', port=4661, name='busy', users=900)
QUIET = ServerEntry(host='203.0.113.20', port=4242, name='quiet', users=10)
SPARE = ServerEntry(host='203.0.113.30', port=5000, name='spare', users=50)
PRIVATE_FILE = 0o600


class TestServerListDownload:
    """Tests of :meth:`ServerList.download` with a file to save the list to."""

    @patch(FETCH, autospec=True)
    def test_downloaded_list_is_saved_as_it_arrived(self, fetch: MagicMock) -> None:
        """The bytes of a list that parsed are saved for its owner only and read back as the same servers.

        :param fetch: the mocked HTTPS download, which returns a list of two servers.
        :type fetch: MagicMock
        """
        fetch.return_value = server_met([BUSY, QUIET])
        SAVED_LIST.parent.mkdir()

        downloaded = ServerList.download(save_to=SAVED_LIST)

        assert SAVED_LIST.read_bytes() == fetch.return_value
        assert stat.S_IMODE(SAVED_LIST.stat().st_mode) == PRIVATE_FILE
        assert ServerList.load(SAVED_LIST).servers == downloaded.servers

    @patch(FETCH, autospec=True, return_value=b'not a server list')
    def test_broken_download_keeps_the_saved_copy(self, fetch: MagicMock) -> None:
        """A download that does not parse is refused and leaves the copy saved before untouched.

        :param fetch: the mocked HTTPS download, which returns bytes of no server list.
        :type fetch: MagicMock
        """
        del fetch
        SAVED_LIST.parent.mkdir()
        good = server_met([BUSY])
        SAVED_LIST.write_bytes(good)

        with pytest.raises(ProtocolError):
            ServerList.download(save_to=SAVED_LIST)
        assert SAVED_LIST.read_bytes() == good


class TestServerMemory:
    """Tests of :class:`ServerMemory`."""

    def test_remembered_servers_come_first_the_latest_login_first(self) -> None:
        """Servers that accepted a login lead, the latest first, and the rest keep the order they came in."""
        STATE_DIR.mkdir()
        memory = ServerMemory.load(STATE_DIR)
        memory.remember(QUIET)
        memory.remember(SPARE)

        assert memory.prefer([BUSY, QUIET, SPARE]) == [SPARE, QUIET, BUSY]

    def test_refused_server_is_forgotten_and_the_memory_survives_a_reload(self) -> None:
        """A server that refused a login is dropped, and a new client reads the order the last one left."""
        STATE_DIR.mkdir()
        memory = ServerMemory.load(STATE_DIR)
        for server in (BUSY, QUIET, SPARE):
            memory.remember(server)
        memory.forget(QUIET)

        assert ServerMemory.load(STATE_DIR).addresses == [SPARE.address, BUSY.address]

    def test_remembered_server_absent_from_the_list_is_not_offered(self) -> None:
        """A remembered server that left the current list is not returned, so it is never dialled."""
        STATE_DIR.mkdir()
        memory = ServerMemory.load(STATE_DIR)
        memory.remember(SPARE)

        assert memory.prefer([BUSY, QUIET]) == [BUSY, QUIET]
