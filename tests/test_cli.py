"""Unit tests of the command line: input errors are reported before anything starts."""

from typing import TYPE_CHECKING

import pytest

from ed2k_client.cli import USAGE_ERROR, main
from ed2k_client.client import DEFAULT_STATE_DIR

if TYPE_CHECKING:
    from pyfakefs.fake_filesystem import FakeFilesystem

OFFLINE = ['--no-server', '--no-kad']
SEARCH = ['search', 'kademlia']


@pytest.mark.usefixtures('fs')
class TestMain:
    """Tests of :func:`main`, each on an empty in-memory file system."""

    def test_bad_server_link_is_a_usage_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        """A mistyped server link is reported in one line instead of a traceback.

        :param capsys: the captured output.
        :type capsys: pytest.CaptureFixture[str]
        """
        code = main([*SEARCH, '--server', 'ed2k://|server|bad|/', *OFFLINE])

        assert (code, capsys.readouterr().err) == (
            USAGE_ERROR,
            "error: not an ed2k server link: 'ed2k://|server|bad|/'\n",
        )

    def test_bad_flag_is_reported_without_a_file_name(self, capsys: pytest.CaptureFixture[str]) -> None:
        """A flag that breaks a setting is reported as itself, not as an error in a configuration file.

        :param capsys: the captured output.
        :type capsys: pytest.CaptureFixture[str]
        """
        code = main([*SEARCH, '--connect-timeout', '0', *OFFLINE])

        assert (code, capsys.readouterr().err) == (USAGE_ERROR, 'error: Timeouts.connect must be positive, not 0.0\n')

    def test_bad_link_stops_the_download_before_the_client_starts(self, fs: FakeFilesystem) -> None:
        """A malformed link among several fails the command before any client, identity or connection exists.

        :param fs: the in-memory file system, which must stay without a state directory.
        :type fs: FakeFilesystem
        """
        good = 'ed2k://|file|a.pdf|5|E737E3459E12C22118C48306FAE1D8EB|/'
        bad = 'ed2k://|file|b.pdf|0|E737E3459E12C22118C48306FAE1D8EB|/'

        code = main(['download', good, bad, *OFFLINE])

        assert code == USAGE_ERROR
        assert not fs.exists(DEFAULT_STATE_DIR)
