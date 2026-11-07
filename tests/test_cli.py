"""Tests of the command line: input errors are reported before anything starts."""

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from ed2k_client.cli import USAGE_ERROR, main
from ed2k_client.client import DEFAULT_STATE_DIR
from ed2k_client.servermet import ServerList

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

    from pyfakefs.fake_filesystem import FakeFilesystem

OFFLINE = ['--no-server', '--no-kad']
SEARCH = ['search', 'kademlia']
MISSING = '/missing/book.pdf'
SHELF = '/books'
HASH = 'hash'
NO_SUCH_PATH = 'error: no such file or directory: '
MISSING_NAME = 'missing.dat'
GOOD_LINK = 'ed2k://|file|a.pdf|5|E737E3459E12C22118C48306FAE1D8EB|/'
SAVED_LIST = '/lists/server.met'
DOWNLOAD = 'download'
SHARE = 'share'


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
        bad = 'ed2k://|file|b.pdf|0|E737E3459E12C22118C48306FAE1D8EB|/'

        code = main([DOWNLOAD, GOOD_LINK, bad, *OFFLINE])

        assert code == USAGE_ERROR
        assert not fs.exists(DEFAULT_STATE_DIR)

    @pytest.mark.parametrize(
        ('command', 'message'),
        [
            ([DOWNLOAD, GOOD_LINK, '--max-peers', '0'], 'DownloadSettings.max_peers must be positive, not 0'),
            ([DOWNLOAD, GOOD_LINK, '--deadline-hours', '0'], 'DownloadSettings.deadline must be positive, not 0.0'),
            ([SHARE, '/', '--upload-slots', '0'], 'ShareSettings.upload_slots must be positive, not 0'),
            (['search', '..'], 'a search needs at least one word'),
        ],
        ids=['no peers', 'no time', 'no upload slots', 'no words'],
    )
    def test_bad_command_value_is_a_usage_error(
        self, fs: FakeFilesystem, capsys: pytest.CaptureFixture[str], command: list[str], message: str
    ) -> None:
        """A flag value of one command, or a query without words, is a usage error before any client starts.

        These values are checked by the settings and the query when they are built, so a command that builds them
        only once its client runs ends in a traceback after the identity and the lock already exist.

        :param fs: the in-memory file system, which must stay without a state directory.
        :type fs: FakeFilesystem
        :param capsys: the captured output.
        :type capsys: pytest.CaptureFixture[str]
        :param command: the command line with the bad value.
        :type command: list[str]
        :param message: the error the command must report.
        :type message: str
        """
        code = main([*command, *OFFLINE])

        assert (code, capsys.readouterr().err) == (USAGE_ERROR, f'error: {message}\n')
        assert not fs.exists(DEFAULT_STATE_DIR)

    @pytest.mark.parametrize(
        'arguments',
        [[HASH, MISSING], [SHARE, MISSING, '--seconds', '0', '--port', '0', *OFFLINE]],
        ids=['hashed file', 'shared path'],
    )
    def test_missing_path_argument_is_a_usage_error(
        self, capsys: pytest.CaptureFixture[str], arguments: list[str]
    ) -> None:
        """A file or directory argument that does not exist is reported in one line before any client starts.

        Without the check, hash ends in a traceback and share keeps its listener open for the whole sharing time with
        nothing to share.

        :param capsys: the captured output.
        :type capsys: pytest.CaptureFixture[str]
        :param arguments: the command line naming the missing path.
        :type arguments: list[str]
        """
        code = main(arguments)

        assert (code, capsys.readouterr().err) == (USAGE_ERROR, f'{NO_SUCH_PATH}{MISSING}\n')

    def test_directory_to_hash_is_a_usage_error(self, fs: FakeFilesystem, capsys: pytest.CaptureFixture[str]) -> None:
        """A directory given to hash is reported in one line, as hash reads files only.

        The directory exists, so the check for missing paths lets it through, and reading it as a file ends in a
        traceback with exit code 1.

        :param fs: the in-memory file system that holds the directory.
        :type fs: FakeFilesystem
        :param capsys: the captured output.
        :type capsys: pytest.CaptureFixture[str]
        """
        fs.create_dir(SHELF)

        code = main([HASH, SHELF])

        assert (code, capsys.readouterr().err) == (USAGE_ERROR, f'error: not a file: {SHELF}\n')

    @patch.object(ServerList, DOWNLOAD, return_value=ServerList(servers=()))
    def test_servers_save_hands_the_file_to_the_download(self, download: MagicMock) -> None:
        """The servers command with --save asks the download to save the list it fetches to that file.

        :param download: the mocked download, which returns an empty list.
        :type download: MagicMock
        """
        code = main(['servers', '--save', SAVED_LIST])

        assert code == 0
        assert str(download.call_args.kwargs['save_to']) == SAVED_LIST


@pytest.mark.integration
class TestMainPathSettings:
    """Tests of :func:`main` with path settings, in a temporary directory.

    pyfakefs replaces ``Path`` in every module with an object that is not a class, so the settings conversion, which
    turns a string into a path only for a ``Path`` class, refuses every path setting on the in-memory file system.
    """

    @pytest.mark.parametrize('flag', ['--nodes-dat', '--server-met'])
    def test_missing_path_flag_is_a_usage_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], flag: str
    ) -> None:
        """A flag naming a missing nodes.dat or server.met is reported in one line instead of failing once it is read.

        :param tmp_path: the directory that holds the state and lacks the named file.
        :type tmp_path: Path
        :param capsys: the captured output.
        :type capsys: pytest.CaptureFixture[str]
        :param flag: the flag that names the missing file.
        :type flag: str
        """
        missing = tmp_path / MISSING_NAME

        code = main([*SEARCH, flag, str(missing), *OFFLINE, '--state-dir', str(tmp_path)])

        assert (code, capsys.readouterr().err) == (USAGE_ERROR, f'{NO_SUCH_PATH}{missing}\n')

    def test_missing_ip_filter_in_the_config_is_a_usage_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """An IP filter that the configuration file names but that does not exist is reported in one line.

        Without the check the client reads the filter while it starts, and the error leaves as a traceback.

        :param tmp_path: the directory that holds the state and the configuration file and lacks the filter.
        :type tmp_path: Path
        :param capsys: the captured output.
        :type capsys: pytest.CaptureFixture[str]
        """
        missing = tmp_path / MISSING_NAME
        config = tmp_path / 'ed2k.toml'
        config.write_text(f"state_dir = '{tmp_path}'\nip_filter = '{missing}'\n", encoding='utf-8')

        code = main(['--config', str(config), *SEARCH, *OFFLINE])

        assert (code, capsys.readouterr().err) == (USAGE_ERROR, f'{NO_SUCH_PATH}{missing}\n')
