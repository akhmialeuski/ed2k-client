"""Unit tests of the settings: their checks, the TOML loader, the command line overrides and the limits they carry."""

import struct
import tomllib
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from ed2k_client.cli import build_config, build_parser
from ed2k_client.client import ClientConfig
from ed2k_client.download import ContentPolicy, DownloadSettings
from ed2k_client.errors import ProtocolError
from ed2k_client.kad.contacts import parse_nodes_dat
from ed2k_client.search import parse_server_results
from ed2k_client.servermet import ServerList
from ed2k_client.settings import (
    IoSettings,
    KadSettings,
    Limits,
    PeerSettings,
    Timeouts,
    settings_from_mapping,
)
from ed2k_client.tags import read_tags
from ed2k_client.wire import Reader

if TYPE_CHECKING:
    from pyfakefs.fake_filesystem import FakeFilesystem

CONFIG = Path('/config/ed2k.toml')
COUNT = struct.Struct('<I')
NODES_DAT_HEADER = struct.Struct('<III')
SERVER_MET_HEADER = struct.Struct('<BI')
CONNECT = 'connect'
CONNECT_NOT_FLOAT = 'connect must be float'
LIMIT_OF_TWO = 'limit of 2'


class TestCheckPositive:
    """Tests of the checks every settings group runs when it is built."""

    @pytest.mark.parametrize(
        'build',
        [
            lambda: Timeouts(connect=0),
            lambda: Limits(tags=-1),
            lambda: KadSettings(alpha=0),
            lambda: DownloadSettings(deadline=0),
            lambda: PeerSettings(blocks_per_request=4),
            lambda: IoSettings(scan_chunk=1024),
        ],
        ids=['zero timeout', 'negative limit', 'zero alpha', 'zero deadline', 'four blocks', 'tiny scan chunk'],
    )
    def test_settings_refuse_impossible_values(self, build: object) -> None:
        """A value that cannot work is refused when the settings object is built, not when the network is used.

        :param build: builds a settings object with one impossible value.
        :type build: object
        """
        assert callable(build)

        with pytest.raises(ValueError, match=r'must|cannot|hold'):
            build()


class TestSettingsFromMapping:
    """Tests of :func:`settings_from_mapping`."""

    def test_mapping_overrides_only_the_given_keys(self) -> None:
        """Keys of a table replace their fields, a whole number fills a float field, and the rest keep their values."""
        timeouts = settings_from_mapping(Timeouts, {CONNECT: 30, 'read': 90.5})

        assert timeouts == replace(Timeouts(), connect=30.0, read=90.5)
        assert isinstance(timeouts.connect, float)

    @pytest.mark.parametrize(
        ('data', 'raised', 'message'),
        [
            ({'conect': 30}, ValueError, 'unknown setting conect'),
            ({CONNECT: 'soon'}, TypeError, CONNECT_NOT_FLOAT),
            ({CONNECT: True}, TypeError, CONNECT_NOT_FLOAT),
        ],
        ids=['typo', 'text for a number', 'boolean for a number'],
    )
    def test_mapping_refuses_bad_keys_and_types(
        self, data: dict[str, object], raised: type[Exception], message: str
    ) -> None:
        """A misspelt key, a text or a boolean where a number belongs is refused with the key in the message.

        :param data: the parsed table.
        :type data: dict[str, object]
        :param raised: the exception class expected.
        :type raised: type[Exception]
        :param message: the text the error must contain.
        :type message: str
        """
        with pytest.raises(raised, match=message):
            settings_from_mapping(Timeouts, data)

    def test_boolean_is_not_an_integer_setting(self) -> None:
        """True passes isinstance(int), so an integer field checks the exact type."""
        with pytest.raises(TypeError, match='tags must be int'):
            settings_from_mapping(Limits, {'tags': True})


class TestClientConfigFromMapping:
    """Tests of :meth:`ClientConfig.from_mapping`."""

    def test_config_table_fills_every_group(self) -> None:
        """A TOML table sets top-level values, nested tables, an enumeration by name, paths and server links."""
        table = tomllib.loads(
            """
    nickname = 'reader'
    download_dir = '/books'
    servers = ['ed2k://|server|85.17.116.222|6082|/']

    [download]
    deadline = 86400
    content_policy = 'any'

    [kad]
    alpha = 3

    [limits]
    string_bytes = 4096
    """
        )

        config = ClientConfig.from_mapping(table)

        assert config.nickname == 'reader'
        assert config.download_dir == Path('/books')
        assert [(server.host, server.port) for server in config.servers] == [('85.17.116.222', 6082)]
        assert config.download == replace(DownloadSettings(), deadline=86_400.0, content_policy=ContentPolicy.ANY)
        assert config.kad == replace(KadSettings(), alpha=3)
        assert config.limits == replace(Limits(), string_bytes=4096)
        assert config.timeouts == Timeouts()


class TestClientConfigFromToml:
    """Tests of :meth:`ClientConfig.from_toml`."""

    @pytest.mark.parametrize(
        ('contents', 'failure'),
        [
            ('[download]\nmax_peers = 0\n', ValueError),
            ('[download]\ncontent_policy = "executables"\n', ValueError),
            ('kad = 5\n', TypeError),
            ("servers = 'ed2k://|server|1.2.3.4|4661|/'\n", TypeError),
        ],
        ids=['zero peers', 'unknown policy', 'scalar for a table', 'text for a list'],
    )
    def test_config_file_refuses_bad_values(self, fs: FakeFilesystem, contents: str, failure: type[Exception]) -> None:
        """A value the settings refuse fails when the file is read.

        :param fs: the in-memory file system.
        :type fs: FakeFilesystem
        :param contents: the configuration file text.
        :type contents: str
        :param failure: the exception class expected.
        :type failure: type[Exception]
        """
        fs.create_file(CONFIG, contents=contents)

        with pytest.raises(failure):
            ClientConfig.from_toml(CONFIG)


class TestBuildConfig:
    """Tests of :func:`build_config`."""

    def test_flags_win_over_the_file(self, fs: FakeFilesystem) -> None:
        """A command line flag overrides the file, and the file overrides the defaults.

        :param fs: the in-memory file system.
        :type fs: FakeFilesystem
        """
        fs.create_file(CONFIG, contents='udp_port = 5000\ntcp_port = 5001\n[timeouts]\nconnect = 40\nread = 50\n')
        arguments = build_parser().parse_args(
            ['--config', str(CONFIG), 'search', 'kademlia', '--udp-port', '0', '--connect-timeout', '5']
        )

        config = build_config(arguments)

        assert (config.udp_port, config.tcp_port) == (0, 5001)
        assert (config.timeouts.connect, config.timeouts.read) == (5.0, 50.0)


class TestLimits:
    """Tests that the :class:`Limits` given to a parser are the ones it applies."""

    def test_reader_limits_reach_strings_and_tags(self) -> None:
        """A Reader built with tighter limits refuses a string and a tag count the defaults would accept."""
        tight = Limits(string_bytes=4, tags=1)

        with pytest.raises(ProtocolError, match='limit of 4'):
            Reader(b'\x05\x00hello', limits=tight).string()
        with pytest.raises(ProtocolError, match='limit of 1'):
            read_tags(Reader(COUNT.pack(2), limits=tight))

    def test_result_limit_reaches_the_search_parser(self) -> None:
        """A server page announcing more results than the limit is refused before any is read."""
        with pytest.raises(ProtocolError, match=LIMIT_OF_TWO):
            parse_server_results(Reader(COUNT.pack(3), limits=Limits(search_results=2)))

    def test_list_limits_reach_server_met_and_nodes_dat(self) -> None:
        """The server and contact counts of the bootstrap files are checked against the configured limits."""
        with pytest.raises(ProtocolError, match=LIMIT_OF_TWO):
            ServerList.parse(SERVER_MET_HEADER.pack(0x0E, 3), limits=Limits(server_met_servers=2))
        with pytest.raises(ProtocolError, match=LIMIT_OF_TWO):
            parse_nodes_dat(NODES_DAT_HEADER.pack(0, 2, 3), limits=Limits(nodes_dat_contacts=2))
