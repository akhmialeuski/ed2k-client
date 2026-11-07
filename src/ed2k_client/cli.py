"""Command line front end of :class:`ed2k_client.Client`.

Subcommands: ``servers`` lists the server list, ``search`` searches a server and Kad, ``download`` fetches a file by
``ed2k://`` link, ``hash`` prints the link of a local file and ``share`` serves files for a while.

Every setting of :class:`ed2k_client.ClientConfig` can be set in a TOML file passed with ``--config``, and the most
used ones also have flags. A flag wins over the file, and the file wins over the defaults.
"""

import argparse
import asyncio
import json
import logging
import sys
import tomllib
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from ed2k_client.client import Client, ClientConfig
from ed2k_client.download import AichPolicy, ContentPolicy
from ed2k_client.errors import Ed2kError
from ed2k_client.hashing import hash_file
from ed2k_client.links import FileLink, ServerLink
from ed2k_client.search import FileType, SearchQuery
from ed2k_client.servermet import DEFAULT_SERVER_MET_URL, ServerEntry, ServerList
from ed2k_client.settings import SECONDS_PER_HOUR, Timeouts, settings_from_mapping

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ed2k_client.download import DownloadProgress
    from ed2k_client.search import SearchResult

MEBIBYTE: int = 1024 * 1024
LOG_FORMAT: str = '%(asctime)s %(levelname)s %(name)s %(message)s'
FLAG: str = 'store_true'
USAGE_ERROR: int = 2
ERROR_PREFIX: str = 'error: '
LINKS_ARGUMENT: str = 'links'
TEXT_ARGUMENT: str = 'text'
PATH_ARGUMENT: str = 'path'
PATHS_ARGUMENT: str = 'paths'

# Network flags and the settings they override, at the top level of ClientConfig and inside its timeouts
CONFIG_FLAGS: tuple[tuple[str, str], ...] = (
    ('state_dir', 'state_dir'),
    ('download_dir', 'download_dir'),
    ('nodes_dat', 'nodes_dat'),
    ('server_met', 'server_met'),
    ('port', 'tcp_port'),
    ('udp_port', 'udp_port'),
)
TIMEOUT_FLAGS: tuple[tuple[str, str], ...] = (('connect_timeout', 'connect'), ('read_timeout', 'read'))


def build_config(arguments: argparse.Namespace) -> ClientConfig:
    """Build the client settings from the configuration file and the flags.

    :param arguments: the parsed command line.
    :type arguments: argparse.Namespace
    :returns: the settings.
    :rtype: ClientConfig
    """
    config = ClientConfig.from_toml(Path(arguments.config)) if arguments.config else ClientConfig()

    # The network flags exist only on the commands that talk to the network
    config = _apply_network_flags(config, arguments) if 'state_dir' in arguments else config
    return _apply_command_flags(config, arguments)


def _apply_command_flags(config: ClientConfig, arguments: argparse.Namespace) -> ClientConfig:
    """Override the settings with the flags of the download and share commands.

    The settings refuse an impossible value when they are built, so building them here lets :func:`main` report it
    before any client starts.

    :param config: the settings from the defaults, the configuration file and the network flags.
    :type config: ClientConfig
    :param arguments: the parsed command line.
    :type arguments: argparse.Namespace
    :returns: the settings.
    :rtype: ClientConfig
    """
    download = config.download
    if getattr(arguments, 'any_content', False):
        download = replace(download, content_policy=ContentPolicy.ANY)
    if getattr(arguments, 'documents_only', False):
        download = replace(download, content_policy=ContentPolicy.DOCUMENTS)
    if getattr(arguments, 'allow_md4_only', False):
        download = replace(download, aich=AichPolicy.PREFER)
    if (hours := getattr(arguments, 'deadline_hours', None)) is not None:
        download = replace(download, deadline=hours * SECONDS_PER_HOUR)
    if (peers := getattr(arguments, 'max_peers', None)) is not None:
        download = replace(download, max_peers=peers)

    share = config.share
    if (slots := getattr(arguments, 'upload_slots', None)) is not None:
        share = replace(share, upload_slots=slots)
    return replace(config, download=download, share=share)


def _apply_network_flags(config: ClientConfig, arguments: argparse.Namespace) -> ClientConfig:
    """Override the settings with the flags shared by the network commands.

    :param config: the settings from the defaults and the configuration file.
    :type config: ClientConfig
    :param arguments: the parsed command line of a network command.
    :type arguments: argparse.Namespace
    :returns: the settings.
    :rtype: ClientConfig
    """
    # A flag that was not given is None and leaves the setting from the file or the default alone. The flags go
    # through the same checks as the file, so a bad value fails the same way
    changes = {field: getattr(arguments, flag) for flag, field in CONFIG_FLAGS if getattr(arguments, flag) is not None}
    timeouts = {
        field: getattr(arguments, flag) for flag, field in TIMEOUT_FLAGS if getattr(arguments, flag) is not None
    }
    config = settings_from_mapping(ClientConfig, changes, base=config)
    config = replace(config, timeouts=settings_from_mapping(Timeouts, timeouts, base=config.timeouts))

    if arguments.server:
        link = ServerLink.parse(arguments.server)
        config = replace(config, servers=(ServerEntry(host=link.host, port=link.port),))
    return config


async def _connect(client: Client, arguments: argparse.Namespace) -> None:
    """Connect to the servers and Kad unless the command line skips them, reporting on stderr.

    :param client: the client.
    :type client: Client
    :param arguments: the parsed command line.
    :type arguments: argparse.Namespace
    """
    if not arguments.no_server:
        for session in (await client.connect()).servers:
            print(f'server {session.server.address} id {session.client_id} low_id {session.low_id}', file=sys.stderr)
    if not arguments.no_kad:
        print(f'kad contacts {await client.connect_kad()}', file=sys.stderr)


def _row(result: SearchResult) -> dict[str, object]:
    """Turn a result into a JSON-ready row.

    :param result: the search result.
    :type result: SearchResult
    :returns: the row.
    :rtype: dict[str, object]
    """
    return {
        'name': result.name,
        'size': result.size,
        'sources': result.sources,
        'complete': result.complete_sources,
        'origin': result.origin,
        'seen_on': result.seen_on,
        'ed2k': str(result.link),
    }


async def _search(arguments: argparse.Namespace) -> None:
    """Run the ``search`` command and print the results as a table or JSON.

    :param arguments: the parsed command line, whose query :func:`main` has already built.
    :type arguments: argparse.Namespace
    """
    async with Client(build_config(arguments)) as client:
        await _connect(client, arguments)
        results = await client.search(arguments.query)

    # The table goes to stdout and the connection status to stderr, so --json output can be piped as it is
    if arguments.json:
        print(json.dumps([_row(result) for result in results], ensure_ascii=False, indent=2))
        return

    # The first number after the index counts the servers and Kad that reported the file
    for index, result in enumerate(results, 1):
        size = result.size / MEBIBYTE
        print(f'{index:3} {result.seen_on:2}x {result.sources:4} {size:8.1f} MiB  {result.origin:6} {result.name}')
        print(f'    {result.link}')


class ProgressPrinter:
    """Print one line per file whenever another part of it is verified."""

    def __init__(self) -> None:
        """Start with nothing reported."""
        self._reported: dict[str, int] = {}

    def __call__(self, progress: DownloadProgress) -> None:
        """Print the progress of a file if its verified size changed.

        :param progress: the snapshot.
        :type progress: DownloadProgress
        """
        if self._reported.get(progress.name) == progress.verified_bytes:
            return
        self._reported[progress.name] = progress.verified_bytes
        share = progress.verified_bytes / progress.size if progress.size else 0
        print(f'{share:6.1%} {progress.name} ({progress.active_peers} peers, {progress.known_sources} sources)')


async def _download(arguments: argparse.Namespace) -> None:
    """Download every link given, concurrently, with one client and therefore one identity.

    :param arguments: the parsed command line, whose links :func:`main` has already parsed.
    :type arguments: argparse.Namespace
    """
    printer = ProgressPrinter()
    async with Client(build_config(arguments)) as client:
        await _connect(client, arguments)

        # return_exceptions keeps one failed link from cancelling the downloads of the others
        outcomes = await asyncio.gather(
            *(client.download(link, progress=printer) for link in arguments.links),
            return_exceptions=True,
        )

    for link, outcome in zip(arguments.links, outcomes, strict=True):
        if isinstance(outcome, BaseException):
            print(f'failed {link.name}: {outcome}')
        else:
            print(f'saved {outcome.path} ({outcome.inspection.kind}, notable {list(outcome.inspection.notable)})')


async def _share(arguments: argparse.Namespace) -> None:
    """Run the ``share`` command: offer files and keep serving for the given time.

    :param arguments: the parsed command line.
    :type arguments: argparse.Namespace
    """
    async with Client(build_config(arguments)) as client:
        await _connect(client, arguments)
        for shared in await client.share(Path(arguments.path)):
            print(f'sharing {FileLink(name=shared.name, size=shared.size, file_hash=shared.file_hash)}')
        await asyncio.sleep(arguments.seconds)


def _servers(arguments: argparse.Namespace) -> None:
    """Run the ``servers`` command, print the server list by users and save it when asked to.

    :param arguments: the parsed command line.
    :type arguments: argparse.Namespace
    """
    config = build_config(arguments)
    save_to = Path(arguments.save) if arguments.save else None
    servers = ServerList.download(
        arguments.url, limits=config.limits, timeout=config.timeouts.bootstrap_fetch, save_to=save_to
    )
    for server in servers.by_users():
        print(f'{server.address:22} {server.users:7} users {server.files:10} files  {server.name}')


def _hash(arguments: argparse.Namespace) -> None:
    """Run the ``hash`` command and print the ed2k link of every file.

    :param arguments: the parsed command line.
    :type arguments: argparse.Namespace
    """
    read_chunk = build_config(arguments).io.read_chunk
    for name in arguments.paths:
        path = Path(name)
        hashes = hash_file(path, read_chunk=read_chunk)
        print(FileLink(name=path.name, size=hashes.size, file_hash=hashes.file_hash))


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with every subcommand.

    :returns: the parser.
    :rtype: argparse.ArgumentParser
    """
    parser = argparse.ArgumentParser(prog='ed2k-client', description=__doc__)
    parser.add_argument('-v', '--verbose', action=FLAG, help='log protocol details')
    parser.add_argument('--config', help='TOML file with settings, see config.example.toml')
    commands = parser.add_subparsers(dest='command', required=True)

    # Options shared by every command that talks to the network
    network = argparse.ArgumentParser(add_help=False)
    network.add_argument('--state-dir', help='identity and caches')
    network.add_argument('--download-dir', help='finished downloads')
    network.add_argument('--server', help='ed2k://|server|ip|port|/ to use instead of the list')
    network.add_argument('--nodes-dat', help='local nodes.dat instead of the download')
    network.add_argument('--server-met', help='local server.met instead of the download, see servers --save')
    network.add_argument('--port', type=int, help='TCP port to announce and to listen on, 0 for any free port')
    network.add_argument('--udp-port', type=int, help='local Kad UDP port, 0 for any free port')
    network.add_argument('--no-server', action=FLAG, help='skip the eD2k server')
    network.add_argument('--no-kad', action=FLAG, help='skip Kad')
    network.add_argument('--connect-timeout', type=float, help='seconds for a TCP connect and its handshake')
    network.add_argument('--read-timeout', type=float, help='seconds of silence before a peer connection drops')

    search = commands.add_parser('search', parents=[network], help='search by words and extension')
    search.add_argument(TEXT_ARGUMENT)
    search.add_argument(
        '--ext', nargs='*', default=[], help='accepted extensions, such as pdf djvu epub, any when absent'
    )
    search.add_argument('--documents', action=FLAG, help='restrict to the server type Doc')
    search.add_argument('--json', action=FLAG)
    search.set_defaults(handler=_search)

    download = commands.add_parser('download', parents=[network], help='download ed2k:// file links concurrently')
    download.add_argument(LINKS_ARGUMENT, nargs='+', metavar='link')
    content = download.add_mutually_exclusive_group()
    content.add_argument('--documents-only', action=FLAG, help='release only PDF and DjVu files without active content')
    content.add_argument('--any-content', action=FLAG, help='release every file, programs included')
    download.add_argument(
        '--allow-md4-only',
        action=FLAG,
        help='accept a part on its MD4 alone when the link has an AICH root but no peer serves the AICH hashes',
    )
    download.add_argument('--deadline-hours', type=float, help='give up after this many hours')
    download.add_argument('--max-peers', type=int, help='sources downloaded from at the same time')
    download.set_defaults(handler=_download)

    share = commands.add_parser('share', parents=[network], help='share a file or directory for a while')
    share.add_argument(PATH_ARGUMENT)
    share.add_argument('--seconds', type=float, default=SECONDS_PER_HOUR)
    share.add_argument('--upload-slots', type=int, help='peers served at the same time')
    share.set_defaults(handler=_share)

    servers = commands.add_parser('servers', help='list the servers of a server.met')
    servers.add_argument('--url', default=DEFAULT_SERVER_MET_URL)
    servers.add_argument('--save', metavar='FILE', help='also save the downloaded server.met to this file')
    servers.set_defaults(handler=_servers, sync=True)

    # servers and hash run without an event loop, because they do no asynchronous work
    file_hash = commands.add_parser('hash', help='print the ed2k link of local files')
    file_hash.add_argument(PATHS_ARGUMENT, nargs='+')
    file_hash.set_defaults(handler=_hash, sync=True)
    return parser


def _check_local_paths(arguments: argparse.Namespace, config: ClientConfig) -> None:
    """Refuse a local path that the command line or the settings name and that does not exist or has the wrong kind.

    :param arguments: the parsed command line.
    :type arguments: argparse.Namespace
    :param config: the settings built from the configuration file and the flags.
    :type config: ClientConfig
    :raises FileNotFoundError: for the first path that does not exist.
    :raises IsADirectoryError: for a path to hash that is a directory, since hash reads files only.
    """
    named = [
        *getattr(arguments, PATHS_ARGUMENT, ()),
        getattr(arguments, PATH_ARGUMENT, None),
        config.nodes_dat,
        config.server_met,
        config.ip_filter,
    ]
    for path in (Path(item) for item in named if item is not None):
        if not path.exists():
            err_msg = f'no such file or directory: {path}'
            raise FileNotFoundError(err_msg)

    for name in getattr(arguments, PATHS_ARGUMENT, ()):
        if Path(name).is_dir():
            err_msg = f'not a file: {name}'
            raise IsADirectoryError(err_msg)


def _parse_inputs(arguments: argparse.Namespace) -> None:
    """Replace the links by their parsed form and build the search query from its words and flags.

    :param arguments: the parsed command line, which gains the parsed values.
    :type arguments: argparse.Namespace
    :raises ProtocolError: on a malformed link.
    :raises ValueError: on a query without words.
    """
    if LINKS_ARGUMENT in arguments:
        arguments.links = [FileLink.parse(link) for link in arguments.links]
    if TEXT_ARGUMENT in arguments:
        file_type = FileType.DOCUMENT if arguments.documents else None
        arguments.query = SearchQuery(text=arguments.text, extensions=tuple(arguments.ext), file_type=file_type)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line.

    :param argv: the arguments, ``sys.argv`` when ``None``.
    :type argv: Sequence[str] | None
    :returns: the process exit code.
    :rtype: int
    """
    arguments = build_parser().parse_args(argv)

    # Every input is checked here, before any client, identity or connection exists: the configuration file, the
    # flags, the local paths, the links and the search query, the last two replaced by their parsed form. Only a TOML
    # error lacks the file in its message
    try:
        _check_local_paths(arguments, build_config(arguments))
        _parse_inputs(arguments)
    except tomllib.TOMLDecodeError as error:
        print(f'{ERROR_PREFIX}{arguments.config}: {error}', file=sys.stderr)
        return USAGE_ERROR
    except (OSError, TypeError, ValueError, Ed2kError) as error:
        print(f'{ERROR_PREFIX}{error}', file=sys.stderr)
        return USAGE_ERROR

    logging.basicConfig(level=logging.DEBUG if arguments.verbose else logging.INFO, format=LOG_FORMAT)
    try:
        if getattr(arguments, 'sync', False):
            arguments.handler(arguments)
        else:
            asyncio.run(arguments.handler(arguments))
    except Ed2kError as error:
        print(f'{ERROR_PREFIX}{error}', file=sys.stderr)
        return 1
    return 0
