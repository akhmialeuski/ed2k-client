"""The ``server.met`` server list and the server entries the client connects to.

Layout per the aMule documentation: a header byte ``0xE0`` or ``0x0E``, a 32-bit count, then per server an IPv4
address in network byte order, a 16-bit TCP port and a counted tag list with the name, the description and the user
and file counts. The client reads lists only from a source the user chose and never adds servers that other
servers announce, because a hostile server could otherwise steer it to fake ones.

A downloaded list can be saved as it arrived and read back later, and :class:`ServerMemory` keeps the servers that
accepted a login, so the next connection tries them first.
"""

import json
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Self

from ed2k_client.errors import ProtocolError
from ed2k_client.fetch import fetch_https
from ed2k_client.settings import DEFAULT_LIMITS, DEFAULT_TIMEOUTS
from ed2k_client.tags import int_value, read_tags, str_value, tag_map
from ed2k_client.wire import Reader

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from ed2k_client.settings import Limits

# aMule accepts both header bytes when it reads a server.met: https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/ServerList.cpp#L125
MET_HEADERS: frozenset[int] = frozenset({0x0E, 0xE0})

# The tags aMule writes for each server, two with numeric names and two with string names:
# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/ServerList.cpp#L756
SERVER_NAME_TAG: int = 0x01
SERVER_DESCRIPTION_TAG: int = 0x0B
USERS_TAG: str = 'users'
FILES_TAG: str = 'files'
DEFAULT_SERVER_MET_URL: str = 'https://upd.emule-security.org/server.met'

# aMule may write names with a UTF-8 byte order mark, which would otherwise show up in the name
BOM: str = '\ufeff'

MEMORY_FILE: str = 'servers.json'
ENCODING: str = 'utf-8'
FILE_MODE: int = 0o600
TEMPORARY_SUFFIX: str = '.tmp'


def _write_private(path: Path, data: bytes) -> None:
    """Write a file readable by its owner only, replacing it atomically.

    :param path: the file.
    :type path: Path
    :param data: the content.
    :type data: bytes
    """
    # Written beside the target and renamed over it, so a crash leaves either the old or the new content
    temporary = path.with_name(path.name + TEMPORARY_SUFFIX)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(data)
    temporary.replace(path)


@dataclass(frozen=True, slots=True)
class ServerEntry:
    """A known eD2k server.

    :ivar host: the IPv4 address.
    :ivar port: the TCP port.
    :ivar name: the advertised name.
    :ivar description: the advertised description.
    :ivar users: the last known number of users.
    :ivar files: the last known number of files.
    """

    host: str
    port: int
    name: str = ''
    description: str = ''
    users: int = 0
    files: int = 0

    @property
    def address(self) -> str:
        """``host:port`` for logs and messages."""
        return f'{self.host}:{self.port}'


@dataclass(frozen=True, slots=True)
class ServerList:
    """Servers read from a ``server.met``.

    :ivar servers: the entries in file order.
    """

    servers: tuple[ServerEntry, ...]

    @classmethod
    def parse(cls, data: bytes, *, limits: Limits = DEFAULT_LIMITS) -> Self:
        """Parse the binary list.

        :param data: the file content.
        :type data: bytes
        :param limits: the cap on the number of servers and on everything read from the file.
        :type limits: Limits
        :returns: the list.
        :rtype: Self
        :raises ProtocolError: on an unknown header or an implausible count.
        """
        reader = Reader(data, limits=limits)
        if reader.u8() not in MET_HEADERS:
            err_msg = 'not a server.met file'
            raise ProtocolError(err_msg)

        count = reader.u32()
        if count > limits.server_met_servers:
            err_msg = f'{count} servers exceed the limit of {limits.server_met_servers}'
            raise ProtocolError(err_msg)

        servers = []
        for _ in range(count):
            host, port = reader.ed2k_ip(), reader.u16()
            tags = tag_map(read_tags(reader))
            servers.append(
                ServerEntry(
                    host=host,
                    port=port,
                    name=str_value(tags, SERVER_NAME_TAG).removeprefix(BOM),
                    description=str_value(tags, SERVER_DESCRIPTION_TAG).removeprefix(BOM),
                    users=int_value(tags, USERS_TAG),
                    files=int_value(tags, FILES_TAG),
                )
            )

        return cls(servers=tuple(servers))

    @classmethod
    def load(cls, path: Path, *, limits: Limits = DEFAULT_LIMITS) -> Self:
        """Read a list from a local ``server.met``.

        :param path: the file.
        :type path: Path
        :param limits: the cap on the number of servers and on everything read from the file.
        :type limits: Limits
        :returns: the list.
        :rtype: Self
        """
        return cls.parse(path.read_bytes(), limits=limits)

    @classmethod
    def download(
        cls,
        url: str = DEFAULT_SERVER_MET_URL,
        *,
        limits: Limits = DEFAULT_LIMITS,
        timeout: float | None = None,
        save_to: Path | None = None,
    ) -> Self:
        """Fetch and parse a list over HTTPS, and save it as it arrived when asked to.

        :param url: the list URL, which must use HTTPS.
        :type url: str
        :param limits: the caps on the download size and on the parsed list.
        :type limits: Limits
        :param timeout: seconds the download may take, the default bootstrap timeout when ``None``.
        :type timeout: float | None
        :param save_to: a file to write the downloaded ``server.met`` to, readable by its owner only.
        :type save_to: Path | None
        :returns: the list.
        :rtype: Self
        """
        body = fetch_https(
            url,
            limit=limits.server_met_bytes,
            timeout=timeout if timeout is not None else DEFAULT_TIMEOUTS.bootstrap_fetch,
        )
        server_list = cls.parse(body, limits=limits)

        # Saved only once it parsed, so a broken download never replaces a good copy
        if save_to is not None:
            _write_private(save_to, body)
        return server_list

    def by_users(self) -> list[ServerEntry]:
        """List servers with the most users first, the order in which the client tries them.

        :returns: the sorted servers.
        :rtype: list[ServerEntry]
        """
        return sorted(self.servers, key=lambda server: -server.users)


@dataclass(slots=True)
class ServerMemory:
    """The servers that accepted a login, the most recent first, kept in the client's state directory.

    Only the order is kept, so no clock is involved: a server that accepts a login moves to the front, and one that
    refuses it is dropped.

    :ivar path: the file the memory lives in.
    :ivar addresses: ``host:port`` of each remembered server, the most recent login first.
    """

    path: Path
    addresses: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, state_dir: Path) -> Self:
        """Read the memory of a state directory, empty when there is none yet.

        :param state_dir: the client's state directory.
        :type state_dir: Path
        :returns: the memory.
        :rtype: Self
        """
        path = state_dir / MEMORY_FILE
        if not path.exists():
            return cls(path=path)
        return cls(path=path, addresses=list(json.loads(path.read_text(encoding=ENCODING))))

    def prefer(self, servers: Sequence[ServerEntry]) -> list[ServerEntry]:
        """Put the remembered servers first, the most recent login first, and keep the order of the others.

        Only servers of the given list are returned, so a remembered server that left the list is never dialled.

        :param servers: the candidates in their own order.
        :type servers: Sequence[ServerEntry]
        :returns: the candidates in the order to try them.
        :rtype: list[ServerEntry]
        """
        rank = {address: index for index, address in enumerate(self.addresses)}

        # sorted() is stable, so the servers nobody remembers keep the order they came in
        return sorted(servers, key=lambda server: rank.get(server.address, len(rank)))

    def remember(self, server: ServerEntry) -> None:
        """Record a server that accepted a login as the most recent one.

        :param server: the server.
        :type server: ServerEntry
        """
        self.addresses = [server.address, *(address for address in self.addresses if address != server.address)]
        self._save()

    def forget(self, server: ServerEntry) -> None:
        """Drop a server that refused a login.

        :param server: the server.
        :type server: ServerEntry
        """
        if server.address in self.addresses:
            self.addresses.remove(server.address)
            self._save()

    def _save(self) -> None:
        """Write the memory, readable by its owner only."""
        _write_private(self.path, json.dumps(self.addresses).encode(ENCODING))
