"""The ``server.met`` server list and the server entries the client connects to.

Layout per the aMule documentation: a header byte ``0xE0`` or ``0x0E``, a 32-bit count, then per server an IPv4
address in network byte order, a 16-bit TCP port and a counted tag list with the name, the description and the user
and file counts. The client reads lists only from a source the user chose and never adds servers that other
servers announce, because a hostile server could otherwise steer it to fake ones.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Self

from ed2k_client.errors import ProtocolError
from ed2k_client.fetch import fetch_https
from ed2k_client.settings import DEFAULT_LIMITS, DEFAULT_TIMEOUTS
from ed2k_client.tags import int_value, read_tags, str_value, tag_map
from ed2k_client.wire import Reader

if TYPE_CHECKING:
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
    def download(
        cls, url: str = DEFAULT_SERVER_MET_URL, *, limits: Limits = DEFAULT_LIMITS, timeout: float | None = None
    ) -> Self:
        """Fetch and parse a list over HTTPS.

        :param url: the list URL, which must use HTTPS.
        :type url: str
        :param limits: the caps on the download size and on the parsed list.
        :type limits: Limits
        :param timeout: seconds the download may take, the default bootstrap timeout when ``None``.
        :type timeout: float | None
        :returns: the list.
        :rtype: Self
        """
        body = fetch_https(
            url,
            limit=limits.server_met_bytes,
            timeout=timeout if timeout is not None else DEFAULT_TIMEOUTS.bootstrap_fetch,
        )
        return cls.parse(body, limits=limits)

    def by_users(self) -> list[ServerEntry]:
        """List servers with the most users first, the order in which the client tries them.

        :returns: the sorted servers.
        :rtype: list[ServerEntry]
        """
        return sorted(self.servers, key=lambda server: -server.users)
