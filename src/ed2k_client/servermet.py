"""The ``server.met`` server list and the server entries the client connects to.

Layout per the aMule documentation: a header byte ``0xE0`` or ``0x0E``, a 32-bit count, then per server an IPv4
address in network byte order, a 16-bit TCP port and a counted tag list with the name, the description and the user
and file counts. The client reads lists only from a source the user chose and never adds servers that other
servers announce, because a hostile server could otherwise steer it to fake ones.
"""

from dataclasses import dataclass
from typing import Self

from ed2k_client.errors import ProtocolError
from ed2k_client.fetch import fetch_https
from ed2k_client.tags import int_value, read_tags, str_value, tag_map
from ed2k_client.wire import Reader

MET_HEADERS: frozenset[int] = frozenset({0x0E, 0xE0})
MAX_SERVERS: int = 5000
MAX_MET_BYTES: int = 2 * 1024 * 1024
SERVER_NAME_TAG: int = 0x01
SERVER_DESCRIPTION_TAG: int = 0x0B
SERVER_MAX_USERS_TAG: int = 0x87
USERS_TAG: str = 'users'
FILES_TAG: str = 'files'
DEFAULT_SERVER_MET_URL: str = 'https://upd.emule-security.org/server.met'
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
    def parse(cls, data: bytes) -> Self:
        """Parse the binary list.

        :param data: the file content.
        :type data: bytes
        :returns: the list.
        :rtype: Self
        :raises ProtocolError: on an unknown header or an implausible count.
        """
        reader = Reader(data)
        if reader.u8() not in MET_HEADERS:
            err_msg = 'not a server.met file'
            raise ProtocolError(err_msg)
        count = reader.u32()
        if count > MAX_SERVERS:
            err_msg = f'{count} servers exceed the limit of {MAX_SERVERS}'
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
    def download(cls, url: str = DEFAULT_SERVER_MET_URL) -> Self:
        """Fetch and parse a list over HTTPS.

        :param url: the list URL, which must use HTTPS.
        :type url: str
        :returns: the list.
        :rtype: Self
        """
        return cls.parse(fetch_https(url, limit=MAX_MET_BYTES))

    def by_users(self) -> list[ServerEntry]:
        """List servers with the most users first, the order in which the client tries them.

        :returns: the sorted servers.
        :rtype: list[ServerEntry]
        """
        return sorted(self.servers, key=lambda server: -server.users)
