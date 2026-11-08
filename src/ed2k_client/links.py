"""Parse and build ``ed2k://`` links for files and servers.

A file link is ``ed2k://|file|<name>|<size>|<hash>|[h=<aich>|][p=<parts>|]/`` with a percent-encoded name, as in
``ED2KLink.cpp`` of aMule. Optional fields after the hash are kept only when they are the AICH root, other fields
are ignored.
"""

import ipaddress
import re
from dataclasses import dataclass
from typing import Self, override
from urllib.parse import quote, unquote

from ed2k_client.constants import MAX_FILE_SIZE
from ed2k_client.errors import ProtocolError
from ed2k_client.hashing import Ed2kHash

SCHEME: str = 'ed2k://'
FILE_FIELDS: int = 4
SERVER_FIELDS: int = 3
AICH_PREFIX: str = 'h='
MAX_PORT: int = 65_535

# Sizes and ports are written in ASCII digits. str.isdigit() also accepts other Unicode digits, some of which int()
# refuses and some of which it reads, so neither kind is a well-formed link
DECIMAL = re.compile(r'[0-9]+')


def valid_file_size(size: int) -> bool:
    """Check that a size from the network is one a file can have.

    :param size: the size in bytes.
    :type size: int
    :returns: whether it lies between 1 byte and the largest eD2k file.
    :rtype: bool
    """
    # A file of 0 bytes has no block to request, and one beyond the largest file has no valid part offsets
    return 0 < size <= MAX_FILE_SIZE


@dataclass(frozen=True, slots=True)
class FileLink:
    """A link to a file.

    :ivar name: the suggested file name, untrusted.
    :ivar size: the file size in bytes.
    :ivar file_hash: the eD2k hash.
    :ivar aich_root: the AICH root hash in base32, when the link carries one.
    """

    name: str
    size: int
    file_hash: Ed2kHash
    aich_root: str | None = None

    @classmethod
    def parse(cls, link: str) -> Self:
        """Parse a file link.

        :param link: the link text.
        :type link: str
        :returns: the link.
        :rtype: Self
        :raises ProtocolError: when the text is not a well-formed file link.
        """
        fields = _fields(link)
        if len(fields) < FILE_FIELDS or fields[0] != 'file':
            err_msg = f'not an ed2k file link: {link!r}'
            raise ProtocolError(err_msg)

        # The name stays untrusted here and is sanitised only where it becomes a file name
        name, size_text, hash_text = unquote(fields[1]), fields[2], fields[3]
        if not DECIMAL.fullmatch(size_text) or not valid_file_size(int(size_text)):
            err_msg = f'invalid size in link: {size_text!r}'
            raise ProtocolError(err_msg)

        aich = next((field.removeprefix(AICH_PREFIX) for field in fields[4:] if field.startswith(AICH_PREFIX)), None)
        return cls(name=name, size=int(size_text), file_hash=Ed2kHash.from_hex(hash_text), aich_root=aich)

    @override
    def __str__(self) -> str:
        """Format the link.

        :returns: the ``ed2k://`` text.
        :rtype: str
        """
        # safe='' encodes the slash too, because a '|' or '/' in a name would end the field or the link
        aich = f'{AICH_PREFIX}{self.aich_root}|' if self.aich_root is not None else ''
        return f'{SCHEME}|file|{quote(self.name, safe="")}|{self.size}|{self.file_hash.hex}|{aich}/'


@dataclass(frozen=True, slots=True)
class ServerLink:
    """A link to a server.

    :ivar host: the IPv4 address.
    :ivar port: the TCP port.
    """

    host: str
    port: int

    @classmethod
    def parse(cls, link: str) -> Self:
        """Parse a server link.

        :param link: the link text.
        :type link: str
        :returns: the link.
        :rtype: Self
        :raises ProtocolError: when the text is not a well-formed server link.
        """
        fields = _fields(link)
        if len(fields) < SERVER_FIELDS or fields[0] != 'server' or not DECIMAL.fullmatch(fields[2]):
            err_msg = f'not an ed2k server link: {link!r}'
            raise ProtocolError(err_msg)
        try:
            host = str(ipaddress.IPv4Address(fields[1]))
        except ValueError as error:
            err_msg = f'invalid server address: {fields[1]!r}'
            raise ProtocolError(err_msg) from error

        port = int(fields[2])
        if not 0 < port <= MAX_PORT:
            err_msg = f'invalid server port: {port}'
            raise ProtocolError(err_msg)
        return cls(host=host, port=port)

    @override
    def __str__(self) -> str:
        """Format the link.

        :returns: the ``ed2k://`` text.
        :rtype: str
        """
        return f'{SCHEME}|server|{self.host}|{self.port}|/'


def _fields(link: str) -> list[str]:
    """Split an ``ed2k://`` link into its fields.

    :param link: the link text.
    :type link: str
    :returns: the non-empty fields.
    :rtype: list[str]
    :raises ProtocolError: when the text is not an ed2k link.
    """
    text = link.strip()
    if not text.lower().startswith(SCHEME + '|') or not text.endswith('/'):
        err_msg = f'not an ed2k link: {link!r}'
        raise ProtocolError(err_msg)

    # Empty fields come from the leading and trailing pipes and from the optional sections
    return [field for field in text[len(SCHEME) + 1 : -1].split('|') if field]
