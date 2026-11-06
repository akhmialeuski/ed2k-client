"""Sources: the peers that hold a file, as servers and Kad report them."""

import ipaddress
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from ed2k_client.constants import LOW_ID_LIMIT, CryptOption

ID_BYTE_ORDER: Literal['little'] = 'little'
NO_CRYPT: CryptOption = CryptOption(0)


class SourceOrigin(StrEnum):
    """Where a source came from."""

    SERVER = 'server'
    KAD = 'kad'
    LINK = 'link'


@dataclass(frozen=True, slots=True)
class Source:
    """A peer that offers a file.

    :ivar client_id: the eD2k ID, the IPv4 address as a number for a High ID.
    :ivar port: the peer's TCP port.
    :ivar user_hash: the peer's user hash when known, which obfuscation needs.
    :ivar crypt: the peer's obfuscation settings.
    :ivar origin: where the source came from.
    """

    client_id: int
    port: int
    user_hash: bytes | None = None
    crypt: CryptOption = NO_CRYPT
    origin: SourceOrigin = SourceOrigin.SERVER

    @property
    def is_low_id(self) -> bool:
        """Whether the peer cannot accept incoming connections."""
        return self.client_id < LOW_ID_LIMIT

    @property
    def host(self) -> str:
        """The dotted address of a High ID source, whose ID is its address in network byte order."""
        return str(ipaddress.IPv4Address(self.client_id.to_bytes(4, ID_BYTE_ORDER)))

    @property
    def wants_obfuscation(self) -> bool:
        """Whether the connection should be obfuscated: the peer supports it and its user hash is known."""
        return bool(self.crypt & (CryptOption.SUPPORTED | CryptOption.REQUESTED | CryptOption.REQUIRED)) and (
            self.user_hash is not None
        )


def client_id_from_host(host: str) -> int:
    """Turn a dotted address into the eD2k ID a High ID client has.

    :param host: the IPv4 address.
    :type host: str
    :returns: the ID.
    :rtype: int
    """
    return int.from_bytes(ipaddress.IPv4Address(host).packed, ID_BYTE_ORDER)
