"""Kad identifiers, contacts and the ``nodes.dat`` bootstrap file.

A Kad ID is a 128-bit number. aMule keeps it as four 32-bit words with the most significant first and writes each
word little-endian (``CFileDataIO::WriteUInt128``), so on the wire every 4-byte group of the big-endian value is
reversed. An MD4 digest becomes an ID by reading its bytes big-endian (``CUInt128::SetValueBE``). A Kad IPv4 address
is the number ``a << 24 | b << 16 | c << 8 | d`` written little-endian, the reverse of the byte order eD2k uses.
"""

import ipaddress
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Self

from ed2k_client.errors import ProtocolError
from ed2k_client.fetch import fetch_https
from ed2k_client.wire import Reader

if TYPE_CHECKING:
    from collections.abc import Iterable

    from ed2k_client.wire import Writer

BYTE_ORDER: Literal['big'] = 'big'
ID_BYTES: int = 16
WORDS = struct.Struct('<4I')
BIG_ENDIAN_WORDS = struct.Struct('>4I')
NODES_DAT_URL: str = 'https://upd.emule-security.org/nodes.dat'
MAX_NODES_BYTES: int = 1024 * 1024
MAX_CONTACTS: int = 20_000
CONTACT_SIZE: int = 25
UDP_KEY_SIZE: int = 8
BOOTSTRAP_EDITION: int = 1
MIN_KAD2_VERSION: int = 2
SUPPORTED_VERSIONS: frozenset[int] = frozenset({1, 2, 3})


@dataclass(frozen=True, slots=True, order=True)
class KadId:
    """A 128-bit Kad identifier.

    :ivar value: the identifier as an integer.
    """

    value: int

    @classmethod
    def from_digest(cls, digest: bytes) -> Self:
        """Read 16 bytes in big-endian order, as an MD4 digest or a stored ID.

        :param digest: the 16 bytes.
        :type digest: bytes
        :returns: the ID.
        :rtype: Self
        """
        return cls(int.from_bytes(digest, BYTE_ORDER))

    @classmethod
    def read(cls, reader: Reader) -> Self:
        """Read an ID in Kad wire order.

        :param reader: the packet reader.
        :type reader: Reader
        :returns: the ID.
        :rtype: Self
        """
        return cls.from_digest(BIG_ENDIAN_WORDS.pack(*WORDS.unpack(reader.take(WORDS.size))))

    def write(self, writer: Writer) -> Writer:
        """Append the ID in Kad wire order.

        :param writer: the payload writer.
        :type writer: Writer
        :returns: the writer.
        :rtype: Writer
        """
        return writer.raw(WORDS.pack(*BIG_ENDIAN_WORDS.unpack(self.digest)))

    @property
    def digest(self) -> bytes:
        """The 16 bytes in big-endian order, which is the MD4 digest for a hash-derived ID."""
        return self.value.to_bytes(ID_BYTES, BYTE_ORDER)

    def distance(self, other: KadId) -> int:
        """Return the XOR distance to another ID.

        :param other: the other ID.
        :type other: KadId
        :returns: the distance.
        :rtype: int
        """
        return self.value ^ other.value


@dataclass(frozen=True, slots=True)
class Contact:
    """A Kad node.

    :ivar kad_id: its ID.
    :ivar host: its IPv4 address.
    :ivar udp_port: its Kad port.
    :ivar tcp_port: its eD2k port.
    :ivar version: its Kad protocol version.
    """

    kad_id: KadId
    host: str
    udp_port: int
    tcp_port: int
    version: int

    @classmethod
    def read(cls, reader: Reader) -> Self:
        """Read the 25-byte contact record of Kad packets and ``nodes.dat``.

        :param reader: the reader.
        :type reader: Reader
        :returns: the contact.
        :rtype: Self
        """
        kad_id = KadId.read(reader)
        host = str(ipaddress.IPv4Address(reader.u32()))
        udp_port, tcp_port, version = reader.u16(), reader.u16(), reader.u8()
        return cls(kad_id=kad_id, host=host, udp_port=udp_port, tcp_port=tcp_port, version=version)

    @property
    def address(self) -> tuple[str, int]:
        """The UDP address."""
        return self.host, self.udp_port


def read_contacts(reader: Reader, count: int) -> list[Contact]:
    """Read ``count`` contact records after checking that they fit the packet.

    :param reader: the reader.
    :type reader: Reader
    :param count: the declared number of records.
    :type count: int
    :returns: the contacts.
    :rtype: list[Contact]
    :raises ProtocolError: when the declared count does not fit.
    """
    if count * CONTACT_SIZE > reader.remaining:
        err_msg = f'{count} contacts do not fit in a payload of {reader.remaining}'
        raise ProtocolError(err_msg)
    return [Contact.read(reader) for _ in range(count)]


def parse_nodes_dat(data: bytes) -> list[Contact]:
    """Parse ``nodes.dat`` of version 1, 2 or 3 (the bootstrap edition) and drop Kad 1 nodes.

    :param data: the file content.
    :type data: bytes
    :returns: the contacts.
    :rtype: list[Contact]
    :raises ProtocolError: on an unknown version or an implausible count.
    """
    reader = Reader(data)
    if reader.u32() != 0:
        err_msg = 'nodes.dat of version 0 cannot tell Kad versions apart'
        raise ProtocolError(err_msg)
    version = reader.u32()
    if version not in SUPPORTED_VERSIONS:
        err_msg = f'unknown nodes.dat version {version}'
        raise ProtocolError(err_msg)
    bootstrap = version == max(SUPPORTED_VERSIONS) and reader.u32() == BOOTSTRAP_EDITION
    count = reader.u32()
    if count > MAX_CONTACTS:
        err_msg = f'{count} contacts exceed the limit of {MAX_CONTACTS}'
        raise ProtocolError(err_msg)
    contacts = []
    for _ in range(count):
        contacts.append(Contact.read(reader))
        if version >= MIN_KAD2_VERSION and not bootstrap:
            reader.take(UDP_KEY_SIZE + 1)
    return [contact for contact in contacts if contact.version >= MIN_KAD2_VERSION]


def download_nodes_dat(url: str = NODES_DAT_URL) -> list[Contact]:
    """Fetch and parse a ``nodes.dat`` over HTTPS.

    :param url: the HTTPS URL.
    :type url: str
    :returns: the contacts.
    :rtype: list[Contact]
    """
    return parse_nodes_dat(fetch_https(url, limit=MAX_NODES_BYTES))


def closest(contacts: Iterable[Contact], target: KadId, *, count: int) -> list[Contact]:
    """Pick the contacts nearest to a target.

    :param contacts: the candidates.
    :type contacts: Iterable[Contact]
    :param target: the target ID.
    :type target: KadId
    :param count: how many to return.
    :type count: int
    :returns: the nearest contacts, nearest first.
    :rtype: list[Contact]
    """
    return sorted(contacts, key=lambda contact: contact.kad_id.distance(target))[:count]
