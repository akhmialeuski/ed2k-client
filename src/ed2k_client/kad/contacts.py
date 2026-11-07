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
from ed2k_client.settings import DEFAULT_LIMITS, DEFAULT_TIMEOUTS
from ed2k_client.wire import Reader

if TYPE_CHECKING:
    from collections.abc import Iterable

    from ed2k_client.settings import Limits
    from ed2k_client.wire import Writer

BYTE_ORDER: Literal['big'] = 'big'
ID_BYTES: int = 16

# Four little-endian words, most significant word first: https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/SafeFile.cpp#L298
WORDS = struct.Struct('<4I')
BIG_ENDIAN_WORDS = struct.Struct('>4I')
NODES_DAT_URL: str = 'https://upd.emule-security.org/nodes.dat'

# <id 16><ip 4><udp port 2><tcp port 2><version 1>
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
        # https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/kademlia/utils/UInt128.cpp#L106
        return cls(int.from_bytes(digest, BYTE_ORDER))

    @classmethod
    def read(cls, reader: Reader) -> Self:
        """Read an ID in Kad wire order.

        :param reader: the packet reader.
        :type reader: Reader
        :returns: the ID.
        :rtype: Self
        """
        # Reading four little-endian words and packing them big-endian reverses each 4-byte group back
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

        # The address is a little-endian number, so IPv4Address gets the number rather than the bytes
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
    # Checked before any record is read, so a huge count costs nothing
    if count * CONTACT_SIZE > reader.remaining:
        err_msg = f'{count} contacts do not fit in a payload of {reader.remaining}'
        raise ProtocolError(err_msg)
    return [Contact.read(reader) for _ in range(count)]


def parse_nodes_dat(data: bytes, *, limits: Limits = DEFAULT_LIMITS) -> list[Contact]:
    """Parse ``nodes.dat`` of version 1, 2 or 3 (the bootstrap edition) and drop Kad 1 nodes.

    :param data: the file content.
    :type data: bytes
    :param limits: the cap on the number of contacts.
    :type limits: Limits
    :returns: the contacts.
    :rtype: list[Contact]
    :raises ProtocolError: on an unknown version or an implausible count.
    """
    # Since version 1 the file starts with a zero where version 0 had its count, as aMule reads it:
    # https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/kademlia/routing/RoutingZone.cpp#L151
    reader = Reader(data, limits=limits)
    if reader.u32() != 0:
        err_msg = 'nodes.dat of version 0 cannot tell Kad versions apart'
        raise ProtocolError(err_msg)

    version = reader.u32()
    if version not in SUPPORTED_VERSIONS:
        err_msg = f'unknown nodes.dat version {version}'
        raise ProtocolError(err_msg)

    # Version 3 carries an edition word, and edition 1 is the bootstrap list without UDP keys
    bootstrap = version == max(SUPPORTED_VERSIONS) and reader.u32() == BOOTSTRAP_EDITION
    count = reader.u32()
    if count > limits.nodes_dat_contacts:
        err_msg = f'{count} contacts exceed the limit of {limits.nodes_dat_contacts}'
        raise ProtocolError(err_msg)

    # Every record of a regular file from version 2 on ends with an 8-byte UDP key and a verified flag
    contacts = []
    for _ in range(count):
        contacts.append(Contact.read(reader))
        if version >= MIN_KAD2_VERSION and not bootstrap:
            reader.take(UDP_KEY_SIZE + 1)

    return [contact for contact in contacts if contact.version >= MIN_KAD2_VERSION]


def download_nodes_dat(
    url: str = NODES_DAT_URL, *, limits: Limits = DEFAULT_LIMITS, timeout: float = DEFAULT_TIMEOUTS.bootstrap_fetch
) -> list[Contact]:
    """Fetch and parse a ``nodes.dat`` over HTTPS.

    :param url: the HTTPS URL.
    :type url: str
    :param limits: the caps on the download size and on the number of contacts.
    :type limits: Limits
    :param timeout: seconds the download may take.
    :type timeout: float
    :returns: the contacts.
    :rtype: list[Contact]
    """
    return parse_nodes_dat(fetch_https(url, limit=limits.nodes_dat_bytes, timeout=timeout), limits=limits)


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
