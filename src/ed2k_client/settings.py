"""Tunable values of the client, grouped by concern, with the defaults the PoC was tested with.

Only values this client chose live here. Values the protocol fixes, such as the 9,728,000-byte part, the obfuscation
magic numbers or the 2^120 Kad search tolerance, stay in :mod:`ed2k_client.constants`, because a different value
would silently break hashes and requests against every other client.

:func:`settings_from_mapping` builds any of these dataclasses from a parsed TOML table, so a configuration file is
checked field by field at the boundary: an unknown key, a wrong type or a non-positive number is refused there.
"""

import enum
import types
import typing
from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ed2k_client.constants import MAX_REQUEST_RANGES

if TYPE_CHECKING:
    from _typeshed import DataclassInstance

KIB: int = 1024
MIB: int = 1024 * KIB
MIN_SCAN_CHUNK: int = 4 * KIB
SECONDS_PER_HOUR: float = 3600.0
LIST_SEPARATOR: str = ', '


def check_positive(settings: DataclassInstance) -> None:
    """Refuse a settings object with a numeric field that is zero or negative.

    :param settings: a frozen settings dataclass.
    :type settings: DataclassInstance
    :raises ValueError: when a numeric field is not positive.
    """
    for item in fields(settings):
        value = getattr(settings, item.name)

        # bool is an int subclass, and a switch is not a quantity
        if isinstance(value, bool) or not isinstance(value, int | float):
            continue
        if value <= 0:
            err_msg = f'{type(settings).__name__}.{item.name} must be positive, not {value}'
            raise ValueError(err_msg)


@dataclass(frozen=True, slots=True)
class Timeouts:
    """How long the client waits, in seconds.

    :ivar connect: a TCP connect, including the obfuscation handshake.
    :ivar read: silence on an open TCP connection before it is dropped.
    :ivar server_login: from the login request to the assigned ID.
    :ivar server_search: one page of server search results.
    :ivar server_sources: the source list a server returns for a file.
    :ivar bootstrap_fetch: the HTTPS download of ``server.met`` or ``nodes.dat``.
    """

    connect: float = 15.0
    read: float = 60.0
    server_login: float = 45.0
    server_search: float = 30.0
    server_sources: float = 20.0
    bootstrap_fetch: float = 30.0

    def __post_init__(self) -> None:
        """Check the values."""
        check_positive(self)


@dataclass(frozen=True, slots=True)
class Limits:
    """Caps on everything that arrives from the network, checked before anything is allocated.

    :ivar control_packet: bytes of a peer packet other than file data.
    :ivar server_packet: bytes of a server packet, whose search pages are large.
    :ivar unpacked_size: bytes a zlib payload may inflate to.
    :ivar tags: tags in one tag list.
    :ivar string_bytes: bytes of one length-prefixed string.
    :ivar search_results: results kept from one search.
    :ivar sources_per_file: sources kept from one source answer.
    :ivar filename_bytes: UTF-8 bytes of a file name written to disk.
    :ivar udp_datagram: bytes of one Kad datagram.
    :ivar server_met_servers: entries read from a ``server.met``.
    :ivar server_met_bytes: bytes of a downloaded ``server.met``.
    :ivar nodes_dat_contacts: entries read from a ``nodes.dat``.
    :ivar nodes_dat_bytes: bytes of a ``nodes.dat``.
    :ivar server_messages: server messages kept for the status.
    :ivar server_message_length: characters kept of one server message.
    :ivar server_result_pages: result pages asked of a server for one search.
    :ivar ignored_packets: unexpected packets a peer may send before the connection is dropped.
    """

    control_packet: int = 512 * KIB
    server_packet: int = 4 * MIB
    unpacked_size: int = 8 * MIB
    tags: int = 256
    string_bytes: int = 64 * KIB
    search_results: int = 1000
    sources_per_file: int = 500
    filename_bytes: int = 200
    udp_datagram: int = 8 * KIB
    server_met_servers: int = 5000
    server_met_bytes: int = 2 * MIB
    nodes_dat_contacts: int = 20_000
    nodes_dat_bytes: int = MIB
    server_messages: int = 50
    server_message_length: int = 1000
    server_result_pages: int = 3
    ignored_packets: int = 32

    def __post_init__(self) -> None:
        """Check the values."""
        check_positive(self)


@dataclass(frozen=True, slots=True)
class KadSettings:
    """How the iterative Kad lookup spreads, after the Kademlia paper's alpha and k.

    :ivar alpha: nodes asked in parallel in each round of a lookup.
    :ivar k: closest nodes a lookup converges on.
    :ivar max_rounds: rounds after which a lookup stops even if it still gets closer.
    :ivar bootstrap_fanout: contacts of ``nodes.dat`` asked at once during the bootstrap.
    :ivar bootstrap_contacts: live contacts after which the bootstrap stops.
    :ivar search_fanout: nodes in the tolerance zone that receive the search itself.
    :ivar search_collect: seconds to collect search answers after the last request.
    :ivar response_timeout: seconds one Kad UDP request waits for its first answer.
    """

    alpha: int = 5
    k: int = 10
    max_rounds: int = 12
    bootstrap_fanout: int = 40
    bootstrap_contacts: int = 60
    search_fanout: int = 8
    search_collect: float = 6.0
    response_timeout: float = 4.0

    def __post_init__(self) -> None:
        """Check the values."""
        check_positive(self)


@dataclass(frozen=True, slots=True)
class PeerSettings:
    """How the client talks to one peer.

    :ivar blocks_per_request: 180 KiB blocks asked in one request, at most the three ranges the packet holds.
    :ivar send_chunk: bytes of file data sent in one packet while sharing.
    :ivar obfuscation_padding: largest random padding of an obfuscation handshake.
    """

    blocks_per_request: int = MAX_REQUEST_RANGES
    send_chunk: int = 10 * KIB
    obfuscation_padding: int = 16

    def __post_init__(self) -> None:
        """Check the values.

        :raises ValueError: when a value is not positive or more blocks are asked than a request holds.
        """
        check_positive(self)
        if self.blocks_per_request > MAX_REQUEST_RANGES:
            err_msg = f'one request holds {MAX_REQUEST_RANGES} blocks, so {self.blocks_per_request} cannot be asked'
            raise ValueError(err_msg)


@dataclass(frozen=True, slots=True)
class ShareSettings:
    """Limits of sharing.

    :ivar upload_slots: peers served at the same time.
    :ivar max_incoming: incoming connections open at the same time.
    """

    upload_slots: int = 2
    max_incoming: int = 16

    def __post_init__(self) -> None:
        """Check the values."""
        check_positive(self)


@dataclass(frozen=True, slots=True)
class IoSettings:
    """Buffer sizes of local file work.

    :ivar read_chunk: bytes read at a time while hashing or verifying a file.
    :ivar scan_chunk: bytes read at a time while the content check scans a PDF.
    :ivar head_window: leading bytes the content check reads to recognise a file type.
    """

    read_chunk: int = MIB
    scan_chunk: int = MIB
    head_window: int = KIB

    def __post_init__(self) -> None:
        """Check the values.

        :raises ValueError: when a value is not positive or the scan chunk is too small to overlap its neighbours.
        """
        check_positive(self)
        if self.scan_chunk < MIN_SCAN_CHUNK:
            err_msg = f'the scan chunk must hold at least {MIN_SCAN_CHUNK} bytes, not {self.scan_chunk}'
            raise ValueError(err_msg)


DEFAULT_TIMEOUTS = Timeouts()
DEFAULT_LIMITS = Limits()
DEFAULT_KAD = KadSettings()
DEFAULT_PEER = PeerSettings()
DEFAULT_SHARE = ShareSettings()
DEFAULT_IO = IoSettings()


def _convert(*, kind: Any, value: object, where: str, base: Any) -> object:
    """Turn one TOML value into the type a settings field declares.

    :param kind: the declared type of the field.
    :type kind: Any
    :param value: the value from TOML.
    :type value: object
    :param where: the dotted key, for the error message.
    :type where: str
    :param base: the field's current value, whose own fields a nested table overrides.
    :type base: Any
    :returns: the converted value.
    :rtype: object
    :raises TypeError: when the value does not fit the type.
    :raises ValueError: when an enumeration has no such member.
    """
    # Path | None and the like: convert to the member that is not None
    if isinstance(kind, types.UnionType):
        members = [member for member in typing.get_args(kind) if member is not type(None)]
        return _convert(kind=members[0], value=value, where=where, base=base)

    # A nested table changes only the fields it names, so the others keep the values of the base
    if isinstance(kind, type) and is_dataclass(kind):
        return settings_from_mapping(kind, value, prefix=f'{where}.', base=base)

    if isinstance(kind, type) and issubclass(kind, enum.Enum):
        try:
            return kind[str(value).upper()]
        except KeyError:
            err_msg = f'{where} must be one of {LIST_SEPARATOR.join(item.name.lower() for item in kind)}'
            raise ValueError(err_msg) from None

    # A subclass check rather than identity, so a substitute such as pyfakefs's FakePath converts too
    if isinstance(kind, type) and issubclass(kind, Path) and isinstance(value, str):
        return kind(value).expanduser()

    # TOML writes a whole number without a decimal point, so 30 is still a valid number of seconds
    if kind is float and isinstance(value, int) and not isinstance(value, bool):
        return float(value)

    # The exact type keeps true out of an integer setting, because bool is an int subclass
    if type(value) is kind:
        return value

    err_msg = f'{where} must be {getattr(kind, "__name__", kind)}, not {type(value).__name__}'
    raise TypeError(err_msg)


def settings_from_mapping[T: DataclassInstance](
    cls: type[T], data: object, *, prefix: str = '', base: T | None = None
) -> T:
    """Build a settings dataclass from a parsed TOML table, starting from its defaults.

    :param cls: the settings dataclass.
    :type cls: type[T]
    :param data: the table, with keys named like the fields.
    :type data: object
    :param prefix: the dotted path of the table, for error messages.
    :type prefix: str
    :param base: the object whose values the table overrides, the defaults when ``None``.
    :type base: T | None
    :returns: the settings.
    :rtype: T
    :raises TypeError: when the value is not a table or a value has the wrong type.
    :raises ValueError: on an unknown key or a value the dataclass refuses.
    """
    if not isinstance(data, Mapping):
        err_msg = f'{prefix.rstrip(".") or "the configuration"} must be a table'
        raise TypeError(err_msg)

    # get_type_hints resolves the annotations at run time, so every type a settings field names must be importable
    # from the module that defines the dataclass
    hints = typing.get_type_hints(cls)
    known = {item.name for item in fields(cls)}
    if unknown := sorted(set(data) - known):
        err_msg = f'unknown setting {LIST_SEPARATOR.join(prefix + key for key in unknown)}'
        raise ValueError(err_msg)

    current = base if base is not None else cls()
    changes = {
        key: _convert(kind=hints[key], value=value, where=prefix + key, base=getattr(current, key))
        for key, value in data.items()
    }
    return replace(current, **changes)
