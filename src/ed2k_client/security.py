"""Defences of the local machine against what arrives from the network.

The client trusts no byte it receives, and four kinds of input reach the disk or the socket layer:

* File names from search results and peers become local file names only after :func:`sanitize_filename`, and every
  path the client writes is checked by :func:`resolve_inside` to stay inside its directory.
* Addresses from servers, Kad and peers are dialled only after :class:`AddressPolicy` accepts them: a global
  unicast IPv4 address outside the IP filter, which keeps a hostile server from turning the client against the
  local network (aMule drops LAN sources in ``CPartFile::AddSources`` for the same reason).
* Downloaded content is inspected by :func:`inspect_document` before it leaves quarantine: the magic bytes must
  match the expected document type, executables and archives are refused, and a PDF is scanned for the active
  content keys that malicious PDFs rely on, following the approach of Didier Stevens' pdfid.
* Shared files are served by hash from an index built by the user, never by a path a peer names.
"""

import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Literal, Self

from ed2k_client.constants import MAX_FILENAME_BYTES
from ed2k_client.errors import SecurityError

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from pathlib import Path

FALLBACK_NAME: str = 'download'
READ_BINARY: Literal['rb'] = 'rb'
WINDOWS_RESERVED: frozenset[str] = frozenset(
    {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))}
)
UNSAFE_CHARACTERS = re.compile(r'[\x00-\x1f\x7f<>:"/\\|?*]')
IPFILTER_LINE = re.compile(r'^\s*([\d.]+)\s*-\s*([\d.]+)\s*,\s*(\d+)\s*,?(.*)$')
IPFILTER_BLOCK_BELOW: int = 127
HEAD_WINDOW: int = 1024
MAX_SUFFIX: int = 16
PDF_MARKER: bytes = b'%PDF-'
DJVU_MARKER: bytes = b'AT&TFORM'
PDF_NAME = re.compile(rb'/([A-Za-z0-9#]+)')
PDF_HEX_ESCAPE = re.compile(rb'#([0-9A-Fa-f]{2})')
PDF_STREAM_START = re.compile(rb'(?<!end)stream\r?\n')
PDF_STREAM_END: bytes = b'endstream'
SCAN_CHUNK: int = 1024 * 1024
SCAN_OVERLAP: int = 64
PDF_DANGEROUS_KEYS: frozenset[bytes] = frozenset(
    {b'JavaScript', b'JS', b'Launch', b'EmbeddedFile', b'EmbeddedFiles', b'RichMedia', b'XFA', b'SubmitForm'}
)
PDF_NOTABLE_KEYS: frozenset[bytes] = frozenset({b'OpenAction', b'AA', b'ObjStm', b'Encrypt', b'URI'})
MAGIC_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b'MZ', 'Windows executable'),
    (b'\x7fELF', 'ELF executable'),
    (b'#!', 'script'),
    (b'\xca\xfe\xba\xbe', 'Mach-O or Java class'),
    (b'\xcf\xfa\xed\xfe', 'Mach-O executable'),
    (b'PK\x03\x04', 'ZIP archive'),
    (b'Rar!', 'RAR archive'),
    (b"7z\xbc\xaf'\x1c", '7-Zip archive'),
    (b'\xd0\xcf\x11\xe0', 'OLE document with possible macros'),
)


class DocumentKind(StrEnum):
    """What the magic bytes of a file say it is."""

    PDF = 'pdf'
    DJVU = 'djvu'
    OTHER = 'other'


@dataclass(frozen=True, slots=True)
class Inspection:
    """The verdict of :func:`inspect_document`.

    :ivar kind: the detected document kind.
    :ivar dangerous: active-content keys or foreign formats that make the file unsafe to open.
    :ivar notable: keys worth knowing about that legitimate books also use.
    """

    kind: DocumentKind
    dangerous: tuple[str, ...] = ()
    notable: tuple[str, ...] = ()

    @property
    def is_safe(self) -> bool:
        """Whether nothing dangerous was found."""
        return not self.dangerous


def sanitize_filename(name: str, *, fallback: str = FALLBACK_NAME) -> str:
    """Turn an untrusted file name into a single safe path component.

    Path separators, control and shell-special characters, leading dots and Windows device names are removed, the
    text is normalised to NFC and cut to :data:`MAX_FILENAME_BYTES` bytes of UTF-8 while the extension is kept.

    :param name: the name as received.
    :type name: str
    :param fallback: the name to use when nothing usable remains.
    :type fallback: str
    :returns: a name that is safe to join to a directory.
    :rtype: str
    """
    cleaned = UNSAFE_CHARACTERS.sub('_', unicodedata.normalize('NFC', name)).strip().lstrip('.').strip()
    stem, dot, suffix = cleaned.rpartition('.')
    if not dot:
        stem, suffix = cleaned, ''
    if stem.upper() in WINDOWS_RESERVED:
        stem = f'_{stem}'
    suffix = suffix[:MAX_SUFFIX]
    budget = MAX_FILENAME_BYTES - len(suffix.encode()) - 1
    stem = stem.encode()[:budget].decode(errors='ignore').rstrip(' .')
    result = f'{stem}.{suffix}' if stem and suffix else stem or suffix
    return result or fallback


def resolve_inside(base: Path, name: str) -> Path:
    """Join a sanitised name to a directory and prove the result stays inside it.

    :param base: the directory.
    :type base: Path
    :param name: a name already passed through :func:`sanitize_filename`.
    :type name: str
    :returns: the resolved path.
    :rtype: Path
    :raises SecurityError: when the path would leave the directory.
    """
    root = base.resolve()
    target = (root / name).resolve()
    if target.parent != root:
        err_msg = f'path {name!r} escapes {root}'
        raise SecurityError(err_msg)
    return target


def unique_path(path: Path) -> Path:
    """Return ``path`` or, when it exists, the first free ``name (n).ext`` beside it.

    :param path: the wanted path.
    :type path: Path
    :returns: a path that does not exist yet.
    :rtype: Path
    """
    candidate = path
    counter = 1
    while candidate.exists():
        candidate = path.with_name(f'{path.stem} ({counter}){path.suffix}')
        counter += 1
    return candidate


@dataclass(frozen=True, slots=True)
class IpRange:
    """An inclusive IPv4 range of an IP filter.

    :ivar first: first address as an integer.
    :ivar last: last address as an integer.
    :ivar description: the reason the range is listed.
    """

    first: int
    last: int
    description: str = ''


@dataclass(slots=True)
class IpFilter:
    """Blocked address ranges in eMule's ``ipfilter.dat`` format.

    :ivar ranges: the blocked ranges.
    """

    ranges: list[IpRange] = field(default_factory=list)

    @classmethod
    def parse(cls, lines: Iterable[str]) -> Self:
        """Parse ``first - last , level , description`` lines and keep the ranges whose level blocks.

        Addresses in this format are zero-padded (``001.002.003.004``), which :mod:`ipaddress` refuses, so each
        octet is converted through :class:`int` first.

        :param lines: the file lines.
        :type lines: Iterable[str]
        :returns: the filter.
        :rtype: Self
        """
        ranges: list[IpRange] = []
        for line in lines:
            match = IPFILTER_LINE.match(line)
            if match is None or int(match.group(3)) >= IPFILTER_BLOCK_BELOW:
                continue
            try:
                first, last = (
                    int(ipaddress.IPv4Address('.'.join(str(int(octet)) for octet in text.split('.'))))
                    for text in (match.group(1), match.group(2))
                )
            except ValueError:
                continue
            ranges.append(IpRange(first=first, last=last, description=match.group(4).strip()))
        return cls(ranges=ranges)

    def blocks(self, address: str) -> bool:
        """Check whether an address falls into a blocked range.

        :param address: the dotted IPv4 address.
        :type address: str
        :returns: whether the address is blocked.
        :rtype: bool
        """
        value = int(ipaddress.IPv4Address(address))
        return any(item.first <= value <= item.last for item in self.ranges)


@dataclass(slots=True)
class AddressPolicy:
    """Decide which network-supplied addresses the client may dial.

    :ivar ip_filter: ranges that are always refused.
    :ivar allow_private: accept loopback and private addresses, for tests on one machine only.
    """

    ip_filter: IpFilter = field(default_factory=IpFilter)
    allow_private: bool = False

    def permits(self, address: str, port: int) -> bool:
        """Check an address and port that came from the network.

        :param address: the dotted IPv4 address.
        :type address: str
        :param port: the TCP or UDP port.
        :type port: int
        :returns: whether the client may connect.
        :rtype: bool
        """
        try:
            ip = ipaddress.IPv4Address(address)
        except ValueError:
            return False
        if not 0 < port < 1 << 16 or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            return False
        if not ip.is_global and not self.allow_private:
            return False
        return not self.ip_filter.blocks(address)


def _decode_name(raw: bytes) -> bytes:
    """Undo ``#xx`` escapes in a PDF name.

    :param raw: the name as written.
    :type raw: bytes
    :returns: the decoded name.
    :rtype: bytes
    """
    return PDF_HEX_ESCAPE.sub(lambda escape: bytes([int(escape.group(1), 16)]), raw)


def _scan_window(window: bytes, *, safe: int, inside: bool, found: set[bytes]) -> tuple[int, bool]:
    """Collect the names outside stream bodies that start before ``safe``.

    Matches that start before ``safe`` lie wholly inside the window, because the window keeps
    :data:`SCAN_OVERLAP` bytes beyond it, more than ``endstream`` or any key of interest needs.

    :param window: the bytes being scanned.
    :type window: bytes
    :param safe: offset before which every match is complete.
    :type safe: int
    :param inside: whether the window starts inside a stream body.
    :type inside: bool
    :param found: the names collected so far, extended in place.
    :type found: set[bytes]
    :returns: the offset the next window resumes at and whether it starts inside a stream body.
    :rtype: tuple[int, bool]
    """
    position = 0
    while position < safe:
        if inside:
            end = window.find(PDF_STREAM_END, position)
            if end < 0 or end >= safe:
                return safe, True
            position, inside = end + len(PDF_STREAM_END), False
            continue
        start = PDF_STREAM_START.search(window, position)
        boundary = start.start() if start is not None and start.start() < safe else safe
        for match in PDF_NAME.finditer(window, position):
            if match.start() >= boundary:
                break
            found.add(_decode_name(match.group(1)))
        if start is None or boundary == safe:
            return safe, False
        position, inside = start.end(), True
    return position, inside


def _pdf_keys(path: Path) -> set[bytes]:
    # Names are read only outside stream bodies: compressed streams are random-looking bytes in which a short key
    # such as /JS turns up by chance every few megabytes, while the dictionaries that make a PDF act sit outside
    # them. The file is read in chunks, so a large book never sits in memory whole.
    """Collect the PDF names written outside stream bodies.

    :param path: the file.
    :type path: Path
    :returns: the decoded names.
    :rtype: set[bytes]
    """
    found: set[bytes] = set()
    inside = False
    pending = b''
    with path.open(READ_BINARY) as stream:
        while True:
            chunk = stream.read(SCAN_CHUNK)
            window = pending + chunk
            safe = len(window) if not chunk else max(0, len(window) - SCAN_OVERLAP)
            position, inside = _scan_window(window, safe=safe, inside=inside, found=found)
            if not chunk:
                return found
            pending = window[position:]


def inspect_document(path: Path) -> Inspection:
    """Classify a downloaded file by its content and look for dangerous parts.

    Names written with ``#xx`` escapes, a known trick to hide ``/JavaScript`` from naive scanners, are decoded
    before matching. Keys inside compressed object streams stay invisible, so ``ObjStm`` is reported as notable.

    :param path: the file.
    :type path: Path
    :returns: the verdict.
    :rtype: Inspection
    """
    with path.open(READ_BINARY) as stream:
        head = stream.read(HEAD_WINDOW)
    for signature, label in MAGIC_SIGNATURES:
        if head.startswith(signature):
            return Inspection(kind=DocumentKind.OTHER, dangerous=(label,))
    if head.startswith(DJVU_MARKER):
        return Inspection(kind=DocumentKind.DJVU)
    if PDF_MARKER not in head:
        return Inspection(kind=DocumentKind.OTHER)
    keys = _pdf_keys(path)
    return Inspection(
        kind=DocumentKind.PDF,
        dangerous=tuple(sorted(key.decode() for key in keys & PDF_DANGEROUS_KEYS)),
        notable=tuple(sorted(key.decode() for key in keys & PDF_NOTABLE_KEYS)),
    )


def check_document(path: Path, *, expected: Sequence[DocumentKind]) -> Inspection:
    """Inspect a file and refuse it unless it is a safe document of an expected kind.

    :param path: the file.
    :type path: Path
    :param expected: the acceptable kinds.
    :type expected: Sequence[DocumentKind]
    :returns: the verdict of a file that passed.
    :rtype: Inspection
    :raises SecurityError: when the content is of another kind or carries dangerous parts.
    """
    verdict = inspect_document(path)
    if verdict.kind not in expected:
        err_msg = f'{path.name}: content is {verdict.kind} {list(verdict.dangerous)}, expected {list(expected)}'
        raise SecurityError(err_msg)
    if not verdict.is_safe:
        err_msg = f'{path.name}: dangerous content {list(verdict.dangerous)}'
        raise SecurityError(err_msg)
    return verdict
