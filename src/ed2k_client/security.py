"""Defences of the local machine against what arrives from the network.

The client trusts no byte it receives, and four kinds of input reach the disk or the socket layer:

* File names from search results and peers become local file names only after :func:`sanitize_filename`, and every
  path the client writes is checked by :func:`resolve_inside` to stay inside its directory.
* Addresses from servers, Kad and peers are dialled only after :class:`AddressPolicy` accepts them: a global
  unicast IPv4 address outside the IP filter, which keeps a hostile server from turning the client against the
  local network (aMule drops LAN sources in ``CPartFile::AddSources`` for the same reason, ``PartFile.cpp`` line 1816).
* Downloaded content is inspected by :func:`inspect_document` before it leaves quarantine: the magic bytes must
  match the expected document type, executables and archives are refused, and a PDF is scanned for the active
  content keys that malicious PDFs rely on, following the approach of Didier Stevens' pdfid.
* Shared files are served by hash from an index built by the user, never by a path a peer names.
"""

import ipaddress
import re
import unicodedata
import zipfile
from dataclasses import dataclass, field, replace
from enum import Enum, StrEnum, auto
from pathlib import PurePath
from typing import TYPE_CHECKING, Literal, Self

from ed2k_client.errors import SecurityError
from ed2k_client.settings import DEFAULT_IO, DEFAULT_LIMITS

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from pathlib import Path

    from ed2k_client.settings import IoSettings

FALLBACK_NAME: str = 'download'
READ_BINARY: Literal['rb'] = 'rb'
WINDOWS_RESERVED: frozenset[str] = frozenset(
    {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))}
)
UNSAFE_CHARACTERS = re.compile(r'[\x00-\x1f\x7f<>:"/\\|?*]')
IPFILTER_LINE = re.compile(r'^\s*([\d.]+)\s*-\s*([\d.]+)\s*,\s*(\d+)\s*,?(.*)$')

# A range blocks when its level is below the filter level, and 127 is aMule's default level:
# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/IPFilter.cpp#L143
# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/Preferences.cpp#L1220
IPFILTER_BLOCK_BELOW: int = 127
MAX_SUFFIX: int = 16
PDF_MARKER: bytes = b'%PDF-'
DJVU_MARKER: bytes = b'AT&TFORM'

# A PDF name is a slash and regular characters, where #xx writes any byte in hex (ISO 32000-1, 7.3.5). The pattern
# takes letters, digits and escapes only, which is all the keys of interest use:
# https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf
PDF_NAME = re.compile(rb'/([A-Za-z0-9#]+)')
PDF_HEX_ESCAPE = re.compile(rb'#([0-9A-Fa-f]{2})')

# A stream body runs from the keyword stream after the >> of its dictionary to endstream (7.3.8). The keyword is a
# token only outside a literal string, which nests parentheses and escapes with a backslash (7.3.4.2), and outside a
# comment, which runs to the end of the line (7.2.4). Bytes that look like a stream start anywhere else keep the
# scanner reading, so a hostile file can make the scan longer but never switch it off.
PDF_WHITESPACE: bytes = rb'[\x00\t\n\x0c\r ]'
PDF_STRING_START: bytes = b'('
PDF_STRING_END: bytes = b')'
PDF_COMMENT_START: bytes = b'%'
PDF_OUTSIDE_TOKEN = re.compile(rb'[(%]|>>' + PDF_WHITESPACE + rb'*stream\r?\n')
PDF_STRING_TOKEN = re.compile(rb'\\.|[()]', re.DOTALL)
PDF_LINE_END = re.compile(rb'[\r\n]')
PDF_STREAM_END: bytes = b'endstream'

# A reader reaches an object by its xref offset wherever it lies, so the header of an object written inside another
# stream's body ends that body for the scan too. The obj keyword follows whitespace in every object header, and in
# compressed data whitespace and obj without a name character after them occur about once in a gigabyte
PDF_STREAM_EXIT = re.compile(re.escape(PDF_STREAM_END) + b'|' + PDF_WHITESPACE + rb'obj(?![A-Za-z0-9#])')

# Longer than endstream, a stream start with a little whitespace and every key of interest, so a match across two
# chunks is seen whole. A stream start padded beyond it is not recognised, which only makes the scan longer
SCAN_OVERLAP: int = 64

# The keys pdfid counts as signs of active content: https://blog.didierstevens.com/programs/pdf-tools/
PDF_DANGEROUS_KEYS: frozenset[bytes] = frozenset(
    {b'JavaScript', b'JS', b'Launch', b'EmbeddedFile', b'EmbeddedFiles', b'RichMedia', b'XFA', b'SubmitForm'}
)
PDF_NOTABLE_KEYS: frozenset[bytes] = frozenset({b'OpenAction', b'AA', b'ObjStm', b'Encrypt', b'URI'})
# Content that runs when opened: programs, scripts and Office documents that may carry macros
ACTIVE_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b'MZ', 'Windows executable'),
    (b'\x7fELF', 'ELF executable'),
    (b'#!', 'script'),
    (b'\xca\xfe\xba\xbe', 'Mach-O or Java class'),
    (b'\xcf\xfa\xed\xfe', 'Mach-O executable'),
    (b'\xd0\xcf\x11\xe0', 'OLE document with possible macros'),
)

# Containers that run nothing themselves. Only the member names of a ZIP are read, because Office files of today
# and Java archives are ZIP files that run when opened
ZIP_SIGNATURE: bytes = b'PK\x03\x04'
ARCHIVE_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (ZIP_SIGNATURE, 'ZIP archive'),
    (b'Rar!', 'RAR archive'),
    (b"7z\xbc\xaf'\x1c", '7-Zip archive'),
)

# A macro-enabled Office file keeps its macros in a vbaProject.bin part, and a Java archive names its entry point in
# META-INF/MANIFEST.MF
MACRO_PROJECT_MEMBER: str = 'vbaproject.bin'
JAVA_MANIFEST_MEMBER: str = 'meta-inf/manifest.mf'
MACRO_DOCUMENT_LABEL: str = 'Office document with macros'
JAVA_ARCHIVE_LABEL: str = 'Java archive'

# Windows opens a file with the program its extension names, whatever the content says, so these names run code
# when the file is opened: programs, scripts, shortcuts and macro-enabled Office formats
ACTIVE_EXTENSIONS: frozenset[str] = frozenset(
    {
        'bat',
        'cmd',
        'com',
        'cpl',
        'exe',
        'hta',
        'jar',
        'js',
        'jse',
        'lnk',
        'msi',
        'msp',
        'pif',
        'ps1',
        'psm1',
        'reg',
        'scr',
        'sh',
        'vb',
        'vbe',
        'vbs',
        'wsf',
        'wsh',
        'docm',
        'dotm',
        'xlsm',
        'xltm',
        'xlam',
        'pptm',
        'potm',
        'ppam',
        'ppsm',
        'sldm',
    }
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


def sanitize_filename(
    name: str, *, fallback: str = FALLBACK_NAME, max_bytes: int = DEFAULT_LIMITS.filename_bytes
) -> str:
    """Turn an untrusted file name into a single safe path component.

    Path separators, control and shell-special characters, leading dots and Windows device names are removed, the
    text is normalised to NFC and cut to ``max_bytes`` bytes of UTF-8 while the extension is kept.

    :param name: the name as received.
    :type name: str
    :param fallback: the name to use when nothing usable remains.
    :type fallback: str
    :param max_bytes: the longest name in UTF-8 bytes, well below the 255 most file systems allow.
    :type max_bytes: int
    :returns: a name that is safe to join to a directory.
    :rtype: str
    """
    # NFC first, so that a name cannot pass the checks in one Unicode form and land on disk in another; a leading
    # dot would hide the file
    cleaned = UNSAFE_CHARACTERS.sub('_', unicodedata.normalize('NFC', name)).strip().lstrip('.').strip()
    stem, dot, suffix = cleaned.rpartition('.')
    if not dot:
        stem, suffix = cleaned, ''

    # CON, NUL and the like open a device on Windows whatever the extension
    if stem.upper() in WINDOWS_RESERVED:
        stem = f'_{stem}'

    # The stem is cut at a byte budget and decoded with errors='ignore', so a multi-byte character cut in half
    # disappears instead of leaving an invalid sequence
    suffix = suffix[:MAX_SUFFIX]
    budget = max_bytes - len(suffix.encode()) - 1
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
    # resolve() follows symbolic links, so a link planted in the directory cannot lead the write elsewhere
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
            # Comments, blank lines and malformed lines are skipped as aMule skips them
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

        # Loopback, private and link-local addresses would let a hostile server point the client at the local
        # network, which only tests on one machine may allow
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


class PdfLexMode(Enum):
    """Where the PDF key scan stands in the token stream of the file."""

    OUTSIDE = auto()
    STRING = auto()
    COMMENT = auto()
    STREAM = auto()


# The token that moves the scan on in each mode other than STREAM, which looks for endstream
MODE_TOKENS: dict[PdfLexMode, re.Pattern[bytes]] = {
    PdfLexMode.OUTSIDE: PDF_OUTSIDE_TOKEN,
    PdfLexMode.STRING: PDF_STRING_TOKEN,
    PdfLexMode.COMMENT: PDF_LINE_END,
}


@dataclass(slots=True)
class PdfKeyScan:
    """Collect the names a PDF writes outside its stream bodies, one window of the file at a time.

    Names count in strings and comments too, because a string or a comment matters only for telling a real stream
    start from bytes that look like one.

    :ivar found: the decoded names collected so far.
    :ivar mode: where the previous window stopped.
    :ivar depth: open parentheses of the literal string the previous window stopped in.
    """

    found: set[bytes] = field(default_factory=set)
    mode: PdfLexMode = PdfLexMode.OUTSIDE
    depth: int = 0

    def scan(self, window: bytes, *, safe: int) -> int:
        """Collect the names outside stream bodies that start before ``safe``.

        Tokens and names that start before ``safe`` lie wholly inside the window, because the window keeps
        :data:`SCAN_OVERLAP` bytes beyond it.

        :param window: the bytes being scanned.
        :type window: bytes
        :param safe: offset before which every match is complete.
        :type safe: int
        :returns: the offset the next window resumes at.
        :rtype: int
        """
        position = segment = 0
        while position < safe:
            # Inside a stream body nothing counts until endstream or an object header, which is scanned from its start
            if self.mode is PdfLexMode.STREAM:
                exit_token = PDF_STREAM_EXIT.search(window, position)
                if exit_token is None or exit_token.start() >= safe:
                    return safe
                ended = exit_token.group() == PDF_STREAM_END
                position = segment = exit_token.end() if ended else exit_token.start()
                self.mode = PdfLexMode.OUTSIDE
                continue

            token = MODE_TOKENS[self.mode].search(window, position)
            if token is None or token.start() >= safe:
                break
            position = token.end()
            if self._step(token.group()):
                self._collect(window, start=segment, limit=token.start())

        if self.mode is not PdfLexMode.STREAM:
            self._collect(window, start=segment, limit=safe)
        return max(position, safe)

    def _step(self, token: bytes) -> bool:
        """Move to the mode a token leads to.

        :param token: the token found in the current mode.
        :type token: bytes
        :returns: whether the token opened a stream body.
        :rtype: bool
        """
        match self.mode:
            case PdfLexMode.OUTSIDE if token == PDF_STRING_START:
                self.mode, self.depth = PdfLexMode.STRING, 1
            case PdfLexMode.OUTSIDE if token == PDF_COMMENT_START:
                self.mode = PdfLexMode.COMMENT
            case PdfLexMode.OUTSIDE:
                self.mode = PdfLexMode.STREAM
                return True
            case PdfLexMode.STRING if token == PDF_STRING_START:
                self.depth += 1
            case PdfLexMode.STRING if token == PDF_STRING_END:
                self.depth -= 1
                self.mode = PdfLexMode.OUTSIDE if self.depth == 0 else PdfLexMode.STRING
            case PdfLexMode.COMMENT:
                self.mode = PdfLexMode.OUTSIDE
            case _:
                # A backslash escape inside a string changes nothing
                pass
        return False

    def _collect(self, window: bytes, *, start: int, limit: int) -> None:
        """Add the names that start between two offsets of the window.

        :param window: the bytes being scanned.
        :type window: bytes
        :param start: the first offset.
        :type start: int
        :param limit: the offset at which names stop counting.
        :type limit: int
        """
        for match in PDF_NAME.finditer(window, start):
            if match.start() >= limit:
                break
            self.found.add(_decode_name(match.group(1)))


def _pdf_keys(path: Path, *, chunk_size: int) -> set[bytes]:
    """Collect the PDF names written outside stream bodies.

    :param path: the file.
    :type path: Path
    :param chunk_size: bytes read at a time.
    :type chunk_size: int
    :returns: the decoded names.
    :rtype: set[bytes]
    """
    # Names are read only outside stream bodies: compressed streams are random-looking bytes in which a short key
    # such as /JS turns up by chance about once in 22 MB, while the dictionaries that make a PDF act sit outside
    # them. The file is read in chunks, so a large book never sits in memory whole
    scan = PdfKeyScan()
    pending = b''
    with path.open(READ_BINARY) as stream:
        while True:
            chunk = stream.read(chunk_size)
            window = pending + chunk

            # The last SCAN_OVERLAP bytes are scanned again with the next chunk, unless this was the end of the file
            safe = len(window) if not chunk else max(0, len(window) - SCAN_OVERLAP)
            position = scan.scan(window, safe=safe)
            if not chunk:
                return scan.found
            pending = window[position:]


def inspect_document(path: Path, *, name: str | None = None, io: IoSettings = DEFAULT_IO) -> Inspection:
    """Classify a downloaded file by its content and look for dangerous parts, in the content and in its name.

    Names written with ``#xx`` escapes, a known trick to hide ``/JavaScript`` from naive scanners, are decoded
    before matching. Keys inside compressed object streams stay invisible, so ``ObjStm`` is reported as notable.

    :param path: the file.
    :type path: Path
    :param name: the name the file will carry, the name of ``path`` when ``None``.
    :type name: str | None
    :param io: how much of the file is read at a time.
    :type io: IoSettings
    :returns: the verdict.
    :rtype: Inspection
    """
    verdict = _inspect_content(path, io=io)

    # The kind comes from the content, while whether opening the file runs it also depends on the name it keeps
    extension = PurePath(name if name is not None else path.name).suffix.lower().removeprefix('.')
    if extension not in ACTIVE_EXTENSIONS:
        return verdict
    return replace(verdict, dangerous=(*verdict.dangerous, f'.{extension} file, which runs when opened'))


def _zip_dangers(path: Path) -> tuple[str, ...]:
    """Name the members that make a ZIP archive run when it is opened.

    :param path: the archive.
    :type path: Path
    :returns: the dangers found, empty for an archive of data or one whose directory cannot be read.
    :rtype: tuple[str, ...]
    """
    # An archive whose central directory is unreadable is opened neither by Office nor by Java, so it stays a plain
    # archive, whose members are not inspected
    try:
        with zipfile.ZipFile(path) as archive:
            members = [member.lower() for member in archive.namelist()]
    except zipfile.BadZipFile:
        return ()

    dangers: list[str] = []
    if any(member.rpartition('/')[2] == MACRO_PROJECT_MEMBER for member in members):
        dangers.append(MACRO_DOCUMENT_LABEL)
    if JAVA_MANIFEST_MEMBER in members:
        dangers.append(JAVA_ARCHIVE_LABEL)
    return tuple(dangers)


def _inspect_content(path: Path, *, io: IoSettings) -> Inspection:
    """Classify a file by its content alone.

    :param path: the file.
    :type path: Path
    :param io: how much of the file is read at a time.
    :type io: IoSettings
    :returns: the verdict on the content.
    :rtype: Inspection
    """
    with path.open(READ_BINARY) as stream:
        head = stream.read(io.head_window)

    # The file type comes from the content, never from the name a peer chose
    for signature, label in ACTIVE_SIGNATURES:
        if head.startswith(signature):
            return Inspection(kind=DocumentKind.OTHER, dangerous=(label,))
    for signature, label in ARCHIVE_SIGNATURES:
        if head.startswith(signature):
            dangers = _zip_dangers(path) if signature == ZIP_SIGNATURE else ()
            return Inspection(kind=DocumentKind.OTHER, dangerous=dangers, notable=(label,))
    if head.startswith(DJVU_MARKER):
        return Inspection(kind=DocumentKind.DJVU)

    # Readers accept %PDF- anywhere in the first kilobyte, so a header behind junk is still a PDF to scan
    if PDF_MARKER not in head:
        return Inspection(kind=DocumentKind.OTHER)

    keys = _pdf_keys(path, chunk_size=io.scan_chunk)
    return Inspection(
        kind=DocumentKind.PDF,
        dangerous=tuple(sorted(key.decode() for key in keys & PDF_DANGEROUS_KEYS)),
        notable=tuple(sorted(key.decode() for key in keys & PDF_NOTABLE_KEYS)),
    )


def check_document(
    path: Path, *, expected: Sequence[DocumentKind] | None, name: str | None = None, io: IoSettings = DEFAULT_IO
) -> Inspection:
    """Inspect a file and refuse it unless it is safe and, when kinds are given, of an expected kind.

    :param path: the file.
    :type path: Path
    :param expected: the acceptable kinds, or ``None`` to accept a file of any kind that carries nothing active.
    :type expected: Sequence[DocumentKind] | None
    :param name: the name the file will carry, the name of ``path`` when ``None``.
    :type name: str | None
    :param io: how much of the file is read at a time.
    :type io: IoSettings
    :returns: the verdict of a file that passed.
    :rtype: Inspection
    :raises SecurityError: when the content is of another kind or the file carries dangerous parts.
    """
    shown = name if name is not None else path.name
    verdict = inspect_document(path, name=name, io=io)
    if expected is not None and verdict.kind not in expected:
        err_msg = f'{shown}: content is {verdict.kind} {list(verdict.dangerous)}, expected {list(expected)}'
        raise SecurityError(err_msg)

    if not verdict.is_safe:
        err_msg = f'{shown}: dangerous content {list(verdict.dangerous)}'
        raise SecurityError(err_msg)
    return verdict
