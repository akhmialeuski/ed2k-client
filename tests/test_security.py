"""Unit tests of the defences: file names, paths, addresses, content inspection and the part file."""

from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from Crypto.Hash import MD4

from ed2k_client.constants import BLOCK_SIZE, PART_SIZE
from ed2k_client.errors import HashMismatchError, ProtocolError, SecurityError
from ed2k_client.hashing import hash_file
from ed2k_client.partfile import Block, PartFile, blocks_of_part
from ed2k_client.security import (
    SCAN_CHUNK,
    AddressPolicy,
    DocumentKind,
    IpFilter,
    check_document,
    inspect_document,
    resolve_inside,
    sanitize_filename,
)

if TYPE_CHECKING:
    from pyfakefs.fake_filesystem import FakeFilesystem

DOWNLOADS = Path('/downloads')
QUARANTINE = Path('/q')
BOOK = 'book.pdf'
PDF_SUFFIX = '.pdf'
PUBLIC_IP = '8.8.8.8'
LOOPBACK = '127.0.0.1'
PORT = 4662


@pytest.mark.parametrize(
    ('name', 'cleaned'),
    [
        ('../../etc/passwd', '_._etc_passwd'),
        ('.bashrc', 'bashrc'),
        ('CON.pdf', '_CON.pdf'),
        ('a\x00b\x1f|c?.djvu', 'a_b__c_.djvu'),
        ('', 'download'),
        ('x' * 400 + PDF_SUFFIX, 'x' * 196 + PDF_SUFFIX),
    ],
)
def test_sanitize_filename(name: str, cleaned: str) -> None:
    """Separators, control characters, dot files, device names and overlong names are neutralised."""
    assert sanitize_filename(name) == cleaned


def test_resolve_inside_refuses_escapes(fs: FakeFilesystem) -> None:
    """A name that still resolves outside the directory is refused."""
    fs.create_dir(DOWNLOADS)

    assert resolve_inside(DOWNLOADS, BOOK) == DOWNLOADS / BOOK
    with pytest.raises(SecurityError):
        resolve_inside(DOWNLOADS, '../' + BOOK)


def test_address_policy_allows_only_global_unfiltered_addresses() -> None:
    """Private, loopback, multicast and filtered addresses and bad ports are refused."""
    ip_filter = IpFilter.parse(
        ['080.039.000.000 - 080.039.255.255 , 000 , Bad range', '1.1.1.1 - 1.1.1.1 , 200 , kept']
    )
    policy = AddressPolicy(ip_filter=ip_filter)

    assert policy.permits(PUBLIC_IP, PORT)
    assert policy.permits('1.1.1.1', PORT)
    for host in (LOOPBACK, '10.0.0.5', '224.0.0.1', '80.39.196.113'):
        assert not policy.permits(host, PORT)
    assert not policy.permits(PUBLIC_IP, 0)
    assert not policy.permits('not-an-ip', PORT)
    assert AddressPolicy(allow_private=True).permits(LOOPBACK, PORT)


@pytest.mark.parametrize(
    ('content', 'kind', 'dangerous'),
    [
        (b'%PDF-1.7\n/Type /Catalog /OpenAction 3 0 R', DocumentKind.PDF, ()),
        (b'%PDF-1.4\n<< /S /J#61vaScript /JS (x) >>', DocumentKind.PDF, ('JS', 'JavaScript')),
        (b'%PDF-1.4\n/Launch /EmbeddedFile', DocumentKind.PDF, ('EmbeddedFile', 'Launch')),
        (b'%PDF-1.4\n1 0 obj << >> stream\n\x00/JS\x00 endstream /Type', DocumentKind.PDF, ()),
        (b'%PDF-1.4\n<< /JS 2 0 R >> stream\nabc\nendstream', DocumentKind.PDF, ('JS',)),
        (b'AT&TFORM\x00\x00\x00\x10DJVM', DocumentKind.DJVU, ()),
        (b'MZ\x90\x00', DocumentKind.OTHER, ('Windows executable',)),
        (b'PK\x03\x04', DocumentKind.OTHER, ('ZIP archive',)),
    ],
)
def test_inspect_document(fs: FakeFilesystem, content: bytes, kind: DocumentKind, dangerous: tuple[str, ...]) -> None:
    """Magic bytes decide the kind, and hex-escaped PDF names do not hide active content."""
    path = QUARANTINE / 'file.bin'
    fs.create_file(path, contents=content)

    verdict = inspect_document(path)

    assert (verdict.kind, verdict.dangerous) == (kind, dangerous)


def test_pdf_scan_is_exact_across_read_chunks(fs: FakeFilesystem) -> None:
    """A stream body that crosses a read chunk hides its bytes, and a key cut by a chunk edge is still found."""
    edge = SCAN_CHUNK - 4
    head = b'%PDF-1.7\n1 0 obj << >> stream\n'
    body = head + b'\x00' * (edge - len(head)) + b'/JS\x00' * 8 + b'\nendstream\n'
    trap = body + b'\x00' * (2 * SCAN_CHUNK - 4 - len(body)) + b'/JavaScript '
    path = QUARANTINE / 'edge.pdf'
    fs.create_file(path, contents=trap)

    assert inspect_document(path).dangerous == ('JavaScript',)


def test_check_document_refuses_wrong_kind(fs: FakeFilesystem) -> None:
    """A DjVu passes when DjVu is expected and fails when only PDF is."""
    path = QUARANTINE / 'book.djvu'
    fs.create_file(path, contents=b'AT&TFORM....')

    assert check_document(path, expected=(DocumentKind.DJVU,)).kind == DocumentKind.DJVU
    with pytest.raises(SecurityError, match='content is djvu'):
        check_document(path, expected=(DocumentKind.PDF,))


def make_part_file(fs: FakeFilesystem, data: bytes) -> PartFile:
    """Create a part file for ``data`` whose hash is computed from the same bytes."""
    source = Path('/src') / BOOK
    fs.create_file(source, contents=data)
    hashes = hash_file(source)
    part_file = PartFile.open(directory=QUARANTINE, name=BOOK, size=len(data), file_hash=hashes.file_hash)
    if hashes.part_hashes:
        part_file.set_hashset(hashes.part_hashes)
    return part_file


def test_part_file_verifies_and_resumes(fs: FakeFilesystem) -> None:
    """Blocks written in pieces complete and verify a part, and a reopened part file remembers it."""
    data = bytes(range(256)) * (2 * BLOCK_SIZE // 256)
    part_file = make_part_file(fs, data)
    blocks = list(part_file.missing_blocks())

    assert part_file.write(block=blocks[0], start=0, data=data[:1000]) is None
    assert part_file.write(block=blocks[0], start=1000, data=data[1000:BLOCK_SIZE]) is None
    assert part_file.write(block=blocks[1], start=BLOCK_SIZE, data=data[BLOCK_SIZE:]) == 0
    assert part_file.complete

    reopened = PartFile.open(directory=QUARANTINE, name=BOOK, size=len(data), file_hash=part_file.file_hash)
    assert reopened.complete


def test_repeated_data_does_not_complete_a_block(fs: FakeFilesystem) -> None:
    """The same piece sent twice covers the same bytes once, so the block stays incomplete."""
    data = bytes(BLOCK_SIZE)
    part_file = make_part_file(fs, data)
    block = next(part_file.missing_blocks())
    half = data[: BLOCK_SIZE // 2]

    part_file.write(block=block, start=0, data=half)
    part_file.write(block=block, start=0, data=half)

    assert list(part_file.missing_blocks()) == [block]


def test_corrupt_part_is_wiped_and_requested_again(fs: FakeFilesystem) -> None:
    """A part whose MD4 fails raises and becomes missing again."""
    part_file = make_part_file(fs, bytes(1000))
    block = next(part_file.missing_blocks())

    with pytest.raises(HashMismatchError):
        part_file.write(block=block, start=0, data=b'\x01' * 1000)
    assert list(part_file.missing_blocks()) == [block]


def test_data_outside_the_block_is_refused(fs: FakeFilesystem) -> None:
    """A peer cannot write outside the block it was asked for."""
    part_file = make_part_file(fs, bytes(1000))

    with pytest.raises(ProtocolError, match='outside block'):
        part_file.write(block=Block(0, 100), start=50, data=bytes(100))


def test_forged_hashset_is_refused(fs: FakeFilesystem) -> None:
    """A hashset that does not combine into the file hash is rejected."""
    data = bytes(PART_SIZE + 10)
    source = Path('/src/big.bin')
    fs.create_file(source, contents=data)
    file_hash = hash_file(source).file_hash
    part_file = PartFile.open(directory=QUARANTINE, name='big.bin', size=len(data), file_hash=file_hash)

    with pytest.raises(ProtocolError, match='hashset'):
        part_file.set_hashset([MD4.new(b'x').digest(), MD4.new(b'y').digest()])


def test_blocks_never_cross_a_part_boundary() -> None:
    """The last block of a part is short, so no request spans two parts."""
    blocks = blocks_of_part(size=2 * PART_SIZE, part=0)

    assert blocks[-1].end == PART_SIZE
    assert all(block.part == 0 for block in blocks)
