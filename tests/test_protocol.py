"""Unit tests of the wire format: framing, tags, search trees, links, server lists, Kad IDs and obfuscation keys."""

import contextlib
import struct
import zlib
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ed2k_client.constants import Protocol
from ed2k_client.errors import ProtocolError
from ed2k_client.hashing import Ed2kHash, md4
from ed2k_client.kad.contacts import KadId, parse_nodes_dat
from ed2k_client.links import FileLink, ServerLink
from ed2k_client.obfuscation import PROTOCOL_BYTES, derive_ciphers, semi_random_marker
from ed2k_client.search import SearchQuery, SearchResult, SearchResults, encode_query, parse_server_results
from ed2k_client.servermet import ServerList
from ed2k_client.tags import Tag, read_tags, write_tags
from ed2k_client.wire import U32, Reader, Writer, decode_udp, inflate, unpack_payload

if TYPE_CHECKING:
    from collections.abc import Callable

# The tree a live eD2k server (ed2k-rust, 85.17.116.222:6082) answered with 300 results on 2026-11-06.
LIVE_TREE_HEX = '0000010800737072696e6765720001020300706466010004020400646a7675010004'
SAMPLE_HASH = Ed2kHash.from_hex('E737E3459E12C22118C48306FAE1D8EB')
AICH_ROOT = bytes(range(20))
AICH_ROOT_TEXT = 'AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQT'
# base64 refuses text that is not ASCII with a plain ValueError rather than binascii.Error
NON_ASCII_ROOT_LINK = 'ed2k://|file|a|5|E737E3459E12C22118C48306FAE1D8EB|h=\u00c4AAQEAYEAUDAOCAJBIFQYDIOB4IBCEQT|/'
BOOK = 'book.pdf'
FIRST_SERVER = '203.0.113.10:4661'
SECOND_SERVER = '203.0.113.20:4242'
THIRD_SERVER = '198.51.100.66:4661'
KAD = 'kad'

# Hostile input for the parsers: anything a sender may put on the wire, and text shaped like an ed2k link so that the
# parse gets past the scheme. Examples are not kept on disk, as a unit test writes no file
FUZZ = settings(database=None)
ANY_BYTES = st.binary(max_size=4096)
FUZZ_INFLATE_LIMIT = 1024
# A small count in front of random bytes gets past the count check, so the parse reaches the records behind it
SMALL_COUNT = st.integers(min_value=0, max_value=8)
COUNTED_BYTES = st.tuples(SMALL_COUNT, ANY_BYTES).map(lambda item: U32.pack(item[0]) + item[1])
SERVER_MET_BYTES = st.tuples(SMALL_COUNT, ANY_BYTES).map(lambda item: bytes([0xE0]) + U32.pack(item[0]) + item[1])
NODES_DAT_BYTES = st.tuples(st.integers(min_value=1, max_value=3), SMALL_COUNT, ANY_BYTES).map(
    lambda item: U32.pack(0) + U32.pack(item[0]) + U32.pack(item[1]) + item[2]
)
LINK_LIKE_TEXT = st.lists(st.text(max_size=24), max_size=6).map(lambda fields: 'ed2k://|' + '|'.join(fields) + '|/')
SERVER_LINK = 'ed2k://|server|45.82.80.155|5687|/'


class TestReader:
    """Tests of :class:`Reader`."""

    def test_reader_refuses_reading_past_the_end(self) -> None:
        """A length that points beyond the buffer becomes a protocol error, never a short read."""
        reader = Reader(b'\x05\x00ab')

        with pytest.raises(ProtocolError, match='need 5 bytes'):
            reader.string()

    def test_reader_refuses_strings_over_the_limit(self) -> None:
        """A declared string length above the limit is refused before the bytes are read."""
        with pytest.raises(ProtocolError, match='exceeds the limit'):
            Reader(b'\xff\xff' + bytes(10)).string(limit=100)


class TestInflate:
    """Tests of :func:`inflate`."""

    def test_inflate_stops_a_compression_bomb(self) -> None:
        """A small zlib stream that would inflate to many megabytes is refused at the limit."""
        bomb = zlib.compress(bytes(50_000_000), 9)

        with pytest.raises(ProtocolError, match='beyond'):
            inflate(bomb, limit=1_000_000)

    @FUZZ
    @given(data=ANY_BYTES)
    def test_any_bytes_inflate_within_the_limit_or_fail(self, data: bytes) -> None:
        """Any payload inflates to at most the limit or fails as a protocol error.

        :param data: the bytes a hostile sender chose.
        :type data: bytes
        """
        with contextlib.suppress(ProtocolError):
            assert len(inflate(data, limit=FUZZ_INFLATE_LIMIT)) <= FUZZ_INFLATE_LIMIT


class TestUnpackPayload:
    """Tests of :func:`unpack_payload`."""

    def test_packed_namespace_follows_the_sender(self) -> None:
        """A packed server packet unpacks as eDonkey, a packed client packet as eMule, as aMule does."""
        body = zlib.compress(b'payload')

        assert unpack_payload(protocol=Protocol.PACKED, opcode=0x33, payload=body).protocol == Protocol.EMULE
        server = unpack_payload(protocol=Protocol.PACKED, opcode=0x33, payload=body, packed_as=Protocol.EDONKEY)
        assert server.protocol == Protocol.EDONKEY
        assert server.payload == b'payload'

    @FUZZ
    @given(data=ANY_BYTES)
    def test_any_datagram_decodes_or_fails(self, data: bytes) -> None:
        """Any UDP datagram decodes to a packet or fails as a protocol error.

        :param data: the datagram a hostile sender chose.
        :type data: bytes
        """
        with contextlib.suppress(ProtocolError):
            decode_udp(data)


class TestReadTags:
    """Tests of :func:`read_tags` and :func:`write_tags`."""

    def test_tags_round_trip_in_every_written_type(self) -> None:
        """Integers, large integers, text, floats, hashes and blobs read back as written."""
        tags = [Tag(0x01, 'книга.pdf'), Tag(0x02, 123), Tag(0x3A, 1 << 40), Tag('files', 7), Tag(0x10, 2.5)]
        tags += [Tag(0x20, SAMPLE_HASH.digest), Tag(0x21, b'blob')]
        writer = Writer()
        write_tags(writer, tags)

        assert read_tags(Reader(writer.getvalue())) == tags

    def test_new_form_and_short_string_tags_are_read(self) -> None:
        """A tag with the high type bit and a one-byte name, and a STR4 value without a length, are understood."""
        data = U32.pack(2) + bytes([0x83, 0x15]) + U32.pack(9) + bytes([0x94, 0x04]) + b'djvu'

        assert read_tags(Reader(data)) == [Tag(0x15, 9), Tag(0x04, 'djvu')]

    def test_unknown_tag_type_fails_the_packet(self) -> None:
        """A tag type whose length cannot be known stops the parse."""
        with pytest.raises(ProtocolError, match='unknown tag type'):
            read_tags(Reader(U32.pack(1) + bytes([0xBF, 0x01, 0x00])))

    @FUZZ
    @given(data=COUNTED_BYTES)
    def test_any_bytes_give_tags_or_fail(self, data: bytes) -> None:
        """Any tag list reads or fails as a protocol error, whatever its counts and lengths claim.

        :param data: the bytes a hostile sender chose.
        :type data: bytes
        """
        with contextlib.suppress(ProtocolError):
            read_tags(Reader(data))


class TestEncodeQuery:
    """Tests of :func:`encode_query`."""

    def test_search_tree_matches_the_one_a_live_server_answered(self) -> None:
        """The keyword and the two extensions encode to the exact bytes a real server accepted."""
        tree = encode_query(SearchQuery(text='springer', extensions=('pdf', '.DJVU')))

        assert tree.hex() == LIVE_TREE_HEX

    def test_search_tree_carries_size_limits(self) -> None:
        """A minimum size becomes a 32-bit greater-than term on the size tag, a huge maximum a 64-bit one."""
        tree = encode_query(SearchQuery(text='kad', min_size=1_048_576, max_size=1 << 33))

        assert bytes([0x03]) + U32.pack(1_048_576) + bytes([0x01, 0x01, 0x00, 0x02]) in tree
        assert bytes([0x08]) + struct.pack('<Q', 1 << 33) + bytes([0x02, 0x01, 0x00, 0x02]) in tree


class TestSearchQuery:
    """Tests of :class:`SearchQuery`."""

    def test_kad_keyword_is_the_longest_word(self) -> None:
        """Kad searches the longest word of at least three bytes, in lower case."""
        assert SearchQuery(text='An Introduction to Kademlia').kad_keyword == 'introduction'
        with pytest.raises(ValueError, match='no word'):
            _ = SearchQuery(text='a b').kad_keyword

    @pytest.mark.parametrize(
        ('name', 'matches'),
        [
            ('Kademlia Explained.pdf', True),
            ("KADEMLIA'S EXPLAINED.djvu", True),
            ('Kademlia.mp4', False),
            ('setup.exe', False),
        ],
        ids=['same case', 'other case inside a longer word', 'one word missing', 'neither word'],
    )
    def test_name_must_hold_every_word(self, name: str, matches: bool) -> None:
        """A name matches only when it holds every word of the query, in any case and inside longer words.

        :param name: the published file name.
        :type name: str
        :param matches: whether the name may stay in the results.
        :type matches: bool
        """
        assert SearchQuery(text='kademlia explained').matches_words(name) is matches


class TestSearchResults:
    """Tests of :class:`SearchResults`."""

    def test_file_reported_by_more_servers_ranks_first(self) -> None:
        """A file several servers report outranks one with more sources from a single server, each counted once."""
        merged = SearchResults()
        lonely = SearchResult(file_hash=Ed2kHash(md4(b'lonely')), name=BOOK, size=10, sources=900)
        shared = SearchResult(file_hash=SAMPLE_HASH, name=BOOK, size=10, sources=3)
        merged.add(lonely, reporter=FIRST_SERVER)
        for reporter in (FIRST_SERVER, FIRST_SERVER, SECOND_SERVER):
            merged.add(shared, reporter=reporter)

        assert [(result.file_hash, result.seen_on) for result in merged.ranked()] == [
            (SAMPLE_HASH, 2),
            (lonely.file_hash, 1),
        ]

    def test_forged_size_cannot_hide_a_file_more_servers_report(self) -> None:
        """A size one reporter gives a known hash becomes a row of its own, below the size the others agree on.

        One hash names one content and so one size, but nothing tells which answer lies. Dropping the hash would let a
        single fake server or Kad node hide any file by echoing it with another size.
        """
        merged = SearchResults()
        honest = SearchResult(file_hash=SAMPLE_HASH, name=BOOK, size=10)
        for result, reporter in ((honest, FIRST_SERVER), (replace(honest, size=99), THIRD_SERVER), (honest, KAD)):
            merged.add(result, reporter=reporter)

        assert [(result.size, result.seen_on) for result in merged.ranked()] == [(10, 2), (99, 1)]
        assert merged.conflicting == {SAMPLE_HASH}


class TestParseServerResults:
    """Tests of :func:`parse_server_results`."""

    def test_server_results_are_parsed_with_more_flag(self) -> None:
        """A result page yields typed results and the trailing flag that announces more pages."""
        tags = Writer()
        write_tags(tags, [Tag(0x01, BOOK), Tag(0x02, 5_648_714), Tag(0x15, 3)])
        page = Writer().u32(1).raw(SAMPLE_HASH.digest).u32(0).u16(0).raw(tags.getvalue()).u8(1).getvalue()

        parsed = parse_server_results(Reader(page))

        assert parsed.more_available
        assert (parsed.results[0].name, parsed.results[0].size, parsed.results[0].sources) == (BOOK, 5_648_714, 3)

    @FUZZ
    @given(data=COUNTED_BYTES)
    def test_any_bytes_give_a_page_or_fail(self, data: bytes) -> None:
        """Any search result page parses or fails as a protocol error.

        :param data: the bytes a hostile server chose.
        :type data: bytes
        """
        with contextlib.suppress(ProtocolError):
            parse_server_results(Reader(data))


class TestLinkParse:
    """Tests of :meth:`FileLink.parse` and :meth:`ServerLink.parse`."""

    def test_file_link_round_trip_and_rejections(self) -> None:
        """A file link parses and formats back, and malformed links are refused."""
        text = f'ed2k://|file|A%20Book.pdf|5648714|E737E3459E12C22118C48306FAE1D8EB|h={AICH_ROOT_TEXT}|/'
        link = FileLink.parse(text)

        assert (link.name, link.size, link.file_hash, link.aich_root) == (
            'A Book.pdf',
            5_648_714,
            SAMPLE_HASH,
            AICH_ROOT,
        )
        assert str(link) == text
        assert FileLink.parse(text.replace(AICH_ROOT_TEXT, AICH_ROOT_TEXT.lower())).aich_root == AICH_ROOT
        bad_links = (
            'http://x',
            'ed2k://|file|a|0|E737E3459E12C22118C48306FAE1D8EB|/',
            'ed2k://|file|a|5|zz|/',
            'ed2k://|file|a|5|E737E3459E12C22118C48306FAE1D8EB|h=ABCDEF|/',
            'ed2k://|file|a|5|E737E3459E12C22118C48306FAE1D8EB|h=!!!!!!!!|/',
            NON_ASCII_ROOT_LINK,
        )
        for bad in bad_links:
            with pytest.raises(ProtocolError):
                FileLink.parse(bad)
        assert str(ServerLink.parse(SERVER_LINK)) == SERVER_LINK

    @pytest.mark.parametrize(
        'parse_link',
        [
            lambda: FileLink.parse('ed2k://|file|a.pdf|\u00b2|E737E3459E12C22118C48306FAE1D8EB|/'),
            lambda: FileLink.parse('ed2k://|file|a.pdf|\u0661\u0662|E737E3459E12C22118C48306FAE1D8EB|/'),
            lambda: ServerLink.parse('ed2k://|server|45.82.80.155|\u00b2|/'),
        ],
        ids=['superscript size', 'arabic-indic size', 'superscript port'],
    )
    def test_link_with_non_ascii_digits_is_refused(self, parse_link: Callable[[], object]) -> None:
        """A size or port written in digits other than ASCII is a malformed link, refused like any other.

        :param parse_link: parses one such link.
        :type parse_link: Callable[[], object]
        """
        with pytest.raises(ProtocolError):
            parse_link()

    @FUZZ
    @given(text=LINK_LIKE_TEXT)
    def test_any_link_text_parses_or_fails(self, text: str) -> None:
        """Any text shaped like a link parses as a file or server link or fails as a protocol error.

        :param text: the text a search result or a user supplied.
        :type text: str
        """
        for parse in (FileLink.parse, ServerLink.parse):
            with contextlib.suppress(ProtocolError):
                parse(text)


class TestServerList:
    """Tests of :meth:`ServerList.parse`."""

    def test_server_met_reads_address_in_network_order(self) -> None:
        """The first server of a list reads as its dotted address, with its name and user count."""
        record = Writer().raw(bytes([176, 123, 5, 89])).u16(4725)
        write_tags(record, [Tag(0x01, '\ufeffeMule Sunrise'), Tag('users', 53_847)])
        data = Writer().u8(0xE0).u32(1).raw(record.getvalue()).getvalue()

        server = ServerList.parse(data).servers[0]

        assert (server.host, server.port, server.name, server.users) == ('176.123.5.89', 4725, 'eMule Sunrise', 53_847)

    @FUZZ
    @given(data=SERVER_MET_BYTES)
    def test_any_bytes_give_a_list_or_fail(self, data: bytes) -> None:
        """Any server.met parses or fails as a protocol error.

        :param data: the bytes a hostile list host chose.
        :type data: bytes
        """
        with contextlib.suppress(ProtocolError):
            ServerList.parse(data)


class TestKadId:
    """Tests of :class:`KadId`."""

    def test_kad_id_reverses_each_word_on_the_wire(self) -> None:
        """A Kad ID is written as four little-endian words, so each 4-byte group of the digest is reversed."""
        digest = bytes(range(16))
        written = KadId.from_digest(digest).write(Writer()).getvalue()

        assert written == bytes([3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12])
        assert KadId.read(Reader(written)).digest == digest


class TestParseNodesDat:
    """Tests of :func:`parse_nodes_dat`."""

    def test_nodes_dat_version_2_is_parsed_and_kad1_dropped(self) -> None:
        """Version 2 records of 34 bytes parse, the IP is the little-endian number, and Kad 1 nodes are dropped."""
        layout = struct.Struct('<IHHB')
        kad2 = bytes(16) + layout.pack(0x5A5E32B2, 4672, 4662, 10) + bytes(9)
        kad1 = bytes(16) + layout.pack(0x01020304, 4672, 4662, 1) + bytes(9)
        data = U32.pack(0) + U32.pack(2) + U32.pack(2) + kad2 + kad1

        contacts = parse_nodes_dat(data)

        assert [(c.host, c.udp_port, c.version) for c in contacts] == [('90.94.50.178', 4672, 10)]

    @FUZZ
    @given(data=NODES_DAT_BYTES)
    def test_any_bytes_give_contacts_or_fail(self, data: bytes) -> None:
        """Any nodes.dat parses or fails as a protocol error.

        :param data: the bytes a hostile list host chose.
        :type data: bytes
        """
        with contextlib.suppress(ProtocolError):
            parse_nodes_dat(data)


class TestDeriveCiphers:
    """Tests of :func:`derive_ciphers`."""

    def test_obfuscation_keys_pair_up(self) -> None:
        """The initiator's send stream decrypts with the receiver's receive stream and vice versa."""
        receiver_hash = bytes(range(16))
        initiator = derive_ciphers(receiver_hash=receiver_hash, key_part=0x1234_5678, initiator=True)
        receiver = derive_ciphers(receiver_hash=receiver_hash, key_part=0x1234_5678, initiator=False)

        assert receiver.receive.apply(initiator.send.apply(b'hello')) == b'hello'
        assert initiator.receive.apply(receiver.send.apply(b'answer')) == b'answer'


class TestSemiRandomMarker:
    """Tests of :func:`semi_random_marker`."""

    def test_marker_byte_never_looks_like_a_protocol(self) -> None:
        """The first byte of an obfuscated connection is never a protocol byte."""
        assert all(semi_random_marker() not in PROTOCOL_BYTES for _ in range(2000))
