"""Unit tests of the wire format: framing, tags, search trees, links, server lists, Kad IDs and obfuscation keys."""

import struct
import zlib

import pytest

from ed2k_client.constants import Protocol
from ed2k_client.errors import ProtocolError
from ed2k_client.hashing import Ed2kHash
from ed2k_client.kad.contacts import KadId, parse_nodes_dat
from ed2k_client.links import FileLink, ServerLink
from ed2k_client.obfuscation import PROTOCOL_BYTES, derive_ciphers, semi_random_marker
from ed2k_client.search import SearchQuery, encode_query, parse_server_results
from ed2k_client.servermet import ServerList
from ed2k_client.tags import Tag, read_tags, write_tags
from ed2k_client.wire import U32, Reader, Writer, inflate, unpack_payload

# The tree a live eD2k server (ed2k-rust, 85.17.116.222:6082) answered with 300 results on 2026-11-06.
LIVE_TREE_HEX = '0000010800737072696e6765720001020300706466010004020400646a7675010004'
SAMPLE_HASH = Ed2kHash.from_hex('E737E3459E12C22118C48306FAE1D8EB')
BOOK = 'book.pdf'
SERVER_LINK = 'ed2k://|server|45.82.80.155|5687|/'
UINT32 = '<I'


def test_reader_refuses_reading_past_the_end() -> None:
    """A length that points beyond the buffer becomes a protocol error, never a short read."""
    reader = Reader(b'\x05\x00ab')

    with pytest.raises(ProtocolError, match='need 5 bytes'):
        reader.string()


def test_reader_refuses_strings_over_the_limit() -> None:
    """A declared string length above the limit is refused before the bytes are read."""
    with pytest.raises(ProtocolError, match='exceeds the limit'):
        Reader(b'\xff\xff' + bytes(10)).string(limit=100)


def test_inflate_stops_a_compression_bomb() -> None:
    """A small zlib stream that would inflate to many megabytes is refused at the limit."""
    bomb = zlib.compress(bytes(50_000_000), 9)

    with pytest.raises(ProtocolError, match='beyond'):
        inflate(bomb, limit=1_000_000)


def test_packed_namespace_follows_the_sender() -> None:
    """A packed server packet unpacks as eDonkey, a packed client packet as eMule, as aMule does."""
    body = zlib.compress(b'payload')

    assert unpack_payload(protocol=Protocol.PACKED, opcode=0x33, payload=body).protocol == Protocol.EMULE
    server = unpack_payload(protocol=Protocol.PACKED, opcode=0x33, payload=body, packed_as=Protocol.EDONKEY)
    assert server.protocol == Protocol.EDONKEY
    assert server.payload == b'payload'


def test_tags_round_trip_in_every_written_type() -> None:
    """Integers, large integers, text, floats, hashes and blobs read back as written."""
    tags = [Tag(0x01, 'книга.pdf'), Tag(0x02, 123), Tag(0x3A, 1 << 40), Tag('files', 7), Tag(0x10, 2.5)]
    tags += [Tag(0x20, SAMPLE_HASH.digest), Tag(0x21, b'blob')]
    writer = Writer()
    write_tags(writer, tags)

    assert read_tags(Reader(writer.getvalue())) == tags


def test_new_form_and_short_string_tags_are_read() -> None:
    """A tag with the high type bit and a one-byte name, and a STR4 value without a length, are understood."""
    data = U32.pack(2) + bytes([0x83, 0x15]) + U32.pack(9) + bytes([0x94, 0x04]) + b'djvu'

    assert read_tags(Reader(data)) == [Tag(0x15, 9), Tag(0x04, 'djvu')]


def test_unknown_tag_type_fails_the_packet() -> None:
    """A tag type whose length cannot be known stops the parse."""
    with pytest.raises(ProtocolError, match='unknown tag type'):
        read_tags(Reader(U32.pack(1) + bytes([0xBF, 0x01, 0x00])))


def test_search_tree_matches_the_one_a_live_server_answered() -> None:
    """The keyword and the two extensions encode to the exact bytes a real server accepted."""
    tree = encode_query(SearchQuery(text='springer', extensions=('pdf', '.DJVU')))

    assert tree.hex() == LIVE_TREE_HEX


def test_search_tree_carries_size_limits() -> None:
    """A minimum size becomes a 32-bit greater-than term on the size tag, a huge maximum a 64-bit one."""
    tree = encode_query(SearchQuery(text='kad', min_size=1_048_576, max_size=1 << 33))

    assert bytes([0x03]) + U32.pack(1_048_576) + bytes([0x01, 0x01, 0x00, 0x02]) in tree
    assert bytes([0x08]) + struct.pack('<Q', 1 << 33) + bytes([0x02, 0x01, 0x00, 0x02]) in tree


def test_kad_keyword_is_the_longest_word() -> None:
    """Kad searches the longest word of at least three bytes, in lower case."""
    assert SearchQuery(text='An Introduction to Kademlia').kad_keyword == 'introduction'
    with pytest.raises(ValueError, match='no word'):
        _ = SearchQuery(text='a b').kad_keyword


def test_server_results_are_parsed_with_more_flag() -> None:
    """A result page yields typed results and the trailing flag that announces more pages."""
    tags = Writer()
    write_tags(tags, [Tag(0x01, BOOK), Tag(0x02, 5_648_714), Tag(0x15, 3)])
    page = Writer().u32(1).raw(SAMPLE_HASH.digest).u32(0).u16(0).raw(tags.getvalue()).u8(1).getvalue()

    parsed = parse_server_results(Reader(page))

    assert parsed.more_available
    assert (parsed.results[0].name, parsed.results[0].size, parsed.results[0].sources) == (BOOK, 5_648_714, 3)


def test_file_link_round_trip_and_rejections() -> None:
    """A file link parses and formats back, and malformed links are refused."""
    text = 'ed2k://|file|A%20Book.pdf|5648714|E737E3459E12C22118C48306FAE1D8EB|h=ABCDEF|/'
    link = FileLink.parse(text)

    assert (link.name, link.size, link.file_hash, link.aich_root) == ('A Book.pdf', 5_648_714, SAMPLE_HASH, 'ABCDEF')
    assert str(link) == text
    for bad in ('http://x', 'ed2k://|file|a|0|E737E3459E12C22118C48306FAE1D8EB|/', 'ed2k://|file|a|5|zz|/'):
        with pytest.raises(ProtocolError):
            FileLink.parse(bad)
    assert str(ServerLink.parse(SERVER_LINK)) == SERVER_LINK


def test_server_met_reads_address_in_network_order() -> None:
    """The first server of a list reads as its dotted address, with its name and user count."""
    record = Writer().raw(bytes([176, 123, 5, 89])).u16(4725)
    write_tags(record, [Tag(0x01, '\ufeffeMule Sunrise'), Tag('users', 53_847)])
    data = Writer().u8(0xE0).u32(1).raw(record.getvalue()).getvalue()

    server = ServerList.parse(data).servers[0]

    assert (server.host, server.port, server.name, server.users) == ('176.123.5.89', 4725, 'eMule Sunrise', 53_847)


def test_kad_id_reverses_each_word_on_the_wire() -> None:
    """A Kad ID is written as four little-endian words, so each 4-byte group of the digest is reversed."""
    digest = bytes(range(16))
    written = KadId.from_digest(digest).write(Writer()).getvalue()

    assert written == bytes([3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12])
    assert KadId.read(Reader(written)).digest == digest


def test_nodes_dat_version_2_is_parsed_and_kad1_dropped() -> None:
    """Version 2 records of 34 bytes parse, the IP is the little-endian number, and Kad 1 nodes are dropped."""
    layout = struct.Struct('<IHHB')
    kad2 = bytes(16) + layout.pack(0x5A5E32B2, 4672, 4662, 10) + bytes(9)
    kad1 = bytes(16) + layout.pack(0x01020304, 4672, 4662, 1) + bytes(9)
    data = U32.pack(0) + U32.pack(2) + U32.pack(2) + kad2 + kad1

    contacts = parse_nodes_dat(data)

    assert [(c.host, c.udp_port, c.version) for c in contacts] == [('90.94.50.178', 4672, 10)]
    assert UINT32 == '<I'


def test_obfuscation_keys_pair_up() -> None:
    """The initiator's send stream decrypts with the receiver's receive stream and vice versa."""
    receiver_hash = bytes(range(16))
    initiator = derive_ciphers(receiver_hash=receiver_hash, key_part=0x1234_5678, initiator=True)
    receiver = derive_ciphers(receiver_hash=receiver_hash, key_part=0x1234_5678, initiator=False)

    assert receiver.receive.apply(initiator.send.apply(b'hello')) == b'hello'
    assert initiator.receive.apply(receiver.send.apply(b'answer')) == b'answer'


def test_marker_byte_never_looks_like_a_protocol() -> None:
    """The first byte of an obfuscated connection is never a protocol byte."""
    assert all(semi_random_marker() not in PROTOCOL_BYTES for _ in range(2000))
