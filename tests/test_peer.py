"""Unit tests of the client to client protocol: upload slots, the hashset a downloader reads and peer packet parsers."""

import asyncio
import contextlib
from pathlib import Path
from unittest.mock import create_autospec

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ed2k_client.aich import AichTree
from ed2k_client.constants import MAX_FILE_SIZE, PART_SIZE, ClientTag, EmuleOp, PeerOp, Protocol
from ed2k_client.errors import ConnectionFailedError, ProtocolError
from ed2k_client.hashing import Ed2kHash, md4, part_count
from ed2k_client.identity import Identity
from ed2k_client.peer import AICH_SHIFT, LocalPeer, PeerConnection, parse_file_status, parse_hello
from ed2k_client.share import SharedLibrary
from ed2k_client.tags import Tag, write_tags
from ed2k_client.transport import PacketStream
from ed2k_client.wire import Packet, Reader, Writer, encode_tcp
from tests.fakes import ScriptedStream
from tests.helpers import aich_tree, recovery_data

STATE_DIR = Path('/state')
FILE_HASH = Ed2kHash(md4(b'book'))
UPLOAD_REQUEST = Packet(protocol=Protocol.EDONKEY, opcode=PeerOp.STARTUPLOADREQ, payload=FILE_HASH.digest)
REMOTE = ('203.0.113.7', 4662)
SLOTS = 2
LOCAL = LocalPeer(identity=Identity.generate(), client_id=0, tcp_port=0, nickname='seeder')
HASH_BYTES = 16
AICH_PART = 1
AICH_SIZE = 2 * PART_SIZE
AICH_ROOT = bytes(range(20))

# Hostile payloads, with no example kept on disk, as a unit test writes no file
FUZZ = settings(database=None)
ANY_BYTES = st.binary(max_size=4096)
FILE_SIZES = st.integers(min_value=1, max_value=MAX_FILE_SIZE)


def aich_answer(payload: bytes) -> Packet:
    """Wrap an AICH answer payload in its packet.

    :param payload: the payload.
    :type payload: bytes
    :returns: the packet.
    :rtype: Packet
    """
    return Packet(protocol=Protocol.EMULE, opcode=EmuleOp.AICHANSWER, payload=payload)


class TestServe:
    """Tests of :meth:`PeerConnection.serve`."""

    @pytest.mark.usefixtures('fs')
    async def test_slot_is_released_when_the_accept_answer_cannot_be_sent(self) -> None:
        """A peer that resets before its slot is confirmed gives the slot back.

        A queued eMule peer disconnects and asks again later, so the slot it finally gets often goes to a dead
        socket. Keeping that slot would let as many such peers as there are slots stop all sharing for good.
        """
        library = SharedLibrary(state_dir=STATE_DIR)
        slots = asyncio.Semaphore(SLOTS)
        reset = ConnectionFailedError('reset by peer')

        for _ in range(SLOTS):
            stream = ScriptedStream([UPLOAD_REQUEST], peer=REMOTE, send_error=reset)
            await PeerConnection(stream=stream, local=LOCAL).serve(library=library, slots=slots)

        assert not slots.locked()


class TestRequestHashset:
    """Tests of :meth:`PeerConnection.request_hashset`."""

    async def test_hashset_of_the_largest_file_is_read(self) -> None:
        """The hashset answer of the largest file eD2k allows arrives whole, beyond the size of one data packet.

        Every part adds 16 bytes, so the answer of a file above 104.9 GiB outgrows the cap of a data packet, and a
        downloader that read it with that cap would refuse it and ban every honest source of the file.
        """
        count = part_count(MAX_FILE_SIZE)
        hashes = [index.to_bytes(HASH_BYTES) for index in range(count)]
        payload = Writer().raw(FILE_HASH.digest).u16(count).raw(b''.join(hashes)).getvalue()
        reader = asyncio.StreamReader()
        reader.feed_data(encode_tcp(protocol=Protocol.EDONKEY, opcode=PeerOp.HASHSETANSWER, payload=payload))
        writer = create_autospec(asyncio.StreamWriter, instance=True)
        writer.get_extra_info.return_value = REMOTE
        connection = PeerConnection(stream=PacketStream(reader=reader, writer=writer), local=LOCAL)

        assert await connection.request_hashset(FILE_HASH) == hashes


class TestParseHello:
    """Tests of :func:`parse_hello`."""

    @FUZZ
    @given(data=ANY_BYTES, answer=st.booleans())
    def test_any_hello_parses_or_fails(self, data: bytes, answer: bool) -> None:
        """Any hello or hello answer parses or fails as a protocol error.

        :param data: the payload a hostile peer chose.
        :type data: bytes
        :param answer: whether it is read as the answer, without the leading hash length.
        :type answer: bool
        """
        with contextlib.suppress(ProtocolError):
            parse_hello(Reader(data), answer=answer)

    @pytest.mark.parametrize(('options', 'aich'), [(1 << AICH_SHIFT, True), (0, False)], ids=['aich', 'no-aich'])
    def test_aich_support_is_read_from_the_options(self, options: int, aich: bool) -> None:
        """The AICH version in bits 29 to 31 of the first option tag says whether the peer answers AICH requests.

        :param options: the first option tag.
        :type options: int
        :param aich: whether the peer counts as answering AICH requests.
        :type aich: bool
        """
        writer = Writer().raw(bytes(16)).u32(0).u16(0)
        write_tags(writer, [Tag(ClientTag.EMULE_MISCOPTIONS1, options)])

        assert parse_hello(Reader(writer.getvalue()), answer=True).aich is aich


class TestParseFileStatus:
    """Tests of :func:`parse_file_status`."""

    @FUZZ
    @given(data=ANY_BYTES, size=FILE_SIZES)
    def test_any_status_parses_or_fails(self, data: bytes, size: int) -> None:
        """Any file status parses into parts of the file or fails as a protocol error.

        :param data: the payload a hostile peer chose.
        :type data: bytes
        :param size: the size of the file asked for.
        :type size: int
        """
        with contextlib.suppress(ProtocolError):
            status = parse_file_status(Reader(data), size=size)
            assert all(0 <= part < part_count(size) for part in status.parts)


class TestRequestAich:
    """Tests of :meth:`PeerConnection.request_aich`."""

    async def test_answer_gives_the_hashes(self) -> None:
        """An answer for the file, part and root asked about gives its hashes, and the request carries all three."""
        tree = aich_tree(bytes(AICH_SIZE))
        root = tree[1]
        payload = Writer().raw(FILE_HASH.digest).u16(AICH_PART).raw(root)
        payload.raw(recovery_data(tree, size=AICH_SIZE, part=AICH_PART))
        stream = ScriptedStream([aich_answer(payload.getvalue())], peer=REMOTE)
        connection = PeerConnection(stream=stream, local=LOCAL)

        count = AichTree(size=AICH_SIZE, root=root).hash_count(AICH_PART)

        hashes = await connection.request_aich(file_hash=FILE_HASH, part=AICH_PART, root=root, count=count)

        assert hashes is not None
        assert len(hashes) == count
        assert stream.sent == [
            (Protocol.EMULE, EmuleOp.AICHREQUEST, Writer().raw(FILE_HASH.digest).u16(AICH_PART).raw(root).getvalue())
        ]

    async def test_file_hash_alone_is_a_refusal(self) -> None:
        """An answer that is the file hash alone means the peer has no hashes for this root."""
        connection = PeerConnection(stream=ScriptedStream([aich_answer(FILE_HASH.digest)], peer=REMOTE), local=LOCAL)

        assert await connection.request_aich(file_hash=FILE_HASH, part=0, root=AICH_ROOT, count=1) is None

    @pytest.mark.parametrize(
        ('payload', 'message'),
        [
            pytest.param(md4(b'other'), 'another file', id='other-file'),
            pytest.param(
                FILE_HASH.digest + Writer().u16(AICH_PART + 1).raw(AICH_ROOT).getvalue(),
                'another part',
                id='other-part',
            ),
            pytest.param(
                FILE_HASH.digest + Writer().u16(AICH_PART).raw(bytes(20)).getvalue(),
                'another part or root',
                id='other-root',
            ),
        ],
    )
    async def test_answer_about_something_else_is_refused(self, payload: bytes, message: str) -> None:
        """An answer about another file, part or root breaks the protocol, since only one request is in flight.

        :param payload: the answer.
        :type payload: bytes
        :param message: what the error names.
        :type message: str
        """
        connection = PeerConnection(stream=ScriptedStream([aich_answer(payload)], peer=REMOTE), local=LOCAL)

        with pytest.raises(ProtocolError, match=message):
            await connection.request_aich(file_hash=FILE_HASH, part=AICH_PART, root=AICH_ROOT, count=1)
