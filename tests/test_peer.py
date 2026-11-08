"""Unit tests of the client to client protocol: the serving side's upload slots and the hashset a downloader reads."""

import asyncio
from pathlib import Path
from unittest.mock import create_autospec

import pytest

from ed2k_client.constants import MAX_FILE_SIZE, PeerOp, Protocol
from ed2k_client.errors import ConnectionFailedError
from ed2k_client.hashing import Ed2kHash, md4, part_count
from ed2k_client.identity import Identity
from ed2k_client.peer import LocalPeer, PeerConnection
from ed2k_client.share import SharedLibrary
from ed2k_client.transport import PacketStream
from ed2k_client.wire import Packet, Writer, encode_tcp
from tests.fakes import ScriptedStream

STATE_DIR = Path('/state')
FILE_HASH = Ed2kHash(md4(b'book'))
UPLOAD_REQUEST = Packet(protocol=Protocol.EDONKEY, opcode=PeerOp.STARTUPLOADREQ, payload=FILE_HASH.digest)
REMOTE = ('203.0.113.7', 4662)
SLOTS = 2
LOCAL = LocalPeer(identity=Identity.generate(), client_id=0, tcp_port=0, nickname='seeder')
HASH_BYTES = 16


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
