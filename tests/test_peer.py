"""Unit tests of the client to client protocol: the serving side's upload slots."""

import asyncio
from pathlib import Path

import pytest

from ed2k_client.constants import PeerOp, Protocol
from ed2k_client.errors import ConnectionFailedError
from ed2k_client.hashing import Ed2kHash, md4
from ed2k_client.identity import Identity
from ed2k_client.peer import LocalPeer, PeerConnection
from ed2k_client.share import SharedLibrary
from ed2k_client.wire import Packet
from tests.fakes import ScriptedStream

STATE_DIR = Path('/state')
FILE_HASH = Ed2kHash(md4(b'book'))
UPLOAD_REQUEST = Packet(protocol=Protocol.EDONKEY, opcode=PeerOp.STARTUPLOADREQ, payload=FILE_HASH.digest)
REMOTE = ('203.0.113.7', 4662)
SLOTS = 2
LOCAL = LocalPeer(identity=Identity.generate(), client_id=0, tcp_port=0, nickname='seeder')


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
