"""Unit tests of the client to client protocol: the serving side's upload slots."""

import asyncio
from pathlib import Path

import pytest

from ed2k_client.constants import PeerOp, Protocol
from ed2k_client.errors import ConnectionFailedError
from ed2k_client.hashing import md4
from ed2k_client.identity import Identity
from ed2k_client.peer import LocalPeer, PeerConnection
from ed2k_client.settings import DEFAULT_LIMITS
from ed2k_client.share import SharedLibrary
from ed2k_client.wire import Packet

STATE_DIR = Path('/state')
UPLOAD_REQUEST = Packet(protocol=Protocol.EDONKEY, opcode=PeerOp.STARTUPLOADREQ, payload=md4(b'book'))
REMOTE = ('203.0.113.7', 4662)
SLOTS = 2


class ResettingStream:
    """A peer connection that asks for an upload slot and is reset before any answer reaches it.

    It stands in for :class:`PacketStream`, whose annotations name imports that exist only for type checkers, so
    ``create_autospec`` cannot read its signature.

    :ivar peer: the remote address.
    :ivar limits: the caps of the connection.
    """

    def __init__(self) -> None:
        """Queue the one request the peer sends."""
        self.peer = REMOTE
        self.limits = DEFAULT_LIMITS
        self._packets = [UPLOAD_REQUEST]

    async def read_packet(self, *, limit: int | None = None) -> Packet:
        """Return the slot request, then report the connection as gone.

        :param limit: ignored.
        :type limit: int | None
        :returns: the slot request.
        :rtype: Packet
        :raises ConnectionFailedError: once the request was read.
        """
        del limit
        if self._packets:
            return self._packets.pop()
        err_msg = 'closed'
        raise ConnectionFailedError(err_msg)

    async def send(self, *, protocol: int, opcode: int, payload: bytes = b'') -> None:
        """Fail every send, as on a connection the peer reset.

        :param protocol: ignored.
        :type protocol: int
        :param opcode: ignored.
        :type opcode: int
        :param payload: ignored.
        :type payload: bytes
        :raises ConnectionFailedError: always.
        """
        del protocol, opcode, payload
        err_msg = 'reset by peer'
        raise ConnectionFailedError(err_msg)


class TestServe:
    """Tests of :meth:`PeerConnection.serve`."""

    @pytest.mark.usefixtures('fs')
    async def test_slot_is_released_when_the_accept_answer_cannot_be_sent(self) -> None:
        """A peer that resets before its slot is confirmed gives the slot back.

        A queued eMule peer disconnects and asks again later, so the slot it finally gets often goes to a dead
        socket. Keeping that slot would let as many such peers as there are slots stop all sharing for good.
        """
        library = SharedLibrary(state_dir=STATE_DIR)
        local = LocalPeer(identity=Identity.generate(), client_id=0, tcp_port=0, nickname='seeder')
        slots = asyncio.Semaphore(SLOTS)

        for _ in range(SLOTS):
            connection = PeerConnection(stream=ResettingStream(), local=local)
            await connection.serve(library=library, slots=slots)

        assert not slots.locked()
