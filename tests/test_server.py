"""Unit tests of the server session: what it keeps of the packets a server sends unasked."""

from ed2k_client.constants import Protocol, ServerOp
from ed2k_client.server import ServerSession
from ed2k_client.servermet import ServerEntry
from ed2k_client.settings import DEFAULT_LIMITS
from ed2k_client.wire import Packet, Writer

SEARCH_PAGE = Packet(protocol=Protocol.EDONKEY, opcode=ServerOp.SEARCHRESULT, payload=Writer().u32(0).getvalue())
FLOOD = 50


def _session() -> ServerSession:
    """Build a session around no connection, enough for dispatching packets by hand.

    :returns: the session.
    :rtype: ServerSession
    """
    return ServerSession(
        stream=None,
        entry=ServerEntry(host='203.0.113.9', port=4661),
        on_callback=None,
        limits=DEFAULT_LIMITS,
    )


class TestDispatch:
    """Tests of how :class:`ServerSession` dispatches search result pages."""

    def test_search_pages_nobody_asked_for_are_dropped(self) -> None:
        """Pages that arrive while no search runs are not kept, so a server cannot grow memory between searches."""
        session = _session()

        for _ in range(FLOOD):
            session._dispatch(SEARCH_PAGE)

        assert session._search_pages.empty()

    async def test_pages_kept_during_a_search_are_bounded(self) -> None:
        """A search keeps no more pages than it may read, however many the server sends while it waits."""
        session = _session()

        async with session._search_lock:
            for _ in range(FLOOD):
                session._dispatch(SEARCH_PAGE)

            assert session._search_pages.qsize() == DEFAULT_LIMITS.server_result_pages
