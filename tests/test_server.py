"""Unit tests of the server session: what it keeps of the packets a server sends, asked or unasked."""

import pytest

from ed2k_client.constants import MAX_FILE_SIZE, FileTag, Protocol, ServerOp
from ed2k_client.hashing import md4
from ed2k_client.search import SearchQuery
from ed2k_client.server import ServerSession
from ed2k_client.servermet import ServerEntry
from ed2k_client.settings import DEFAULT_LIMITS, DEFAULT_TIMEOUTS, Timeouts
from ed2k_client.tags import Tag, write_tags
from ed2k_client.wire import Packet, Writer

SEARCH_PAGE = Packet(protocol=Protocol.EDONKEY, opcode=ServerOp.SEARCHRESULT, payload=Writer().u32(0).getvalue())
FLOOD = 50
BOOK = 'book.pdf'
BOOK_SIZE = 5_000_000
BROKEN = 'broken.pdf'
QUERY = SearchQuery(text='book', extensions=('pdf',))
COOKING = 'cooking recipes.pdf'
PHYSICS_QUERY = SearchQuery(text='physics', extensions=('pdf',))
SHORT_WAIT = Timeouts(server_search=0.05)


class AnsweringStream:
    """A server connection that answers each search request with the next page, as a server's reader delivers it.

    :ivar session: the session whose reader gets the pages.
    """

    def __init__(self, *pages: Packet, late_by: int = 0) -> None:
        """Keep the pages to answer with, one per search request.

        :param pages: the result pages, in the order of the requests they answer.
        :type pages: Packet
        :param late_by: how many requests later each page arrives, as from a server slower than the search timeout.
        :type late_by: int
        """
        self.session: ServerSession | None = None
        self._pages = list(pages)
        self._late_by = late_by
        self._owed: list[Packet] = []

    async def send(self, *, protocol: int, opcode: int, payload: bytes = b'') -> None:
        """Hand the page that is due to the session when the request is a search.

        :param protocol: the namespace byte.
        :type protocol: int
        :param opcode: the operation code.
        :type opcode: int
        :param payload: the body.
        :type payload: bytes
        """
        del protocol, payload
        if opcode != ServerOp.SEARCHREQUEST or self.session is None:
            return
        self._owed.append(self._pages.pop(0))
        if len(self._owed) > self._late_by:
            self.session._dispatch(self._owed.pop(0))


def _session(stream: AnsweringStream | None = None, *, timeouts: Timeouts = DEFAULT_TIMEOUTS) -> ServerSession:
    """Build a session around a stand-in connection, or none when packets are dispatched by hand.

    :param stream: the connection, ``None`` for none.
    :type stream: AnsweringStream | None
    :param timeouts: how long the session waits for a result page.
    :type timeouts: Timeouts
    :returns: the session.
    :rtype: ServerSession
    """
    session = ServerSession(
        stream=stream,
        entry=ServerEntry(host='203.0.113.9', port=4661),
        on_callback=None,
        timeouts=timeouts,
        limits=DEFAULT_LIMITS,
    )
    if stream is not None:
        stream.session = session
    return session


def _page(files: list[tuple[str, int]]) -> Packet:
    """Build a search result page that lists files by name and size.

    :param files: the ``(name, size)`` of each result.
    :type files: list[tuple[str, int]]
    :returns: the page.
    :rtype: Packet
    """
    writer = Writer().u32(len(files))
    for name, size in files:
        writer.raw(md4(name.encode())).u32(0).u16(0)
        write_tags(writer, [Tag(FileTag.NAME, name), Tag(FileTag.SIZE, size)])
    return Packet(protocol=Protocol.EDONKEY, opcode=ServerOp.SEARCHRESULT, payload=writer.getvalue())


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


class TestSearch:
    """Tests of :meth:`ServerSession.search`."""

    @pytest.mark.parametrize('size', [0, MAX_FILE_SIZE + 1], ids=['no size', 'beyond the largest file'])
    async def test_result_with_an_impossible_size_is_dropped(self, size: int) -> None:
        """A result whose size no file can have is left out, while the other results of the page are kept.

        A result without a size tag reads as 0 bytes, which has no block to fetch, so its download would dial its
        sources until the deadline, and a size beyond the largest file breaks the part file.

        :param size: the size the server reports for the broken result.
        :type size: int
        """
        session = _session(AnsweringStream(_page([(BOOK, BOOK_SIZE), (BROKEN, size)])))

        results = await session.search(QUERY)

        assert [(result.name, result.size) for result in results] == [(BOOK, BOOK_SIZE)]

    async def test_page_of_a_timed_out_search_is_not_the_next_answer(self) -> None:
        """A page that answers a search after its timeout is not returned as the result of the search after it.

        Result pages carry no search id, so a page that arrives once the next search has sent its request reaches
        that search, and a search for one subject would return the books of another.
        """
        late = AnsweringStream(_page([(COOKING, BOOK_SIZE)]), _page([]), late_by=1)
        session = _session(late, timeouts=SHORT_WAIT)
        await session.search(SearchQuery(text='cooking', extensions=('pdf',)))

        results = await session.search(PHYSICS_QUERY)

        assert [result.name for result in results] == []
