"""Search queries, their binary expression tree and the results they return.

A query becomes a tree in prefix notation, as ``CSearchList::CreateSearchData`` in aMule writes it: a boolean node
is the byte ``0x00`` with the operator, a keyword is ``0x01`` with a string, a string tag comparison is ``0x02`` and
a numeric one is ``0x03`` (32 bits) or ``0x08`` (64 bits). The same tree serves a server search and the restrictive
part of a Kad keyword search.
"""

import re
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import TYPE_CHECKING, Self

from ed2k_client.constants import LARGE_FILE_THRESHOLD, LOW_ID_LIMIT, FileTag, SearchOperator
from ed2k_client.errors import ProtocolError
from ed2k_client.hashing import Ed2kHash
from ed2k_client.links import FileLink, valid_file_size
from ed2k_client.tags import int_value, read_tags, str_value, tag_map
from ed2k_client.wire import Writer

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from ed2k_client.tags import Tag
    from ed2k_client.wire import Reader

# Kad splits a query at these characters and drops words shorter than three UTF-8 bytes:
# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/kademlia/kademlia/SearchManager.cpp#L259
WORD_SPLIT = re.compile(r'[\s()\[\]{}<>,._\-!?:;\\/"]+')
MIN_KAD_WORD_BYTES: int = 3


class SearchNodeKind(IntEnum):
    """First byte of each node of the search tree."""

    # https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/SearchList.cpp#L171

    BOOLEAN = 0x00
    KEYWORD = 0x01
    STRING_TAG = 0x02
    NUMBER32 = 0x03
    NUMBER64 = 0x08


class BooleanOperator(IntEnum):
    """Operators of a boolean node."""

    AND = 0x00
    OR = 0x01
    NOT = 0x02


class FileType(StrEnum):
    """File type strings that eD2k servers index."""

    DOCUMENT = 'Doc'
    ARCHIVE = 'Arc'
    AUDIO = 'Audio'
    VIDEO = 'Video'
    IMAGE = 'Image'
    PROGRAM = 'Pro'
    CD_IMAGE = 'Iso'


class SearchOrigin(StrEnum):
    """Where a result came from."""

    SERVER = 'server'
    KAD = 'kad'


@dataclass(frozen=True, slots=True)
class SearchQuery:
    """What to look for.

    :ivar text: the words to find in file names.
    :ivar extensions: accepted extensions without the dot, any of them matches.
    :ivar file_type: the server-side file type, ``Doc`` for books.
    :ivar min_size: smallest file size in bytes, 0 for no limit.
    :ivar max_size: largest file size in bytes, 0 for no limit.
    :ivar min_sources: fewest sources a result must report, 0 for no limit.
    """

    text: str
    extensions: tuple[str, ...] = ()
    file_type: FileType | None = None
    min_size: int = 0
    max_size: int = 0
    min_sources: int = 0

    def __post_init__(self) -> None:
        """Normalise the extensions and refuse an empty query.

        :raises ValueError: when the query has no words.
        """
        if not self.words:
            err_msg = 'a search needs at least one word'
            raise ValueError(err_msg)

        # A frozen dataclass sets its own fields only through object.__setattr__
        object.__setattr__(self, 'extensions', tuple(ext.lower().lstrip('.') for ext in self.extensions))

    @property
    def words(self) -> tuple[str, ...]:
        """The words of the query, split the way Kad splits them."""
        # re.split can yield None for unmatched groups, so the type is narrowed to real words
        return tuple(word for word in WORD_SPLIT.split(self.text) if isinstance(word, str) and word)

    @property
    def kad_keyword(self) -> str:
        """The word a Kad search looks up: the longest word of three or more UTF-8 bytes, in lower case.

        aMule takes the first word. The longest one is used here because it is usually the rarest, so the
        responsible nodes return fewer unrelated files before the restrictive tree filters them.
        """
        # aMule's choice: https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/kademlia/kademlia/SearchManager.cpp#L156
        candidates = [word.lower() for word in self.words if len(word.encode()) >= MIN_KAD_WORD_BYTES]
        if not candidates:
            err_msg = f'no word of {MIN_KAD_WORD_BYTES} or more bytes in {self.text!r}'
            raise ValueError(err_msg)
        return max(candidates, key=lambda word: len(word.encode()))

    def matches_extension(self, name: str) -> bool:
        """Check a file name against the accepted extensions.

        :param name: the file name.
        :type name: str
        :returns: whether the extension is accepted or no extension was asked for.
        :rtype: bool
        """
        return not self.extensions or name.lower().rpartition('.')[2] in self.extensions

    def accepts(self, result: SearchResult) -> bool:
        """Check a result from a server or Kad against the extensions and the sizes a file can have.

        :param result: the result.
        :type result: SearchResult
        :returns: whether the result is kept.
        :rtype: bool
        """
        # The size is untrusted, and a link built from an impossible one never completes or breaks the part file
        return self.matches_extension(result.name) and valid_file_size(result.size)


@dataclass(frozen=True, slots=True)
class SearchResult:
    """One file found by a search.

    :ivar file_hash: the eD2k hash.
    :ivar name: the file name as published, untrusted.
    :ivar size: the size in bytes.
    :ivar sources: the number of sources the index knows.
    :ivar complete_sources: the number of sources with the complete file.
    :ivar file_type: the indexed file type.
    :ivar origin: where the result came from.
    """

    file_hash: Ed2kHash
    name: str
    size: int
    sources: int = 0
    complete_sources: int = 0
    file_type: str = ''
    origin: SearchOrigin = SearchOrigin.SERVER

    @classmethod
    def from_tags(cls, *, file_hash: Ed2kHash, tags: Iterable[Tag], origin: SearchOrigin) -> Self:
        """Build a result from the tags of a server or Kad answer.

        :param file_hash: the hash the answer names.
        :type file_hash: Ed2kHash
        :param tags: the tags that describe the file.
        :type tags: Iterable[Tag]
        :param origin: where the answer came from.
        :type origin: SearchOrigin
        :returns: the result.
        :rtype: Self
        """
        indexed = tag_map(tags)

        # A size above 4 GiB arrives as SIZE with the low 32 bits and SIZE_HI with the high ones
        size = int_value(indexed, FileTag.SIZE) | int_value(indexed, FileTag.SIZE_HI) << 32
        return cls(
            file_hash=file_hash,
            name=str_value(indexed, FileTag.NAME),
            size=size,
            sources=int_value(indexed, FileTag.SOURCES),
            complete_sources=int_value(indexed, FileTag.COMPLETE_SOURCES),
            file_type=str_value(indexed, FileTag.TYPE),
            origin=origin,
        )

    @property
    def extension(self) -> str:
        """The lower-case extension of the published name."""
        return self.name.lower().rpartition('.')[2] if '.' in self.name else ''

    @property
    def link(self) -> FileLink:
        """The ``ed2k://`` link of the file."""
        return FileLink(name=self.name, size=self.size, file_hash=self.file_hash)


@dataclass(slots=True)
class SearchResults:
    """Results merged by file hash, the way a client shows one row per distinct file.

    :ivar by_hash: the best result seen for each hash.
    """

    by_hash: dict[Ed2kHash, SearchResult] = field(default_factory=dict)

    def add(self, result: SearchResult) -> None:
        """Merge one result, keeping the higher source count.

        :param result: the result.
        :type result: SearchResult
        """
        known = self.by_hash.get(result.file_hash)
        if known is None or result.sources > known.sources:
            self.by_hash[result.file_hash] = result

    def ranked(self) -> list[SearchResult]:
        """List the results with the most sources first.

        :returns: the sorted results.
        :rtype: list[SearchResult]
        """
        return sorted(self.by_hash.values(), key=lambda item: (-item.complete_sources, -item.sources, item.name))


def _write_boolean(writer: Writer, operator: BooleanOperator, operands: Sequence[bytes]) -> None:
    """Join operands with one boolean operator as a left-deep tree in prefix notation.

    :param writer: the tree writer.
    :type writer: Writer
    :param operator: the operator.
    :type operator: BooleanOperator
    :param operands: the encoded operands.
    :type operands: Sequence[bytes]
    """
    # Prefix notation of a left-deep tree: n operands need n - 1 operators in front of them
    for _ in range(len(operands) - 1):
        writer.u8(SearchNodeKind.BOOLEAN).u8(operator)
    for operand in operands:
        writer.raw(operand)


def _string_tag(tag: FileTag, value: str) -> bytes:
    """Encode a comparison of a string tag.

    :param tag: the tag.
    :type tag: FileTag
    :param value: the wanted value.
    :type value: str
    :returns: the node bytes.
    :rtype: bytes
    """
    # The tag name is written as a one-byte name with a 16-bit length of 1
    return Writer().u8(SearchNodeKind.STRING_TAG).string(value).u16(1).u8(tag).getvalue()


def _number_tag(*, tag: FileTag, operator: SearchOperator, value: int, allow_64bit: bool) -> bytes:
    """Encode a comparison of a numeric tag in 32 or 64 bits.

    :param tag: the tag.
    :type tag: FileTag
    :param operator: the comparison.
    :type operator: SearchOperator
    :param value: the bound.
    :type value: int
    :param allow_64bit: whether the receiver reads 64-bit numbers.
    :type allow_64bit: bool
    :returns: the node bytes.
    :rtype: bytes
    """
    # A receiver without 64-bit support gets the bound clamped to 4 GiB, which is the most it can compare against
    writer = Writer()
    if value > LARGE_FILE_THRESHOLD and allow_64bit:
        writer.u8(SearchNodeKind.NUMBER64).u64(value)
    else:
        writer.u8(SearchNodeKind.NUMBER32).u32(min(value, LARGE_FILE_THRESHOLD))

    return writer.u8(operator).u16(1).u8(tag).getvalue()


def encode_query(query: SearchQuery, *, allow_64bit: bool = True) -> bytes:
    """Encode a query as the binary expression tree.

    :param query: the query.
    :type query: SearchQuery
    :param allow_64bit: whether the receiver understands 64-bit numbers, as the server's LARGEFILES flag says.
    :type allow_64bit: bool
    :returns: the tree bytes.
    :rtype: bytes
    """
    # Every word must match, and any one of the extensions may, so the extensions form one OR group among the ANDs
    terms = [Writer().u8(SearchNodeKind.KEYWORD).string(word).getvalue() for word in query.words]
    if query.extensions:
        alternatives = Writer()
        _write_boolean(alternatives, BooleanOperator.OR, [_string_tag(FileTag.FORMAT, e) for e in query.extensions])
        terms.append(alternatives.getvalue())
    if query.file_type is not None:
        terms.append(_string_tag(FileTag.TYPE, query.file_type))

    limits = (
        (query.min_size, FileTag.SIZE, SearchOperator.GREATER),
        (query.max_size, FileTag.SIZE, SearchOperator.LESS),
        (query.min_sources, FileTag.SOURCES, SearchOperator.GREATER),
    )
    terms.extend(
        _number_tag(tag=tag, operator=operator, value=value, allow_64bit=allow_64bit)
        for value, tag, operator in limits
        if value > 0
    )

    writer = Writer()
    _write_boolean(writer, BooleanOperator.AND, terms)
    return writer.getvalue()


@dataclass(frozen=True, slots=True)
class ServerSearchPage:
    """One ``OP_SEARCHRESULT`` packet.

    :ivar results: the files in it.
    :ivar more_available: whether the server holds further results for ``OP_QUERY_MORE_RESULT``.
    """

    results: tuple[SearchResult, ...]
    more_available: bool


def parse_server_results(reader: Reader) -> ServerSearchPage:
    """Parse ``<count 4>(<hash 16><id 4><port 2><tags>)[count][<more 1>]``.

    :param reader: the payload reader.
    :type reader: Reader
    :returns: the page.
    :rtype: ServerSearchPage
    :raises ProtocolError: when the count exceeds the reader's ``search_results`` limit.
    """
    count = reader.u32()
    if count > reader.limits.search_results:
        err_msg = f'{count} search results exceed the limit of {reader.limits.search_results}'
        raise ProtocolError(err_msg)

    results = []
    for _ in range(count):
        file_hash = Ed2kHash(reader.hash16())
        reader.take(6)  # the client ID and port of one source, which OP_GETSOURCES reports properly
        results.append(SearchResult.from_tags(file_hash=file_hash, tags=read_tags(reader), origin=SearchOrigin.SERVER))

    # The trailing flag exists only on servers that page their results
    more = reader.u8() if reader.remaining == 1 else 0
    return ServerSearchPage(results=tuple(results), more_available=bool(more))


def is_low_id(client_id: int) -> bool:
    """Check whether a client ID is a Low ID, which cannot accept incoming connections.

    :param client_id: the ID.
    :type client_id: int
    :returns: whether the ID is below 16,777,216.
    :rtype: bool
    """
    return client_id < LOW_ID_LIMIT
