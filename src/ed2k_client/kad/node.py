"""A Kad 2 node that searches the network without a server.

The node bootstraps from ``nodes.dat`` contacts with ``KADEMLIA2_BOOTSTRAP_REQ``, walks towards a target with
``KADEMLIA2_REQ`` (asking up to five nodes at a time, as aMule's ``ALPHA_QUERY``), and sends the search itself to
the nodes in the target's tolerance zone. aMule refuses a search when the top 32 bits of the distance between its ID
and the target exceed ``SEARCHTOLERANCE`` (2^24), so only nodes closer than 2^120 are asked.

The node is firewalled by design: it answers nothing, publishes nothing and keeps no routing table between runs. A
datagram is accepted only from an address the node is waiting on for that opcode, which mirrors aMule's packet
tracking and drops spoofed or unsolicited answers.
"""

import asyncio
import ipaddress
import logging
import random
from collections import defaultdict
from dataclasses import dataclass, field
from functools import partial
from typing import TYPE_CHECKING, Self, override

from ed2k_client.constants import (
    CryptOption,
    FileTag,
    KadOp,
    Protocol,
)
from ed2k_client.errors import NotConnectedError, ProtocolError
from ed2k_client.hashing import Ed2kHash, md4
from ed2k_client.kad.contacts import Contact, KadId, closest, read_contacts
from ed2k_client.search import SearchOrigin, SearchResult, encode_query
from ed2k_client.settings import DEFAULT_KAD, DEFAULT_LIMITS
from ed2k_client.sources import Source, SourceOrigin, client_id_from_host
from ed2k_client.tags import UINT32_MAX, int_value, read_tags, tag_map
from ed2k_client.wire import Writer, decode_udp, encode_udp

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from types import TracebackType

    from ed2k_client.search import SearchQuery
    from ed2k_client.security import AddressPolicy
    from ed2k_client.settings import KadSettings, Limits
    from ed2k_client.tags import Tag
    from ed2k_client.wire import Packet

logger = logging.getLogger(__name__)

# One entry of a search answer: a file hash, or a publisher's user hash in a source search, and its tags
type SearchAnswer = tuple[Ed2kHash, list[Tag]]

# The request type of KADEMLIA2_REQ that asks for closer nodes: https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/include/protocol/kad/Constants.h#L54
FIND_NODE: int = 0x0B

# A node answers a search only when the top 32 bits of its distance to the target are at most 2^24, which is a
# distance below 2^120: https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/kademlia/net/KademliaUDPListener.cpp#L1032
SEARCH_TOLERANCE: int = 1 << 120

# Bit 15 of the start position marks a keyword search whose tree the node must apply: https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/kademlia/net/KademliaUDPListener.cpp#L939
RESTRICTIVE_FLAG: int = 0x8000

# A node that is not firewalled publishes itself as type 1, or 4 for files above 4 GiB, and only those can be dialled
# without a buddy: https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/kademlia/kademlia/Search.cpp#L641
DIRECT_SOURCE_TYPES: frozenset[int] = frozenset({1, 4})


@dataclass(frozen=True, slots=True)
class KadRequest:
    """One Kad request and the answer it expects.

    :ivar opcode: the request opcode.
    :ivar payload: the request body.
    :ivar answer: the opcode of the expected answer.
    """

    opcode: int
    payload: bytes
    answer: int


BOOTSTRAP_REQUEST = KadRequest(opcode=KadOp.BOOTSTRAP_REQ, payload=b'', answer=KadOp.BOOTSTRAP_RES)


@dataclass(slots=True)
class _Datagrams(asyncio.DatagramProtocol):
    """Route datagrams to the waiters registered for their sender and opcode.

    :ivar waiters: the queues of the requests in flight, by the ``(host, port, opcode)`` of the answer they await.
        Several requests to one node for one kind of answer each get every such answer and keep their own.
    :ivar limits: the caps on a datagram and on everything read from it.
    """

    waiters: dict[tuple[str, int, int], list[asyncio.Queue[Packet]]] = field(default_factory=dict)
    limits: Limits = DEFAULT_LIMITS

    @override
    def datagram_received(self, data: bytes, addr: tuple[str | int, int]) -> None:
        """Hand a datagram to the matching waiter or drop it.

        :param data: the datagram.
        :type data: bytes
        :param addr: the sender.
        :type addr: tuple[str | int, int]
        """
        if len(data) > self.limits.udp_datagram:
            return
        try:
            packet = decode_udp(data, limits=self.limits)
        except ProtocolError:
            return

        # Only an answer from the node asked, with the opcode expected, reaches a waiter, as aMule tracks requests:
        # https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/kademlia/net/KademliaUDPListener.cpp#L690
        for queue in self.waiters.get((str(addr[0]), addr[1], packet.opcode), ()):
            queue.put_nowait(packet)


class KadNode:
    """A firewalled Kad 2 participant that searches keywords and sources.

    :ivar kad_id: this node's ID.
    :ivar contacts: live contacts by ID.
    """

    def __init__(
        self,
        *,
        kad_id: bytes,
        policy: AddressPolicy,
        udp_port: int = 0,
        settings: KadSettings = DEFAULT_KAD,
        limits: Limits = DEFAULT_LIMITS,
    ) -> None:
        """Prepare the node; use it as an async context manager to open its socket.

        :param kad_id: this node's 16-byte ID.
        :type kad_id: bytes
        :param policy: which addresses may be contacted.
        :type policy: AddressPolicy
        :param udp_port: the local UDP port, 0 for any.
        :type udp_port: int
        :param settings: how lookups and searches spread and how long one request waits.
        :type settings: KadSettings
        :param limits: the caps on datagrams and search results.
        :type limits: Limits
        """
        self.kad_id = KadId.from_digest(kad_id)
        self.contacts: dict[KadId, Contact] = {}
        self._policy = policy
        self._udp_port = udp_port
        self._settings = settings
        self._limits = limits
        self._protocol = _Datagrams(limits=limits)
        self._transport: asyncio.DatagramTransport | None = None

    async def __aenter__(self) -> Self:
        """Open the UDP socket.

        :returns: the node.
        :rtype: Self
        """
        loop = asyncio.get_running_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: self._protocol, local_addr=('0.0.0.0', self._udp_port)
        )
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None
    ) -> None:
        """Close the UDP socket.

        :param exc_type: the exception type, if any.
        :type exc_type: type[BaseException] | None
        :param exc: the exception, if any.
        :type exc: BaseException | None
        :param traceback: the traceback, if any.
        :type traceback: TracebackType | None
        """
        if self._transport is not None:
            self._transport.close()

    async def _ask[T](
        self, contact: Contact, request: KadRequest, *, parse: Callable[[Packet], T], collect: float = 0.0
    ) -> list[T]:
        """Send one request, gather the answers of one contact and parse each of them.

        :param contact: the node.
        :type contact: Contact
        :param request: the request and the answer it expects.
        :type request: KadRequest
        :param parse: reads one answer, raising :class:`ProtocolError` when it is malformed.
        :type parse: Callable[[Packet], T]
        :param collect: seconds to keep collecting after the first answer, for multi-packet answers.
        :type collect: float
        :returns: the parsed answers, empty on timeout.
        :rtype: list[T]
        :raises NotConnectedError: when the socket is not open.
        """
        if self._transport is None:
            err_msg = 'the Kad node is not started'
            raise NotConnectedError(err_msg)

        # The waiter is registered before the request goes out, so a fast answer cannot arrive unclaimed
        key = (contact.host, contact.udp_port, request.answer)
        queue: asyncio.Queue[Packet] = asyncio.Queue()
        queues = self._protocol.waiters.setdefault(key, [])
        queues.append(queue)
        try:
            datagram = encode_udp(protocol=Protocol.KAD, opcode=request.opcode, payload=request.payload)
            self._transport.sendto(datagram, contact.address)
            packets = await _drain(queue, first=self._settings.response_timeout, collect=collect)
        finally:
            queues.remove(queue)
            if not queues:
                del self._protocol.waiters[key]

        # Every answer is parsed here, at the edge of the network, so a malformed one costs only itself and never
        # the lookup or the search that the other nodes are answering
        parsed: list[T] = []
        for packet in packets:
            try:
                parsed.append(parse(packet))
            except ProtocolError as error:
                logger.info('Dropping a malformed answer from %s:%d: %s', contact.host, contact.udp_port, error)
        return parsed

    def _usable(self, contacts: Sequence[Contact]) -> list[Contact]:
        """Keep the contacts the address policy allows, except this node.

        :param contacts: the candidates.
        :type contacts: Sequence[Contact]
        :returns: the usable contacts.
        :rtype: list[Contact]
        """
        return [c for c in contacts if c.kad_id != self.kad_id and self._policy.permits(c.host, c.udp_port)]

    async def bootstrap(self, seeds: Sequence[Contact], *, want: int | None = None) -> int:
        """Learn live contacts from seed nodes.

        :param seeds: contacts from ``nodes.dat``.
        :type seeds: Sequence[Contact]
        :param want: stop after this many live contacts, the ``bootstrap_contacts`` setting when ``None``.
        :type want: int | None
        :returns: the number of live contacts.
        :rtype: int
        """
        enough = want if want is not None else self._settings.bootstrap_contacts

        # Shuffled, so that many clients with the same nodes.dat do not all start with the same seeds
        pool = self._usable(seeds)
        random.shuffle(pool)
        fanout = self._settings.bootstrap_fanout
        for start in range(0, len(pool), fanout):
            batch = pool[start : start + fanout]
            replies = await asyncio.gather(
                *(self._ask(seed, BOOTSTRAP_REQUEST, parse=partial(_bootstrap_answer, seed=seed)) for seed in batch)
            )
            for responder, found in (answer for answers in replies for answer in answers):
                self.contacts[responder.kad_id] = responder
                for contact in self._usable(found):
                    self.contacts.setdefault(contact.kad_id, contact)
            if len(self.contacts) >= enough:
                break

        logger.info('Kad bootstrap: %d live contacts', len(self.contacts))
        return len(self.contacts)

    async def lookup(self, target: KadId) -> list[Contact]:
        """Walk towards a target and return the nearest nodes that answered.

        :param target: the target ID.
        :type target: KadId
        :returns: responsive contacts, nearest first.
        :rtype: list[Contact]
        """
        candidates = dict(self.contacts)
        asked: set[KadId] = set()
        answered: dict[KadId, Contact] = {}
        k, alpha = self._settings.k, self._settings.alpha

        # Each round asks the alpha closest unasked of the k closest known nodes, so the walk stops by itself once
        # nobody closer turns up, and max_rounds only bounds a walk that keeps finding nodes
        for _ in range(self._settings.max_rounds):
            batch = [c for c in closest(candidates.values(), target, count=k) if c.kad_id not in asked][:alpha]
            if not batch:
                break
            asked.update(c.kad_id for c in batch)

            # KADEMLIA2_REQ carries the receiver's own ID, which the receiver checks before answering:
            # https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/kademlia/net/KademliaUDPListener.cpp#L659
            replies = await asyncio.gather(
                *(
                    self._ask(
                        c,
                        KadRequest(
                            opcode=KadOp.REQ,
                            payload=c.kad_id.write(target.write(Writer().u8(FIND_NODE))).getvalue(),
                            answer=KadOp.RES,
                        ),
                        parse=partial(_closer_contacts, target=target),
                    )
                    for c in batch
                )
            )

            for contact, answers in zip(batch, replies, strict=True):
                if answers:
                    answered[contact.kad_id] = contact
                for found in self._usable([found for answer in answers for found in answer]):
                    candidates.setdefault(found.kad_id, found)

        return closest(answered.values(), target, count=k)

    async def _search(self, *, target: KadId, opcode: int, payload: bytes, limit: int) -> list[SearchAnswer]:
        """Send a search to the nodes in the target's tolerance zone and gather the entries of their answers.

        :param target: the target.
        :type target: KadId
        :param opcode: the search opcode.
        :type opcode: int
        :param payload: the request body.
        :type payload: bytes
        :param limit: the most entries read from one answer.
        :type limit: int
        :returns: the entries of every well-formed answer.
        :rtype: list[SearchAnswer]
        """
        nodes = [c for c in await self.lookup(target) if c.kad_id.distance(target) < SEARCH_TOLERANCE]
        logger.info('Kad search: %d nodes in the tolerance zone', len(nodes))

        # A node may split its answer over several datagrams, so each request keeps collecting for a while
        collect = self._settings.search_collect
        parse = partial(_search_answers, target=target, limit=limit)
        request = KadRequest(opcode=opcode, payload=payload, answer=KadOp.SEARCH_RES)
        replies = await asyncio.gather(
            *(self._ask(node, request, parse=parse, collect=collect) for node in nodes[: self._settings.search_fanout])
        )
        return [entry for answers in replies for entries in answers for entry in entries]

    async def search_keyword(self, query: SearchQuery) -> list[SearchResult]:
        """Search file names through the keyword index.

        :param query: the query, whose longest word becomes the target.
        :type query: SearchQuery
        :returns: the results, filtered by the query's extensions.
        :rtype: list[SearchResult]
        """
        # The keyword index is keyed by the MD4 of one word, and the full query tree narrows the node's answer
        target = KadId.from_digest(md4(query.kad_keyword.encode()))
        payload = target.write(Writer()).u16(RESTRICTIVE_FLAG).raw(encode_query(query)).getvalue()
        results: dict[Ed2kHash, SearchResult] = {}

        # The same file comes back from several nodes, and the first answer for a hash is kept
        limit = self._limits.search_results
        for file_hash, tags in await self._search(
            target=target, opcode=KadOp.SEARCH_KEY_REQ, payload=payload, limit=limit
        ):
            result = SearchResult.from_tags(file_hash=file_hash, tags=tags, origin=SearchOrigin.KAD)
            if query.accepts(result):
                results.setdefault(file_hash, result)

        return list(results.values())[: self._limits.search_results]

    async def search_sources(self, *, file_hash: Ed2kHash, size: int) -> list[Source]:
        """Find peers that publish a file in the source index.

        :param file_hash: the file.
        :type file_hash: Ed2kHash
        :param size: the file size.
        :type size: int
        :returns: directly reachable sources.
        :rtype: list[Source]
        """
        # <target 16><start position 2><size 8>, where the source index is keyed by the file hash itself
        target = KadId.from_digest(file_hash.digest)
        payload = target.write(Writer()).u16(0).u64(size).getvalue()
        sources: dict[tuple[int, int], Source] = {}

        # In a source answer the hash of each entry is the publishing client's user hash
        limit = self._limits.sources_per_file
        for answer_hash, tags in await self._search(
            target=target, opcode=KadOp.SEARCH_SOURCE_REQ, payload=payload, limit=limit
        ):
            # An address tag may be written as a 64-bit number, and one that does not fit IPv4 names no peer
            indexed = tag_map(tags)
            address = int_value(indexed, FileTag.SOURCE_IP)
            if int_value(indexed, FileTag.SOURCE_TYPE) not in DIRECT_SOURCE_TYPES or address > UINT32_MAX:
                continue

            host = str(ipaddress.IPv4Address(address))
            client_id, port = client_id_from_host(host), int_value(indexed, FileTag.SOURCE_PORT)
            source = Source(
                client_id=client_id,
                port=port,
                user_hash=answer_hash.digest,
                crypt=CryptOption(int_value(indexed, FileTag.ENCRYPTION)),
                origin=SourceOrigin.KAD,
            )
            sources.setdefault((client_id, port), source)

        return list(sources.values())


async def _drain(queue: asyncio.Queue[Packet], *, first: float, collect: float) -> list[Packet]:
    """Wait for a first answer, then keep collecting for a while.

    :param queue: the answers of one request.
    :type queue: asyncio.Queue[Packet]
    :param first: seconds to wait for the first answer.
    :type first: float
    :param collect: seconds to keep collecting after the first answer.
    :type collect: float
    :returns: the answers.
    :rtype: list[Packet]
    """
    answers: list[Packet] = []

    # Silence before the first answer means the node is gone, silence after it means the answer is complete
    try:
        answers.append(await asyncio.wait_for(queue.get(), first))
        async with asyncio.timeout(collect):
            while True:
                answers.append(await queue.get())
    except TimeoutError:
        pass
    return answers


def _bootstrap_answer(packet: Packet, *, seed: Contact) -> tuple[Contact, list[Contact]]:
    """Parse a bootstrap answer into its responder and the contacts it lists.

    :param packet: the answer.
    :type packet: Packet
    :param seed: the node that answered.
    :type seed: Contact
    :returns: the responder and the listed contacts.
    :rtype: tuple[Contact, list[Contact]]
    :raises ProtocolError: when the answer is malformed.
    """
    # <responder id 16><tcp port 2><version 1><count 2><contacts>: https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/kademlia/net/KademliaUDPListener.cpp#L450
    reader = packet.reader()
    responder_id = KadId.read(reader)
    tcp_port, version = reader.u16(), reader.u8()
    responder = Contact(kad_id=responder_id, host=seed.host, udp_port=seed.udp_port, tcp_port=tcp_port, version=version)
    return responder, read_contacts(reader, reader.u16())


def _closer_contacts(packet: Packet, *, target: KadId) -> list[Contact]:
    """Parse ``KADEMLIA2_RES``, ``<target 16><count 1><contacts>``, into its contacts.

    :param packet: the answer.
    :type packet: Packet
    :param target: the target asked for.
    :type target: KadId
    :returns: the contacts, empty when the answer is for another target, which a concurrent lookup asked.
    :rtype: list[Contact]
    :raises ProtocolError: when the answer is malformed.
    """
    reader = packet.reader()
    if KadId.read(reader) != target:
        return []
    return read_contacts(reader, reader.u8())


def _search_answers(packet: Packet, *, target: KadId, limit: int) -> list[SearchAnswer]:
    """Parse a search answer for the expected target into hashes and tags.

    :param packet: the answer.
    :type packet: Packet
    :param target: the target asked for.
    :type target: KadId
    :param limit: the most entries read from one answer.
    :type limit: int
    :returns: the entries, empty when the answer is for another target.
    :rtype: list[SearchAnswer]
    :raises ProtocolError: when the answer is malformed.
    """
    # <sender id 16><target 16><count 2> then per entry <hash 16><tags with a one-byte count>
    reader = packet.reader()
    KadId.read(reader)
    if KadId.read(reader) != target:
        return []

    answers: defaultdict[Ed2kHash, list[Tag]] = defaultdict(list)
    for _ in range(min(reader.u16(), limit)):
        answer = Ed2kHash(KadId.read(reader).digest)
        answers[answer].extend(read_tags(reader, count_size=1))
    return list(answers.items())
