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
from typing import TYPE_CHECKING, Self, override

from ed2k_client.constants import (
    KAD_RESPONSE_TIMEOUT,
    MAX_SEARCH_RESULTS,
    MAX_UDP_DATAGRAM,
    CryptOption,
    FileTag,
    KadOp,
    Protocol,
)
from ed2k_client.errors import NotConnectedError, ProtocolError
from ed2k_client.hashing import Ed2kHash, md4
from ed2k_client.kad.contacts import Contact, KadId, closest, read_contacts
from ed2k_client.search import SearchOrigin, SearchResult, encode_query
from ed2k_client.sources import Source, SourceOrigin, client_id_from_host
from ed2k_client.tags import int_value, read_tags, tag_map
from ed2k_client.wire import Writer, decode_udp, encode_udp

if TYPE_CHECKING:
    from collections.abc import Sequence
    from types import TracebackType

    from ed2k_client.search import SearchQuery
    from ed2k_client.security import AddressPolicy
    from ed2k_client.tags import Tag
    from ed2k_client.wire import Packet

logger = logging.getLogger(__name__)

FIND_NODE: int = 0x0B
SEARCH_TOLERANCE: int = 1 << 120
ALPHA: int = 5
K: int = 10
MAX_ROUNDS: int = 12
BOOTSTRAP_FANOUT: int = 40
SEARCH_FANOUT: int = 8
SEARCH_COLLECT: float = 6.0
RESTRICTIVE_FLAG: int = 0x8000
DIRECT_SOURCE_TYPES: frozenset[int] = frozenset({1, 4})


@dataclass(slots=True)
class _Datagrams(asyncio.DatagramProtocol):
    """Route datagrams to the waiter registered for their sender and opcode.

    :ivar waiters: queues by ``(host, port, opcode)`` of the answers the node is waiting for.
    """

    waiters: dict[tuple[str, int, int], asyncio.Queue[Packet]] = field(default_factory=dict)

    @override
    def datagram_received(self, data: bytes, addr: tuple[str | int, int]) -> None:
        """Hand a datagram to the matching waiter or drop it.

        :param data: the datagram.
        :type data: bytes
        :param addr: the sender.
        :type addr: tuple[str | int, int]
        """
        if len(data) > MAX_UDP_DATAGRAM:
            return
        try:
            packet = decode_udp(data)
        except ProtocolError:
            return
        queue = self.waiters.get((str(addr[0]), addr[1], packet.opcode))
        if queue is not None:
            queue.put_nowait(packet)


class KadNode:
    """A firewalled Kad 2 participant that searches keywords and sources.

    :ivar kad_id: this node's ID.
    :ivar contacts: live contacts by ID.
    """

    def __init__(self, *, kad_id: bytes, policy: AddressPolicy, udp_port: int = 0) -> None:
        """Prepare the node; use it as an async context manager to open its socket.

        :param kad_id: this node's 16-byte ID.
        :type kad_id: bytes
        :param policy: which addresses may be contacted.
        :type policy: AddressPolicy
        :param udp_port: the local UDP port, 0 for any.
        :type udp_port: int
        """
        self.kad_id = KadId.from_digest(kad_id)
        self.contacts: dict[KadId, Contact] = {}
        self._policy = policy
        self._udp_port = udp_port
        self._protocol = _Datagrams()
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

    async def _ask(
        self, contact: Contact, *, opcode: int, payload: bytes, answer: int, collect: float = 0.0
    ) -> list[Packet]:
        """Send one request and gather the answers of one contact.

        :param contact: the node.
        :type contact: Contact
        :param opcode: the request opcode.
        :type opcode: int
        :param payload: the request body.
        :type payload: bytes
        :param answer: the expected answer opcode.
        :type answer: int
        :param collect: seconds to keep collecting after the first answer, for multi-packet answers.
        :type collect: float
        :returns: the answers, empty on timeout.
        :rtype: list[Packet]
        :raises NotConnectedError: when the socket is not open.
        """
        if self._transport is None:
            err_msg = 'the Kad node is not started'
            raise NotConnectedError(err_msg)
        key = (contact.host, contact.udp_port, answer)
        queue: asyncio.Queue[Packet] = asyncio.Queue()
        self._protocol.waiters[key] = queue
        try:
            self._transport.sendto(encode_udp(protocol=Protocol.KAD, opcode=opcode, payload=payload), contact.address)
            return await _drain(queue, collect=collect)
        finally:
            self._protocol.waiters.pop(key, None)

    def _usable(self, contacts: Sequence[Contact]) -> list[Contact]:
        """Keep the contacts the address policy allows, except this node.

        :param contacts: the candidates.
        :type contacts: Sequence[Contact]
        :returns: the usable contacts.
        :rtype: list[Contact]
        """
        return [c for c in contacts if c.kad_id != self.kad_id and self._policy.permits(c.host, c.udp_port)]

    async def bootstrap(self, seeds: Sequence[Contact], *, want: int = 60) -> int:
        """Learn live contacts from seed nodes.

        :param seeds: contacts from ``nodes.dat``.
        :type seeds: Sequence[Contact]
        :param want: stop after this many live contacts.
        :type want: int
        :returns: the number of live contacts.
        :rtype: int
        """
        pool = self._usable(seeds)
        random.shuffle(pool)
        for start in range(0, len(pool), BOOTSTRAP_FANOUT):
            batch = pool[start : start + BOOTSTRAP_FANOUT]
            replies = await asyncio.gather(
                *(
                    self._ask(seed, opcode=KadOp.BOOTSTRAP_REQ, payload=b'', answer=KadOp.BOOTSTRAP_RES)
                    for seed in batch
                )
            )
            for seed, answers in zip(batch, replies, strict=True):
                for packet in answers:
                    self._absorb_bootstrap(seed, packet)
            if len(self.contacts) >= want:
                break
        logger.info('Kad bootstrap: %d live contacts', len(self.contacts))
        return len(self.contacts)

    def _absorb_bootstrap(self, seed: Contact, packet: Packet) -> None:
        """Add the responder and the contacts of a bootstrap answer.

        :param seed: the node that answered.
        :type seed: Contact
        :param packet: the answer.
        :type packet: Packet
        """
        reader = packet.reader()
        responder_id = KadId.read(reader)
        tcp_port, version = reader.u16(), reader.u8()
        self.contacts[responder_id] = Contact(
            kad_id=responder_id, host=seed.host, udp_port=seed.udp_port, tcp_port=tcp_port, version=version
        )
        for contact in self._usable(read_contacts(reader, reader.u16())):
            self.contacts.setdefault(contact.kad_id, contact)

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
        for _ in range(MAX_ROUNDS):
            batch = [c for c in closest(candidates.values(), target, count=K) if c.kad_id not in asked][:ALPHA]
            if not batch:
                break
            asked.update(c.kad_id for c in batch)
            # KADEMLIA2_REQ carries the receiver's own ID, which the receiver checks before answering.
            replies = await asyncio.gather(
                *(
                    self._ask(
                        c,
                        opcode=KadOp.REQ,
                        payload=c.kad_id.write(target.write(Writer().u8(FIND_NODE))).getvalue(),
                        answer=KadOp.RES,
                    )
                    for c in batch
                )
            )
            for contact, answers in zip(batch, replies, strict=True):
                if answers:
                    answered[contact.kad_id] = contact
                for packet in answers:
                    reader = packet.reader()
                    KadId.read(reader)
                    for found in self._usable(read_contacts(reader, reader.u8())):
                        candidates.setdefault(found.kad_id, found)
        return closest(answered.values(), target, count=K)

    async def _search(self, *, target: KadId, opcode: int, payload: bytes) -> list[Packet]:
        """Send a search to the nodes in the target's tolerance zone and gather their answers.

        :param target: the target.
        :type target: KadId
        :param opcode: the search opcode.
        :type opcode: int
        :param payload: the request body.
        :type payload: bytes
        :returns: the answers.
        :rtype: list[Packet]
        """
        nodes = [c for c in await self.lookup(target) if c.kad_id.distance(target) < SEARCH_TOLERANCE]
        logger.info('Kad search: %d nodes in the tolerance zone', len(nodes))
        replies = await asyncio.gather(
            *(
                self._ask(node, opcode=opcode, payload=payload, answer=KadOp.SEARCH_RES, collect=SEARCH_COLLECT)
                for node in nodes[:SEARCH_FANOUT]
            )
        )
        return [packet for answers in replies for packet in answers]

    async def search_keyword(self, query: SearchQuery) -> list[SearchResult]:
        """Search file names through the keyword index.

        :param query: the query, whose longest word becomes the target.
        :type query: SearchQuery
        :returns: the results, filtered by the query's extensions.
        :rtype: list[SearchResult]
        """
        target = KadId.from_digest(md4(query.kad_keyword.encode()))
        payload = target.write(Writer()).u16(RESTRICTIVE_FLAG).raw(encode_query(query)).getvalue()
        results: dict[Ed2kHash, SearchResult] = {}
        for packet in await self._search(target=target, opcode=KadOp.SEARCH_KEY_REQ, payload=payload):
            for file_hash, tags in _search_answers(packet, target):
                result = SearchResult.from_tags(file_hash=file_hash, tags=tags, origin=SearchOrigin.KAD)
                if query.matches_extension(result.name) and result.size > 0:
                    results.setdefault(file_hash, result)
        return list(results.values())[:MAX_SEARCH_RESULTS]

    async def search_sources(self, *, file_hash: Ed2kHash, size: int) -> list[Source]:
        """Find peers that publish a file in the source index.

        :param file_hash: the file.
        :type file_hash: Ed2kHash
        :param size: the file size.
        :type size: int
        :returns: directly reachable sources.
        :rtype: list[Source]
        """
        target = KadId.from_digest(file_hash.digest)
        payload = target.write(Writer()).u16(0).u64(size).getvalue()
        sources: dict[tuple[int, int], Source] = {}
        for packet in await self._search(target=target, opcode=KadOp.SEARCH_SOURCE_REQ, payload=payload):
            for answer_hash, tags in _search_answers(packet, target):
                indexed = tag_map(tags)
                if int_value(indexed, FileTag.SOURCE_TYPE) not in DIRECT_SOURCE_TYPES:
                    continue
                host = str(ipaddress.IPv4Address(int_value(indexed, FileTag.SOURCE_IP)))
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


async def _drain(queue: asyncio.Queue[Packet], *, collect: float) -> list[Packet]:
    """Wait for a first answer, then keep collecting for a while.

    :param queue: the answers of one request.
    :type queue: asyncio.Queue[Packet]
    :param collect: seconds to keep collecting after the first answer.
    :type collect: float
    :returns: the answers.
    :rtype: list[Packet]
    """
    answers: list[Packet] = []
    try:
        answers.append(await asyncio.wait_for(queue.get(), KAD_RESPONSE_TIMEOUT))
        async with asyncio.timeout(collect):
            while True:
                answers.append(await queue.get())
    except TimeoutError:
        pass
    return answers


def _search_answers(packet: Packet, target: KadId) -> list[tuple[Ed2kHash, list[Tag]]]:
    """Parse a search answer for the expected target into hashes and tags.

    :param packet: the answer.
    :type packet: Packet
    :param target: the target asked for.
    :type target: KadId
    :returns: the entries, empty when the answer is for another target.
    :rtype: list[tuple[Ed2kHash, list[Tag]]]
    """
    reader = packet.reader()
    KadId.read(reader)
    if KadId.read(reader) != target:
        return []
    answers: defaultdict[Ed2kHash, list[Tag]] = defaultdict(list)
    for _ in range(min(reader.u16(), MAX_SEARCH_RESULTS)):
        answer = Ed2kHash(KadId.read(reader).digest)
        answers[answer].extend(read_tags(reader, count_size=1))
    return list(answers.items())
