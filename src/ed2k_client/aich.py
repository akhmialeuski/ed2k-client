"""AICH, the SHA-1 hash tree eMule keeps over a file, and the proof of block hashes against its root.

The tree follows ``CAICHHashTree`` of aMule:
https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/SHAHashSet.cpp#L102
Its leaves are blocks of 180 KiB that start at a part boundary, the request blocks of :mod:`ed2k_client.partfile`,
and its upper levels split the file into whole parts first. A node holding an odd number of units gives the larger
half to the side it hangs on, and the root counts as a left node. A node is named by its path from the root: the root
is 1, and every step down appends one bit, 1 for the left child and 0 for the right one.

The root comes from the ``h=`` field of a link, which makes it trusted. A peer with the complete file answers a
request for one part with the hashes of the part's blocks and of the sibling of every node on the way up. The client
folds them to the root and keeps only hashes that took part in reproducing it, so a forged answer needs a second
preimage of SHA-1. The blocks of a downloaded part are then compared with their proven hashes one by one.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Self

from Crypto.Hash import SHA1

from ed2k_client.constants import AICH_HASH_LENGTH, BLOCK_SIZE, PART_SIZE
from ed2k_client.errors import ProtocolError

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from ed2k_client.wire import Reader

ROOT_IDENT: int = 1

# aMule refuses a 32-bit identifier above 2^22, which no file under the size limit needs:
# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/SHAHashSet.cpp#L592
MAX_IDENT: int = 0x400000


def combine(left: bytes, right: bytes) -> bytes:
    """Hash two child hashes into the hash of their parent.

    :param left: the left child's hash.
    :type left: bytes
    :param right: the right child's hash.
    :type right: bytes
    :returns: the parent's hash.
    :rtype: bytes
    """
    return SHA1.new(left + right).digest()


@dataclass(frozen=True, slots=True)
class AichNode:
    """One node of the tree: the bytes it covers and its name.

    :ivar ident: the path from the root as bits, 1 for the root.
    :ivar start: the first byte offset it covers.
    :ivar size: the number of bytes it covers.
    :ivar left: whether it is a left child, which the root counts as.
    """

    ident: int
    start: int
    size: int
    left: bool

    @classmethod
    def root(cls, size: int) -> Self:
        """Build the root of a file's tree.

        :param size: the file size.
        :type size: int
        :returns: the root.
        :rtype: Self
        """
        return cls(ident=ROOT_IDENT, start=0, size=size, left=True)

    @property
    def leaf(self) -> bool:
        """Whether the node is one block and has no children."""
        return self.size <= BLOCK_SIZE

    def children(self) -> tuple[Self, Self]:
        """Split the node the way aMule splits it.

        :returns: the left and the right child.
        :rtype: tuple[Self, Self]
        """
        # A node larger than a part is split by whole parts, a part or less by blocks:
        # https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/SHAHashSet.cpp#L128
        unit = BLOCK_SIZE if self.size <= PART_SIZE else PART_SIZE
        units = -(-self.size // unit)
        left_size = (units + self.left) // 2 * unit
        cls = type(self)
        return (
            cls(ident=self.ident << 1 | 1, start=self.start, size=left_size, left=True),
            cls(ident=self.ident << 1, start=self.start + left_size, size=self.size - left_size, left=False),
        )

    def path_to(self, *, start: int, size: int) -> list[Self]:
        """Walk down to the node that covers exactly a range.

        :param start: the first byte offset of the range.
        :type start: int
        :param size: the length of the range.
        :type size: int
        :returns: the nodes from this one down to the one covering the range.
        :rtype: list[Self]
        :raises ValueError: when no node covers exactly that range.
        """
        node, path = self, [self]
        while (node.start, node.size) != (start, size):
            if node.leaf:
                err_msg = f'no node covers {size} bytes at {start}'
                raise ValueError(err_msg)
            left, right = node.children()
            node = left if start < right.start else right
            path.append(node)
        return path

    def leaves(self) -> Iterator[Self]:
        """Yield the blocks under this node from left to right.

        :returns: the leaves.
        :rtype: Iterator[Self]
        """
        if self.leaf:
            yield self
            return
        for child in self.children():
            yield from child.leaves()

    def descendant(self, ident: int) -> Self:
        """Find the node an identifier names.

        :param ident: the identifier.
        :type ident: int
        :returns: the node.
        :rtype: Self
        :raises ProtocolError: when the identifier names no node of this tree.
        """
        node = self
        for shift in range(ident.bit_length() - 2, -1, -1):
            if node.leaf:
                err_msg = f'AICH identifier {ident} reaches below a block'
                raise ProtocolError(err_msg)
            left, right = node.children()
            node = left if ident >> shift & 1 else right
        return node


def read_recovery(reader: Reader, *, count: int) -> dict[int, bytes]:
    """Read the hashes of a recovery answer by node identifier.

    aMule writes 16-bit identifiers and a closing zero count for a file under 4 GB, and a zero count followed by
    32-bit identifiers for a larger one: https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/SHAHashSet.cpp#L534

    :param reader: the reader, placed after the part number and the root.
    :type reader: Reader
    :param count: how many hashes the requested part needs.
    :type count: int
    :returns: the hashes, not yet proven.
    :rtype: dict[int, bytes]
    :raises ProtocolError: on another count, a repeated identifier or one that would replace the root.
    """
    wide = False
    found = reader.u16()
    if found == 0:
        wide, found = True, reader.u16()
    if found != count:
        err_msg = f'AICH answer with {found} hashes where {count} were due'
        raise ProtocolError(err_msg)

    hashes: dict[int, bytes] = {}
    for _ in range(found):
        ident = reader.u32() if wide else reader.u16()
        if not ROOT_IDENT < ident <= MAX_IDENT or ident in hashes:
            err_msg = f'AICH answer with the invalid or repeated identifier {ident}'
            raise ProtocolError(err_msg)
        hashes[ident] = reader.take(AICH_HASH_LENGTH)
    return hashes


class AichTree:
    """The hashes of one file's tree that are proven against its trusted root.

    :ivar size: the file size.
    :ivar root: the trusted root hash.
    """

    def __init__(self, *, size: int, root: bytes) -> None:
        """Start from the trusted root alone.

        :param size: the file size.
        :type size: int
        :param root: the root hash from the link.
        :type root: bytes
        """
        self.size = size
        self.root = root
        self._top = AichNode.root(size)
        self._proven: dict[int, bytes] = {ROOT_IDENT: root}

    def _part_path(self, part: int) -> list[AichNode]:
        """Walk from the root to the node of one part.

        :param part: the part index.
        :type part: int
        :returns: the nodes from the root down to the part.
        :rtype: list[AichNode]
        """
        start = part * PART_SIZE
        return self._top.path_to(start=start, size=min(PART_SIZE, self.size - start))

    def block_hash(self, *, start: int, size: int) -> bytes | None:
        """Look up the proven hash of one block.

        :param start: the first byte offset of the block.
        :type start: int
        :param size: the block length.
        :type size: int
        :returns: the hash, or ``None`` while it is not proven.
        :rtype: bytes | None
        """
        return self._proven.get(self._top.path_to(start=start, size=size)[-1].ident)

    def ready(self, part: int) -> bool:
        """Check whether every block of a part has a proven hash.

        :param part: the part index.
        :type part: int
        :returns: whether the part can be checked block by block.
        :rtype: bool
        """
        return all(leaf.ident in self._proven for leaf in self._part_path(part)[-1].leaves())

    def source_part(self, part: int) -> int:
        """Name the part whose recovery answer proves the blocks of a part.

        A part of one block is a leaf, and aMule serves no answer for it. Being the last part, it is the right
        sibling of a node on the way to the part before it, so that part's answer carries its hash:
        https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/DownloadClient.cpp#L1681

        :param part: the part index.
        :type part: int
        :returns: the part to ask for.
        :rtype: int
        """
        return part - 1 if part > 0 and self._part_path(part)[-1].leaf else part

    def hash_count(self, part: int) -> int:
        """Count the hashes a recovery answer for a part carries.

        :param part: the part index.
        :type part: int
        :returns: one sibling per level above the part plus one hash per block.
        :rtype: int
        """
        path = self._part_path(part)
        return len(path) - 1 + sum(1 for _ in path[-1].leaves())

    def accept(self, *, part: int, hashes: Mapping[int, bytes]) -> None:
        """Prove the hashes of a recovery answer against the root and keep the proven ones.

        :param part: the part the answer was asked for.
        :type part: int
        :param hashes: the hashes by node identifier.
        :type hashes: Mapping[int, bytes]
        :raises ProtocolError: when the hashes do not reproduce the root or leave a block of the part out.
        """
        folded: dict[int, bytes] = {}
        if self._fold(self._top, hashes=hashes, ancestors=self._ancestors(hashes), folded=folded) != self.root:
            err_msg = f'AICH answer for part {part} does not lead to the root of the link'
            raise ProtocolError(err_msg)

        proven = self._proven_by(folded=folded, hashes=hashes)
        if any(leaf.ident not in proven for leaf in self._part_path(part)[-1].leaves()):
            err_msg = f'the recovery hashes leave blocks of part {part} out'
            raise ProtocolError(err_msg)
        self._proven.update(proven)

    def _ancestors(self, hashes: Mapping[int, bytes]) -> set[int]:
        """Collect the nodes above the given ones, the only nodes a fold has to visit.

        Folding along them alone makes a 4 GB file cost as much as a small one.

        :param hashes: the hashes by node identifier.
        :type hashes: Mapping[int, bytes]
        :returns: the identifiers of every strict ancestor of a given node.
        :rtype: set[int]
        :raises ProtocolError: when an identifier names no node of this file's tree.
        """
        ancestors: set[int] = set()
        for ident in hashes:
            self._top.descendant(ident)
            parent = ident
            while parent > ROOT_IDENT:
                parent >>= 1
                ancestors.add(parent)
        return ancestors

    def _fold(
        self, node: AichNode, *, hashes: Mapping[int, bytes], ancestors: set[int], folded: dict[int, bytes]
    ) -> bytes | None:
        """Compute a node's hash from below where possible and check it against a given one.

        :param node: the node.
        :type node: AichNode
        :param hashes: the hashes of the answer.
        :type hashes: Mapping[int, bytes]
        :param ancestors: the nodes above the given ones.
        :type ancestors: set[int]
        :param folded: receives every hash computed from children.
        :type folded: dict[int, bytes]
        :returns: the hash, or ``None`` when neither the answer nor its children give one.
        :rtype: bytes | None
        :raises ProtocolError: when a given hash contradicts the hash of its children.
        """
        given = hashes.get(node.ident)
        if node.ident not in ancestors:
            return given
        left, right = (
            self._fold(child, hashes=hashes, ancestors=ancestors, folded=folded) for child in node.children()
        )
        if left is None or right is None:
            return given
        digest = combine(left, right)
        if given is not None and given != digest:
            err_msg = f'AICH hash of node {node.ident} contradicts its children'
            raise ProtocolError(err_msg)
        folded[node.ident] = digest
        return digest

    def _proven_by(self, *, folded: Mapping[int, bytes], hashes: Mapping[int, bytes]) -> dict[int, bytes]:
        """Collect the hashes the root was computed from, so a stray hash beside them proves nothing.

        :param folded: the hashes computed from children.
        :type folded: Mapping[int, bytes]
        :param hashes: the hashes of the answer.
        :type hashes: Mapping[int, bytes]
        :returns: the proven hashes by node identifier.
        :rtype: dict[int, bytes]
        """
        # Every child of a folded node gave its parent a hash, either folded from below or taken from the answer
        proven: dict[int, bytes] = {}
        pending = [self._top]
        while pending:
            node = pending.pop()
            if node.ident in folded:
                proven[node.ident] = folded[node.ident]
                pending.extend(node.children())
            else:
                proven[node.ident] = hashes[node.ident]
        return proven
