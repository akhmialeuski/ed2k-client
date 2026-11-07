"""Unit tests of the AICH tree: its shape, the recovery answer and the proof of block hashes against the root."""

import contextlib
import random

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ed2k_client.aich import ROOT_IDENT, AichNode, AichTree, read_recovery
from ed2k_client.constants import BLOCK_SIZE, PART_SIZE
from ed2k_client.errors import ProtocolError
from ed2k_client.hashing import data_part_count
from ed2k_client.wire import Reader, Writer
from tests.helpers import aich_tree, recovery_data

# The example file of the comment in aMule's SHAHashSet.h, two full parts and 50,000 bytes
AMULE_EXAMPLE_SIZE = 19_506_000
FIRST_PART_LEFT_BLOCKS = 27
SECOND_PART_LEFT_BLOCKS = 26
# The two siblings on the way down to the first part, and its 53 blocks
AMULE_EXAMPLE_FIRST_PART_HASHES = 55
SIZES = [
    pytest.param(BLOCK_SIZE + 1, id='two-blocks'),
    pytest.param(PART_SIZE, id='exact-part'),
    pytest.param(PART_SIZE + 1, id='one-byte-tail'),
    pytest.param(PART_SIZE + BLOCK_SIZE, id='one-block-tail'),
    pytest.param(AMULE_EXAMPLE_SIZE, id='amule-example'),
    pytest.param(5 * PART_SIZE + 100, id='six-parts'),
]
SEED = 5
FUZZ = settings(database=None)

# A hostile answer for the middle part of a three-part file: the due count of hashes, each naming a real node or one
# just below a block, so the fold is reached rather than the count check
FUZZ_TREE = AichTree(size=3 * PART_SIZE, root=bytes(20))
FUZZ_DUE = FUZZ_TREE.hash_count(1)
FUZZ_IDENTS = [node.ident for node in AichNode.root(3 * PART_SIZE).leaves()] + [2, 3, 0b111]
FUZZ_ENTRIES = st.lists(
    st.tuples(
        st.one_of(st.sampled_from(FUZZ_IDENTS), st.sampled_from(FUZZ_IDENTS).map(lambda ident: ident << 1)),
        st.binary(min_size=20, max_size=20),
    ),
    min_size=FUZZ_DUE,
    max_size=FUZZ_DUE,
)


def content(size: int) -> bytes:
    """Make reproducible content of a size.

    :param size: the size in bytes.
    :type size: int
    :returns: the content.
    :rtype: bytes
    """
    return random.Random(SEED).randbytes(size)


def answer(tree: dict[int, bytes], *, size: int, part: int, wide: bool = False) -> dict[int, bytes]:
    """Read the recovery answer a complete source sends for a part.

    :param tree: every hash of the file's tree.
    :type tree: dict[int, bytes]
    :param size: the file size.
    :type size: int
    :param part: the part.
    :type part: int
    :param wide: whether the answer uses 32-bit identifiers.
    :type wide: bool
    :returns: the hashes by identifier.
    :rtype: dict[int, bytes]
    """
    raw = recovery_data(tree, size=size, part=part, wide=wide)
    return read_recovery(Reader(raw), count=AichTree(size=size, root=tree[ROOT_IDENT]).hash_count(part))


class TestAichNode:
    """Tests of :class:`AichNode`."""

    def test_split_follows_the_amule_example(self) -> None:
        """The example tree of aMule's header splits as it draws, the larger half going to the side of the branch."""
        left, right = AichNode.root(AMULE_EXAMPLE_SIZE).children()
        first, second = left.children()

        assert (left.size, right.size) == (2 * PART_SIZE, AMULE_EXAMPLE_SIZE - 2 * PART_SIZE)
        assert (first.size, second.size) == (PART_SIZE, PART_SIZE)
        assert first.children()[0].size == FIRST_PART_LEFT_BLOCKS * BLOCK_SIZE
        assert second.children()[0].size == SECOND_PART_LEFT_BLOCKS * BLOCK_SIZE

    def test_identifiers_name_the_path_from_the_root(self) -> None:
        """A left step appends a 1 bit and a right step a 0 bit, so the right child of the left child is 0b110."""
        root = AichNode.root(AMULE_EXAMPLE_SIZE)
        left, right = root.children()

        assert (root.ident, left.ident, right.ident, left.children()[1].ident) == (1, 0b11, 0b10, 0b110)
        assert root.descendant(0b110) == left.children()[1]

    def test_identifier_below_a_block_is_refused(self) -> None:
        """An identifier deeper than the tree names no node."""
        with pytest.raises(ProtocolError, match='below a block'):
            AichNode.root(BLOCK_SIZE).descendant(0b11)


class TestReadRecovery:
    """Tests of :func:`read_recovery`."""

    @pytest.mark.parametrize('wide', [False, True], ids=['16-bit', '32-bit'])
    def test_both_layouts_read_the_same_hashes(self, wide: bool) -> None:
        """The 16-bit and the 32-bit layout aMule writes carry the same hashes.

        :param wide: whether the answer uses 32-bit identifiers.
        :type wide: bool
        """
        size = 2 * PART_SIZE
        tree = aich_tree(content(size))

        assert answer(tree, size=size, part=1, wide=wide) == answer(tree, size=size, part=1)

    @pytest.mark.parametrize(
        ('payload', 'message'),
        [
            pytest.param(Writer().u16(2).getvalue(), 'were due', id='wrong-count'),
            pytest.param(Writer().u16(1).u16(ROOT_IDENT).raw(bytes(20)).getvalue(), 'identifier 1', id='root'),
            pytest.param(Writer().u16(1).u16(0).raw(bytes(20)).getvalue(), 'identifier 0', id='zero'),
        ],
    )
    def test_malformed_answers_are_refused(self, payload: bytes, message: str) -> None:
        """A count other than due, the root's identifier and an identifier naming nothing are refused.

        :param payload: the answer.
        :type payload: bytes
        :param message: what the error names.
        :type message: str
        """
        with pytest.raises(ProtocolError, match=message):
            read_recovery(Reader(payload), count=1)

    def test_repeated_identifier_is_refused(self) -> None:
        """An answer that names a node twice is refused, so a second hash cannot replace the first."""
        payload = Writer().u16(2).u16(2).raw(bytes(20)).u16(2).raw(bytes(20)).getvalue()

        with pytest.raises(ProtocolError, match='repeated'):
            read_recovery(Reader(payload), count=2)

    @FUZZ
    @given(entries=FUZZ_ENTRIES)
    def test_any_answer_is_proven_or_refused(self, entries: list[tuple[int, bytes]]) -> None:
        """Any answer of the due length over real nodes of a three-part file is proven or fails as a protocol error.

        :param entries: the identifiers and hashes a hostile peer chose.
        :type entries: list[tuple[int, bytes]]
        """
        writer = Writer().u16(len(entries))
        for ident, digest in entries:
            writer.u16(ident).raw(digest)
        with contextlib.suppress(ProtocolError):
            FUZZ_TREE.accept(part=1, hashes=read_recovery(Reader(writer.getvalue()), count=FUZZ_DUE))


class TestAichTree:
    """Tests of :class:`AichTree`."""

    @pytest.mark.parametrize('size', SIZES)
    def test_answers_prove_every_block(self, size: int) -> None:
        """Answers for the parts a tree asks for prove the hash of every block of the file.

        :param size: the file size.
        :type size: int
        """
        tree = aich_tree(content(size))
        proof = AichTree(size=size, root=tree[ROOT_IDENT])
        for part in range(data_part_count(size)):
            if not proof.ready(part):
                asked = proof.source_part(part)
                proof.accept(part=asked, hashes=answer(tree, size=size, part=asked))

        for leaf in AichNode.root(size).leaves():
            assert proof.block_hash(start=leaf.start, size=leaf.size) == tree[leaf.ident]

    def test_one_block_tail_is_proven_by_the_part_before_it(self) -> None:
        """A last part of one block, which aMule serves no answer for, is proven by the answer for the part before."""
        size = PART_SIZE + BLOCK_SIZE
        tree = aich_tree(content(size))
        proof = AichTree(size=size, root=tree[ROOT_IDENT])

        assert proof.source_part(1) == 0
        proof.accept(part=0, hashes=answer(tree, size=size, part=0))
        assert proof.ready(1)

    def test_forged_block_hash_is_refused(self) -> None:
        """A block hash changed in the answer no longer folds to the root, and nothing from it is kept."""
        size = 2 * PART_SIZE
        tree = aich_tree(content(size))
        proof = AichTree(size=size, root=tree[ROOT_IDENT])
        hashes = answer(tree, size=size, part=1)
        leaf = next(AichNode.root(size).path_to(start=PART_SIZE, size=PART_SIZE)[-1].leaves())
        hashes[leaf.ident] = bytes(20)

        with pytest.raises(ProtocolError, match='root of the link'):
            proof.accept(part=1, hashes=hashes)
        assert not proof.ready(1)

    def test_answer_for_another_part_proves_nothing_for_this_one(self) -> None:
        """An answer that folds to the root but carries the blocks of another part is refused for this part.

        Without the check a peer could answer every request with the one part it has and leave the others unproven
        while the client believes them checked.
        """
        size = 3 * PART_SIZE
        tree = aich_tree(content(size))
        proof = AichTree(size=size, root=tree[ROOT_IDENT])

        with pytest.raises(ProtocolError, match='leave blocks of part 2 out'):
            proof.accept(part=2, hashes=answer(tree, size=size, part=0))

    def test_stray_hash_beside_a_valid_answer_is_not_kept(self) -> None:
        """A hash the root was not computed from stays unproven, even inside an answer that folds to the root."""
        size = 3 * PART_SIZE
        tree = aich_tree(content(size))
        proof = AichTree(size=size, root=tree[ROOT_IDENT])
        hashes = answer(tree, size=size, part=0)
        stray = next(AichNode.root(size).path_to(start=2 * PART_SIZE, size=PART_SIZE)[-1].leaves())
        hashes[stray.ident] = bytes(20)

        proof.accept(part=0, hashes=hashes)

        assert proof.ready(0)
        assert proof.block_hash(start=stray.start, size=stray.size) is None

    def test_hash_count_matches_the_amule_example(self) -> None:
        """A part's count is one sibling per level above it plus one hash per block, as aMule's example tree has it.

        The first part of the example lies two levels below the root and holds 27 and 26 blocks in its halves, so its
        answer carries 55 hashes. The count is checked against that figure rather than against the test helper that
        writes answers, which walks the same path and would agree with any mistake in it.
        """
        proof = AichTree(size=AMULE_EXAMPLE_SIZE, root=bytes(20))

        assert proof.hash_count(0) == AMULE_EXAMPLE_FIRST_PART_HASHES
