import bisect
from dataclasses import dataclass
import enum
import io
import itertools
import operator
from typing import IO, Collection, Iterable, Optional, Sequence, Tuple, Union

from eth_typing import Hash32
from eth_utils import ValidationError, to_tuple
from eth_utils.toolz import cons, sliding_window
from ssz.constants import CHUNK_SIZE, ZERO_BYTES32, ZERO_HASHES
from ssz.hash import hash_eth2
from ssz.hash_tree import compute_hash_tree
from ssz.sedes import List as ListSedes
from ssz.utils import mix_in_length

from ddht.exceptions import ParseError
from ddht.v5_1.alexandria.leb128 import encode_leb128, parse_leb128
from ddht.v5_1.alexandria.sedes import ByteList

# 1 gigabyte
GB = 1024 * 1024 * 1024  # 2**30

content_sedes = ByteList(max_length=GB)


Key = Tuple[bool, ...]


@to_tuple
def compute_chunks(data: bytes) -> Iterable[Hash32]:
    """
    An optimized version of SSZ chunk computation specifically for byte
    strings.
    """
    if not data:
        yield ZERO_BYTES32
        return
    elif len(data) > GB:
        raise Exception("too big")
    data_length = len(data)
    if data_length % CHUNK_SIZE == 0:
        padded_data = data
    else:
        padding_byte_count = CHUNK_SIZE - data_length % CHUNK_SIZE
        padded_data = data + b"\x00" * padding_byte_count

    padded_length = len(padded_data)
    for left_boundary, right_boundary in sliding_window(
        2, range(0, padded_length + 1, CHUNK_SIZE)
    ):
        yield padded_data[left_boundary:right_boundary]


def display_path(path: Key) -> str:
    """
    Converts a tree path to a string of 1s and 0s for more legible display.
    """
    return "".join((str(int(bit)) for bit in path))


@to_tuple
def chunk_index_to_path(index: int, path_bit_size: int) -> Iterable[bool]:
    """
    Given a chunk index, convert it to the path into the binary tree where the
    chunk is located.
    """
    for power_of_two in reversed(POWERS_OF_TWO[:path_bit_size]):
        yield bool(index & power_of_two)


def path_to_left_chunk_index(path: Key, path_bit_size: int) -> int:
    """
    Given a path, convert it to a chunk index.  In the case where the path is
    to an intermediate tree node, return the chunk index on the leftmost branch
    of the subtree.
    """
    return sum(
        power_of_two
        for path_bit, power_of_two in itertools.zip_longest(
            path, reversed(POWERS_OF_TWO[:path_bit_size]), fillvalue=False,
        )
        if path_bit
    )


POWERS_OF_TWO = [2 ** n for n in range(256)]


@to_tuple
def decompose_into_powers_of_two(value: int) -> Iterable[int]:
    for i in range(value.bit_length()):
        power_of_two = POWERS_OF_TWO[i]
        if value & power_of_two:
            yield power_of_two


@dataclass(frozen=True)
class ProofElement:
    path: Key
    value: Hash32

    @property
    def depth(self) -> int:
        return len(self.path)

    def __str__(self) -> str:
        return f"{display_path(self.path)}: {self.value.hex()}"

    def serialize(self, previous: Optional[Key]) -> bytes:
        """
        data := common-bytes || length-byte || path || value
        """
        if previous is None:
            path = self.path
            common_bits = 0
        else:
            common_path = get_longest_common_path(self.path, previous)
            common_bits = len(common_path)
            path = self.path[common_bits:]

        path_length = len(path)

        assert path_length < 32
        assert common_bits < 32 - path_length.bit_length() - len(path)

        path_as_int = sum(
            power_of_two
            for path_bit, power_of_two in zip(path, POWERS_OF_TWO[:path_length],)
            if path_bit
        )
        full_encoded_path_as_int = (
            path_length ^ (path_as_int << 5) ^ (common_bits << (5 + path_length))
        )
        return encode_leb128(full_encoded_path_as_int) + self.value

    @classmethod
    def deserialize(cls, stream: io.BytesIO, previous: Optional[Key]) -> "ProofElement":
        header_as_int = parse_leb128(stream)
        value = stream.read(32)
        if len(value) != 32:
            raise ParseError("Premature end of stream")

        path_length = header_as_int & 0b11111
        path_as_int = (header_as_int >> 5) & (2 ** path_length - 1)
        common_bits = header_as_int >> (5 + path_length)

        partial_path = tuple(
            bool(path_as_int & power_of_two)
            for power_of_two in POWERS_OF_TWO[:path_length]
        )
        if common_bits:
            if previous is None or len(previous) < common_bits:
                raise Exception("Need previous path when common bits is not 0")
            else:
                full_path = previous[:common_bits] + partial_path
        else:
            full_path = partial_path

        return cls(full_path, value)


class DataPartial:
    """
    A wrapper around a partial data proof which allows data retrieval by
    indexing or slicing.

    Raise `IndexError` if the requested data is not part of the proof.
    """

    def __init__(self, length: int, segments: Tuple[Tuple[int, bytes], ...]) -> None:
        self._length = length
        self._segments = segments

    def __len__(self) -> int:
        return self._length

    def __getitem__(self, index_or_slice: Union[int, slice]):
        if isinstance(index_or_slice, slice):
            if index_or_slice.step is not None:
                raise Exception("step values not supported")
            start_at = index_or_slice.start or 0
            end_at = index_or_slice.stop
        elif isinstance(index_or_slice, int):
            start_at = index_or_slice
            end_at = index_or_slice + 1
        else:
            raise TypeError(f"Unsupported type: {type(index_or_slice)}")

        data_length = end_at - start_at

        candidate_index = max(0, bisect.bisect_left(self._segments, (start_at,)) - 1)
        segment_start, segment_data = self._segments[candidate_index]
        segment_length = len(segment_data)
        segment_end = max(segment_start, segment_start + segment_length - 1)
        if not (
            segment_start <= start_at <= segment_end and data_length <= segment_length
        ):
            raise IndexError(
                f"Requested data is out of bounds: segment=({segment_start} - "
                f"{segment_end}) slice=({start_at} - {end_at})"
            )

        if isinstance(index_or_slice, slice):
            offset_slice = slice(start_at - segment_start, end_at - segment_start)
            return segment_data[offset_slice]
        elif isinstance(index_or_slice, int):
            offset_index = index_or_slice - segment_start
            return segment_data[offset_index]
        else:
            raise TypeError(f"Unsupported type: {type(index_or_slice)}")


@to_tuple
def _parse_element_stream(stream: IO[bytes]) -> Iterable[ProofElement]:
    previous_path = None
    while True:
        try:
            element = ProofElement.deserialize(stream, previous=previous_path)
        except ParseError:
            break
        else:
            previous_path = element.path
            yield element


@dataclass(frozen=True)
class Proof:
    """
    Representation of a merkle proof for an SSZ byte string (aka List[uint8,
    max_length=...]).
    """

    sedes: ListSedes
    hash_tree_root: Hash32
    elements: Tuple[ProofElement, ...]

    def serialize(self) -> bytes:
        # TODO: we can elimenate the need for the tree object by 1) directly
        # fetching the length node since we know its path and 2) directly
        # filtering the data elements out since we know the bounds on their
        # paths.
        tree = ProofTree.from_proof(self)
        length = tree.get_data_length()
        num_data_chunks = (length + CHUNK_SIZE - 1) // CHUNK_SIZE
        last_data_chunk_index = max(0, num_data_chunks - 1)
        path_bit_length = self.sedes.chunk_count.bit_length()
        last_data_chunk_path = chunk_index_to_path(last_data_chunk_index, path_bit_length)
        data_nodes = tuple(
            node for node in tree.walk(end_at=last_data_chunk_path) if node.is_terminal
        )
        data_only_elements = tuple(
            ProofElement(path=node.path, value=node.value) for node in data_nodes
        )

        serialized_elements = b"".join(
            (
                element.serialize(previous.path if previous is not None else None)
                for previous, element in sliding_window(
                    2,
                    cons(None, sorted(data_only_elements, key=operator.attrgetter("path"))),
                )
            )
        )
        return encode_leb128(length) + serialized_elements

    @classmethod
    def deserialize(
        cls,
        stream: IO[bytes],
        hash_tree_root: Hash32,
        sedes: ListSedes = content_sedes,
    ) -> "Proof":
        length = parse_leb128(stream)

        data_elements = _parse_element_stream(stream)

        num_data_chunks = (length + CHUNK_SIZE - 1) // CHUNK_SIZE
        last_data_chunk_index = max(0, num_data_chunks - 1)
        path_bit_length = sedes.chunk_count.bit_length()

        num_padding_chunks = sedes.chunk_count - num_data_chunks

        padding_elements = get_padding_elements(
            last_data_chunk_index,
            num_padding_chunks,
            path_bit_length,
        )
        length_element = ProofElement(path=(True,), value=length.to_bytes(CHUNK_SIZE, 'little'))

        elements = data_elements + padding_elements + (length_element,)

        return cls(sedes, hash_tree_root, elements)

    def to_partial(self, start_at: int, partial_data_length: int) -> "Proof":
        """
        Return another proof with the minimal number of tree elements necessary
        to prove the slice of the underlying bytestring denoted by the
        `start_at` and `partial_data_length` parameters.
        """
        # First retrieve the overall data length from the proof.  The `length`
        # shoudl always be found on the path `(True,)` which should always be present in the
        tree = ProofTree.from_proof(self)
        length = tree.get_data_length()

        path_bit_length = self.sedes.chunk_count.bit_length()

        # Ensure that we aren't requesting data that exceeds the overall length
        # of the underlying data.
        end_at = start_at + partial_data_length
        if end_at > length:
            raise Exception(
                f"Cannot create partial that exceeds the data length: {end_at} > {length}"
            )

        # Compute the chunk indices and corresponding paths for the locations
        # in the tree where the partial data starts and ends.
        first_partial_chunk_index = start_at // CHUNK_SIZE
        last_partial_chunk_index = max(
            0, (start_at + partial_data_length + CHUNK_SIZE - 1) // CHUNK_SIZE - 1,
        )

        first_partial_chunk_path = chunk_index_to_path(
            first_partial_chunk_index, path_bit_length
        )
        last_partial_chunk_path = chunk_index_to_path(
            last_partial_chunk_index, path_bit_length
        )

        # Get all of the leaf nodes for the section of the tree where the
        # partial data is located.  Ensure that we have a contiguous section of
        # leaf nodes for this part of the tree.
        leaf_nodes_for_partial = tuple(
            node
            for node in tree.walk(first_partial_chunk_path, last_partial_chunk_path)
            if node.is_leaf
        )
        expected_partial_chunk_count = (
            last_partial_chunk_index - first_partial_chunk_index
        ) + 1
        if len(leaf_nodes_for_partial) != expected_partial_chunk_count:
            raise Exception(
                "Proof is missing leaf nodes required for partial construction."
            )

        # Compute the total number of non-padding chunks in the tree.
        num_data_chunks = (length + CHUNK_SIZE - 1) // CHUNK_SIZE
        last_data_chunk_index = max(0, num_data_chunks - 1)
        last_data_chunk_path = chunk_index_to_path(
            last_data_chunk_index, path_bit_length
        )

        #
        # Data chunks left of the partial
        #
        # start-at : 0
        # end-at   : first_partial_chunk_index - 1
        if first_partial_chunk_index > 0:
            nodes_left_of_partial = tree.get_subtree_proof_nodes(
                chunk_index_to_path(0, path_bit_length),
                chunk_index_to_path(first_partial_chunk_index - 1, path_bit_length),
            )
        else:
            nodes_left_of_partial = ()

        #
        # Data chunks right of the partial
        #
        # start-at : last_partial_chunk_index + 1
        # end-at   : last_data_chunk_index
        if last_partial_chunk_index + 1 <= last_data_chunk_index:
            nodes_right_of_partial = tree.get_subtree_proof_nodes(
                chunk_index_to_path(last_partial_chunk_index + 1, path_bit_length),
                last_data_chunk_path,
            )
        else:
            nodes_right_of_partial = ()

        #
        # Padding
        #
        # start-at : last_partial_chunk_index + 1
        # end-at   : N/A
        if last_data_chunk_index + 1 <= self.sedes.chunk_count - 1:
            first_padding_chunk_path = chunk_index_to_path(
                last_data_chunk_index + 1, path_bit_length
            )
            actual_first_padding_node = tree.get_deepest_node_on_path(
                first_padding_chunk_path
            )
            padding_nodes = tuple(
                node
                for node in tree.walk(actual_first_padding_node.path)
                if node.is_terminal
            )
        else:
            padding_nodes = ()

        # Now re-assembly the sections of the tree for the minimal proof for
        # the partial data.
        partial_nodes = (
            nodes_left_of_partial
            + leaf_nodes_for_partial
            + nodes_right_of_partial
            + padding_nodes
        )
        partial_elements = tuple(
            ProofElement(path=node.path, value=node.value) for node in partial_nodes
        )
        return Proof(self.sedes, self.hash_tree_root, partial_elements)

    def get_proven_data(self) -> DataPartial:
        """
        Returns a view over the proven data which can be accessed similar to a
        bytestring by either indexing or slicing.
        """
        tree = ProofTree.from_proof(self)
        length = tree.get_data_length()
        segments = self.get_proven_data_segments(length, tree)
        return DataPartial(length, segments)

    @to_tuple
    def get_proven_data_segments(
        self, length: int, tree: "ProofTree"
    ) -> Iterable[Tuple[int, bytes]]:
        num_data_chunks = (length + CHUNK_SIZE - 1) // CHUNK_SIZE

        path_bit_length = self.sedes.chunk_count.bit_length()

        last_data_chunk_index = max(0, num_data_chunks - 1)
        last_data_chunk_path = chunk_index_to_path(
            last_data_chunk_index, path_bit_length
        )

        last_data_chunk_data_size = length % CHUNK_SIZE

        next_chunk_index = 0
        segment_start_index = 0
        data_segment = b""

        # Walk over the section of the tree where the data chunks are located,
        # merging contigious chunks into a single segment.
        for node in tree.walk(end_at=last_data_chunk_path):
            if not node.is_leaf:
                continue
            chunk_index = path_to_left_chunk_index(node.path, path_bit_length)

            if chunk_index == last_data_chunk_index:
                if last_data_chunk_data_size:
                    chunk_data = node.value[:last_data_chunk_data_size]
                else:
                    chunk_data = node.value
            else:
                chunk_data = node.value

            if chunk_index == next_chunk_index:
                data_segment += chunk_data
            else:
                if data_segment:
                    yield (segment_start_index, data_segment)
                data_segment = chunk_data
                segment_start_index = chunk_index * CHUNK_SIZE

            next_chunk_index = chunk_index + 1

        if length:
            if data_segment:
                yield (segment_start_index, data_segment)
        if not length:
            yield 0, b""


def validate_proof(proof: Proof) -> None:
    tree = ProofTree.from_proof(proof)

    if tree.hash_tree_root != proof.hash_tree_root:
        raise ValidationError("Merkle root mismatch")


def is_proof_valid(proof) -> None:
    tree = ProofTree.from_proof(proof)

    return tree.hash_tree_root == proof.hash_tree_root


@to_tuple
def get_padding_elements(
    start_index: int, num_padding_chunks: int, path_bit_length: int
) -> Iterable[ProofElement]:
    """
    Get the padding elements for a proof.

    By decomposing the number of chunks needed into the powers of two which
    make up the number we can construct the minimal right hand sub-tree(s)
    needed to pad the hash tree.
    """
    for power_of_two in decompose_into_powers_of_two(num_padding_chunks):
        depth = power_of_two.bit_length() - 1
        left_index = start_index + power_of_two
        left_path = chunk_index_to_path(left_index, path_bit_length)
        padding_hash_tree_root = ZERO_HASHES[depth]
        yield ProofElement(left_path[: path_bit_length - depth], padding_hash_tree_root)


@to_tuple
def compute_proof_elements(
    chunks: Sequence[Hash32], chunk_count: int
) -> Iterable[ProofElement]:
    """
    Compute all of the proof elements, including the right hand padding
    elements for a proof over the given chunks.
    """
    # By using the full bit-length here we leave room for the length which gets
    # mixed in at the root of the tree.
    path_bit_length = chunk_count.bit_length()

    for idx, chunk in enumerate(chunks):
        path = chunk_index_to_path(idx, path_bit_length)
        yield ProofElement(path, chunk)

    start_index = len(chunks) - 1
    num_padding_chunks = chunk_count - len(chunks)

    yield from get_padding_elements(start_index, num_padding_chunks, path_bit_length)


def compute_proof(data: bytes, sedes: ListSedes) -> Proof:
    """
    Compute the full proof, including the mixed-in length value.
    """
    chunks = compute_chunks(data)
    chunk_count = sedes.chunk_count

    hash_tree = tuple(map(tuple, compute_hash_tree(chunks, chunk_count)))
    data_hash_tree_root = hash_tree[-1][0]

    hash_tree_root = mix_in_length(data_hash_tree_root, len(data))

    data_elements = compute_proof_elements(chunks, chunk_count)
    length_element = ProofElement(
        path=(True,), value=len(data).to_bytes(CHUNK_SIZE, "little"),
    )
    all_elements = data_elements + (length_element,)

    return Proof(sedes, hash_tree_root, all_elements)


class NodePosition(enum.IntEnum):
    left = 0
    right = 1
    root = 2


def construct_node(
    elements: Collection[ProofElement], path: Key, path_bit_length: int
) -> "Node":
    """
    Construct the tree of nodes for a ProofTree.
    """
    #
    # TERMINAL NODE
    #
    # - First we check to see if the tree terminates at this path.  If so there
    # should only be a single node.
    terminal_elements = tuple(el for el in elements if el.path == path)

    if terminal_elements:
        if len(terminal_elements) > 1:
            raise ValidationError(f"Multiple terminal elements: {terminal_elements}")
        elif not path:
            raise ValidationError(
                f"Invalid tree termination at root path: {terminal_elements}"
            )

        terminal = terminal_elements[0]
        return Node(
            path=path,
            value=terminal.value,
            left=None,
            right=None,
            position=NodePosition(path[-1]),
            path_bit_length=path_bit_length,
        )

    depth = len(path)

    # If the tree does not terminate then it always branches in both
    # directions.  Split the elements into their left/right sides and construct
    # the subtrees, and then the node at this level.
    left_elements = tuple(el for el in elements if el.path[depth] is False)
    right_elements = tuple(el for el in elements if el.path[depth] is True)

    left_node: Optional[Node]
    right_node: Optional[Node]

    if left_elements:
        left_node = construct_node(
            left_elements, path=path + (False,), path_bit_length=path_bit_length,
        )
    else:
        left_node = None

    if right_elements:
        right_node = construct_node(
            right_elements, path=path + (True,), path_bit_length=path_bit_length,
        )
    else:
        right_node = None

    if path:
        position = NodePosition(path[-1])
    else:
        position = NodePosition.root

    return Node(
        path=path,
        value=None,
        left=left_node,
        right=right_node,
        position=position,
        path_bit_length=path_bit_length,
    )


class BrokenTree(Exception):
    """
    Exception signaling that there are missing nodes in a `ProofTree` which are
    required for the proof to be valid.
    """

    ...


class TerminalPathError(Exception):
    """
    Exception signaling an attempt to navigate too deep into a tree.

    Can occur at either a leaf node, or a padding node.
    """

    ...


class Node:
    """
    Representation of a single node within a proof tree.
    """

    _computed_value: Optional[Hash32] = None

    def __init__(
        self,
        path: Key,
        value: Optional[Hash32],
        left: Optional["Node"],
        right: Optional["Node"],
        position: NodePosition,
        path_bit_length: int,
    ) -> None:
        self.path = path
        self._value = value
        self._left = left
        self._right = right
        self.position = position
        self._path_bit_length = path_bit_length

    def __str__(self) -> str:
        if self._left is not None:
            left = "L"
        else:
            left = "?" if self.is_terminal else "X"

        if self._right is not None:
            right = "R"
        else:
            right = "?" if self.is_terminal else "X"
        return f"Node[path={display_path(self.path)} children=({left}^{right})]"

    @property
    def value(self) -> Hash32:
        """
        The value at this node.  For intermediate nodes, this is a hash.  For
        leaf nodes this is the actual data.  Intermediate nodes that were not
        part of the proof are lazily computed.
        """
        if self._value is not None:
            return self._value
        elif self._computed_value is None:
            if self._left is None or self._right is None:
                raise BrokenTree(f"Tree path breaks below: {display_path(self.path)}")
            self._computed_value = hash_eth2(self._left.value + self._right.value)
        return self._computed_value

    @property
    def left(self) -> "Node":
        """
        The left child of this node.
        """
        if self._left is None:
            if self.is_terminal:
                raise TerminalPathError(
                    f"Tree path terminates: {display_path(self.path)}"
                )
            else:
                raise BrokenTree(f"Tree path breaks left of: {display_path(self.path)}")
        return self._left

    @property
    def right(self) -> "Node":
        """
        The right child of this node.
        """
        if self._right is None:
            if self.is_terminal:
                raise TerminalPathError(
                    f"Tree path terminates: {display_path(self.path)}"
                )
            else:
                raise BrokenTree(
                    f"Tree path breaks right of: {display_path(self.path)}"
                )
        return self._right

    @property
    def depth(self) -> int:
        """
        The number of layers below the merkle root that this node is located.
        """
        return len(self.path)

    @property
    def is_computed(self) -> bool:
        """
        Boolean whether this node was computed or part of the original proof.
        """
        return not self._value

    @property
    def is_intermediate(self) -> bool:
        """
        Boolean whether this node is an intermediate tree node or part of the actual data.
        """
        return not self.is_leaf

    @property
    def is_leaf(self) -> bool:
        """
        Boolean whether this node is part of the actual data.
        """
        return len(self.path) == self._path_bit_length or self.path == (True,)

    @property
    def is_terminal(self) -> bool:
        """
        Boolean whether it is possible to navigate below this node in the tree.
        """
        return self._left is None and self._right is None and self._value is not None

    @property
    def is_padding(self) -> bool:
        """
        Boolean whether this node *looks* like padding.  Will return true for
        content trees in which the data is empty bytes.

        TODO: Fix the false-positive cases for this helper.
        """
        return self._value == ZERO_HASHES[self._path_bit_length - self.depth]


class Visitor:
    """
    Thin helper for navigating around a ProofTree.
    """

    tree: "ProofTree"
    node: Node

    def __init__(self, tree: "ProofTree", node: Node) -> None:
        self.tree = tree
        self.node = node

    def visit_left(self) -> "Visitor":
        return Visitor(self.tree, self.node.left)

    def visit_right(self) -> "Visitor":
        return Visitor(self.tree, self.node.right)


@to_tuple
def get_longest_common_path(*paths: Key) -> Iterable[bool]:
    """
    Return the longs common prefix for the provided paths.
    """
    if not paths:
        return
    elif len(paths) == 1:
        yield from paths[0]
        return
    elif not any(paths):
        return

    for crumbs in zip(*paths):
        if all(crumbs) or not any(crumbs):
            yield crumbs[0]
        else:
            break


@to_tuple
def group_by_subtree(
    first_chunk_index: int, num_chunks: int
) -> Iterable[Tuple[Key, ...]]:
    r"""
    Group the paths into groups that belong to the same subtree.

    This helper function is used when constructing partial proofs. After
    setting aside the leaf nodes that correspond to the data we wish to prove,
    the remaining leaf nodes can be replaced by the hashes of the largest
    subtrees that contains them.

    Given a 4-bit tree like this

    0:                           0
                                / \
                              /     \
                            /         \
                          /             \
                        /                 \
                      /                     \
                    /                         \
    1:             0                           1
                 /   \                       /   \
               /       \                   /       \
             /           \               /           \
    2:      0             1             0             1
          /   \         /   \         /   \         /   \
    3:   0     1       0     1       0     1       0     1
        / \   / \     / \   / \     / \   / \     / \   / \
    4: A   B C   D   E   F G   H   I   J K   L   M   N O   P

                |-------------------------|

    If we are given the chunks D-K which map to indices 3-10 we want them
    divided up into the largest subgroups that all belong in the same subtree.

    2:      0             1             0             1
          /   \         /   \         /   \         /   \
    3:   0     1       0     1       0     1       0     1
        / \   / \     / \   / \     / \   / \     / \   / \
    4: A   B C   D   E   F G   H   I   J K   L   M   N O   P
                |-| |-----------| |-----|-|

    These groups are

    - D
    - E, F, G, H
    - I, J
    - K

    The algorithm for doing this is as follows:

    1) Find the largest power of 2 that can fit into the chunk range.  This is
    referred to as the `group_size`.  For this example the number is 8 since we
    have a span of 8 items.  Divide the range up into groups aligned with this
    value.


    3:   0     1       0     1       0     1       0     1
        / \   / \     / \   / \     / \   / \     / \   / \
    4: A   B C   D   E   F G   H   I   J K   L   M   N O   P

                |-------------------------|
                (D, E, F, G, H)    (I, J, K)
       <=========(0-7)=========>   <=========8-16==========>

    2) Any group that is the full lenght (in this case 8) is final.  All groups
    that are not full move onto the next round. In this case none of the groups
    are final.

    3) Now we change our group size to the previous power of two which is 4 in
    this case. Again we divide the range up into groups of this size.


    3:   0     1       0     1       0     1       0     1
        / \   / \     / \   / \     / \   / \     / \   / \
    4: A   B C   D   E   F G   H   I   J K   L   M   N O   P

                |-------------------------|
                (D)  (E, F, G, H)  (I, J, K)
       <==(0-3)==>   <==(4-7)==>   <==(8-11)=>   <=(12-15)=>

    4) In this case the group `(E, F, G, H)` is full so it moves into the
    *final* category, leaving the range (D,) and (I, J, K) for the next round
    which uses 2 as the group size.

    3:   0     1       0     1       0     1       0     1
        / \   / \     / \   / \     / \   / \     / \   / \
    4: A   B C   D   E   F G   H   I   J K   L   M   N O   P

                |-------------------------|
                (D)                (I, J) (K)
       <0-1> <2-3>   <4-5> <6-7>   <8-9> <10-11> ...

    5) At group size 2 we finalize (I, J). All remaining groups will finalize
    at group size 1.

    """
    last_chunk_index = first_chunk_index + num_chunks

    chunk_indices = tuple(range(first_chunk_index, last_chunk_index))
    chunks_to_process = (chunk_indices,)

    max_group_bit_size = num_chunks.bit_length() - 1

    final_groups = []

    for group_bit_size in range(max_group_bit_size, -1, -1):
        if not chunks_to_process:
            break
        next_chunks_to_process = []
        for chunk in chunks_to_process:
            chunk_start_index = chunk[0]
            chunk_end_index = chunk[-1]

            group_size = 2 ** group_bit_size
            group_start_at = chunk_start_index - (chunk_start_index % group_size)
            group_end_at = chunk_end_index + (group_size - chunk_end_index % group_size)

            group_candidates = tuple(
                chunk[
                    max(0, start_at - chunk_start_index) : start_at
                    - chunk_start_index
                    + group_size
                ]  # noqa: E501
                for start_at in range(group_start_at, group_end_at + 1, group_size)
            )
            final_groups.extend(
                tuple(group for group in group_candidates if len(group) == group_size)
            )
            next_chunks_to_process.extend(
                filter(
                    bool,
                    tuple(
                        group for group in group_candidates if len(group) < group_size
                    ),
                )
            )
        chunks_to_process = next_chunks_to_process

    return tuple(sorted(final_groups))


class ProofTree:
    """
    Tree representation of a Proof
    """

    root_node: Node

    _hash_tree_root: Optional[Hash32] = None

    def __init__(self, root_node: Node) -> None:
        self.root_node = root_node

    @classmethod
    def from_proof(cls, proof: Proof) -> "ProofTree":
        path_bit_length = proof.sedes.chunk_count.bit_length()
        root_node = construct_node(
            proof.elements, path=(), path_bit_length=path_bit_length
        )
        return cls(root_node)

    @property
    def hash_tree_root(self) -> Hash32:
        if self._hash_tree_root is None:
            self._hash_tree_root = self.root_node.value
        return self._hash_tree_root

    def get_data_length(self) -> int:
        length_node = self.get_node((True,))
        if not length_node.is_leaf:
            raise Exception("Bad Proof")
        return int.from_bytes(length_node.value, "little")

    def get_node(self, path: Key) -> Node:
        return self.get_nodes_on_path(path)[-1]

    @to_tuple
    def get_nodes_on_path(self, path: Key) -> Iterable[Node]:
        node = self.root_node
        yield node
        for el in path:
            if el is False:
                node = node.left
            elif el is True:
                node = node.right
            else:
                raise Exception("Invariant")
            yield node

    def get_deepest_node_on_path(self, path: Key) -> Node:
        node = self.root_node
        for el in path:
            if el is False:
                node = node.left
            elif el is True:
                node = node.right
            else:
                raise Exception("Invariant")
            if node.is_terminal:
                break

        return node

    def visit(self, path: Key) -> Visitor:
        node = self.get_node(path)
        return Visitor(self, node)

    def visit_left(self) -> Visitor:
        return self.visit((False,))

    def visit_right(self) -> Visitor:
        return self.visit((True,))

    def walk(
        self, start_at: Optional[Key] = None, end_at: Optional[Key] = None
    ) -> Iterable[Visitor]:
        if end_at is not None and start_at is not None and end_at < start_at:
            raise Exception("Invariant")

        if start_at is None:
            nodes_on_path = (self.root_node,)
        else:
            nodes_on_path = self.get_nodes_on_path(start_at)

        stack = []
        for parent, child in sliding_window(2, nodes_on_path):
            if child.position is NodePosition.left:
                stack.append(parent.right)

        stack.append(nodes_on_path[-1])

        while stack:
            node = stack.pop()
            if end_at is not None and node.path > end_at:
                break

            yield node
            if not node.is_terminal:
                stack.append(node.right)
                stack.append(node.left)

    @to_tuple
    def get_subtree_proof_nodes(self, start_at: Key, end_at: Key,) -> Iterable[Node]:
        if len(start_at) != len(end_at):
            raise Exception("Paths must be at the same depth")
        path_bit_length = len(start_at)
        first_chunk_index = path_to_left_chunk_index(start_at, path_bit_length)
        last_chunk_index = path_to_left_chunk_index(end_at, path_bit_length)

        if last_chunk_index < first_chunk_index:
            raise Exception("end path is before starting path")

        num_chunks = last_chunk_index - first_chunk_index + 1
        chunk_groups = group_by_subtree(first_chunk_index, num_chunks)
        subtree_node_paths = tuple(
            get_longest_common_path(
                chunk_index_to_path(group[0], path_bit_length),
                chunk_index_to_path(group[-1], path_bit_length),
            )
            for group in chunk_groups
        )
        for path in subtree_node_paths:
            yield self.get_node(path)
