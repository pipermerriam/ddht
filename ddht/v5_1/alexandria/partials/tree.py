import enum
from typing import Collection, Optional, Iterable

from eth_typing import Hash32
from eth_utils import ValidationError, to_tuple
from ssz.constants import ZERO_HASHES
from ssz.hash import hash_eth2

from ddht.v5_1.alexandria.typing import TreePath
from ddht.v5_1.alexandria._utils import display_path


class NodePosition(enum.IntEnum):
    left = 0
    right = 1
    root = 2


def construct_node(
    elements: Collection[ProofElement], path: TreePath, path_bit_length: int
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
        path: TreePath,
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

    def get_node(self, path: TreePath) -> Node:
        return self.get_nodes_on_path(path)[-1]

    @to_tuple
    def get_nodes_on_path(self, path: TreePath) -> Iterable[Node]:
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

    def get_deepest_node_on_path(self, path: TreePath) -> Node:
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

    def visit(self, path: TreePath) -> Visitor:
        node = self.get_node(path)
        return Visitor(self, node)

    def visit_left(self) -> Visitor:
        return self.visit((False,))

    def visit_right(self) -> Visitor:
        return self.visit((True,))

    def walk(
        self, start_at: Optional[TreePath] = None, end_at: Optional[TreePath] = None
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
    def get_subtree_proof_nodes(self, start_at: TreePath, end_at: TreePath) -> Iterable[Node]:
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
