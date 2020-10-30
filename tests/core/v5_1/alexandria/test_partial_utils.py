import pytest

from ddht.v5_1.alexandria.partials.chunking import (
    chunk_index_to_path,
    group_by_subtree,
)
from ddht.v5_1.alexandria.partials._utils import (
    decompose_into_powers_of_two,
    get_longest_common_path,
    get_chunk_count_for_data_length,
)


@pytest.mark.parametrize(
    "first_chunk_index,num_chunks,expected",
    (
        # Tree for reference
        #
        # 0:                            0
        #                              / \
        #                            /     \
        #                          /         \
        #                        /             \
        #                      /                 \
        #                    /                     \
        #                  /                         \
        # 1:              0                           1
        #               /   \                       /   \
        #             /       \                   /       \
        #           /           \               /           \
        # 2:       0             1             0             1
        #        /   \         /   \         /   \         /   \
        # 3:    0     1       0     1       0     1       0     1
        #      / \   / \     / \   / \     / \   / \     / \   / \
        # 4:  A   B C   D   E   F G   H   I   J K   L   M   N O   P
        #
        # Indices:
        #     0   1 2   3   4   5 6   7   8   9 1   1   1   1 1   1
        #                                       0   1   2   3 4   5
        (0, 1, ((0,),)),
        (1, 1, ((1,),)),
        (2, 1, ((2,),)),
        (3, 1, ((3,),)),
        (4, 1, ((4,),)),
        (5, 1, ((5,),)),
        (6, 1, ((6,),)),
        (7, 1, ((7,),)),
        (8, 1, ((8,),)),
        (9, 1, ((9,),)),
        (9, 4, ((9,), (10, 11), (12,))),
        (3, 8, ((3,), (4, 5, 6, 7), (8, 9), (10,),),),
    ),
)
def test_groub_by_subtree(first_chunk_index, num_chunks, expected):
    actual = group_by_subtree(first_chunk_index, num_chunks)
    assert actual == expected


def p(*crumbs):
    return tuple(bool(crumb) for crumb in crumbs)


@pytest.mark.parametrize(
    "paths,expected",
    (
        ((), (),),  # no paths
        ((p(0, 1, 0),), p(0, 1, 0),),  # single path
        (((),), (),),  # single empty path
        (((), ()), (),),  # all empty paths
        ((p(1, 1, 1), p(0, 0, 0)), (),),  # no common crumbs
        ((p(0, 1, 1), p(0, 0, 0)), p(0,),),  # single crumb in common
        ((p(0, 0, 1), p(0, 0, 0)), p(0, 0),),  # multiple crumbs in common
        ((p(0, 0, 0), p(0, 0, 0)), p(0, 0, 0),),  # all crumbs in common
    ),
)
def test_get_longest_common_path(paths, expected):
    common_path = get_longest_common_path(*paths)
    assert common_path == expected


@pytest.mark.parametrize(
    "chunk_index,expected",
    (
        (0, p(0, 0, 0, 0)),
        (1, p(0, 0, 0, 1)),
        (3, p(0, 0, 1, 1)),
        (15, p(1, 1, 1, 1)),
    ),
)
def test_chunk_index_to_path(chunk_index, expected):
    path = chunk_index_to_path(chunk_index, 4)
    assert path == expected


@pytest.mark.parametrize(
    "value,expected",
    (
        (1, (1,)),
        (2, (2,)),
        (3, (1, 2)),
        (4, (4,)),
        (5, (1, 4)),
        (6, (2, 4)),
        (7, (1, 2, 4)),
        (8, (8,)),
        (9, (1, 8)),
        (31, (1, 2, 4, 8, 16)),
        (33, (1, 32)),
    ),
)
def test_decompose_into_powers_of_two(value, expected):
    actual = decompose_into_powers_of_two(value)
    assert actual == expected
    assert sum(actual) == value


@pytest.mark.parametrize(
    'length,expected',
    (
        (0, 0),
        (1, 1),
        (31, 1),
        (32, 1),
        (33, 2),
    ),
)
def test_get_chunk_count_for_data_length(length, expected):
    actual = get_chunk_count_for_data_length(length)
    assert actual == expected
