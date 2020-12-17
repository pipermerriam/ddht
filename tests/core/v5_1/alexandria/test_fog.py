import pytest

from ddht.v5_1.alexandria.fog import explore_path, reduce_unexplored


r"""
|-------------------------------------------------------------------------------|
|                         XOR Distance Metric Neighbors                         |
|-------------------------------------------------------------------------------|
| 0  | 1  | 2  | 3  | 4  | 5  | 6  | 7  | 8  | 9  | 10 | 11 | 12 | 13 | 14 | 15 |
|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|
| 1  | 0  | 3  | 2  | 5  | 4  | 7  | 6  | 9  | 8  | 11 | 10 | 13 | 12 | 15 | 14 |
| 2  | 3  | 0  | 1  | 6  | 7  | 4  | 5  | 10 | 11 | 8  | 9  | 14 | 15 | 12 | 13 |
| 3  | 2  | 1  | 0  | 7  | 6  | 5  | 4  | 11 | 10 | 9  | 8  | 15 | 14 | 13 | 12 |
| 4  | 5  | 6  | 7  | 0  | 1  | 2  | 3  | 12 | 13 | 14 | 15 | 8  | 9  | 10 | 11 |
| 5  | 4  | 7  | 6  | 1  | 0  | 3  | 2  | 13 | 12 | 15 | 14 | 9  | 8  | 11 | 10 |
| 6  | 7  | 4  | 5  | 2  | 3  | 0  | 1  | 14 | 15 | 12 | 13 | 10 | 11 | 8  | 9  |
| 7  | 6  | 5  | 4  | 3  | 2  | 1  | 0  | 15 | 14 | 13 | 12 | 11 | 10 | 9  | 8  |
| 8  | 9  | 10 | 11 | 12 | 13 | 14 | 15 | 0  | 1  | 2  | 3  | 4  | 5  | 6  | 7  |
| 9  | 8  | 11 | 10 | 13 | 12 | 15 | 14 | 1  | 0  | 3  | 2  | 5  | 4  | 7  | 6  |
| 10 | 11 | 8  | 9  | 14 | 15 | 12 | 13 | 2  | 3  | 0  | 1  | 6  | 7  | 4  | 5  |
| 11 | 10 | 9  | 8  | 15 | 14 | 13 | 12 | 3  | 2  | 1  | 0  | 7  | 6  | 5  | 4  |
| 12 | 13 | 14 | 15 | 8  | 9  | 10 | 11 | 4  | 5  | 6  | 7  | 0  | 1  | 2  | 3  |
| 13 | 12 | 15 | 14 | 9  | 8  | 11 | 10 | 5  | 4  | 7  | 6  | 1  | 0  | 3  | 2  |
| 14 | 15 | 12 | 13 | 10 | 11 | 8  | 9  | 6  | 7  | 4  | 5  | 2  | 3  | 0  | 1  |
| 15 | 14 | 13 | 12 | 11 | 10 | 9  | 8  | 7  | 6  | 5  | 4  | 3  | 2  | 1  | 0  |
|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|


    0:                           X
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
           / \           / \           / \           / \
          /   \         /   \         /   \         /   \
    3:   0     1       0     1       0     1       0     1
        / \   / \     / \   / \     / \   / \     / \   / \
    4: 0   1 2   3   4   5 6   7   8   9 A   B   C   D E   F
"""


def p(*crumbs):
    return tuple(bool(crumb) for crumb in crumbs)


UNEXPLORED = ((),)


@pytest.mark.parametrize(
    'unexplored,expected',
    (
        ((p(0), p(1)), ()),
    ),
)
def test_reduce_unexplored(unexplored, expected):
    actual = reduce_unexplored(unexplored)
    assert actual == expected


@pytest.mark.parametrize(
    'unexplored,to_explore,expected',
    (
        (UNEXPLORED, (), ()),
        (UNEXPLORED, (True,), ((False,))),
        (UNEXPLORED, (False,), ((True,))),
        #(((True,),), (False,), ()),
    ),
)
def test_explore_path(unexplored, to_explore, expected):
    actual = explore_path(unexplored, to_explore)
    assert actual == expected
