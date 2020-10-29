import io

from hypothesis import given, settings
from hypothesis import strategies as st
import pytest

from ddht.v5_1.alexandria.constants import GB
from ddht.v5_1.alexandria.partials.proof import (
    Proof,
    ProofElement,
    compute_proof,
    validate_proof,
)
from ddht.v5_1.alexandria.sedes import (
    content_sedes,
)

VALUE = bytes(bytearray((i for i in range(32))))


def p(*crumbs):
    return tuple(bool(crumb) for crumb in crumbs)


@pytest.mark.parametrize(
    "path,value,previous",
    (
        ((), VALUE, None,),
        ((True,), VALUE, None,),
        ((False,), VALUE, None,),
        ((True,) * 25, VALUE, None,),
        ((False,) * 25, VALUE, None,),
        ((False, False, True, True, False, False), VALUE, None,),
        ((True, True, False, False, True, True), VALUE, None,),
        # Previous path without any common bits
        ((True, False, True, False, True, False), VALUE, (False, True),),
        # Previous path without one common bit
        ((True, False, True, False, True, False), VALUE, (True, True),),
        # Previous path without multiple common bits
        (
            (True, False, True, False, True, False),
            VALUE,
            (True, False, True, False, False),
        ),
        # Exceed single byte boundaries
        (
            (
                True,
                False,
                True,
                False,
                True,
                False,
                True,
                False,
                True,
                False,
                True,
                False,
            ),
            VALUE,
            (True, False),
        ),
        (
            (
                True,
                False,
                True,
                False,
                True,
                False,
                True,
                False,
                True,
                False,
                True,
                False,
            ),
            VALUE,
            (True, False, True, False, True, False, True, False, True, False),
        ),
    ),
)
def test_proof_element_serialization_round_trip(path, value, previous):
    path = tuple(path)
    element = ProofElement(path, value)
    serialized = element.serialize(previous)
    result = ProofElement.deserialize(io.BytesIO(serialized), previous)
    assert result == element


@given(data=st.data(),)
def test_proof_element_serialization_round_trip_fuzzy(data):
    path = data.draw(st.lists(st.booleans(), min_size=0, max_size=25).map(tuple))
    value = data.draw(st.binary(min_size=32, max_size=32))
    previous = data.draw(
        st.one_of(
            st.lists(st.booleans(), min_size=0, max_size=25 - len(path)).map(tuple),
            st.none(),
        )
    )

    element = ProofElement(path, value)
    serialized = element.serialize(previous)
    result = ProofElement.deserialize(io.BytesIO(serialized), previous)
    assert result == element


@settings(max_examples=1000)
@given(data=st.binary(min_size=0, max_size=GB))
def test_proof_serialization_and_deserialization(data):
    proof = compute_proof(data, sedes=content_sedes)

    serialized = proof.serialize()
    result = Proof.deserialize(io.BytesIO(serialized), proof.hash_tree_root)

    validate_proof(result)

    assert result == proof
