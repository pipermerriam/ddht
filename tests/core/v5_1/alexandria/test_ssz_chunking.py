from hypothesis import given, settings
from hypothesis import strategies as st
from ssz import sedes
from ssz.utils import pack

from ddht.v5_1.alexandria.constants import GB
from ddht.v5_1.alexandria.partials.chunking import (
    compute_chunks,
)


@settings(max_examples=1000)
@given(data=st.binary(min_size=0, max_size=GB))
def test_ssz_compute_chunks(data):
    expected = pack(tuple(sedes.uint8.serialize(v) for v in data))
    actual = compute_chunks(data)
    assert expected == actual
