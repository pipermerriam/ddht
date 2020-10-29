import hashlib
import logging
import sys
from typing import Tuple

from ddht.v5_1.alexandria.partials.proof import compute_proof
from ddht.v5_1.alexandria.sedes import content_sedes

try:
    import texttable
except ImportError as err:
    raise ImportError(
        "The `texttable` python library is required to use the benchmarking "
        "suite.  Installable usin `pip install ddht[benchmark]`"
    ) from err


MB = 1024 * 1024


logger = logging.getLogger('ddht.benchmarks')


SEGMENTS = (
    ('32b-first', (0, 32)),
    ('32b-offset-1c', (32, 32)),
    ('32b-offset-4c', (128, 32)),

    ('64b-first', (0, 64)),
    ('64b-offset-1c', (32, 64)),
    ('64b-offset-4c', (128, 64)),

    ('128b-first', (0, 128)),
    ('128b-offset-1c', (32, 128)),
    ('128b-offset-4c', (128, 128)),

    ('256b-first', (0, 256)),
    ('256b-offset-1c', (32, 256)),
    ('256b-offset-4c', (128, 256)),

    ('512b-first', (0, 512)),
    ('512b-offset-1c', (32, 512)),
    ('512b-offset-4c', (128, 512)),

    ('768b-first', (0, 768)),
    ('768b-offset-1c', (32, 768)),
    ('768b-offset-4c', (128, 768)),

    ('1kb-first', (0, 1024)),
    ('1kb-offset-1c', (32, 1024)),
    ('1kb-offset-4c', (128, 1024)),
)


def benchmark(benchmark_name: str,
              content: bytes,
              segments: Tuple[Tuple[str, Tuple[int, int]], ...]):
    full_proof = compute_proof(content, sedes=content_sedes)

    proofs = tuple(
        full_proof.to_partial(start_at=start_at, partial_data_length=partial_data_length)
        for (name, (start_at, partial_data_length))
        in segments
    )
    serialized_proofs = tuple(
        proof.serialize() for proof in proofs
    )

    sizes = tuple(
        len(serialized_proof) for serialized_proof in serialized_proofs
    )

    table_header = ("name", "start", "end", "length", "size")
    table_rows = tuple(
        (name, start_at, start_at + partial_data_length, partial_data_length, size)
        for ((name, (start_at, partial_data_length)), size) in zip(segments, sizes)
    )

    table = texttable.Texttable()
    table.set_cols_align(("l", "r", "r", "r", "r"))
    table.header(table_header)
    table.add_rows(table_rows, header=False)

    logger.info("##########################")
    logger.info(f"benchmark: {benchmark_name}")
    logger.info("##########################\n")
    logger.info(table.draw())


def do_benchmarks():
    content_1mb = b"".join(
        (hashlib.sha256(i.to_bytes(32, "big")).digest() for i in range(MB // 32))
    )
    benchmark("1MB", content_1mb, SEGMENTS)


if __name__ == "__main__":
    handler_stream = logging.StreamHandler(sys.stderr)
    handler_stream.setLevel(logging.INFO)

    logger.setLevel(logging.INFO)
    logger.addHandler(handler_stream)

    do_benchmarks()
