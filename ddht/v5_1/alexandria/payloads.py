from typing import NamedTuple, Sequence, Tuple

from eth_enr import ENR, ENRAPI
import rlp


class PingPayload(NamedTuple):
    enr_seq: int


class PongPayload(NamedTuple):
    enr_seq: int


class FindNodesPayload(NamedTuple):
    distances: Tuple[int, ...]


class FoundNodesPayload(NamedTuple):
    total: int
    encoded_enrs: Tuple[bytes, ...]

    @property
    def enrs(self) -> Tuple[ENRAPI]:
        return tuple(  # type: ignore
            rlp.decode(raw_enr, sedes=ENR) for raw_enr in self.encoded_enrs
        )

    @classmethod
    def from_enrs(cls, total: int, enrs: Sequence[ENRAPI]) -> "FoundNodesPayload":
        encoded_enrs = tuple(rlp.encode(enr) for enr in enrs)
        return cls(total, encoded_enrs)