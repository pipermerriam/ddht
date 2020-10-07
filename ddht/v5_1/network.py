import itertools
import logging
import operator
from typing import Collection, Iterable, List, Optional, Set, Tuple

from eth_enr import ENRAPI, ENRDatabaseAPI, ENRManagerAPI
from eth_enr.exceptions import OldSequenceNumber
from eth_typing import NodeID
from eth_utils import to_tuple
from eth_utils.toolz import groupby, take
import trio

from ddht._utils import humanize_node_id
from ddht.constants import ROUTING_TABLE_BUCKET_SIZE
from ddht.endpoint import Endpoint
from ddht.kademlia import (
    KademliaRoutingTable,
    compute_distance,
    compute_log_distance,
    iter_closest_nodes,
)
from ddht.v5_1.abc import ClientAPI, DispatcherAPI, EventsAPI, NetworkAPI, PoolAPI
from ddht.v5_1.messages import PongMessage


class Network(NetworkAPI):
    logger = logging.getLogger("ddht.Network")

    _bootnodes: Tuple[ENRAPI, ...]

    def __init__(self, client: ClientAPI) -> None:
        self.client = client

        self.routing_table = KademliaRoutingTable(
            self.client.enr_manager.enr.node_id, ROUTING_TABLE_BUCKET_SIZE,
        )

    #
    # Proxied ClientAPI properties
    #
    @property
    def local_node_id(self) -> NodeID:
        return self.client.local_node_id

    @property
    def events(self) -> EventsAPI:
        return self.client.events

    @property
    def dispatcher(self) -> DispatcherAPI:
        return self.client.dispatcher

    @property
    def enr_manager(self) -> ENRManagerAPI:
        return self.client.enr_manager

    @property
    def pool(self) -> PoolAPI:
        return self.client.pool

    @property
    def enr_db(self) -> ENRDatabaseAPI:
        return self.client.enr_db

    #
    # High Level API
    #
    async def ping(
        self, node_id: NodeID, *, endpoint: Optional[Endpoint] = None
    ) -> PongMessage:
        if endpoint is None:
            endpoint = self._endpoint_for_node_id(node_id)
        response = await self.client.ping(endpoint, node_id)
        return response.message

    async def find_nodes(
        self, node_id: NodeID, *distances: int, endpoint: Optional[Endpoint] = None,
    ) -> Tuple[ENRAPI, ...]:
        if not distances:
            raise TypeError("Must provide at least one distance")

        if endpoint is None:
            endpoint = self._endpoint_for_node_id(node_id)
        responses = await self.client.find_nodes(endpoint, node_id, distances=distances)
        return tuple(enr for response in responses for enr in response.message.enrs)

    async def talk(
        self,
        node_id: NodeID,
        *,
        protocol: bytes,
        payload: bytes,
        endpoint: Optional[Endpoint] = None,
    ) -> bytes:
        if endpoint is None:
            endpoint = self._endpoint_for_node_id(node_id)
        response = await self.client.talk(endpoint, node_id, protocol, payload)
        return response.message.payload

    async def _retrieve_latest_enr(
        self, node_id: NodeID, *, endpoint: Optional[Endpoint] = None
    ) -> ENRAPI:
        enrs = await self.find_nodes(node_id, 0, endpoint=endpoint)
        if not enrs:
            raise Exception("Invalid response")
        # This reduce ensures that if they sent back multiple ENRS that we only
        # get the one with the highest sequence number.
        enr = _reduce_enrs(enrs)[0]
        if not enr.node_id == node_id:
            raise Exception("Invalid response")
        return enr

    async def get_enr(
        self, node_id: NodeID, *, enr_seq: int = 0, endpoint: Optional[Endpoint] = None
    ) -> ENRAPI:
        try:
            enr = self.enr_db.get_enr(node_id)
        except KeyError:
            enr = await self._retrieve_latest_enr(node_id, endpoint=endpoint)
        else:
            if enr_seq > enr.sequence_number:
                enr = await self._retrieve_latest_enr(node_id, endpoint=endpoint)
                self.enr_db.set_enr(enr)

        return enr

    async def recursive_find_nodes(self, target: NodeID) -> Tuple[ENRAPI, ...]:
        self.logger.debug("Recursive find nodes: %s", humanize_node_id(target))

        queried_node_ids = set()
        unresponsive_node_ids = set()
        received_enrs: List[ENRAPI] = []
        received_node_ids: Set[NodeID] = set()

        async def do_lookup(node_id: NodeID) -> None:
            queried_node_ids.add(node_id)

            distance = compute_log_distance(node_id, target)
            try:
                enrs = await self.find_nodes(node_id, distance)
            except trio.EndOfChannel:
                unresponsive_node_ids.add(node_id)
                return

            for enr in enrs:
                received_node_ids.add(enr.node_id)
                try:
                    self.enr_db.set_enr(enr)
                except OldSequenceNumber:
                    received_enrs.append(self.enr_db.get_enr(enr.node_id))
                else:
                    received_enrs.append(enr)

        for lookup_round_counter in itertools.count():
            candidates = iter_closest_nodes(
                target, self.routing_table, received_node_ids
            )
            responsive_candidates = itertools.dropwhile(
                lambda node: node in unresponsive_node_ids, candidates
            )
            closest_k_candidates = take(
                self.routing_table.bucket_size, responsive_candidates
            )
            closest_k_unqueried_candidates = (
                candidate
                for candidate in closest_k_candidates
                if candidate not in queried_node_ids and candidate != self.local_node_id
            )
            nodes_to_query = tuple(take(3, closest_k_unqueried_candidates))

            if nodes_to_query:
                self.logger.debug(
                    "Starting lookup round %d for %s",
                    lookup_round_counter + 1,
                    humanize_node_id(target),
                )
                async with trio.open_nursery() as nursery:
                    for peer in nodes_to_query:
                        nursery.start_soon(do_lookup, peer)
            else:
                self.logger.debug(
                    "Lookup for %s finished in %d rounds",
                    humanize_node_id(target),
                    lookup_round_counter,
                )
                break

        # now sort and return the ENR records in order of closesness to the target.
        return tuple(
            sorted(
                _reduce_enrs(received_enrs),
                key=lambda enr: compute_distance(enr.node_id, target),
            )
        )

    #
    # Utility
    #
    def _endpoint_for_node_id(self, node_id: NodeID) -> Endpoint:
        enr = self.enr_db.get_enr(node_id)
        return Endpoint.from_enr(enr)


@to_tuple
def _reduce_enrs(enrs: Collection[ENRAPI]) -> Iterable[ENRAPI]:
    """
    Given a set of ENR records, filter out ones with duplicate node_id,
    retaining only the one with the highest sequence number.
    """
    enrs_by_node_id = groupby(operator.attrgetter("node_id"), enrs)
    for _, enr_group in enrs_by_node_id.items():
        if len(enr_group) == 1:
            yield enr_group[0]
        else:
            yield max(enr_group, key=operator.attrgetter("sequence_number"))
