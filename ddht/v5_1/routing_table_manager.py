import logging
import secrets
from typing import Collection, List, Optional

from async_service import Service
from eth_enr import ENRAPI
from eth_enr.exceptions import OldSequenceNumber
from eth_typing import NodeID
from eth_utils.toolz import cons, first
from lru import LRU
import trio

from ddht._utils import every, humanize_node_id
from ddht.abc import RoutingTableAPI
from ddht.endpoint import Endpoint
from ddht.v5_1.abc import NetworkAPI
from ddht.v5_1.constants import ROUTING_TABLE_KEEP_ALIVE
from ddht.v5_1.messages import FindNodeMessage, PongMessage


class RoutingTableManager(Service):
    logger = logging.getLogger("ddht.RoutingTableManager")

    def __init__(
        self,
        network: NetworkAPI,
        routing_table: RoutingTableAPI,
        bootnodes: Collection[ENRAPI],
    ) -> None:
        self._bootnodes = bootnodes
        self.network = network
        self.routing_table = routing_table

        self._routing_table_ready = trio.Event()
        self._last_pong_at = LRU(2048)

    async def run(self) -> None:
        self.manager.run_daemon_task(self._track_last_pong)
        self.manager.run_daemon_task(self._ping_oldest_routing_table_entry)
        self.manager.run_daemon_task(self._serve_find_nodes)
        self.manager.run_daemon_task(self._periodically_report_routing_table)

        # First load all the bootnode ENRs into our database
        for enr in self._bootnodes:
            try:
                self.network.enr_db.set_enr(enr)
            except OldSequenceNumber:
                pass

        # Now repeatedly try to bond with each bootnode until one succeeds.
        async with trio.open_nursery() as nursery:
            while self.manager.is_running:
                for enr in self._bootnodes:
                    if enr.node_id == self.network.local_node_id:
                        continue
                    endpoint = Endpoint.from_enr(enr)
                    nursery.start_soon(self._bond, enr.node_id, endpoint)

                with trio.move_on_after(10):
                    await self._routing_table_ready.wait()
                    break

        # TODO: Need better logic here for more quickly populating the
        # routing table.  Should start off aggressively filling in the
        # table, only backing off once the table contains some minimum
        # number of records **or** searching for new records fails to find
        # new nodes.  Maybe use a TokenBucket
        async for _ in every(30):
            async with trio.open_nursery() as nursery:
                target_node_id = NodeID(secrets.token_bytes(32))
                found_enrs = await self.network.recursive_find_nodes(target_node_id)
                for enr in found_enrs:
                    if enr.node_id == self.network.local_node_id:
                        continue
                    endpoint = Endpoint.from_enr(enr)
                    nursery.start_soon(self._bond, enr.node_id, endpoint)

    async def _bond(self, node_id: NodeID, endpoint: Endpoint) -> None:
        await self.bond(node_id, endpoint=endpoint)

    async def bond(
        self, node_id: NodeID, *, endpoint: Optional[Endpoint] = None
    ) -> bool:
        try:
            pong = await self.network.ping(node_id, endpoint=endpoint)
        except trio.EndOfChannel:
            self.logger.debug(
                "Bonding with %s timed out during ping", humanize_node_id(node_id)
            )
            return False

        try:
            enr = await self.network.get_enr(
                node_id, enr_seq=pong.enr_seq, endpoint=endpoint
            )
        except trio.EndOfChannel:
            self.logger.debug(
                "Bonding with %s timed out during ENR retrieval",
                humanize_node_id(node_id),
            )
            return False

        self.routing_table.update(enr.node_id)

        self._routing_table_ready.set()
        return True

    async def _periodically_report_routing_table(self) -> None:
        async for _ in every(30, initial_delay=30):
            non_empty_buckets = tuple(
                (idx, bucket)
                for idx, bucket in enumerate(reversed(self.routing_table.buckets))
                if bucket
            )
            total_size = sum(len(bucket) for idx, bucket in non_empty_buckets)
            bucket_info = "|".join(
                tuple(f"{idx}:{len(bucket)}" for idx, bucket in non_empty_buckets)
            )
            self.logger.debug(
                "routing-table-info: size=%d  buckets=%s", total_size, bucket_info,
            )

    async def _track_last_pong(self) -> None:
        async with self.network.dispatcher.subscribe(PongMessage) as subscription:
            async for message in subscription:
                self._last_pong_at[message.sender_node_id] = trio.current_time()

    async def _ping_oldest_routing_table_entry(self) -> None:
        await self._routing_table_ready.wait()

        while self.manager.is_running:
            # Here we preserve the lazy iteration while still checking that the
            # iterable is not empty before passing it into `min` below which
            # throws an ambiguous `ValueError` otherwise if the iterable is
            # empty.
            nodes_iter = self.routing_table.iter_all_random()
            try:
                first_node_id = first(nodes_iter)
            except StopIteration:
                await trio.sleep(ROUTING_TABLE_KEEP_ALIVE)
                continue
            else:
                least_recently_ponged_node_id = min(
                    cons(first_node_id, nodes_iter),
                    key=lambda node_id: self._last_pong_at.get(node_id, 0),
                )

            too_old_at = trio.current_time() - ROUTING_TABLE_KEEP_ALIVE
            try:
                last_pong_at = self._last_pong_at[least_recently_ponged_node_id]
            except KeyError:
                pass
            else:
                if last_pong_at > too_old_at:
                    await trio.sleep(last_pong_at - too_old_at)
                    continue

            did_bond = await self.bond(least_recently_ponged_node_id)
            if not did_bond:
                self.routing_table.remove(least_recently_ponged_node_id)

    async def _serve_find_nodes(self) -> None:
        async with self.network.dispatcher.subscribe(FindNodeMessage) as subscription:
            async for request in subscription:
                response_enrs: List[ENRAPI] = []
                distances = set(request.message.distances)
                if len(distances) != len(request.message.distances):
                    self.logger.debug(
                        "Ignoring invalid FindNodeMessage from %s@%s: duplicate distances",
                        humanize_node_id(request.sender_node_id),
                        request.sender_endpoint,
                    )
                    continue
                elif not distances:
                    self.logger.debug(
                        "Ignoring invalid FindNodeMessage from %s@%s: empty distances",
                        humanize_node_id(request.sender_node_id),
                        request.sender_endpoint,
                    )
                    continue
                elif any(
                    distance > self.routing_table.num_buckets for distance in distances
                ):
                    self.logger.debug(
                        "Ignoring invalid FindNodeMessage from %s@%s: distances: %s",
                        humanize_node_id(request.sender_node_id),
                        request.sender_endpoint,
                        distances,
                    )
                    continue

                for distance in distances:
                    if distance == 0:
                        response_enrs.append(self.network.enr_manager.enr)
                    elif distance <= self.routing_table.num_buckets:
                        node_ids_at_distance = self.routing_table.get_nodes_at_log_distance(
                            distance,
                        )
                        for node_id in node_ids_at_distance:
                            response_enrs.append(self.network.enr_db.get_enr(node_id))
                    else:
                        raise Exception("Should be unreachable")

                await self.network.client.send_found_nodes(
                    request.sender_endpoint,
                    request.sender_node_id,
                    enrs=response_enrs,
                    request_id=request.message.request_id,
                )
