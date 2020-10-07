from typing import Any, Optional, Type

from eth_typing import NodeID

from ddht.alexandria.abc import AlexandriaAPI, TResponse
from ddht.alexandria.constants import ALEXANDRIA_PROTOCOL_ID
from ddht.alexandria.messages import (
    AlexandriaMessage,
    PingMessage,
    PongMessage,
    decode_message,
)
from ddht.alexandria.payloads import PingPayload, PongPayload
from ddht.endpoint import Endpoint
from ddht.exceptions import DecodingError
from ddht.v5_1.abc import NetworkAPI

# TBaseMessage = TypeVar("TBaseMessage")
#
#
# class SubscriptionManagerAPI(ABC, Generic
#     #
#     # Subscription API
#     #
#     @asynccontextmanager
#     async def subscribe(
#         self,
#         message_type: Type[TMessage],
#         endpoint: Optional[Endpoint] = None,
#         node_id: Optional[NodeID] = None,
#     ) -> AsyncIterator[trio.abc.ReceiveChannel[InboundMessage[TMessage]]]:
#         message_id = self._registry.get_message_id(message_type)
#         send_channel, receive_channel = trio.open_memory_channel[
#             InboundMessage[TMessage]
#         ](256)
#         subscription = _Subcription(send_channel, endpoint, node_id)
#         self._subscriptions[message_id].add(subscription)
#         try:
#             async with receive_channel:
#                 yield receive_channel
#         finally:
#             self._subscriptions[message_id].remove(subscription)
#
#     @asynccontextmanager
#     async def subscribe_request(
#         self, request: AnyOutboundMessage, response_message_type: Type[TMessage],
#     ) -> AsyncIterator[trio.abc.ReceiveChannel[InboundMessage[TMessage]]]:  # noqa: E501
#         node_id = request.receiver_node_id
#         request_id = request.message.request_id
#
#         self.logger.debug(
#             "Sending request: %s with request id %s", request, request_id.hex(),
#         )
#
#         send_channel, receive_channel = trio.open_memory_channel[TMessage](256)
#         key = (node_id, request_id)
#         if key in self._active_request_ids:
#             raise Exception("Invariant")
#         self._active_request_ids.add(key)
#
#         async with trio.open_nursery() as nursery:
#             nursery.start_soon(
#                 self._manage_request_response,
#                 request,
#                 response_message_type,
#                 send_channel,
#             )
#             try:
#                 async with receive_channel:
#                     yield receive_channel
#             finally:
#                 self._active_request_ids.remove(key)
#                 nursery.cancel_scope.cancel()
#
#     async def _manage_request_response(
#         self,
#         request: AnyOutboundMessage,
#         response_message_type: Type[TMessage],
#         send_channel: trio.abc.SendChannel[InboundMessage[TMessage]],
#     ) -> None:
#         request_id = request.message.request_id
#
#         with trio.move_on_after(REQUEST_RESPONSE_TIMEOUT) as scope:
#             subscription_ctx = self.subscribe(
#                 response_message_type,
#                 request.receiver_endpoint,
#                 request.receiver_node_id,
#             )
#             async with subscription_ctx as subscription:
#                 self.logger.debug(
#                     "Sending request with request id %s", request_id.hex(),
#                 )
#                 # Send the request
#                 await self.send_message(request)
#
#                 # Wait for the response
#                 async with send_channel:
#                     async for response in subscription:
#                         if response.message.request_id != request_id:
#                             continue
#                         else:
#                             await send_channel.send(response)
#         if scope.cancelled_caught:
#             self.logger.warning(
#                 "Abandoned request response monitor: request=%s message_type=%s",
#                 request,
#                 response_message_type,
#             )


class Alexandria(AlexandriaAPI):
    protocol = ALEXANDRIA_PROTOCOL_ID

    def __init__(self, network: NetworkAPI) -> None:
        self.network = network

    #
    # Low Level Message Sending
    #
    async def send_message(
        self,
        node_id: NodeID,
        endpoint: Endpoint,
        message: AlexandriaMessage[Any],
        *,
        request_id: Optional[bytes] = None,
    ) -> bytes:
        data_payload = message.to_wire_bytes()
        request_id = await self.network.client.send_talk_request(
            endpoint,
            node_id,
            protocol=ALEXANDRIA_PROTOCOL_ID,
            payload=data_payload,
            request_id=request_id,
        )
        return request_id

    async def send_ping(
        self,
        node_id: NodeID,
        endpoint: Endpoint,
        *,
        enr_seq: int,
        request_id: Optional[bytes] = None,
    ) -> bytes:
        message = PingMessage(PingPayload(enr_seq))
        return await self.send_message(
            node_id, endpoint, message, request_id=request_id
        )

    async def send_pong(
        self,
        node_id: NodeID,
        endpoint: Endpoint,
        *,
        enr_seq: int,
        request_id: Optional[bytes] = None,
    ) -> bytes:
        message = PongMessage(PongPayload(enr_seq))
        return await self.send_message(
            node_id, endpoint, message, request_id=request_id
        )

    #
    # High Level Request/Response
    #
    async def request(
        self,
        node_id: NodeID,
        endpoint: Optional[Endpoint],
        request: AlexandriaMessage[Any],
        response_class: Type[TResponse],
    ) -> TResponse:
        request_data = request.to_wire_bytes()
        response_data = await self.network.talk(
            node_id,
            protocol=ALEXANDRIA_PROTOCOL_ID,
            payload=request_data,
            endpoint=endpoint,
        )
        response = decode_message(response_data)
        if not isinstance(response, response_class):
            raise DecodingError(
                f"Invalid response. expected={response_class}  got={type(response)}"
            )
        return response

    async def ping(
        self, node_id: NodeID, *, endpoint: Optional[Endpoint] = None
    ) -> PongPayload:
        request = PingMessage(PingPayload(self.network.enr_manager.enr.sequence_number))
        response = await self.request(node_id, endpoint, request, PongMessage)
        return response.payload
