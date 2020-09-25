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
        request_id: Optional[int] = None,
    ) -> int:
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
        self, node_id: NodeID, endpoint: Endpoint, *, enr_seq: int
    ) -> int:
        message = PingMessage(PingPayload(enr_seq))
        return await self.send_message(node_id, endpoint, message)

    async def send_pong(
        self,
        node_id: NodeID,
        endpoint: Endpoint,
        *,
        enr_seq: int,
        request_id: Optional[int] = None,
    ) -> int:
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
