from abc import abstractmethod
from typing import Any, Optional, Type, TypeVar

from eth_typing import NodeID

from ddht.alexandria.messages import AlexandriaMessage
from ddht.alexandria.payloads import PongPayload
from ddht.endpoint import Endpoint
from ddht.v5_1.abc import NetworkAPI, TalkProtocolAPI

TResponse = TypeVar("TResponse", bound=AlexandriaMessage[Any])


class AlexandriaAPI(TalkProtocolAPI):
    network: NetworkAPI

    #
    # Low Level Message Sending
    #
    @abstractmethod
    async def send_message(
        self,
        node_id: NodeID,
        endpoint: Endpoint,
        message: AlexandriaMessage[Any],
        *,
        request_id: Optional[int] = None,
    ) -> int:
        ...

    @abstractmethod
    async def send_ping(
        self, node_id: NodeID, endpoint: Endpoint, *, enr_seq: int
    ) -> int:
        ...

    @abstractmethod
    async def send_pong(
        self,
        node_id: NodeID,
        endpoint: Endpoint,
        *,
        enr_seq: int,
        request_id: Optional[int] = None,
    ) -> int:
        ...

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
        ...

    @abstractmethod
    async def ping(
        self, node_id: NodeID, *, endpoint: Optional[Endpoint] = None
    ) -> PongPayload:
        ...
