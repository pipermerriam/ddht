from async_service import Service

from ddbt.abc import PingPongAPI, SubscriptionManagerAPI
from ddht.v5_1.messages import PingMessage


class PongResponder(Service):
    def __init__(self,
                 client: PingPongAPI,
                 subscription_manager: SubscriptionManagerAPI) -> None:
        self._client = client
        self._subscription_manager = subscription_manager

    async def run(self) -> None:
        async with self.subscription_manager.subscribe(PingMessage) as subscription:
            async for request in subscription:
                await self.client.send_pong(
                    request.sender_node_id,
                    request.sender_endpoint,
                    request_id=request.message.request_id,
                )
