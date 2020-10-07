from async_service import Service

from ddht.v5_1.abc import NetworkAPI
from ddht.v5_1.messages import PingMessage, PongMessage


class PongResponder(Service):
    def __init__(self, network: NetworkAPI) -> None:
        self.network = network

    async def run(self) -> None:
        async with self.network.dispatcher.subscribe(PingMessage) as subscription:
            async for request in subscription:
                await self.network.dispatcher.send_message(
                    request.to_response(
                        PongMessage(
                            request.message.request_id,
                            self.network.enr_manager.enr.sequence_number,
                            request.sender_endpoint.ip_address,
                            request.sender_endpoint.port,
                        )
                    )
                )
