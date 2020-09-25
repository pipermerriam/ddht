import pytest
import trio

from ddht.v5_1.messages import TalkRequestMessage
from ddht.alexandria.alexandria import Alexandria
from ddht.alexandria.messages import PingMessage, decode_message, PongMessage


@pytest.fixture
async def alice_network(alice, bob):
    alice.enr_db.set_enr(bob.enr)
    async with alice.network() as alice_network:
        yield alice_network


@pytest.fixture
async def bob_network(alice, bob):
    bob.enr_db.set_enr(alice.enr)
    async with bob.network() as bob_network:
        yield bob_network


@pytest.mark.trio
async def test_alexandria_api_send_ping(alice_network, bob, bob_network):
    alexandria = Alexandria(alice_network)

    async with bob_network.dispatcher.subscribe(TalkRequestMessage) as subscription:
        await alexandria.send_ping(bob.node_id, bob.endpoint, enr_seq=100)
        with trio.fail_after(1):
            talk_response = await subscription.receive()
        message = decode_message(talk_response.message.payload)
        assert isinstance(message, PingMessage)
        assert message.payload.enr_seq == 100


@pytest.mark.trio
async def test_alexandria_api_send_pong(alice_network, bob, bob_network):
    alexandria = Alexandria(alice_network)

    async with bob_network.dispatcher.subscribe(TalkRequestMessage) as subscription:
        await alexandria.send_pong(bob.node_id, bob.endpoint, enr_seq=100)
        with trio.fail_after(1):
            talk_response = await subscription.receive()
        message = decode_message(talk_response.message.payload)
        assert isinstance(message, PongMessage)
        assert message.payload.enr_seq == 100


@pytest.mark.trio
async def test_alexandria_api_ping_request_response(alice_network, bob_network):
    assert False
