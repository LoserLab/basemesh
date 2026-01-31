"""Integration tests for store-and-forward (deferred) transaction flow."""

import struct
import threading
import time

import pytest

from basemesh.constants import MsgType, NATIVE_ETH_ADDRESS
from basemesh.protocol import (
    decode_tx_request,
    encode_gateway_beacon,
    encode_nonce_resp,
    encode_gas_resp,
    encode_tx_result,
    encode_ack,
    pack_message,
    BEACON_CAP_RELAY,
)
from basemesh.store import IntentStatus, IntentStore
from basemesh.wallet import WalletManager
from basemesh.client import ClientNode

from mock_mesh import MockMeshInterface


@pytest.fixture
def deferred_setup(tmp_path):
    """Set up a client node with mock mesh, wallet, and intent store."""
    wallet_dir = tmp_path / "wallets"
    wallet_dir.mkdir()
    queue_dir = tmp_path / "queue"
    queue_dir.mkdir()

    mesh = MockMeshInterface()
    wm = WalletManager(wallet_dir=wallet_dir)
    wm.create_wallet("testwallet", passphrase="testpass")
    store = IntentStore(queue_dir=queue_dir)
    client = ClientNode(
        mesh=mesh, wallet_manager=wm,
        gateway_node_id="!aabbccdd",
        intent_store=store,
        result_timeout=2.0,
    )
    client.connect()
    return client, mesh, wm, store


class TestQueueIntent:
    def test_queue_mode3(self, deferred_setup):
        client, mesh, wm, store = deferred_setup
        address = wm.get_address("testwallet")
        intent = client.queue_intent(
            mode=3, wallet_name="testwallet",
            recipient="0x" + "ab" * 20,
            amount=0.5, passphrase="testpass",
        )
        assert intent.status == IntentStatus.PENDING
        assert intent.mode == 3
        assert intent.amount == 0.5
        # Verify persisted
        reloaded = store.get(intent.id)
        assert reloaded is not None

    def test_queue_mode1(self, deferred_setup):
        client, mesh, wm, store = deferred_setup
        intent = client.queue_intent(
            mode=1, wallet_name="testwallet",
            recipient="0x" + "cd" * 20,
            amount=0.01, passphrase="testpass",
        )
        assert intent.mode == 1

    def test_queue_validates_wallet_exists(self, deferred_setup):
        client, mesh, wm, store = deferred_setup
        with pytest.raises(FileNotFoundError):
            client.queue_intent(
                mode=3, wallet_name="nonexistent",
                recipient="0x" + "ab" * 20, amount=1.0,
            )

    def test_queue_validates_passphrase(self, deferred_setup):
        client, mesh, wm, store = deferred_setup
        with pytest.raises(Exception):
            client.queue_intent(
                mode=3, wallet_name="testwallet",
                recipient="0x" + "ab" * 20, amount=1.0,
                passphrase="wrongpass",
            )

    def test_queue_no_store_raises(self, tmp_path):
        wallet_dir = tmp_path / "wallets"
        wallet_dir.mkdir()
        mesh = MockMeshInterface()
        wm = WalletManager(wallet_dir=wallet_dir)
        wm.create_wallet("w", passphrase="p")
        client = ClientNode(mesh=mesh, wallet_manager=wm)
        client.connect()
        with pytest.raises(RuntimeError, match="No intent store"):
            client.queue_intent(mode=3, wallet_name="w",
                                recipient="0x" + "ab" * 20, amount=1.0)

    def test_duplicate_rejected(self, deferred_setup):
        client, mesh, wm, store = deferred_setup
        client.queue_intent(
            mode=3, wallet_name="testwallet",
            recipient="0x" + "ab" * 20, amount=0.5,
            passphrase="testpass",
        )
        with pytest.raises(ValueError, match="Duplicate"):
            client.queue_intent(
                mode=3, wallet_name="testwallet",
                recipient="0x" + "ab" * 20, amount=0.5,
                passphrase="testpass",
            )


class TestFlushIntent:
    def test_flush_mode1_sends_tx_chunks(self, deferred_setup):
        """Mode 1 flush: fetches nonce/gas from gateway, signs, sends TX_CHUNKs."""
        client, mesh, wm, store = deferred_setup
        intent = client.queue_intent(
            mode=1, wallet_name="testwallet",
            recipient="0x" + "ab" * 20,
            amount=0.001, passphrase="testpass",
        )

        # Background thread: respond to NONCE_REQ, GAS_REQ, then inject TX_RESULT
        def gateway_responder():
            # Wait for nonce request
            deadline = time.time() + 5
            while time.time() < deadline:
                nonce_reqs = mesh.get_sent_of_type(MsgType.NONCE_REQ)
                if nonce_reqs:
                    hdr, _ = nonce_reqs[0]
                    resp = encode_nonce_resp(42)
                    msg = pack_message(MsgType.NONCE_RESP, hdr.msg_id, 0, 1, resp)
                    mesh.inject_message(msg, "!aabbccdd")
                    break
                time.sleep(0.05)

            # Wait for gas request
            deadline = time.time() + 5
            while time.time() < deadline:
                gas_reqs = mesh.get_sent_of_type(MsgType.GAS_REQ)
                if gas_reqs:
                    hdr, _ = gas_reqs[0]
                    resp = encode_gas_resp(1000000000, 84532)
                    msg = pack_message(MsgType.GAS_RESP, hdr.msg_id, 0, 1, resp)
                    mesh.inject_message(msg, "!aabbccdd")
                    break
                time.sleep(0.05)

            # Wait for TX_CHUNK and inject TX_RESULT
            deadline = time.time() + 5
            while time.time() < deadline:
                tx_chunks = mesh.get_sent_of_type(MsgType.TX_CHUNK)
                if tx_chunks:
                    hdr, _ = tx_chunks[0]
                    # ACK the chunks
                    for chunk_hdr, _ in tx_chunks:
                        ack_payload = encode_ack(chunk_hdr.msg_id, chunk_hdr.chunk_num)
                        ack_msg = pack_message(MsgType.ACK, 900, 0, 1, ack_payload)
                        mesh.inject_message(ack_msg, "!aabbccdd")
                    # Send TX_RESULT
                    result_payload = encode_tx_result(hdr.msg_id, True, b"0xmode1hash")
                    result_msg = pack_message(MsgType.TX_RESULT, 901, 0, 1, result_payload)
                    mesh.inject_message(result_msg, "!aabbccdd")
                    return
                time.sleep(0.05)

        thread = threading.Thread(target=gateway_responder, daemon=True)
        thread.start()

        result = client.flush_intent(intent, "testpass")
        thread.join(timeout=10)

        # Verify TX_CHUNKs were sent
        tx_chunks = mesh.get_sent_of_type(MsgType.TX_CHUNK)
        assert len(tx_chunks) >= 1

        # Verify intent is marked as sent
        updated = store.get(intent.id)
        assert updated.status == IntentStatus.SENT

    def test_flush_mode3_sends_tx_request(self, deferred_setup):
        client, mesh, wm, store = deferred_setup
        intent = client.queue_intent(
            mode=3, wallet_name="testwallet",
            recipient="0x" + "ab" * 20,
            amount=0.5, passphrase="testpass",
        )
        before = time.time()

        # Flush the intent — inject a TX_RESULT to complete it
        def inject_result():
            time.sleep(0.3)
            # Find the TX_REQUEST in sent messages and get its msg_id
            for msg in mesh.sent_messages:
                from basemesh.protocol import unpack_message
                try:
                    hdr, payload = unpack_message(msg["data"])
                    if hdr.msg_type == MsgType.TX_REQUEST:
                        result_payload = encode_tx_result(hdr.msg_id, True, b"0xdeadbeef")
                        result_msg = pack_message(MsgType.TX_RESULT, 999, 0, 1, result_payload)
                        mesh.inject_message(result_msg, "!aabbccdd")
                        return
                except Exception:
                    pass

        thread = threading.Thread(target=inject_result, daemon=True)
        thread.start()

        result = client.flush_intent(intent, "testpass")
        thread.join(timeout=5)

        # Verify TX_REQUEST was sent
        tx_requests = mesh.get_sent_of_type(MsgType.TX_REQUEST)
        assert len(tx_requests) >= 1

        # Verify the timestamp is fresh (not from intent creation time)
        hdr, payload = tx_requests[0]
        req = decode_tx_request(payload)
        after = time.time()
        assert req["timestamp"] >= int(before)
        assert req["timestamp"] <= int(after) + 1

        # Verify intent is marked as sent
        updated = store.get(intent.id)
        assert updated.status == IntentStatus.SENT

    def test_flush_timeout_keeps_pending(self, deferred_setup):
        """If flush times out (no TX_RESULT), intent stays pending."""
        client, mesh, wm, store = deferred_setup
        intent = client.queue_intent(
            mode=3, wallet_name="testwallet",
            recipient="0x" + "ab" * 20,
            amount=0.5, passphrase="testpass",
        )
        result = client.flush_intent(intent, "testpass")
        # No TX_RESULT injected, so result should be None or error
        updated = store.get(intent.id)
        # Should still be pending (or failed if max_attempts reached)
        assert updated.status in (IntentStatus.PENDING, IntentStatus.FAILED)


class TestFlushAllPending:
    def test_flush_all_with_passphrase_map(self, deferred_setup):
        client, mesh, wm, store = deferred_setup
        intent = client.queue_intent(
            mode=3, wallet_name="testwallet",
            recipient="0x" + "ab" * 20,
            amount=0.5,
        )

        # Inject TX_RESULT for any TX_REQUEST that gets sent
        def inject_results():
            time.sleep(0.3)
            for msg in mesh.sent_messages:
                from basemesh.protocol import unpack_message
                try:
                    hdr, payload = unpack_message(msg["data"])
                    if hdr.msg_type == MsgType.TX_REQUEST:
                        result_payload = encode_tx_result(hdr.msg_id, True, b"0xabc")
                        result_msg = pack_message(MsgType.TX_RESULT, 999, 0, 1, result_payload)
                        mesh.inject_message(result_msg, "!aabbccdd")
                        return
                except Exception:
                    pass

        thread = threading.Thread(target=inject_results, daemon=True)
        thread.start()

        results = client.flush_all_pending(
            passphrase_map={"testwallet": "testpass"},
        )
        thread.join(timeout=5)
        assert len(results) >= 1

    def test_flush_skips_no_passphrase(self, deferred_setup):
        client, mesh, wm, store = deferred_setup
        intent = client.queue_intent(
            mode=3, wallet_name="testwallet",
            recipient="0x" + "ab" * 20,
            amount=0.5,
        )
        # Don't provide passphrase
        results = client.flush_all_pending()
        assert len(results) == 0
        # Intent should still be pending with error about passphrase
        updated = store.get(intent.id)
        assert updated.status == IntentStatus.PENDING
        assert "passphrase" in updated.last_error.lower()

    def test_flush_wallet_filter(self, tmp_path):
        """flush_all_pending with wallet_filter only flushes matching intents."""
        wallet_dir = tmp_path / "wallets"
        wallet_dir.mkdir()
        queue_dir = tmp_path / "queue"
        queue_dir.mkdir()

        mesh = MockMeshInterface()
        wm = WalletManager(wallet_dir=wallet_dir)
        wm.create_wallet("alice", passphrase="ap")
        wm.create_wallet("bob", passphrase="bp")
        store = IntentStore(queue_dir=queue_dir)
        client = ClientNode(
            mesh=mesh, wallet_manager=wm,
            gateway_node_id="!aabbccdd",
            intent_store=store,
            result_timeout=1.0,
        )
        client.connect()

        store.add(mode=3, wallet_name="alice",
                  recipient="0x" + "ab" * 20, amount=0.5)
        store.add(mode=3, wallet_name="bob",
                  recipient="0x" + "cd" * 20, amount=1.0)

        # Only flush alice's intents (with wrong passphrase to keep it simple)
        # Bob's intent should not be touched
        results = client.flush_all_pending(
            passphrase_map={"alice": "ap"},
            wallet_filter="alice",
        )

        # Bob's intent should still be pending with no error
        bob_intents = [i for i in store.pending_intents()
                       if i.wallet_name == "bob"]
        assert len(bob_intents) == 1
        assert bob_intents[0].last_error is None

    def test_flush_no_gateway(self, tmp_path):
        wallet_dir = tmp_path / "wallets"
        wallet_dir.mkdir()
        queue_dir = tmp_path / "queue"
        queue_dir.mkdir()
        mesh = MockMeshInterface()
        wm = WalletManager(wallet_dir=wallet_dir)
        wm.create_wallet("w", passphrase="p")
        store = IntentStore(queue_dir=queue_dir)
        client = ClientNode(
            mesh=mesh, wallet_manager=wm,
            intent_store=store,
        )
        client.connect()
        store.add(mode=3, wallet_name="w",
                  recipient="0x" + "ab" * 20, amount=1.0)
        results = client.flush_all_pending(passphrase_map={"w": "p"})
        assert len(results) == 0


class TestFailedAfterMaxAttempts:
    def test_reaches_max(self, deferred_setup):
        client, mesh, wm, store = deferred_setup
        intent = client.queue_intent(
            mode=3, wallet_name="testwallet",
            recipient="0x" + "ab" * 20,
            amount=0.5, passphrase="testpass",
        )
        # Flush repeatedly with no result — each time increments attempts
        for _ in range(intent.max_attempts):
            refreshed = store.get(intent.id)
            if refreshed.status == IntentStatus.FAILED:
                break
            client.flush_intent(refreshed, "testpass")

        final = store.get(intent.id)
        assert final.status == IntentStatus.FAILED


class TestAutoFlushOnBeacon:
    def test_beacon_triggers_flush(self, tmp_path):
        wallet_dir = tmp_path / "wallets"
        wallet_dir.mkdir()
        queue_dir = tmp_path / "queue"
        queue_dir.mkdir()

        mesh = MockMeshInterface()
        wm = WalletManager(wallet_dir=wallet_dir)
        wm.create_wallet("aw", passphrase="ap")
        store = IntentStore(queue_dir=queue_dir)
        client = ClientNode(
            mesh=mesh, wallet_manager=wm,
            intent_store=store,
            auto_flush=True,
            result_timeout=1.0,
        )
        client.connect()
        client.cache_passphrase("aw", "ap")

        # Queue an intent
        store.add(mode=3, wallet_name="aw",
                  recipient="0x" + "ab" * 20, amount=0.5)

        # Inject a beacon to trigger auto-flush
        payload = encode_gateway_beacon(1, BEACON_CAP_RELAY, uptime_seconds=60)
        msg = pack_message(MsgType.GATEWAY_BEACON, 500, 0, 1, payload)
        mesh.inject_message(msg, "!gateway01")

        # Wait for auto-flush thread to start and send the TX_REQUEST
        time.sleep(1.5)

        # Should have sent at least one TX_REQUEST
        tx_requests = mesh.get_sent_of_type(MsgType.TX_REQUEST)
        assert len(tx_requests) >= 1

    def test_no_flush_without_passphrase(self, tmp_path):
        wallet_dir = tmp_path / "wallets"
        wallet_dir.mkdir()
        queue_dir = tmp_path / "queue"
        queue_dir.mkdir()

        mesh = MockMeshInterface()
        wm = WalletManager(wallet_dir=wallet_dir)
        wm.create_wallet("aw", passphrase="ap")
        store = IntentStore(queue_dir=queue_dir)
        client = ClientNode(
            mesh=mesh, wallet_manager=wm,
            intent_store=store,
            auto_flush=True,
            result_timeout=1.0,
        )
        client.connect()
        # Don't cache passphrase

        store.add(mode=3, wallet_name="aw",
                  recipient="0x" + "ab" * 20, amount=0.5)

        # Inject beacon
        payload = encode_gateway_beacon(1, BEACON_CAP_RELAY, uptime_seconds=60)
        msg = pack_message(MsgType.GATEWAY_BEACON, 500, 0, 1, payload)
        mesh.inject_message(msg, "!gateway01")

        time.sleep(1.0)

        # No TX_REQUEST should have been sent (passphrase missing)
        tx_requests = mesh.get_sent_of_type(MsgType.TX_REQUEST)
        assert len(tx_requests) == 0

        # Intent should still be pending
        pending = store.pending_intents()
        assert len(pending) == 1
