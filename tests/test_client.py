"""Tests for the BaseMesh client node."""

import struct
import threading
import time
import pytest

from eth_account import Account

from basemesh.constants import (
    MsgType, WEI_PER_ETH, NATIVE_ETH_ADDRESS,
    DEFAULT_DISCOVERY_TIMEOUT, DEFAULT_RESULT_TIMEOUT,
)
from basemesh.protocol import (
    pack_message,
    encode_ack,
    encode_balance_resp,
    encode_nonce_resp,
    encode_gas_resp,
    encode_gateway_beacon,
    encode_tx_result,
    encode_addr_share,
    BEACON_CAP_RELAY,
)
from basemesh.wallet import WalletManager, address_to_bytes
from basemesh.client import ClientNode, _to_raw_amount

from mock_mesh import MockMeshInterface


@pytest.fixture
def client_setup(tmp_wallet_dir):
    """Set up a client node with mock mesh and test wallet."""
    mesh = MockMeshInterface()
    wm = WalletManager(wallet_dir=tmp_wallet_dir)
    wm.create_wallet("testwallt", passphrase="testpass")
    client = ClientNode(mesh=mesh, wallet_manager=wm, gateway_node_id="!aabbccdd")
    client.connect()
    return client, mesh, wm


class TestClientConnect:
    def test_connect(self, client_setup):
        client, mesh, _ = client_setup
        assert mesh.connected


class TestClientAddressShare:
    def test_share_sends_message(self, client_setup):
        client, mesh, _ = client_setup
        # share_address blocks for ACK_TIMEOUT * (MAX_RETRIES+1), so run in thread
        thread = threading.Thread(
            target=client.share_address,
            args=("testwallt",),
            kwargs={"label": "Test Node"},
            daemon=True,
        )
        thread.start()
        time.sleep(0.5)
        # Check that a message was sent
        assert len(mesh.sent_messages) > 0
        thread.join(timeout=1)

    def test_received_addresses(self, client_setup):
        client, mesh, wm = client_setup
        # Simulate receiving an address share
        addr = b"\xab" * 20
        payload = encode_addr_share(addr, label="Remote Node")
        msg = pack_message(MsgType.ADDR_SHARE, 100, 0, 1, payload)
        mesh.inject_message(msg, "!11223344")
        addrs = client.get_received_addresses()
        assert "!11223344" in addrs
        assert addrs["!11223344"]["label"] == "Remote Node"


class TestClientBalance:
    def test_check_balance_sends(self, client_setup):
        client, mesh, _ = client_setup
        msg_id = client.check_balance("0xAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAb")
        assert len(mesh.sent_messages) > 0

    def test_balance_response_handled(self, client_setup):
        client, mesh, _ = client_setup
        addr = b"\xab" * 20
        balance_wei = 5 * WEI_PER_ETH
        payload = encode_balance_resp(addr, balance_wei)
        msg = pack_message(MsgType.BALANCE_RESP, 200, 0, 1, payload)
        mesh.inject_message(msg, "!aabbccdd")
        result = client.wait_for_balance(timeout=1)
        assert result is not None
        assert result["amount"] == balance_wei
        assert result["eth"] == 5.0


class TestClientNonce:
    def test_nonce_response_handled(self, client_setup):
        client, mesh, _ = client_setup

        def fetch_in_bg():
            return client.fetch_nonce("0xAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAb")

        thread = threading.Thread(target=fetch_in_bg, daemon=True)
        thread.start()
        time.sleep(0.3)

        # Inject nonce response
        payload = encode_nonce_resp(42)
        msg = pack_message(MsgType.NONCE_RESP, 300, 0, 1, payload)
        mesh.inject_message(msg, "!aabbccdd")
        thread.join(timeout=5)


class TestClientGasInfo:
    def test_gas_response_handled(self, client_setup):
        client, mesh, _ = client_setup

        def fetch_in_bg():
            return client.fetch_gas_info()

        thread = threading.Thread(target=fetch_in_bg, daemon=True)
        thread.start()
        time.sleep(0.3)

        payload = encode_gas_resp(1_000_000_000, 8453)
        msg = pack_message(MsgType.GAS_RESP, 400, 0, 1, payload)
        mesh.inject_message(msg, "!aabbccdd")
        thread.join(timeout=5)


class TestClientGatewayDiscovery:
    def test_beacon_handled(self, client_setup):
        client, mesh, _ = client_setup
        # Reset gateway to test auto-discovery
        client._gateway_id = None

        payload = encode_gateway_beacon(1, BEACON_CAP_RELAY, uptime_seconds=60)
        msg = pack_message(MsgType.GATEWAY_BEACON, 500, 0, 1, payload)
        mesh.inject_message(msg, "!gateway01")
        assert client._gateway_id == "!gateway01"


class TestClientTxResult:
    def test_tx_result_success(self, client_setup):
        client, mesh, _ = client_setup
        tx_hash = b"0x1234abcdef"
        payload = encode_tx_result(999, True, tx_hash)
        msg = pack_message(MsgType.TX_RESULT, 600, 0, 1, payload)

        # Pre-register the msg_id
        client._results = {}
        mesh.inject_message(msg, "!aabbccdd")
        result = client.wait_for_result(999, timeout=1)
        assert result is not None
        assert result["success"] is True

    def test_tx_result_failure(self, client_setup):
        client, mesh, _ = client_setup
        error = b"insufficient funds"
        payload = encode_tx_result(888, False, error)
        msg = pack_message(MsgType.TX_RESULT, 601, 0, 1, payload)
        mesh.inject_message(msg, "!aabbccdd")
        result = client.wait_for_result(888, timeout=1)
        assert result is not None
        assert result["success"] is False


class TestAmountConversion:
    def test_eth_18_decimals(self):
        assert _to_raw_amount(1.0, 18) == 10**18
        assert _to_raw_amount(0.5, 18) == 5 * 10**17

    def test_usdc_6_decimals(self):
        assert _to_raw_amount(10.0, 6) == 10_000_000
        assert _to_raw_amount(1.5, 6) == 1_500_000

    def test_precision_no_float_error(self):
        # 0.1 + 0.2 = 0.30000000000000004 in float
        # Decimal should handle this correctly
        result = _to_raw_amount(0.1, 18)
        assert result == 100_000_000_000_000_000

    def test_zero_amount(self):
        assert _to_raw_amount(0, 18) == 0
        assert _to_raw_amount(0, 6) == 0

    def test_large_amount(self):
        assert _to_raw_amount(1000.0, 18) == 1000 * 10**18


class TestClientTimeouts:
    def test_custom_discovery_timeout(self, tmp_wallet_dir):
        """Custom discovery_timeout causes fast return on no beacon."""
        mesh = MockMeshInterface()
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        wm.create_wallet("tw", passphrase="p")
        client = ClientNode(mesh=mesh, wallet_manager=wm, discovery_timeout=1.0)
        client.connect()
        client._gateway_id = None

        start = time.time()
        result = client.discover_gateway()
        elapsed = time.time() - start
        assert result is None
        assert elapsed < 3.0

    def test_custom_result_timeout(self, tmp_wallet_dir):
        """Custom result_timeout causes fast return on no result."""
        mesh = MockMeshInterface()
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        wm.create_wallet("tw", passphrase="p")
        client = ClientNode(
            mesh=mesh, wallet_manager=wm,
            gateway_node_id="!aabbccdd", result_timeout=1.0,
        )
        client.connect()

        start = time.time()
        result = client.wait_for_result(99999)
        elapsed = time.time() - start
        assert result is None
        assert elapsed < 3.0

    def test_default_timeouts_match_constants(self, tmp_wallet_dir):
        """Default timeouts match the named constants."""
        mesh = MockMeshInterface()
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        wm.create_wallet("tw", passphrase="p")
        client = ClientNode(mesh=mesh, wallet_manager=wm)
        assert client._discovery_timeout == DEFAULT_DISCOVERY_TIMEOUT
        assert client._result_timeout == DEFAULT_RESULT_TIMEOUT

    def test_explicit_timeout_overrides_default(self, tmp_wallet_dir):
        """Explicit timeout parameter overrides constructor default."""
        mesh = MockMeshInterface()
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        wm.create_wallet("tw", passphrase="p")
        client = ClientNode(
            mesh=mesh, wallet_manager=wm,
            gateway_node_id="!aabbccdd", balance_timeout=1.0,
        )
        client.connect()

        start = time.time()
        result = client.wait_for_balance(timeout=0.5)
        elapsed = time.time() - start
        assert result is None
        assert elapsed < 2.0
