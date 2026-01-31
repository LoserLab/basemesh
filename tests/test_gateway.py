"""Tests for the BaseMesh gateway node."""

import struct
import time
import pytest
from unittest.mock import MagicMock, patch

from eth_account import Account

from basemesh.constants import MsgType, WEI_PER_ETH, NATIVE_ETH_ADDRESS, ErrorCode, ETH_ADDRESS_SIZE
from basemesh.config import GatewayConfig
from basemesh.protocol import (
    pack_message,
    unpack_message,
    decode_ack,
    decode_balance_resp,
    decode_nonce_resp,
    decode_gas_resp,
    decode_nack,
    decode_tx_result,
    encode_addr_share,
    encode_balance_req,
    encode_nonce_req,
    encode_gas_req,
    encode_tx_request,
)
from basemesh.crypto import sign_payload
from basemesh.wallet import WalletManager, address_to_bytes
from basemesh.gateway import GatewayNode

from mock_mesh import MockMeshInterface


@pytest.fixture
def gateway_setup(tmp_wallet_dir):
    """Set up a gateway with mock mesh and mocked web3."""
    mesh = MockMeshInterface()
    wm = WalletManager(wallet_dir=tmp_wallet_dir)
    wm.create_wallet("hotwallt", passphrase="gwpass")

    config = GatewayConfig(
        hot_wallet="hotwallt",
        allowed_requesters=[],
        max_transfer_eth=1.0,
        max_requests_per_minute=100.0,
        rate_limit_burst=10,
    )

    with patch("basemesh.gateway.Web3") as MockWeb3:
        mock_w3_instance = MagicMock()
        mock_w3_instance.eth.gas_price = 1_000_000_000
        mock_w3_instance.eth.get_transaction_count.return_value = 5
        mock_w3_instance.eth.get_balance.return_value = 10 * WEI_PER_ETH
        mock_w3_instance.eth.send_raw_transaction.return_value = b"\xab" * 32
        MockWeb3.return_value = mock_w3_instance
        MockWeb3.HTTPProvider = MagicMock()
        MockWeb3.to_checksum_address = lambda x: x if x.startswith("0x") else "0x" + x

        gw = GatewayNode(
            mesh=mesh,
            rpc_url="http://localhost:8545",
            chain_id=84532,
            wallet_manager=wm,
            gateway_config=config,
        )
        gw._hot_private_key = wm.load_private_key("hotwallt", passphrase="gwpass")
        gw._hot_address = wm.get_address("hotwallt")
        gw._w3 = mock_w3_instance

        # Register handlers manually (start() would block)
        mesh.connected = True
        mesh.register_handler = gw._mesh.register_handler
        gw._mesh = mesh
        gw._mesh.register_handler(MsgType.TX_CHUNK, gw._handle_tx_chunk)
        gw._mesh.register_handler(MsgType.TX_REQUEST, gw._handle_tx_request)
        gw._mesh.register_handler(MsgType.BALANCE_REQ, gw._handle_balance_req)
        gw._mesh.register_handler(MsgType.NONCE_REQ, gw._handle_nonce_req)
        gw._mesh.register_handler(MsgType.GAS_REQ, gw._handle_gas_req)
        gw._mesh.register_handler(MsgType.ADDR_SHARE, gw._handle_addr_share)

        yield gw, mesh, wm, mock_w3_instance


def _make_signed_tx_request(amount_wei, token_addr=NATIVE_ETH_ADDRESS):
    """Helper to create a signed TX_REQUEST with a current timestamp."""
    acct = Account.create()
    sender_addr = address_to_bytes(acct.address)
    dest_addr = b"\x22" * 20
    ts = int(time.time())

    signed_data = (sender_addr + dest_addr
                   + struct.pack("!Q", amount_wei) + token_addr
                   + struct.pack("!I", ts))
    sig = sign_payload(acct.key.hex(), signed_data)

    payload = encode_tx_request(sender_addr, dest_addr, amount_wei, sig,
                                token_addr=token_addr, timestamp=ts)
    return payload, acct, ts


class TestGatewayAddrShare:
    def test_addr_share_acked(self, gateway_setup):
        gw, mesh, _, _ = gateway_setup
        addr = b"\xab" * 20
        payload = encode_addr_share(addr, label="Remote")
        msg = pack_message(MsgType.ADDR_SHARE, 100, 0, 1, payload)
        mesh.inject_message(msg, "!client01")

        acks = mesh.get_sent_of_type(MsgType.ACK)
        assert len(acks) > 0


class TestGatewayBalance:
    def test_balance_response(self, gateway_setup):
        gw, mesh, _, mock_w3 = gateway_setup
        addr = b"\xab" * 20
        payload = encode_balance_req(addr)
        msg = pack_message(MsgType.BALANCE_REQ, 200, 0, 1, payload)
        mesh.inject_message(msg, "!client01")

        resps = mesh.get_sent_of_type(MsgType.BALANCE_RESP)
        assert len(resps) > 0
        _, resp_payload = resps[0]
        decoded = decode_balance_resp(resp_payload)
        assert decoded["amount"] == 10 * WEI_PER_ETH

    def test_balance_query_failure_sends_nack(self, gateway_setup):
        gw, mesh, _, mock_w3 = gateway_setup
        mock_w3.eth.get_balance.side_effect = Exception("RPC error")

        addr = b"\xab" * 20
        payload = encode_balance_req(addr)
        msg = pack_message(MsgType.BALANCE_REQ, 201, 0, 1, payload)
        mesh.inject_message(msg, "!client01")

        nacks = mesh.get_sent_of_type(MsgType.NACK)
        assert len(nacks) > 0
        _, nack_payload = nacks[0]
        decoded = decode_nack(nack_payload)
        assert decoded["error_code"] == ErrorCode.RPC_ERROR


class TestGatewayNonce:
    def test_nonce_response(self, gateway_setup):
        gw, mesh, _, mock_w3 = gateway_setup
        addr = b"\xab" * 20
        payload = encode_nonce_req(addr)
        msg = pack_message(MsgType.NONCE_REQ, 300, 0, 1, payload)
        mesh.inject_message(msg, "!client01")

        resps = mesh.get_sent_of_type(MsgType.NONCE_RESP)
        assert len(resps) > 0
        _, resp_payload = resps[0]
        decoded = decode_nonce_resp(resp_payload)
        assert decoded["nonce"] == 5


class TestGatewayGas:
    def test_gas_response(self, gateway_setup):
        gw, mesh, _, _ = gateway_setup
        payload = encode_gas_req()
        msg = pack_message(MsgType.GAS_REQ, 400, 0, 1, payload)
        mesh.inject_message(msg, "!client01")

        resps = mesh.get_sent_of_type(MsgType.GAS_RESP)
        assert len(resps) > 0
        _, resp_payload = resps[0]
        decoded = decode_gas_resp(resp_payload)
        assert decoded["gas_price"] == 1_000_000_000
        assert decoded["chain_id"] == 84532


class TestGatewayTxRequest:
    def test_unauthorized_no_hot_wallet(self, gateway_setup):
        gw, mesh, _, _ = gateway_setup
        gw._hot_private_key = None

        payload, _, _ = _make_signed_tx_request(WEI_PER_ETH // 10)
        msg = pack_message(MsgType.TX_REQUEST, 500, 0, 1, payload)
        mesh.inject_message(msg, "!client01")

        nacks = mesh.get_sent_of_type(MsgType.NACK)
        assert len(nacks) > 0

    def test_amount_exceeded(self, gateway_setup):
        gw, mesh, _, _ = gateway_setup

        payload, _, _ = _make_signed_tx_request(2 * WEI_PER_ETH)  # 2 ETH, max is 1 ETH
        msg = pack_message(MsgType.TX_REQUEST, 501, 0, 1, payload)
        mesh.inject_message(msg, "!client01")

        nacks = mesh.get_sent_of_type(MsgType.NACK)
        assert len(nacks) > 0
        _, nack_payload = nacks[0]
        decoded = decode_nack(nack_payload)
        assert decoded["error_code"] == ErrorCode.AMOUNT_EXCEEDED

    def test_expired_timestamp_rejected(self, gateway_setup):
        gw, mesh, _, _ = gateway_setup

        acct = Account.create()
        sender_addr = address_to_bytes(acct.address)
        dest_addr = b"\x22" * 20
        amount_wei = WEI_PER_ETH // 10
        old_ts = int(time.time()) - 600  # 10 minutes ago (beyond 5-min window)

        signed_data = (sender_addr + dest_addr
                       + struct.pack("!Q", amount_wei) + NATIVE_ETH_ADDRESS
                       + struct.pack("!I", old_ts))
        sig = sign_payload(acct.key.hex(), signed_data)

        payload = encode_tx_request(sender_addr, dest_addr, amount_wei, sig,
                                    timestamp=old_ts)
        msg = pack_message(MsgType.TX_REQUEST, 502, 0, 1, payload)
        mesh.inject_message(msg, "!client01")

        nacks = mesh.get_sent_of_type(MsgType.NACK)
        assert len(nacks) > 0
        _, nack_payload = nacks[0]
        decoded = decode_nack(nack_payload)
        assert decoded["error_code"] == ErrorCode.INVALID_TX
        assert "expired" in decoded["error_msg"].lower() or "timestamp" in decoded["error_msg"].lower()

    def test_replay_rejected(self, gateway_setup):
        gw, mesh, _, mock_w3 = gateway_setup

        payload, _, _ = _make_signed_tx_request(WEI_PER_ETH // 10)

        # First request succeeds (gets past validation)
        msg1 = pack_message(MsgType.TX_REQUEST, 503, 0, 1, payload)
        mesh.inject_message(msg1, "!client01")

        # Second identical request should be rejected as replay
        msg2 = pack_message(MsgType.TX_REQUEST, 504, 0, 1, payload)
        mesh.inject_message(msg2, "!client01")

        nacks = mesh.get_sent_of_type(MsgType.NACK)
        replay_nacks = [n for n in nacks
                        if decode_nack(n[1])["error_code"] == ErrorCode.INVALID_TX
                        and "replay" in decode_nack(n[1])["error_msg"].lower()]
        assert len(replay_nacks) >= 1

    def test_insufficient_balance_rejected(self, gateway_setup):
        gw, mesh, _, mock_w3 = gateway_setup
        # Set hot wallet balance very low
        mock_w3.eth.get_balance.return_value = 1000  # tiny balance

        payload, _, _ = _make_signed_tx_request(WEI_PER_ETH // 10)
        msg = pack_message(MsgType.TX_REQUEST, 505, 0, 1, payload)
        mesh.inject_message(msg, "!client01")

        nacks = mesh.get_sent_of_type(MsgType.NACK)
        balance_nacks = [n for n in nacks
                         if decode_nack(n[1])["error_code"] == ErrorCode.INSUFFICIENT_BALANCE]
        assert len(balance_nacks) >= 1


class TestGatewayRateLimit:
    def test_rate_limited(self, gateway_setup):
        gw, mesh, _, _ = gateway_setup
        gw._rate_limiter._burst = 1
        for bucket in gw._rate_limiter._buckets.values():
            bucket.max_tokens = 1

        # First request OK
        addr = b"\xab" * 20
        payload = encode_nonce_req(addr)
        msg1 = pack_message(MsgType.NONCE_REQ, 600, 0, 1, payload)
        mesh.inject_message(msg1, "!spammer")

        # Second should be rate limited
        msg2 = pack_message(MsgType.NONCE_REQ, 601, 0, 1, payload)
        mesh.inject_message(msg2, "!spammer")

        nacks = mesh.get_sent_of_type(MsgType.NACK)
        assert len(nacks) >= 1


class TestGatewayRpcValidation:
    def test_chain_id_mismatch_raises(self, tmp_wallet_dir):
        """start() raises RuntimeError on chain_id mismatch."""
        mesh = MockMeshInterface()
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        config = GatewayConfig()

        with patch("basemesh.gateway.Web3") as MockWeb3:
            mock_w3 = MagicMock()
            mock_w3.eth.chain_id = 1  # mainnet, but we expect 84532
            MockWeb3.return_value = mock_w3
            MockWeb3.HTTPProvider = MagicMock()

            gw = GatewayNode(
                mesh=mesh, rpc_url="http://localhost:8545",
                chain_id=84532, wallet_manager=wm, gateway_config=config,
            )
            gw._mesh = mesh

            with pytest.raises(RuntimeError, match="Chain ID mismatch"):
                with patch.object(mesh, "run"), patch.object(mesh, "connect"):
                    gw.start()

    def test_rpc_unreachable_raises(self, tmp_wallet_dir):
        """start() raises RuntimeError if RPC is unreachable."""
        mesh = MockMeshInterface()
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        config = GatewayConfig()

        with patch("basemesh.gateway.Web3") as MockWeb3:
            mock_w3 = MagicMock()
            type(mock_w3.eth).chain_id = property(
                lambda self: (_ for _ in ()).throw(
                    ConnectionError("Connection refused")
                )
            )
            MockWeb3.return_value = mock_w3
            MockWeb3.HTTPProvider = MagicMock()

            gw = GatewayNode(
                mesh=mesh, rpc_url="http://localhost:8545",
                chain_id=84532, wallet_manager=wm, gateway_config=config,
            )
            gw._mesh = mesh

            with pytest.raises(RuntimeError, match="Failed to connect"):
                with patch.object(mesh, "run"), patch.object(mesh, "connect"):
                    gw.start()

    def test_successful_validation(self, tmp_wallet_dir):
        """start() succeeds when chain_id matches."""
        mesh = MockMeshInterface()
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        config = GatewayConfig()

        with patch("basemesh.gateway.Web3") as MockWeb3:
            mock_w3 = MagicMock()
            mock_w3.eth.chain_id = 84532
            mock_w3.eth.block_number = 1000
            mock_w3.eth.gas_price = 1_000_000_000
            MockWeb3.return_value = mock_w3
            MockWeb3.HTTPProvider = MagicMock()
            MockWeb3.to_checksum_address = lambda x: x if x.startswith("0x") else "0x" + x

            gw = GatewayNode(
                mesh=mesh, rpc_url="http://localhost:8545",
                chain_id=84532, wallet_manager=wm, gateway_config=config,
            )
            gw._mesh = mesh

            # Should not raise
            with patch.object(mesh, "run"), patch.object(mesh, "connect"):
                gw.start()


class TestGatewayErc20Limit:
    def test_erc20_amount_exceeded(self, gateway_setup):
        """ERC-20 transfer exceeding max_transfer_token_units is rejected."""
        gw, mesh, _, mock_w3 = gateway_setup
        gw._config.max_transfer_token_units = 1_000_000  # 1 USDC

        token_addr = b"\x33" * ETH_ADDRESS_SIZE
        payload, _, _ = _make_signed_tx_request(2_000_000, token_addr=token_addr)
        msg = pack_message(MsgType.TX_REQUEST, 700, 0, 1, payload)
        mesh.inject_message(msg, "!client01")

        nacks = mesh.get_sent_of_type(MsgType.NACK)
        amount_nacks = [n for n in nacks
                        if decode_nack(n[1])["error_code"] == ErrorCode.AMOUNT_EXCEEDED]
        assert len(amount_nacks) >= 1

    def test_erc20_within_limit_allowed(self, gateway_setup):
        """ERC-20 transfer within limit is not rejected for amount."""
        gw, mesh, _, mock_w3 = gateway_setup
        gw._config.max_transfer_token_units = 5_000_000  # 5 USDC

        token_addr = b"\x33" * ETH_ADDRESS_SIZE
        payload, _, _ = _make_signed_tx_request(1_000_000, token_addr=token_addr)
        msg = pack_message(MsgType.TX_REQUEST, 701, 0, 1, payload)

        mock_contract = MagicMock()
        mock_contract.functions.balanceOf.return_value.call.return_value = 10_000_000
        mock_w3.eth.contract.return_value = mock_contract

        mesh.inject_message(msg, "!client01")

        nacks = mesh.get_sent_of_type(MsgType.NACK)
        amount_nacks = [n for n in nacks
                        if decode_nack(n[1])["error_code"] == ErrorCode.AMOUNT_EXCEEDED]
        assert len(amount_nacks) == 0

    def test_erc20_no_limit_when_zero(self, gateway_setup):
        """When max_transfer_token_units=0, no ERC-20 limit is enforced."""
        gw, mesh, _, mock_w3 = gateway_setup
        gw._config.max_transfer_token_units = 0  # no limit

        token_addr = b"\x33" * ETH_ADDRESS_SIZE
        payload, _, _ = _make_signed_tx_request(999_999_999, token_addr=token_addr)
        msg = pack_message(MsgType.TX_REQUEST, 702, 0, 1, payload)

        mock_contract = MagicMock()
        mock_contract.functions.balanceOf.return_value.call.return_value = 10**18
        mock_w3.eth.contract.return_value = mock_contract

        mesh.inject_message(msg, "!client01")

        nacks = mesh.get_sent_of_type(MsgType.NACK)
        amount_nacks = [n for n in nacks
                        if decode_nack(n[1])["error_code"] == ErrorCode.AMOUNT_EXCEEDED]
        assert len(amount_nacks) == 0
