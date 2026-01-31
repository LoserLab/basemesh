"""Tests for the BaseMesh binary protocol."""

import struct
import pytest

from basemesh.constants import (
    MAGIC, PROTOCOL_VERSION, HEADER_SIZE, MAX_CHUNK_DATA,
    ETH_ADDRESS_SIZE, ETH_SIGNATURE_SIZE, NATIVE_ETH_ADDRESS,
    MsgType,
)
from basemesh.protocol import (
    BaseMeshHeader,
    crc8,
    pack_message,
    unpack_message,
    encode_tx_request,
    decode_tx_request,
    encode_addr_share,
    decode_addr_share,
    encode_ack,
    decode_ack,
    encode_nack,
    decode_nack,
    encode_balance_req,
    decode_balance_req,
    encode_balance_resp,
    decode_balance_resp,
    encode_nonce_req,
    decode_nonce_req,
    encode_nonce_resp,
    decode_nonce_resp,
    encode_gas_req,
    decode_gas_req,
    encode_gas_resp,
    decode_gas_resp,
    encode_gateway_beacon,
    decode_gateway_beacon,
    encode_tx_result,
    decode_tx_result,
    BEACON_CAP_RELAY,
    BEACON_CAP_HOT_WALLET,
    BEACON_CAP_ERC20,
)


class TestCRC8:
    def test_empty(self):
        assert crc8(b"") == 0x00

    def test_known_value(self):
        result = crc8(b"\x01\x02\x03")
        assert isinstance(result, int)
        assert 0 <= result <= 255

    def test_deterministic(self):
        data = b"hello basemesh"
        assert crc8(data) == crc8(data)

    def test_different_data(self):
        assert crc8(b"\x01") != crc8(b"\x02")


class TestPackUnpack:
    def test_round_trip_empty_payload(self):
        raw = pack_message(MsgType.ACK, 1234, 0, 1, b"")
        header, payload = unpack_message(raw)
        assert header.msg_type == MsgType.ACK
        assert header.msg_id == 1234
        assert header.chunk_num == 0
        assert header.total_chunks == 1
        assert payload == b""

    def test_round_trip_with_payload(self):
        data = b"test payload data"
        raw = pack_message(MsgType.TX_CHUNK, 5678, 2, 5, data)
        header, payload = unpack_message(raw)
        assert header.msg_type == MsgType.TX_CHUNK
        assert header.msg_id == 5678
        assert header.chunk_num == 2
        assert header.total_chunks == 5
        assert payload == data

    def test_magic_bytes(self):
        raw = pack_message(MsgType.ACK, 1, 0, 1, b"")
        assert raw[0:2] == MAGIC  # "BM"
        assert raw[0] == 0x42  # 'B'
        assert raw[1] == 0x4D  # 'M'

    def test_version(self):
        raw = pack_message(MsgType.ACK, 1, 0, 1, b"")
        assert raw[2] == PROTOCOL_VERSION

    def test_invalid_magic_rejected(self):
        raw = pack_message(MsgType.ACK, 1, 0, 1, b"")
        bad = b"\x00\x00" + raw[2:]
        with pytest.raises(ValueError, match="Invalid magic"):
            unpack_message(bad)

    def test_invalid_version_rejected(self):
        raw = pack_message(MsgType.ACK, 1, 0, 1, b"")
        bad = raw[:2] + b"\xFF" + raw[3:]
        with pytest.raises(ValueError, match="Unsupported protocol version"):
            unpack_message(bad)

    def test_checksum_mismatch_rejected(self):
        raw = pack_message(MsgType.ACK, 1, 0, 1, b"test")
        bad = raw[:-1] + bytes([(raw[-1] ^ 0xFF)])
        with pytest.raises(ValueError, match="Checksum mismatch"):
            unpack_message(bad)

    def test_too_short_rejected(self):
        with pytest.raises(ValueError, match="Message too short"):
            unpack_message(b"\x42\x4d\x01")

    def test_payload_too_large_rejected(self):
        with pytest.raises(ValueError, match="Payload too large"):
            pack_message(MsgType.TX_CHUNK, 1, 0, 1, b"\x00" * (MAX_CHUNK_DATA + 1))

    def test_payload_length_mismatch(self):
        raw = pack_message(MsgType.ACK, 1, 0, 1, b"hello")
        # Truncate the payload
        truncated = raw[:HEADER_SIZE + 2]
        with pytest.raises(ValueError, match="Payload length mismatch"):
            unpack_message(truncated)

    def test_header_size(self):
        raw = pack_message(MsgType.ACK, 1, 0, 1, b"")
        assert len(raw) == HEADER_SIZE


class TestTxRequest:
    def setup_method(self):
        self.sig = b"\xaa" * ETH_SIGNATURE_SIZE
        self.sender = b"\x11" * ETH_ADDRESS_SIZE
        self.dest = b"\x22" * ETH_ADDRESS_SIZE
        self.amount = 1_000_000_000_000_000_000  # 1 ETH in wei
        self.token = b"\x33" * ETH_ADDRESS_SIZE

    def test_round_trip_native_eth(self):
        payload = encode_tx_request(self.sender, self.dest, self.amount, self.sig,
                                    timestamp=1700000000)
        decoded = decode_tx_request(payload)
        assert decoded["signature"] == self.sig
        assert decoded["sender_addr"] == self.sender
        assert decoded["dest_addr"] == self.dest
        assert decoded["amount_wei"] == self.amount
        assert decoded["token_addr"] == NATIVE_ETH_ADDRESS
        assert decoded["timestamp"] == 1700000000
        assert decoded["memo"] == ""

    def test_round_trip_erc20(self):
        payload = encode_tx_request(self.sender, self.dest, self.amount, self.sig,
                                    token_addr=self.token, timestamp=1700000000)
        decoded = decode_tx_request(payload)
        assert decoded["token_addr"] == self.token

    def test_round_trip_with_memo(self):
        payload = encode_tx_request(self.sender, self.dest, self.amount, self.sig,
                                    timestamp=1700000000, memo="payment for coffee")
        decoded = decode_tx_request(payload)
        assert decoded["memo"] == "payment for coffee"

    def test_invalid_signature_size(self):
        with pytest.raises(ValueError, match="Signature"):
            encode_tx_request(self.sender, self.dest, self.amount, b"\xaa" * 64)

    def test_invalid_sender_size(self):
        with pytest.raises(ValueError, match="Sender"):
            encode_tx_request(b"\x11" * 32, self.dest, self.amount, self.sig)

    def test_too_short_payload(self):
        with pytest.raises(ValueError, match="too short"):
            decode_tx_request(b"\x00" * 10)

    def test_payload_size(self):
        payload = encode_tx_request(self.sender, self.dest, self.amount, self.sig)
        # 65 + 20 + 20 + 8 + 20 + 4 = 137 bytes
        assert len(payload) == 137

    def test_timestamp_default_zero(self):
        payload = encode_tx_request(self.sender, self.dest, self.amount, self.sig)
        decoded = decode_tx_request(payload)
        assert decoded["timestamp"] == 0


class TestAddrShare:
    def test_round_trip(self):
        addr = b"\xab" * ETH_ADDRESS_SIZE
        payload = encode_addr_share(addr, label="Node Alpha")
        decoded = decode_addr_share(payload)
        assert decoded["address"] == addr
        assert decoded["label"] == "Node Alpha"

    def test_no_label(self):
        addr = b"\xab" * ETH_ADDRESS_SIZE
        payload = encode_addr_share(addr)
        decoded = decode_addr_share(payload)
        assert decoded["address"] == addr
        assert decoded["label"] == ""

    def test_invalid_address_size(self):
        with pytest.raises(ValueError, match="Address"):
            encode_addr_share(b"\xab" * 32)

    def test_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            decode_addr_share(b"\x00" * 10)

    def test_payload_size_no_label(self):
        payload = encode_addr_share(b"\xab" * ETH_ADDRESS_SIZE)
        assert len(payload) == 20


class TestAck:
    def test_round_trip(self):
        payload = encode_ack(1234, 5, 0)
        decoded = decode_ack(payload)
        assert decoded["acked_msg_id"] == 1234
        assert decoded["acked_chunk"] == 5
        assert decoded["status"] == 0

    def test_default_chunk(self):
        payload = encode_ack(100)
        decoded = decode_ack(payload)
        assert decoded["acked_chunk"] == 0xFF

    def test_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            decode_ack(b"\x00\x01")


class TestNack:
    def test_round_trip(self):
        payload = encode_nack(1234, 0x04, "RPC failed")
        decoded = decode_nack(payload)
        assert decoded["nacked_msg_id"] == 1234
        assert decoded["error_code"] == 0x04
        assert decoded["error_msg"] == "RPC failed"

    def test_no_message(self):
        payload = encode_nack(100, 0x01)
        decoded = decode_nack(payload)
        assert decoded["error_msg"] == ""

    def test_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            decode_nack(b"\x00")


class TestBalanceReq:
    def test_round_trip_native(self):
        addr = b"\xab" * ETH_ADDRESS_SIZE
        payload = encode_balance_req(addr)
        decoded = decode_balance_req(payload)
        assert decoded["address"] == addr
        assert decoded["token_addr"] == NATIVE_ETH_ADDRESS

    def test_round_trip_erc20(self):
        addr = b"\xab" * ETH_ADDRESS_SIZE
        token = b"\xcd" * ETH_ADDRESS_SIZE
        payload = encode_balance_req(addr, token_addr=token)
        decoded = decode_balance_req(payload)
        assert decoded["address"] == addr
        assert decoded["token_addr"] == token

    def test_invalid_address(self):
        with pytest.raises(ValueError):
            encode_balance_req(b"\xab" * 32)

    def test_payload_size(self):
        payload = encode_balance_req(b"\xab" * ETH_ADDRESS_SIZE)
        assert len(payload) == 40  # 20 + 20


class TestBalanceResp:
    def test_round_trip_native(self):
        addr = b"\xab" * ETH_ADDRESS_SIZE
        amount = 5_000_000_000_000_000_000  # 5 ETH
        payload = encode_balance_resp(addr, amount)
        decoded = decode_balance_resp(payload)
        assert decoded["address"] == addr
        assert decoded["amount"] == amount
        assert decoded["token_addr"] == NATIVE_ETH_ADDRESS

    def test_round_trip_erc20(self):
        addr = b"\xab" * ETH_ADDRESS_SIZE
        token = b"\xcd" * ETH_ADDRESS_SIZE
        payload = encode_balance_resp(addr, 1000000, token_addr=token)
        decoded = decode_balance_resp(payload)
        assert decoded["token_addr"] == token
        assert decoded["amount"] == 1000000

    def test_payload_size(self):
        payload = encode_balance_resp(b"\xab" * ETH_ADDRESS_SIZE, 100)
        assert len(payload) == 48  # 20 + 8 + 20


class TestNonceReq:
    def test_round_trip(self):
        addr = b"\xab" * ETH_ADDRESS_SIZE
        payload = encode_nonce_req(addr)
        decoded = decode_nonce_req(payload)
        assert decoded["address"] == addr

    def test_invalid_address(self):
        with pytest.raises(ValueError):
            encode_nonce_req(b"\xab" * 32)

    def test_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            decode_nonce_req(b"\x00" * 10)


class TestNonceResp:
    def test_round_trip(self):
        payload = encode_nonce_resp(42)
        decoded = decode_nonce_resp(payload)
        assert decoded["nonce"] == 42

    def test_large_nonce(self):
        payload = encode_nonce_resp(2**63)
        decoded = decode_nonce_resp(payload)
        assert decoded["nonce"] == 2**63

    def test_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            decode_nonce_resp(b"\x00" * 4)


class TestGasReq:
    def test_encode_empty(self):
        payload = encode_gas_req()
        assert payload == b""

    def test_decode_empty(self):
        decoded = decode_gas_req(b"")
        assert decoded == {}


class TestGasResp:
    def test_round_trip(self):
        payload = encode_gas_resp(1_000_000_000, 8453)  # 1 gwei, Base mainnet
        decoded = decode_gas_resp(payload)
        assert decoded["gas_price"] == 1_000_000_000
        assert decoded["chain_id"] == 8453

    def test_payload_size(self):
        payload = encode_gas_resp(100, 84532)
        assert len(payload) == 12  # 8 + 4

    def test_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            decode_gas_resp(b"\x00" * 8)


class TestGatewayBeacon:
    def test_round_trip_no_wallet(self):
        payload = encode_gateway_beacon(1, BEACON_CAP_RELAY, uptime_seconds=3600)
        decoded = decode_gateway_beacon(payload)
        assert decoded["version"] == 1
        assert decoded["capabilities"] == BEACON_CAP_RELAY
        assert decoded["uptime_seconds"] == 3600
        assert decoded["hot_wallet_addr"] == b""

    def test_round_trip_with_wallet(self):
        addr = b"\xab" * ETH_ADDRESS_SIZE
        caps = BEACON_CAP_RELAY | BEACON_CAP_HOT_WALLET | BEACON_CAP_ERC20
        payload = encode_gateway_beacon(1, caps, hot_wallet_addr=addr, uptime_seconds=120)
        decoded = decode_gateway_beacon(payload)
        assert decoded["hot_wallet_addr"] == addr
        assert decoded["capabilities"] == caps

    def test_invalid_address_size(self):
        with pytest.raises(ValueError, match="Hot wallet"):
            encode_gateway_beacon(1, 0x01, hot_wallet_addr=b"\xab" * 32)

    def test_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            decode_gateway_beacon(b"\x00" * 3)

    def test_min_payload_size(self):
        payload = encode_gateway_beacon(1, 0x01)
        assert len(payload) == 6  # 1 + 1 + 4

    def test_payload_size_with_wallet(self):
        payload = encode_gateway_beacon(1, 0x01, hot_wallet_addr=b"\xab" * ETH_ADDRESS_SIZE)
        assert len(payload) == 26  # 6 + 20


class TestTxResult:
    def test_round_trip_success(self):
        tx_hash = b"0xabcdef1234567890"
        payload = encode_tx_result(1000, True, tx_hash)
        decoded = decode_tx_result(payload)
        assert decoded["orig_msg_id"] == 1000
        assert decoded["success"] is True
        assert decoded["data"] == tx_hash

    def test_round_trip_failure(self):
        error = b"insufficient funds"
        payload = encode_tx_result(2000, False, error)
        decoded = decode_tx_result(payload)
        assert decoded["orig_msg_id"] == 2000
        assert decoded["success"] is False
        assert decoded["data"] == error

    def test_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            decode_tx_result(b"\x00\x01")
