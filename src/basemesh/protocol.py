"""Binary message protocol for BaseMesh.

Defines the 10-byte header format, CRC-8 integrity check, and
payload encoders/decoders for all message types.
"""

from __future__ import annotations
import struct
from dataclasses import dataclass

from basemesh.constants import (
    MAGIC,
    PROTOCOL_VERSION,
    HEADER_SIZE,
    HEADER_FORMAT,
    MAX_CHUNK_DATA,
    ETH_ADDRESS_SIZE,
    ETH_SIGNATURE_SIZE,
    NATIVE_ETH_ADDRESS,
    MsgType,
)


@dataclass
class BaseMeshHeader:
    """10-byte binary header for all BaseMesh messages."""

    msg_type: int
    msg_id: int
    chunk_num: int
    total_chunks: int
    payload_len: int
    checksum: int = 0


def crc8(data: bytes) -> int:
    """CRC-8/MAXIM checksum (polynomial 0x31)."""
    crc = 0x00
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = (crc << 1) ^ 0x31
            else:
                crc <<= 1
            crc &= 0xFF
    return crc


def pack_message(msg_type: int, msg_id: int, chunk_num: int,
                 total_chunks: int, payload: bytes) -> bytes:
    """Pack a complete BaseMesh message (header + payload).

    Computes the CRC-8 checksum over the header (minus checksum byte) + payload.
    """
    if len(payload) > MAX_CHUNK_DATA:
        raise ValueError(f"Payload too large: {len(payload)} > {MAX_CHUNK_DATA}")

    # Pack header without checksum first
    header_no_crc = struct.pack(
        "!2sBBHBBB",
        MAGIC,
        PROTOCOL_VERSION,
        msg_type,
        msg_id,
        chunk_num,
        total_chunks,
        len(payload),
    )
    # CRC over header bytes + payload
    check = crc8(header_no_crc + payload)
    return header_no_crc + struct.pack("!B", check) + payload


def unpack_message(raw: bytes) -> tuple[BaseMeshHeader, bytes]:
    """Unpack raw bytes into (header, payload).

    Validates magic, version, and checksum.
    Raises ValueError on any validation failure.
    """
    if len(raw) < HEADER_SIZE:
        raise ValueError(f"Message too short: {len(raw)} < {HEADER_SIZE}")

    magic = raw[0:2]
    if magic != MAGIC:
        raise ValueError(f"Invalid magic: {magic!r}")

    version = raw[2]
    if version != PROTOCOL_VERSION:
        raise ValueError(f"Unsupported protocol version: {version}")

    msg_type = raw[3]
    msg_id = struct.unpack("!H", raw[4:6])[0]
    chunk_num = raw[6]
    total_chunks = raw[7]
    payload_len = raw[8]
    checksum = raw[9]

    payload = raw[HEADER_SIZE : HEADER_SIZE + payload_len]
    if len(payload) != payload_len:
        raise ValueError(
            f"Payload length mismatch: expected {payload_len}, got {len(payload)}"
        )

    # Verify checksum
    header_no_crc = raw[0:9]
    expected_crc = crc8(header_no_crc + payload)
    if checksum != expected_crc:
        raise ValueError(
            f"Checksum mismatch: got 0x{checksum:02x}, expected 0x{expected_crc:02x}"
        )

    header = BaseMeshHeader(
        msg_type=msg_type,
        msg_id=msg_id,
        chunk_num=chunk_num,
        total_chunks=total_chunks,
        payload_len=payload_len,
        checksum=checksum,
    )
    return header, payload


# --- Payload encoders/decoders ---


def encode_tx_request(sender_addr: bytes, dest_addr: bytes,
                      amount_wei: int, signature: bytes,
                      token_addr: bytes = NATIVE_ETH_ADDRESS,
                      timestamp: int = 0,
                      memo: str = "") -> bytes:
    """Encode TX_REQUEST payload.

    Layout: signature(65) + sender_addr(20) + dest_addr(20) + amount_wei(8)
            + token_addr(20) + timestamp(4) + memo
    token_addr = 20 zero bytes for native ETH.
    timestamp = unix timestamp for replay protection.
    """
    if len(signature) != ETH_SIGNATURE_SIZE:
        raise ValueError(f"Signature must be {ETH_SIGNATURE_SIZE} bytes")
    if len(sender_addr) != ETH_ADDRESS_SIZE:
        raise ValueError(f"Sender address must be {ETH_ADDRESS_SIZE} bytes")
    if len(dest_addr) != ETH_ADDRESS_SIZE:
        raise ValueError(f"Destination address must be {ETH_ADDRESS_SIZE} bytes")
    if len(token_addr) != ETH_ADDRESS_SIZE:
        raise ValueError(f"Token address must be {ETH_ADDRESS_SIZE} bytes")

    payload = (signature + sender_addr + dest_addr
               + struct.pack("!Q", amount_wei) + token_addr
               + struct.pack("!I", timestamp))
    if memo:
        payload += memo.encode("utf-8")
    return payload


def decode_tx_request(payload: bytes) -> dict:
    """Decode TX_REQUEST payload."""
    min_size = ETH_SIGNATURE_SIZE + ETH_ADDRESS_SIZE * 3 + 8 + 4  # 65+20+20+8+20+4 = 137
    if len(payload) < min_size:
        raise ValueError(f"TX_REQUEST too short: {len(payload)} < {min_size}")

    offset = 0
    signature = payload[offset:offset + ETH_SIGNATURE_SIZE]
    offset += ETH_SIGNATURE_SIZE

    sender_addr = payload[offset:offset + ETH_ADDRESS_SIZE]
    offset += ETH_ADDRESS_SIZE

    dest_addr = payload[offset:offset + ETH_ADDRESS_SIZE]
    offset += ETH_ADDRESS_SIZE

    amount_wei = struct.unpack("!Q", payload[offset:offset + 8])[0]
    offset += 8

    token_addr = payload[offset:offset + ETH_ADDRESS_SIZE]
    offset += ETH_ADDRESS_SIZE

    timestamp = struct.unpack("!I", payload[offset:offset + 4])[0]
    offset += 4

    memo = payload[offset:].decode("utf-8") if len(payload) > offset else ""

    return {
        "signature": signature,
        "sender_addr": sender_addr,
        "dest_addr": dest_addr,
        "amount_wei": amount_wei,
        "token_addr": token_addr,
        "timestamp": timestamp,
        "memo": memo,
    }


def encode_addr_share(address: bytes, label: str = "") -> bytes:
    """Encode ADDR_SHARE payload: 20-byte address + optional label."""
    if len(address) != ETH_ADDRESS_SIZE:
        raise ValueError(f"Address must be {ETH_ADDRESS_SIZE} bytes")
    payload = address
    if label:
        payload += label.encode("utf-8")
    return payload


def decode_addr_share(payload: bytes) -> dict:
    """Decode ADDR_SHARE payload."""
    if len(payload) < ETH_ADDRESS_SIZE:
        raise ValueError(f"ADDR_SHARE too short: {len(payload)} < {ETH_ADDRESS_SIZE}")
    address = payload[0:ETH_ADDRESS_SIZE]
    label = payload[ETH_ADDRESS_SIZE:].decode("utf-8") if len(payload) > ETH_ADDRESS_SIZE else ""
    return {"address": address, "label": label}


def encode_ack(acked_msg_id: int, acked_chunk: int = 0xFF,
               status: int = 0) -> bytes:
    """Encode ACK payload: msg_id(2) + chunk(1) + status(1)."""
    return struct.pack("!HBB", acked_msg_id, acked_chunk, status)


def decode_ack(payload: bytes) -> dict:
    """Decode ACK payload."""
    if len(payload) < 4:
        raise ValueError(f"ACK too short: {len(payload)} < 4")
    acked_msg_id, acked_chunk, status = struct.unpack("!HBB", payload[0:4])
    return {
        "acked_msg_id": acked_msg_id,
        "acked_chunk": acked_chunk,
        "status": status,
    }


def encode_nack(nacked_msg_id: int, error_code: int,
                error_msg: str = "") -> bytes:
    """Encode NACK payload: msg_id(2) + error_code(1) + error_msg."""
    payload = struct.pack("!HB", nacked_msg_id, error_code)
    if error_msg:
        payload += error_msg.encode("utf-8")
    return payload


def decode_nack(payload: bytes) -> dict:
    """Decode NACK payload."""
    if len(payload) < 3:
        raise ValueError(f"NACK too short: {len(payload)} < 3")
    nacked_msg_id, error_code = struct.unpack("!HB", payload[0:3])
    error_msg = payload[3:].decode("utf-8") if len(payload) > 3 else ""
    return {
        "nacked_msg_id": nacked_msg_id,
        "error_code": error_code,
        "error_msg": error_msg,
    }


def encode_balance_req(address: bytes,
                       token_addr: bytes = NATIVE_ETH_ADDRESS) -> bytes:
    """Encode BALANCE_REQ payload: address(20) + token_addr(20)."""
    if len(address) != ETH_ADDRESS_SIZE:
        raise ValueError(f"Address must be {ETH_ADDRESS_SIZE} bytes")
    if len(token_addr) != ETH_ADDRESS_SIZE:
        raise ValueError(f"Token address must be {ETH_ADDRESS_SIZE} bytes")
    return address + token_addr


def decode_balance_req(payload: bytes) -> dict:
    """Decode BALANCE_REQ payload."""
    if len(payload) < ETH_ADDRESS_SIZE * 2:
        raise ValueError(f"BALANCE_REQ too short: {len(payload)} < {ETH_ADDRESS_SIZE * 2}")
    address = payload[0:ETH_ADDRESS_SIZE]
    token_addr = payload[ETH_ADDRESS_SIZE:ETH_ADDRESS_SIZE * 2]
    return {"address": address, "token_addr": token_addr}


def encode_balance_resp(address: bytes, amount: int,
                        token_addr: bytes = NATIVE_ETH_ADDRESS) -> bytes:
    """Encode BALANCE_RESP: address(20) + amount(8) + token_addr(20)."""
    if len(address) != ETH_ADDRESS_SIZE:
        raise ValueError(f"Address must be {ETH_ADDRESS_SIZE} bytes")
    if len(token_addr) != ETH_ADDRESS_SIZE:
        raise ValueError(f"Token address must be {ETH_ADDRESS_SIZE} bytes")
    return address + struct.pack("!Q", amount) + token_addr


def decode_balance_resp(payload: bytes) -> dict:
    """Decode BALANCE_RESP payload."""
    min_size = ETH_ADDRESS_SIZE + 8 + ETH_ADDRESS_SIZE  # 48
    if len(payload) < min_size:
        raise ValueError(f"BALANCE_RESP too short: {len(payload)} < {min_size}")
    address = payload[0:ETH_ADDRESS_SIZE]
    amount = struct.unpack("!Q", payload[ETH_ADDRESS_SIZE:ETH_ADDRESS_SIZE + 8])[0]
    token_addr = payload[ETH_ADDRESS_SIZE + 8:ETH_ADDRESS_SIZE * 2 + 8]
    return {"address": address, "amount": amount, "token_addr": token_addr}


def encode_nonce_req(address: bytes) -> bytes:
    """Encode NONCE_REQ payload: 20-byte address."""
    if len(address) != ETH_ADDRESS_SIZE:
        raise ValueError(f"Address must be {ETH_ADDRESS_SIZE} bytes")
    return address


def decode_nonce_req(payload: bytes) -> dict:
    """Decode NONCE_REQ payload."""
    if len(payload) < ETH_ADDRESS_SIZE:
        raise ValueError(f"NONCE_REQ too short: {len(payload)} < {ETH_ADDRESS_SIZE}")
    return {"address": payload[0:ETH_ADDRESS_SIZE]}


def encode_nonce_resp(nonce: int) -> bytes:
    """Encode NONCE_RESP payload: nonce(8)."""
    return struct.pack("!Q", nonce)


def decode_nonce_resp(payload: bytes) -> dict:
    """Decode NONCE_RESP payload."""
    if len(payload) < 8:
        raise ValueError(f"NONCE_RESP too short: {len(payload)} < 8")
    nonce = struct.unpack("!Q", payload[0:8])[0]
    return {"nonce": nonce}


def encode_gas_req() -> bytes:
    """Encode GAS_REQ payload (empty)."""
    return b""


def decode_gas_req(payload: bytes) -> dict:
    """Decode GAS_REQ payload."""
    return {}


def encode_gas_resp(gas_price: int, chain_id: int) -> bytes:
    """Encode GAS_RESP: gas_price(8) + chain_id(4)."""
    return struct.pack("!QI", gas_price, chain_id)


def decode_gas_resp(payload: bytes) -> dict:
    """Decode GAS_RESP payload."""
    if len(payload) < 12:
        raise ValueError(f"GAS_RESP too short: {len(payload)} < 12")
    gas_price, chain_id = struct.unpack("!QI", payload[0:12])
    return {"gas_price": gas_price, "chain_id": chain_id}


# Gateway beacon capability flags
BEACON_CAP_RELAY = 0x01       # Can relay signed transactions (Mode 1)
BEACON_CAP_HOT_WALLET = 0x02  # Has hot wallet for transfers (Mode 3)
BEACON_CAP_BALANCE = 0x04     # Can query balances
BEACON_CAP_NONCE = 0x08       # Can provide account nonce
BEACON_CAP_GAS = 0x10         # Can provide gas price
BEACON_CAP_ERC20 = 0x20       # Supports ERC-20 token transfers


def encode_gateway_beacon(version: int, capabilities: int,
                          hot_wallet_addr: bytes = b"",
                          uptime_seconds: int = 0) -> bytes:
    """Encode GATEWAY_BEACON: version(1) + caps(1) + uptime(4) + addr(0 or 20)."""
    payload = struct.pack("!BBI", version, capabilities, uptime_seconds)
    if hot_wallet_addr:
        if len(hot_wallet_addr) != ETH_ADDRESS_SIZE:
            raise ValueError(f"Hot wallet address must be {ETH_ADDRESS_SIZE} bytes")
        payload += hot_wallet_addr
    return payload


def decode_gateway_beacon(payload: bytes) -> dict:
    """Decode GATEWAY_BEACON payload."""
    if len(payload) < 6:
        raise ValueError(f"GATEWAY_BEACON too short: {len(payload)} < 6")
    version, capabilities, uptime = struct.unpack("!BBI", payload[0:6])
    hot_wallet_addr = payload[6:26] if len(payload) >= 26 else b""
    return {
        "version": version,
        "capabilities": capabilities,
        "uptime_seconds": uptime,
        "hot_wallet_addr": hot_wallet_addr,
    }


def encode_tx_result(orig_msg_id: int, success: bool,
                     data: bytes) -> bytes:
    """Encode TX_RESULT: orig_msg_id(2) + success(1) + tx_hash_or_error."""
    return struct.pack("!HB", orig_msg_id, 1 if success else 0) + data


def decode_tx_result(payload: bytes) -> dict:
    """Decode TX_RESULT payload."""
    if len(payload) < 3:
        raise ValueError(f"TX_RESULT too short: {len(payload)} < 3")
    orig_msg_id, success_byte = struct.unpack("!HB", payload[0:3])
    success = success_byte == 1
    data = payload[3:]
    return {
        "orig_msg_id": orig_msg_id,
        "success": success,
        "data": data,
    }
