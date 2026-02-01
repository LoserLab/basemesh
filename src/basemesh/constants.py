"""Shared constants for the BaseMesh protocol."""

import struct

# Protocol
MAGIC = b"\x42\x4d"  # "BM"
PROTOCOL_VERSION = 1
HEADER_SIZE = 10
HEADER_FORMAT = "!2sBBHBBBB"  # big-endian: magic(2) version(1) type(1) id(2) chunk(1) total(1) len(1) crc(1)

# LoRa payload limits
MAX_LORA_PAYLOAD = 233  # Meshtastic DATA_PAYLOAD_LEN
SAFE_LORA_PAYLOAD = 220  # conservative limit
MAX_CHUNK_DATA = SAFE_LORA_PAYLOAD - HEADER_SIZE  # 210 bytes per chunk

# Timeouts and retries
CHUNK_REASSEMBLY_TIMEOUT = 120  # seconds
ACK_TIMEOUT = 30  # seconds
MAX_RETRIES = 3
RETRY_DELAY = 10  # seconds
INTER_CHUNK_DELAY = 2.0  # seconds between chunks

# Default timeouts (seconds) — configurable via CLI
DEFAULT_DISCOVERY_TIMEOUT = 120.0
DEFAULT_NONCE_TIMEOUT = 60.0
DEFAULT_GAS_TIMEOUT = 60.0
DEFAULT_RESULT_TIMEOUT = 120.0
DEFAULT_BALANCE_TIMEOUT = 60.0

# Store-and-forward
MAX_FLUSH_ATTEMPTS = 3  # Max attempts to send a queued intent before marking failed

# Ethereum / Base
WEI_PER_ETH = 1_000_000_000_000_000_000  # 10^18
ETH_ADDRESS_SIZE = 20
ETH_SIGNATURE_SIZE = 65  # r(32) + s(32) + v(1)

# Chain IDs
BASE_MAINNET_CHAIN_ID = 8453
BASE_SEPOLIA_CHAIN_ID = 84532

# RPC URLs
DEFAULT_RPC_URL = "https://mainnet.base.org"
BASE_MAINNET_RPC_URL = "https://mainnet.base.org"
BASE_SEPOLIA_RPC_URL = "https://sepolia.base.org"

# Zero address (used to indicate native ETH in token_addr fields)
NATIVE_ETH_ADDRESS = b"\x00" * ETH_ADDRESS_SIZE

# Standard ERC-20 transfer gas limit
ERC20_GAS_LIMIT = 100_000
ETH_TRANSFER_GAS_LIMIT = 21_000

# Well-known token addresses on Base
USDC_BASE_MAINNET = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
USDC_BASE_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"

USDC_ADDRESSES = {
    "base-mainnet": USDC_BASE_MAINNET,
    "base-sepolia": USDC_BASE_SEPOLIA,
}
USDC_DECIMALS = 6

BNKR_BASE_MAINNET = "0x22aF33FE49fD1Fa80c7149773dDe5890D3c76F3b"

BNKR_ADDRESSES = {
    "base-mainnet": BNKR_BASE_MAINNET,
}
BNKR_DECIMALS = 18


class MsgType:
    """BaseMesh message types (1 byte)."""

    TX_CHUNK = 0x01      # Chunk of a serialized signed transaction
    TX_REQUEST = 0x02    # Request gateway to create & send a transfer
    ADDR_SHARE = 0x03    # Share an Ethereum address
    ACK = 0x10           # Acknowledgment
    NACK = 0x11          # Negative acknowledgment
    BALANCE_REQ = 0x20   # Request ETH/token balance
    BALANCE_RESP = 0x21  # Balance response
    NONCE_REQ = 0x22     # Request account nonce
    NONCE_RESP = 0x23    # Nonce response
    GAS_REQ = 0x24       # Request gas price + chain ID
    GAS_RESP = 0x25      # Gas price + chain ID response
    TX_RESULT = 0x30     # Transaction result (tx hash or error)
    GATEWAY_BEACON = 0x40  # Gateway presence beacon


class ErrorCode:
    """Error codes for NACK messages."""

    UNKNOWN = 0x00
    CHECKSUM_FAIL = 0x01
    REASSEMBLY_TIMEOUT = 0x02
    INVALID_TX = 0x03
    RPC_ERROR = 0x04
    UNAUTHORIZED = 0x05
    AMOUNT_EXCEEDED = 0x06
    INSUFFICIENT_BALANCE = 0x07
    RATE_LIMITED = 0x08
    GAS_ESTIMATION_FAILED = 0x09
