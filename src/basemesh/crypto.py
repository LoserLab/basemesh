"""Payload signing and verification for BaseMesh message authentication.

Uses secp256k1 ECDSA signatures via eth-account to authenticate protocol
messages (e.g., proving a TX_REQUEST came from a known node).
This is distinct from Ethereum transaction signing.
"""

from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3


def sign_payload(private_key: str, payload: bytes) -> bytes:
    """Sign a protocol payload with an Ethereum private key.

    Returns a 65-byte signature (r + s + v).
    Uses EIP-191 personal sign for standard, stable message signing.
    """
    message = encode_defunct(primitive=payload)
    signed = Account.sign_message(message, private_key)
    return signed.signature


def verify_payload(address: str, payload: bytes, signature: bytes) -> bool:
    """Verify that a payload was signed by the holder of the given address.

    Recovers the signer address from the signature and compares to the
    expected address (case-insensitive checksum comparison).
    """
    try:
        message = encode_defunct(primitive=payload)
        recovered = Account.recover_message(message, signature=signature)
        return recovered.lower() == address.lower()
    except Exception:
        return False


def compute_payload_hash(payload: bytes) -> bytes:
    """Keccak-256 hash of a payload for compact referencing."""
    return Web3.keccak(payload)
