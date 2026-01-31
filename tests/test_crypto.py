"""Tests for BaseMesh crypto (secp256k1 signing/verification)."""

import pytest
from eth_account import Account

from basemesh.crypto import sign_payload, verify_payload, compute_payload_hash


@pytest.fixture
def account():
    """Generate a test Ethereum account."""
    return Account.create()


class TestSignVerify:
    def test_sign_returns_65_bytes(self, account):
        sig = sign_payload(account.key.hex(), b"hello")
        assert len(sig) == 65

    def test_round_trip(self, account):
        payload = b"test message for signing"
        sig = sign_payload(account.key.hex(), payload)
        assert verify_payload(account.address, payload, sig)

    def test_wrong_address_fails(self, account):
        other = Account.create()
        payload = b"test message"
        sig = sign_payload(account.key.hex(), payload)
        assert not verify_payload(other.address, payload, sig)

    def test_tampered_payload_fails(self, account):
        payload = b"original message"
        sig = sign_payload(account.key.hex(), payload)
        assert not verify_payload(account.address, b"tampered message", sig)

    def test_tampered_signature_fails(self, account):
        payload = b"test message"
        sig = sign_payload(account.key.hex(), payload)
        tampered_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
        assert not verify_payload(account.address, payload, tampered_sig)

    def test_empty_payload(self, account):
        sig = sign_payload(account.key.hex(), b"")
        assert verify_payload(account.address, b"", sig)

    def test_large_payload(self, account):
        payload = b"\xab" * 1000
        sig = sign_payload(account.key.hex(), payload)
        assert verify_payload(account.address, payload, sig)

    def test_case_insensitive_address(self, account):
        payload = b"test"
        sig = sign_payload(account.key.hex(), payload)
        assert verify_payload(account.address.lower(), payload, sig)
        assert verify_payload(account.address.upper(), payload, sig)


class TestPayloadHash:
    def test_returns_32_bytes(self):
        h = compute_payload_hash(b"hello")
        assert len(h) == 32

    def test_deterministic(self):
        data = b"same input"
        assert compute_payload_hash(data) == compute_payload_hash(data)

    def test_different_data(self):
        assert compute_payload_hash(b"a") != compute_payload_hash(b"b")
