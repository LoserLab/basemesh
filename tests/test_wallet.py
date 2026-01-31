"""Tests for BaseMesh wallet management."""

import json
import os
import pytest
from pathlib import Path

from eth_account import Account

from basemesh.wallet import (
    WalletManager,
    address_to_bytes,
    bytes_to_address,
    create_eth_transfer,
    _encrypt_secret,
    _decrypt_secret,
)


class TestEncryption:
    def test_round_trip(self):
        secret = os.urandom(32)
        enc = _encrypt_secret(secret, "testpass")
        dec = _decrypt_secret(enc, "testpass")
        assert dec == secret

    def test_wrong_passphrase_fails(self):
        secret = os.urandom(32)
        enc = _encrypt_secret(secret, "correct")
        with pytest.raises(Exception):
            _decrypt_secret(enc, "wrong")

    def test_different_salts(self):
        secret = os.urandom(32)
        enc1 = _encrypt_secret(secret, "pass")
        enc2 = _encrypt_secret(secret, "pass")
        assert enc1["salt"] != enc2["salt"]
        assert enc1["ciphertext"] != enc2["ciphertext"]


class TestWalletManager:
    def test_create_wallet(self, tmp_wallet_dir):
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        address = wm.create_wallet("test", passphrase="pass123")
        assert address.startswith("0x")
        assert len(address) == 42

    def test_create_wallet_with_mnemonic(self, tmp_wallet_dir):
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        address, mnemonic = wm.create_wallet_with_mnemonic("test", passphrase="pass123")
        assert address.startswith("0x")
        words = mnemonic.split()
        assert len(words) in (12, 24)

    def test_recover_wallet(self, tmp_wallet_dir):
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        address1, mnemonic = wm.create_wallet_with_mnemonic("orig", passphrase="pass123")
        address2 = wm.recover_wallet("recovered", mnemonic, passphrase="pass456")
        assert address1 == address2

    def test_load_private_key(self, tmp_wallet_dir):
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        wm.create_wallet("test", passphrase="mypass")
        pk = wm.load_private_key("test", passphrase="mypass")
        assert pk.startswith("0x")
        assert len(pk) == 66  # 0x + 64 hex chars

    def test_load_account(self, tmp_wallet_dir):
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        address = wm.create_wallet("test", passphrase="mypass")
        acct = wm.load_account("test", passphrase="mypass")
        assert acct.address == address

    def test_get_address(self, tmp_wallet_dir):
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        address = wm.create_wallet("test", passphrase="pass123")
        loaded = wm.get_address("test")
        assert loaded == address

    def test_list_wallets(self, tmp_wallet_dir):
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        wm.create_wallet("alice", passphrase="pass1")
        wm.create_wallet("bob", passphrase="pass2")
        wallets = wm.list_wallets()
        names = [w["name"] for w in wallets]
        assert "alice" in names
        assert "bob" in names
        assert all(w["encrypted"] for w in wallets)

    def test_delete_wallet(self, tmp_wallet_dir):
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        wm.create_wallet("deleteme", passphrase="pass")
        wm.delete_wallet("deleteme")
        with pytest.raises(FileNotFoundError):
            wm.get_address("deleteme")

    def test_duplicate_wallet_rejected(self, tmp_wallet_dir):
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        wm.create_wallet("dup", passphrase="pass")
        with pytest.raises(FileExistsError):
            wm.create_wallet("dup", passphrase="pass")

    def test_not_found_raises(self, tmp_wallet_dir):
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        with pytest.raises(FileNotFoundError):
            wm.get_address("nonexistent")

    def test_passphrase_required(self, tmp_wallet_dir):
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        with pytest.raises(ValueError, match="passphrase"):
            wm.create_wallet("test", passphrase="")

    def test_import_wallet(self, tmp_wallet_dir):
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        acct = Account.create()
        address = wm.import_wallet("imported", acct.key.hex(), passphrase="pass")
        assert address == acct.address

    def test_file_permissions(self, tmp_wallet_dir):
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        wm.create_wallet("secure", passphrase="pass")
        wallet_path = tmp_wallet_dir / "secure.json"
        mode = os.stat(wallet_path).st_mode & 0o777
        assert mode == 0o600

    def test_wallet_file_structure(self, tmp_wallet_dir):
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        wm.create_wallet("test", passphrase="pass")
        with open(tmp_wallet_dir / "test.json") as f:
            data = json.load(f)
        assert "address" in data
        assert data["address"].startswith("0x")
        assert data["encrypted"] is True
        assert "secret" in data
        assert "salt" in data["secret"]
        assert "nonce" in data["secret"]
        assert "ciphertext" in data["secret"]


class TestAddressConversion:
    def test_round_trip(self):
        addr = "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B"
        addr_bytes = address_to_bytes(addr)
        assert len(addr_bytes) == 20
        recovered = bytes_to_address(addr_bytes)
        # Checksummed comparison
        assert recovered.lower() == addr.lower()

    def test_without_prefix(self):
        addr_bytes = address_to_bytes("Ab5801a7D398351b8bE11C439e05C5B3259aeC9B")
        assert len(addr_bytes) == 20

    def test_bytes_to_address_checksummed(self):
        addr_bytes = b"\xab" * 20
        result = bytes_to_address(addr_bytes)
        assert result.startswith("0x")
        assert len(result) == 42


class TestWalletNameSanitization:
    def test_valid_names(self, tmp_wallet_dir):
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        wm.create_wallet("my-wallet", passphrase="pass")
        wm.create_wallet("wallet_2", passphrase="pass")
        wm.create_wallet("MyWallet123", passphrase="pass")

    def test_path_traversal_rejected(self, tmp_wallet_dir):
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        with pytest.raises(ValueError, match="Invalid wallet name"):
            wm.create_wallet("../evil", passphrase="pass")

    def test_dot_slash_rejected(self, tmp_wallet_dir):
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        with pytest.raises(ValueError, match="Invalid wallet name"):
            wm.create_wallet("./hidden", passphrase="pass")

    def test_special_chars_rejected(self, tmp_wallet_dir):
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        with pytest.raises(ValueError, match="Invalid wallet name"):
            wm.create_wallet("wallet/name", passphrase="pass")
        with pytest.raises(ValueError, match="Invalid wallet name"):
            wm.create_wallet("wallet name", passphrase="pass")

    def test_empty_name_rejected(self, tmp_wallet_dir):
        wm = WalletManager(wallet_dir=tmp_wallet_dir)
        with pytest.raises(ValueError, match="Invalid wallet name"):
            wm.create_wallet("", passphrase="pass")
