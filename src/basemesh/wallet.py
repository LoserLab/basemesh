"""Ethereum wallet/keypair management for BaseMesh.

Private keys are stored locally on disk, encrypted with a passphrase.
Keys are NEVER transmitted over the air.
"""

from __future__ import annotations
import json
import logging
import os
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from eth_account import Account
from web3 import Web3

from basemesh.constants import (
    ETH_TRANSFER_GAS_LIMIT,
    ERC20_GAS_LIMIT,
    NATIVE_ETH_ADDRESS,
)

logger = logging.getLogger(__name__)

DEFAULT_WALLET_DIR = Path.home() / ".basemesh" / "wallets"
PBKDF2_ITERATIONS = 480_000
SALT_SIZE = 16
NONCE_SIZE = 12

# Standard ERC-20 ABI for transfer and balanceOf
ERC20_ABI = [
    {
        "constant": False,
        "inputs": [
            {"name": "_to", "type": "address"},
            {"name": "_value", "type": "uint256"},
        ],
        "name": "transfer",
        "outputs": [{"name": "", "type": "bool"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "symbol",
        "outputs": [{"name": "", "type": "string"}],
        "type": "function",
    },
]


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a passphrase using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _encrypt_secret(secret_bytes: bytes, passphrase: str) -> dict:
    """Encrypt secret key bytes with AES-256-GCM."""
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, secret_bytes, None)
    return {
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
    }


def _decrypt_secret(enc_data: dict, passphrase: str) -> bytes:
    """Decrypt secret key bytes from AES-256-GCM."""
    salt = bytes.fromhex(enc_data["salt"])
    nonce = bytes.fromhex(enc_data["nonce"])
    ciphertext = bytes.fromhex(enc_data["ciphertext"])
    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# Enable unaudited HD wallet features in eth-account
Account.enable_unaudited_hdwallet_features()

# Ethereum BIP44 derivation path: m/44'/60'/0'/0/0
ETHEREUM_DERIVATION_PATH = "m/44'/60'/0'/0/0"


class WalletManager:
    """Manages Ethereum accounts stored locally on disk."""

    def __init__(self, wallet_dir: Path = DEFAULT_WALLET_DIR):
        self._wallet_dir = wallet_dir
        self._wallet_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self._wallet_dir, 0o700)

    def _wallet_path(self, name: str) -> Path:
        import re
        if not re.match(r'^[a-zA-Z0-9_\-]+$', name):
            raise ValueError(
                f"Invalid wallet name '{name}': "
                "only alphanumeric characters, hyphens, and underscores are allowed"
            )
        path = (self._wallet_dir / f"{name}.json").resolve()
        if not str(path).startswith(str(self._wallet_dir.resolve())):
            raise ValueError(f"Invalid wallet name '{name}': path traversal detected")
        return path

    def create_wallet(self, name: str, passphrase: str = "") -> str:
        """Generate a new Ethereum account and save to disk.

        Returns the checksummed address.
        """
        path = self._wallet_path(name)
        if path.exists():
            raise FileExistsError(f"Wallet '{name}' already exists")

        acct = Account.create()
        self._save_account(name, acct, passphrase)
        logger.info("Created wallet '%s': %s", name, acct.address)
        return acct.address

    def create_wallet_with_mnemonic(self, name: str,
                                     passphrase: str = "") -> tuple[str, str]:
        """Generate a new wallet backed by a BIP39 mnemonic.

        Returns (address, mnemonic_phrase). The mnemonic is NOT stored --
        display it once and tell the user to write it down.
        """
        path = self._wallet_path(name)
        if path.exists():
            raise FileExistsError(f"Wallet '{name}' already exists")

        acct, mnemonic_phrase = Account.create_with_mnemonic(
            account_path=ETHEREUM_DERIVATION_PATH
        )
        self._save_account(name, acct, passphrase)
        logger.info("Created mnemonic-backed wallet '%s': %s", name, acct.address)
        return acct.address, mnemonic_phrase

    def recover_wallet(self, name: str, mnemonic_phrase: str,
                       passphrase: str = "") -> str:
        """Recover a wallet from a BIP39 mnemonic phrase."""
        path = self._wallet_path(name)
        if path.exists():
            raise FileExistsError(f"Wallet '{name}' already exists")

        acct = Account.from_mnemonic(
            mnemonic_phrase, account_path=ETHEREUM_DERIVATION_PATH
        )
        self._save_account(name, acct, passphrase)
        logger.info("Recovered wallet '%s': %s", name, acct.address)
        return acct.address

    def import_wallet(self, name: str, private_key: str,
                      passphrase: str = "") -> str:
        """Import an existing account from a hex private key."""
        path = self._wallet_path(name)
        if path.exists():
            raise FileExistsError(f"Wallet '{name}' already exists")

        acct = Account.from_key(private_key)
        self._save_account(name, acct, passphrase)
        logger.info("Imported wallet '%s': %s", name, acct.address)
        return acct.address

    def load_private_key(self, name: str, passphrase: str = "") -> str:
        """Load the private key from disk. Returns hex-encoded private key."""
        path = self._wallet_path(name)
        if not path.exists():
            raise FileNotFoundError(f"Wallet '{name}' not found")

        with open(path) as f:
            data = json.load(f)

        if data.get("encrypted"):
            secret_bytes = _decrypt_secret(data["secret"], passphrase)
        else:
            logger.warning(
                "Wallet '%s' is unencrypted. Re-create it with a passphrase.", name
            )
            secret_bytes = bytes.fromhex(data["secret"])

        return "0x" + secret_bytes.hex()

    def load_account(self, name: str, passphrase: str = "") -> Account:
        """Load a full account from disk."""
        private_key = self.load_private_key(name, passphrase=passphrase)
        return Account.from_key(private_key)

    def get_address(self, name: str) -> str:
        """Load only the address (no passphrase needed)."""
        path = self._wallet_path(name)
        if not path.exists():
            raise FileNotFoundError(f"Wallet '{name}' not found")

        with open(path) as f:
            data = json.load(f)

        return data["address"]

    def list_wallets(self) -> list[dict]:
        """List all wallet names and their addresses."""
        wallets = []
        for path in sorted(self._wallet_dir.glob("*.json")):
            with open(path) as f:
                data = json.load(f)
            wallets.append({
                "name": path.stem,
                "address": data["address"],
                "encrypted": data.get("encrypted", False),
            })
        return wallets

    def delete_wallet(self, name: str) -> None:
        """Delete a wallet file."""
        path = self._wallet_path(name)
        if not path.exists():
            raise FileNotFoundError(f"Wallet '{name}' not found")
        path.unlink()
        logger.info("Deleted wallet '%s'", name)

    def _save_account(self, name: str, acct, passphrase: str) -> None:
        """Save an account to disk. Always encrypted -- passphrase is required."""
        if not passphrase:
            raise ValueError(
                "A passphrase is required to protect your private key. "
                "Wallet files are never stored unencrypted."
            )

        # Store the 32-byte private key
        secret_bytes = acct.key
        data = {
            "address": acct.address,
            "encrypted": True,
            "secret": _encrypt_secret(secret_bytes, passphrase),
        }

        path = self._wallet_path(name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)


def create_eth_transfer(private_key: str, to_address: str,
                        amount_wei: int, nonce: int,
                        gas_price: int, chain_id: int) -> bytes:
    """Create, sign, and serialize an ETH transfer transaction.

    Returns raw signed transaction bytes ready for chunking.
    Private key never leaves this function.
    """
    tx = {
        "to": Web3.to_checksum_address(to_address),
        "value": amount_wei,
        "gas": ETH_TRANSFER_GAS_LIMIT,
        "gasPrice": gas_price,
        "nonce": nonce,
        "chainId": chain_id,
    }
    signed = Account.sign_transaction(tx, private_key)
    return bytes(signed.raw_transaction)


def create_erc20_transfer(private_key: str, token_address: str,
                          to_address: str, amount: int,
                          nonce: int, gas_price: int,
                          chain_id: int) -> bytes:
    """Create, sign, and serialize an ERC-20 transfer transaction.

    Returns raw signed transaction bytes ready for chunking.
    Private key never leaves this function.
    """
    w3 = Web3()
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(token_address),
        abi=ERC20_ABI,
    )
    tx_data = contract.functions.transfer(
        Web3.to_checksum_address(to_address), amount
    ).build_transaction({
        "gas": ERC20_GAS_LIMIT,
        "gasPrice": gas_price,
        "nonce": nonce,
        "chainId": chain_id,
    })
    signed = Account.sign_transaction(tx_data, private_key)
    return bytes(signed.raw_transaction)


def address_to_bytes(address: str) -> bytes:
    """Convert a checksummed hex address to 20 raw bytes."""
    return bytes.fromhex(address[2:]) if address.startswith("0x") else bytes.fromhex(address)


def bytes_to_address(addr_bytes: bytes) -> str:
    """Convert 20 raw bytes to a checksummed hex address."""
    return Web3.to_checksum_address("0x" + addr_bytes.hex())
