"""Tests for BaseMesh CLI: token resolution, flag validation, and wallet commands."""

import json
import os
import pytest
from unittest.mock import patch
from pathlib import Path

import click
from click.testing import CliRunner

from basemesh.cli import resolve_token, cli
from basemesh.wallet import WalletManager
from basemesh.constants import (
    USDC_ADDRESSES,
    USDC_DECIMALS,
    BNKR_ADDRESSES,
    BNKR_DECIMALS,
)


class TestResolveToken:
    """Tests for the resolve_token() helper."""

    def test_native_eth_default(self):
        addr, decimals = resolve_token(None, usdc=False, network="base-mainnet")
        assert addr is None
        assert decimals == 18

    def test_usdc_mainnet(self):
        addr, decimals = resolve_token(None, usdc=True, network="base-mainnet")
        assert addr == USDC_ADDRESSES["base-mainnet"]
        assert decimals == USDC_DECIMALS

    def test_usdc_sepolia(self):
        addr, decimals = resolve_token(None, usdc=True, network="base-sepolia")
        assert addr == USDC_ADDRESSES["base-sepolia"]
        assert decimals == USDC_DECIMALS

    def test_bnkr_mainnet(self):
        addr, decimals = resolve_token(
            None, usdc=False, network="base-mainnet", bnkr=True
        )
        assert addr == BNKR_ADDRESSES["base-mainnet"]
        assert decimals == BNKR_DECIMALS

    def test_bnkr_no_sepolia(self):
        with pytest.raises(click.UsageError, match="No BNKR address configured"):
            resolve_token(None, usdc=False, network="base-sepolia", bnkr=True)

    def test_usdc_unknown_network(self):
        with pytest.raises(click.UsageError, match="No USDC address configured"):
            resolve_token(None, usdc=True, network="unknown-net")

    def test_custom_token_address(self):
        addr, decimals = resolve_token(
            "0xDeadBeef", usdc=False, network="base-mainnet"
        )
        assert addr == "0xDeadBeef"
        assert decimals == 18

    def test_usdc_and_token_conflict(self):
        with pytest.raises(click.UsageError, match="Cannot use"):
            resolve_token("0xDeadBeef", usdc=True, network="base-mainnet")

    def test_bnkr_and_token_conflict(self):
        with pytest.raises(click.UsageError, match="Cannot use"):
            resolve_token(
                "0xDeadBeef", usdc=False, network="base-mainnet", bnkr=True
            )

    def test_usdc_and_bnkr_conflict(self):
        with pytest.raises(click.UsageError, match="Cannot use"):
            resolve_token(None, usdc=True, network="base-mainnet", bnkr=True)

    def test_all_three_conflict(self):
        with pytest.raises(click.UsageError, match="Cannot use"):
            resolve_token(
                "0xDeadBeef", usdc=True, network="base-mainnet", bnkr=True
            )


@pytest.fixture()
def isolated_wallets(tmp_path):
    """Patch WalletManager so all instances use a temp directory."""
    wallet_dir = tmp_path / "wallets"
    wallet_dir.mkdir()
    _original_init = WalletManager.__init__

    def _patched_init(self, wallet_dir_arg=None):
        _original_init(self, wallet_dir=wallet_dir)

    with patch.object(WalletManager, "__init__", _patched_init):
        yield wallet_dir


class TestWalletCLI:
    """Tests for wallet CLI commands using Click's CliRunner."""

    def test_wallet_create(self, isolated_wallets):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["wallet", "create", "--name", "testwallet", "--no-mnemonic"],
            input="testpass\ntestpass\n",
        )
        assert result.exit_code == 0, result.output
        assert "Wallet created: testwallet" in result.output

    def test_wallet_create_duplicate(self, isolated_wallets):
        runner = CliRunner()
        runner.invoke(
            cli,
            ["wallet", "create", "--name", "dup", "--no-mnemonic"],
            input="testpass\ntestpass\n",
        )
        result = runner.invoke(
            cli,
            ["wallet", "create", "--name", "dup", "--no-mnemonic"],
            input="testpass\ntestpass\n",
        )
        assert result.exit_code != 0
        assert "already exists" in result.output

    def test_wallet_list_empty(self, isolated_wallets):
        runner = CliRunner()
        result = runner.invoke(cli, ["wallet", "list"])
        assert result.exit_code == 0
        assert "No wallets found" in result.output

    def test_wallet_list_with_wallet(self, isolated_wallets):
        runner = CliRunner()
        runner.invoke(
            cli,
            ["wallet", "create", "--name", "listedwallet", "--no-mnemonic"],
            input="testpass\ntestpass\n",
        )
        result = runner.invoke(cli, ["wallet", "list"])
        assert result.exit_code == 0
        assert "listedwallet" in result.output

    def test_wallet_delete(self, isolated_wallets):
        runner = CliRunner()
        runner.invoke(
            cli,
            ["wallet", "create", "--name", "todelete", "--no-mnemonic"],
            input="testpass\ntestpass\n",
        )
        result = runner.invoke(
            cli, ["wallet", "delete", "--name", "todelete", "--yes"]
        )
        assert result.exit_code == 0
        assert "deleted" in result.output

    def test_wallet_delete_nonexistent(self, isolated_wallets):
        runner = CliRunner()
        result = runner.invoke(
            cli, ["wallet", "delete", "--name", "ghost", "--yes"]
        )
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_wallet_create_with_mnemonic(self, isolated_wallets):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["wallet", "create", "--name", "mnemonicwallet", "--skip-backup-check"],
            input="testpass\ntestpass\n",
        )
        assert result.exit_code == 0, result.output
        assert "RECOVERY PHRASE" in result.output
        assert "mnemonicwallet" in result.output


class TestSendFlagHelp:
    """Verify --bnkr flag appears in help for all send commands."""

    def test_send_relay_has_bnkr(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["send", "relay", "--help"])
        assert "--bnkr" in result.output
        assert "--usdc" in result.output

    def test_send_request_has_bnkr(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["send", "request", "--help"])
        assert "--bnkr" in result.output

    def test_send_deferred_has_bnkr(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["send", "deferred", "--help"])
        assert "--bnkr" in result.output

    def test_balance_has_bnkr(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["balance", "--help"])
        assert "--bnkr" in result.output
