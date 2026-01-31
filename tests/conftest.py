"""Shared pytest fixtures for basemesh tests."""

import sys
from unittest.mock import MagicMock

# Mock meshtastic and its submodules before any basemesh imports need them
for mod_name in ["meshtastic", "meshtastic.serial_interface",
                 "meshtastic.tcp_interface", "pubsub"]:
    if mod_name not in sys.modules:
        sys.modules[mod_name] = MagicMock()

import pytest
from pathlib import Path


@pytest.fixture
def tmp_wallet_dir(tmp_path):
    """Temporary directory for wallet files."""
    d = tmp_path / "wallets"
    d.mkdir()
    return d
