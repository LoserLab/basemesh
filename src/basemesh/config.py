"""YAML configuration loading for BaseMesh."""

from __future__ import annotations
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from basemesh.constants import (
    DEFAULT_RPC_URL,
    BASE_MAINNET_RPC_URL,
    BASE_SEPOLIA_RPC_URL,
    BASE_MAINNET_CHAIN_ID,
    BASE_SEPOLIA_CHAIN_ID,
)

logger = logging.getLogger(__name__)

RPC_URLS = {
    "base-mainnet": BASE_MAINNET_RPC_URL,
    "base-sepolia": BASE_SEPOLIA_RPC_URL,
}

CHAIN_IDS = {
    "base-mainnet": BASE_MAINNET_CHAIN_ID,
    "base-sepolia": BASE_SEPOLIA_CHAIN_ID,
}


@dataclass
class MeshConfig:
    connection_type: str = "serial"
    device_path: Optional[str] = None
    hostname: Optional[str] = None


@dataclass
class BaseChainConfig:
    network: str = "base-sepolia"
    rpc_url: Optional[str] = None
    chain_id: Optional[int] = None


@dataclass
class GatewayConfig:
    hot_wallet: Optional[str] = None
    allowed_requesters: list[str] = field(default_factory=list)
    max_transfer_eth: float = 0.1
    max_transfer_token_units: int = 0  # 0 = no limit; raw token units for ERC-20
    max_requests_per_minute: float = 10.0
    rate_limit_burst: int = 3
    beacon_interval: int = 60


@dataclass
class BaseMeshConfig:
    mesh: MeshConfig = field(default_factory=MeshConfig)
    base: BaseChainConfig = field(default_factory=BaseChainConfig)
    gateway: GatewayConfig = field(default_factory=GatewayConfig)
    log_level: str = "INFO"


def load_config(path: Path) -> BaseMeshConfig:
    """Load configuration from a YAML file."""
    with open(path) as f:
        raw = yaml.safe_load(f) or {}

    config = BaseMeshConfig()

    if "mesh" in raw:
        m = raw["mesh"]
        config.mesh = MeshConfig(
            connection_type=m.get("connection_type", "serial"),
            device_path=m.get("device_path"),
            hostname=m.get("hostname"),
        )

    if "base" in raw:
        b = raw["base"]
        config.base = BaseChainConfig(
            network=b.get("network", "base-sepolia"),
            rpc_url=b.get("rpc_url"),
            chain_id=b.get("chain_id"),
        )

    if "gateway" in raw:
        g = raw["gateway"]
        config.gateway = GatewayConfig(
            hot_wallet=g.get("hot_wallet"),
            allowed_requesters=g.get("allowed_requesters", []),
            max_transfer_eth=g.get("max_transfer_eth", 0.1),
            max_transfer_token_units=g.get("max_transfer_token_units", 0),
            max_requests_per_minute=g.get("max_requests_per_minute", 10.0),
            rate_limit_burst=g.get("rate_limit_burst", 3),
            beacon_interval=g.get("beacon_interval", 60),
        )

    config.log_level = raw.get("log_level", "INFO")
    return config


def get_rpc_url(config: BaseChainConfig) -> str:
    """Resolve RPC URL from config (custom URL or network name)."""
    if config.rpc_url:
        return config.rpc_url
    return RPC_URLS.get(config.network, BASE_SEPOLIA_RPC_URL)


def get_chain_id(config: BaseChainConfig) -> int:
    """Resolve chain ID from config."""
    if config.chain_id is not None:
        return config.chain_id
    return CHAIN_IDS.get(config.network, BASE_SEPOLIA_CHAIN_ID)
