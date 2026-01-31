"""HTTP API layer for BaseMesh gateway.

Exposes gateway capabilities as REST endpoints for Mirra Resource
registration.  The API server runs alongside the mesh event loop in a
daemon thread.

Requires optional dependencies: pip install basemesh[http]
"""

from __future__ import annotations

import logging
import time
from decimal import Decimal
from typing import Optional, TYPE_CHECKING

from fastapi import FastAPI, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from basemesh.gateway import GatewayNode

from basemesh.constants import WEI_PER_ETH, PROTOCOL_VERSION

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class TransferRequest(BaseModel):
    """Request body for POST /v1/transfer."""

    to: str = Field(..., description="Recipient Ethereum address (0x...)")
    amount_wei: int = Field(
        ..., gt=0,
        description="Amount in wei (ETH) or raw token units (ERC-20)",
    )
    token_address: Optional[str] = Field(
        None,
        description="ERC-20 token contract address. Omit for native ETH.",
    )


class TransferResponse(BaseModel):
    success: bool
    tx_hash: Optional[str] = None
    error: Optional[str] = None


class BalanceResponse(BaseModel):
    address: str
    balance_wei: int
    token_address: Optional[str] = None


class StatusResponse(BaseModel):
    status: str = "ok"
    uptime_seconds: int
    chain_id: int
    protocol_version: int
    hot_wallet_address: Optional[str] = None
    capabilities: list


class GasResponse(BaseModel):
    gas_price_wei: int
    chain_id: int


class NonceResponse(BaseModel):
    address: str
    nonce: int


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_api(gateway: "GatewayNode") -> FastAPI:
    """Create a FastAPI application wired to the given GatewayNode.

    The gateway's Web3 connection, hot wallet, nonce lock, rate limiter,
    and config are all accessed directly -- no copies, no new connections.
    """
    app = FastAPI(
        title="BaseMesh Gateway API",
        description=(
            "HTTP API for the BaseMesh gateway. Exposes blockchain "
            "operations (balance queries, gas price, transfers) for "
            "Mirra Resource registration."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # --- Auth dependency ---

    async def verify_api_key(x_api_key: str = Header(...)):
        if not gateway._config.api_key:
            raise HTTPException(500, "API key not configured on server")
        if x_api_key != gateway._config.api_key:
            raise HTTPException(401, "Invalid API key")
        return x_api_key

    # --- Rate limit dependency ---

    async def check_rate_limit(x_api_key: str = Depends(verify_api_key)):
        if not gateway._rate_limiter.is_allowed(f"http:{x_api_key[:8]}"):
            raise HTTPException(429, "Rate limited")
        return x_api_key

    # --- Helper ---

    def _checksum(address: str) -> str:
        from web3 import Web3
        try:
            return Web3.to_checksum_address(address)
        except Exception:
            raise HTTPException(400, f"Invalid address: {address}")

    # --- Endpoints ---

    @app.get(
        "/v1/status",
        response_model=StatusResponse,
        dependencies=[Depends(check_rate_limit)],
        summary="Gateway status and capabilities",
    )
    async def get_status():
        caps = ["relay", "balance", "nonce", "gas", "erc20"]
        if gateway._hot_address:
            caps.append("hot_wallet")
        uptime = int(time.time() - gateway._start_time)
        return StatusResponse(
            uptime_seconds=uptime,
            chain_id=gateway._chain_id,
            protocol_version=PROTOCOL_VERSION,
            hot_wallet_address=gateway._hot_address,
            capabilities=caps,
        )

    @app.get(
        "/v1/balance/{address}",
        response_model=BalanceResponse,
        dependencies=[Depends(check_rate_limit)],
        summary="Query ETH or ERC-20 balance",
    )
    async def get_balance(
        address: str,
        token: Optional[str] = Query(
            None, description="ERC-20 token contract address",
        ),
    ):
        checksum_addr = _checksum(address)
        try:
            if token:
                from basemesh.wallet import ERC20_ABI
                checksum_token = _checksum(token)
                contract = gateway._w3.eth.contract(
                    address=checksum_token, abi=ERC20_ABI,
                )
                balance = contract.functions.balanceOf(checksum_addr).call()
                return BalanceResponse(
                    address=checksum_addr,
                    balance_wei=balance,
                    token_address=checksum_token,
                )
            else:
                balance = gateway._w3.eth.get_balance(checksum_addr)
                return BalanceResponse(
                    address=checksum_addr,
                    balance_wei=balance,
                )
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(502, f"RPC error: {e}")

    @app.get(
        "/v1/gas",
        response_model=GasResponse,
        dependencies=[Depends(check_rate_limit)],
        summary="Current gas price and chain ID",
    )
    async def get_gas():
        try:
            gas_price = gateway._w3.eth.gas_price
        except Exception as e:
            raise HTTPException(502, f"RPC error: {e}")
        return GasResponse(
            gas_price_wei=gas_price,
            chain_id=gateway._chain_id,
        )

    @app.get(
        "/v1/nonce/{address}",
        response_model=NonceResponse,
        dependencies=[Depends(check_rate_limit)],
        summary="Account nonce (transaction count)",
    )
    async def get_nonce(address: str):
        checksum_addr = _checksum(address)
        try:
            nonce = gateway._w3.eth.get_transaction_count(checksum_addr)
        except Exception as e:
            raise HTTPException(502, f"RPC error: {e}")
        return NonceResponse(address=checksum_addr, nonce=nonce)

    @app.post(
        "/v1/transfer",
        response_model=TransferResponse,
        dependencies=[Depends(check_rate_limit)],
        summary="Submit a transfer from the gateway hot wallet",
    )
    async def post_transfer(req: TransferRequest):
        if not gateway._hot_private_key:
            raise HTTPException(503, "No hot wallet configured")

        dest = _checksum(req.to)
        is_erc20 = req.token_address is not None

        # --- Enforce transfer limits ---
        if not is_erc20:
            max_wei = int(
                Decimal(str(gateway._config.max_transfer_eth))
                * Decimal(WEI_PER_ETH)
            )
            if req.amount_wei > max_wei:
                raise HTTPException(
                    400,
                    f"Amount exceeds limit of "
                    f"{gateway._config.max_transfer_eth} ETH",
                )
        else:
            max_token = gateway._config.max_transfer_token_units
            if max_token > 0 and req.amount_wei > max_token:
                raise HTTPException(
                    400,
                    f"Amount exceeds token limit of {max_token} units",
                )

        # --- Check hot wallet balance ---
        try:
            from web3 import Web3
            hot_addr = Web3.to_checksum_address(gateway._hot_address)
            if is_erc20:
                from basemesh.wallet import ERC20_ABI
                token_addr = _checksum(req.token_address)
                contract = gateway._w3.eth.contract(
                    address=token_addr, abi=ERC20_ABI,
                )
                hot_balance = contract.functions.balanceOf(hot_addr).call()
                if hot_balance < req.amount_wei:
                    raise HTTPException(
                        400,
                        "Insufficient token balance in hot wallet",
                    )
            else:
                hot_balance = gateway._w3.eth.get_balance(hot_addr)
                gas_estimate = req.amount_wei + (
                    gateway._w3.eth.gas_price * 21_000
                )
                if hot_balance < gas_estimate:
                    raise HTTPException(
                        400,
                        "Insufficient ETH balance in hot wallet "
                        "(including gas)",
                    )
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(502, f"Balance check failed: {e}")

        # --- Build, sign, broadcast ---
        try:
            nonce = gateway._get_next_nonce()
            gas_price = gateway._w3.eth.gas_price
        except Exception as e:
            raise HTTPException(502, f"Failed to fetch tx params: {e}")

        try:
            if is_erc20:
                from basemesh.wallet import create_erc20_transfer
                tx_bytes = create_erc20_transfer(
                    gateway._hot_private_key,
                    req.token_address, dest,
                    req.amount_wei,
                    nonce, gas_price, gateway._chain_id,
                )
            else:
                from basemesh.wallet import create_eth_transfer
                tx_bytes = create_eth_transfer(
                    gateway._hot_private_key,
                    dest, req.amount_wei,
                    nonce, gas_price, gateway._chain_id,
                )
        except Exception as e:
            raise HTTPException(500, f"Transaction creation failed: {e}")

        success, result = gateway._broadcast_to_base(tx_bytes)
        if success:
            logger.info("HTTP transfer success: %s -> %s tx=%s",
                        gateway._hot_address, dest, result)
            return TransferResponse(success=True, tx_hash=result)
        else:
            logger.error("HTTP transfer failed: %s", result)
            return TransferResponse(success=False, error=result)

    return app
