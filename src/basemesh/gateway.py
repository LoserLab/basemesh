"""Gateway node logic for BaseMesh.

The internet-connected gateway listens for BaseMesh messages on the mesh,
reassembles chunked transactions, and broadcasts them to Base via RPC.
Supports all three operating modes.
"""

from __future__ import annotations
from decimal import Decimal
import logging
import struct
import threading
import time
from typing import Optional

from web3 import Web3

from basemesh.chunker import ChunkReassembler, chunk_payload, generate_msg_id
from basemesh.config import GatewayConfig
from basemesh.constants import (
    WEI_PER_ETH,
    NATIVE_ETH_ADDRESS,
    PROTOCOL_VERSION,
    MsgType,
    ErrorCode,
)
from basemesh.rate_limiter import RateLimiter
from basemesh.crypto import verify_payload
from basemesh.mesh import MeshInterface
from basemesh.protocol import (
    BEACON_CAP_BALANCE,
    BEACON_CAP_NONCE,
    BEACON_CAP_GAS,
    BEACON_CAP_HOT_WALLET,
    BEACON_CAP_RELAY,
    BEACON_CAP_ERC20,
    BaseMeshHeader,
    decode_balance_req,
    decode_nonce_req,
    decode_gas_req,
    decode_tx_request,
    decode_addr_share,
    encode_ack,
    encode_balance_resp,
    encode_nonce_resp,
    encode_gas_resp,
    encode_gateway_beacon,
    encode_nack,
    encode_tx_result,
    pack_message,
)
from basemesh.wallet import (
    WalletManager,
    ERC20_ABI,
    address_to_bytes,
    bytes_to_address,
)

logger = logging.getLogger(__name__)


class GatewayNode:
    """Internet-connected gateway that bridges mesh <-> Base RPC.

    Supports:
    - Mode 1: Receives pre-signed TX chunks, reassembles, broadcasts to RPC
    - Mode 2: Relays wallet-to-wallet address exchanges
    - Mode 3: Holds a hot wallet, creates TXs on behalf of remote nodes
    """

    def __init__(self, mesh: MeshInterface, rpc_url: str, chain_id: int,
                 wallet_manager: Optional[WalletManager] = None,
                 gateway_config: Optional[GatewayConfig] = None):
        self._mesh = mesh
        self._w3 = Web3(Web3.HTTPProvider(rpc_url))
        self._chain_id = chain_id
        self._reassembler = ChunkReassembler()
        self._wallet_mgr = wallet_manager or WalletManager()
        self._config = gateway_config or GatewayConfig()
        self._known_addresses: dict[str, bytes] = {}  # mesh_id -> eth address bytes
        self._hot_private_key: Optional[str] = None
        self._hot_address: Optional[str] = None
        self._start_time = time.time()
        self._beacon_thread: Optional[threading.Thread] = None
        self._http_thread: Optional[threading.Thread] = None
        self._running = False
        self._nonce_lock = threading.Lock()
        self._local_nonce: Optional[int] = None
        self._seen_requests: dict[bytes, float] = {}  # signature -> expiry time
        self._replay_window = 300  # 5 minutes
        self._rate_limiter = RateLimiter(
            max_per_minute=self._config.max_requests_per_minute,
            burst=self._config.rate_limit_burst,
        )

    def start(self, hot_wallet_passphrase: str = "") -> None:
        """Register handlers and start listening on mesh."""
        # Load hot wallet if configured
        if self._config.hot_wallet:
            try:
                self._hot_private_key = self._wallet_mgr.load_private_key(
                    self._config.hot_wallet, passphrase=hot_wallet_passphrase
                )
                self._hot_address = self._wallet_mgr.get_address(
                    self._config.hot_wallet
                )
                logger.info("Hot wallet loaded: %s", self._hot_address)
            except Exception as e:
                logger.error("Failed to load hot wallet: %s", e)
                raise

        # Validate RPC connection before starting
        logger.info("Validating RPC connection...")
        try:
            rpc_chain_id = self._w3.eth.chain_id
            logger.info("RPC connected. Chain ID: %d", rpc_chain_id)
            if rpc_chain_id != self._chain_id:
                raise RuntimeError(
                    f"Chain ID mismatch: configured {self._chain_id}, "
                    f"RPC returned {rpc_chain_id}. "
                    f"Check your RPC URL and chain_id configuration."
                )
            block_number = self._w3.eth.block_number
            logger.info("Current block number: %d", block_number)
        except RuntimeError:
            raise
        except Exception as e:
            raise RuntimeError(
                f"Failed to connect to RPC endpoint: {e}. "
                f"Ensure the RPC URL is correct and the service is reachable."
            ) from e

        self._mesh.register_handler(MsgType.TX_CHUNK, self._handle_tx_chunk)
        self._mesh.register_handler(MsgType.TX_REQUEST, self._handle_tx_request)
        self._mesh.register_handler(MsgType.BALANCE_REQ, self._handle_balance_req)
        self._mesh.register_handler(MsgType.NONCE_REQ, self._handle_nonce_req)
        self._mesh.register_handler(MsgType.GAS_REQ, self._handle_gas_req)
        self._mesh.register_handler(MsgType.ADDR_SHARE, self._handle_addr_share)
        self._mesh.connect()

        self._running = True
        self._start_beacon_thread()

        if self._config.http_port:
            self._start_http_server()

        logger.info("Gateway node started. Listening for BaseMesh messages...")
        self._mesh.run()

    def _start_beacon_thread(self) -> None:
        """Start the periodic beacon broadcast thread."""
        self._beacon_thread = threading.Thread(
            target=self._beacon_loop, daemon=True
        )
        self._beacon_thread.start()

    def _start_http_server(self) -> None:
        """Start the FastAPI HTTP server in a daemon thread."""
        try:
            import uvicorn
            from basemesh.http_api import create_api
        except ImportError:
            logger.error(
                "HTTP API requires additional dependencies. "
                "Install with: pip install basemesh[http]"
            )
            raise RuntimeError(
                "FastAPI/uvicorn not installed. "
                "Install with: pip install basemesh[http]"
            )

        if not self._config.api_key:
            raise RuntimeError(
                "HTTP API requires an API key. "
                "Set --api-key or api_key in config."
            )

        app = create_api(self)
        port = self._config.http_port

        def _run_server():
            uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")

        self._http_thread = threading.Thread(
            target=_run_server, daemon=True, name="http-api",
        )
        self._http_thread.start()
        logger.info("HTTP API started on port %d", port)

    def _beacon_loop(self) -> None:
        """Periodically broadcast gateway beacon."""
        while self._running:
            self._send_beacon()
            self._rate_limiter.cleanup_stale()
            self._cleanup_seen_requests()
            time.sleep(self._config.beacon_interval)

    def _cleanup_seen_requests(self) -> None:
        """Remove expired entries from the replay deduplication cache."""
        now = time.time()
        expired = [sig for sig, expiry in self._seen_requests.items() if expiry < now]
        for sig in expired:
            del self._seen_requests[sig]

    def _send_beacon(self) -> None:
        """Broadcast a gateway beacon message."""
        caps = (BEACON_CAP_RELAY | BEACON_CAP_BALANCE | BEACON_CAP_NONCE
                | BEACON_CAP_GAS | BEACON_CAP_ERC20)
        hot_wallet_addr = b""
        if self._hot_address:
            caps |= BEACON_CAP_HOT_WALLET
            hot_wallet_addr = address_to_bytes(self._hot_address)

        uptime = int(time.time() - self._start_time)
        payload = encode_gateway_beacon(
            PROTOCOL_VERSION, caps, hot_wallet_addr, uptime,
        )
        msg = pack_message(
            MsgType.GATEWAY_BEACON, generate_msg_id(), 0, 1, payload
        )
        self._mesh.send(msg, want_ack=False)
        logger.debug("Beacon sent (uptime=%ds)", uptime)

    def _check_rate_limit(self, sender_id: str, msg_id: int) -> bool:
        """Check rate limit for sender. Sends NACK if rate-limited."""
        if not self._rate_limiter.is_allowed(sender_id):
            logger.warning("Rate limited: %s", sender_id)
            self._send_nack(
                msg_id, ErrorCode.RATE_LIMITED,
                "Rate limited", sender_id,
            )
            return False
        return True

    def _get_next_nonce(self) -> int:
        """Get the next nonce for the hot wallet, using a local counter to avoid races.

        Thread-safe: uses _nonce_lock to prevent concurrent transactions
        from using the same nonce.
        """
        with self._nonce_lock:
            rpc_nonce = self._w3.eth.get_transaction_count(
                Web3.to_checksum_address(self._hot_address)
            )
            if self._local_nonce is None or rpc_nonce > self._local_nonce:
                self._local_nonce = rpc_nonce
            nonce = self._local_nonce
            self._local_nonce += 1
            return nonce

    def _handle_tx_chunk(self, header: BaseMeshHeader, payload: bytes,
                         sender_id: str) -> None:
        """Handle incoming TX_CHUNK messages (Mode 1).

        Reassemble chunks. When complete, broadcast to Base RPC.
        """
        if not self._check_rate_limit(sender_id, header.msg_id):
            return

        logger.info(
            "TX_CHUNK from %s: msg_id=%d chunk=%d/%d",
            sender_id, header.msg_id, header.chunk_num + 1, header.total_chunks,
        )

        # Send ACK for this chunk
        ack_payload = encode_ack(header.msg_id, header.chunk_num)
        ack_msg = pack_message(
            MsgType.ACK, generate_msg_id(), 0, 1, ack_payload
        )
        self._mesh.send(ack_msg, destination_id=sender_id, want_ack=False)

        # Feed to reassembler
        complete_data = self._reassembler.receive_chunk(
            sender_id, header.msg_id, header.chunk_num, header.total_chunks, payload
        )

        if complete_data is None:
            return

        logger.info(
            "Transaction fully reassembled (%d bytes) from %s",
            len(complete_data), sender_id,
        )

        # Broadcast to Base
        success, result = self._broadcast_to_base(complete_data)
        self._send_tx_result(header.msg_id, success, result, sender_id)

    def _handle_tx_request(self, header: BaseMeshHeader, payload: bytes,
                           sender_id: str) -> None:
        """Handle TX_REQUEST messages (Mode 3).

        Verify sender authorization, create transfer from hot wallet,
        sign and broadcast.
        """
        if not self._check_rate_limit(sender_id, header.msg_id):
            return

        logger.info("TX_REQUEST from %s", sender_id)

        if not self._hot_private_key:
            logger.warning("TX_REQUEST received but no hot wallet configured")
            self._send_nack(
                header.msg_id, ErrorCode.UNAUTHORIZED,
                "No hot wallet configured", sender_id,
            )
            return

        try:
            req = decode_tx_request(payload)
        except ValueError as e:
            logger.error("Invalid TX_REQUEST: %s", e)
            self._send_nack(
                header.msg_id, ErrorCode.INVALID_TX, str(e), sender_id,
            )
            return

        # Verify timestamp freshness (replay protection)
        request_time = req.get("timestamp", 0)
        now = int(time.time())
        if abs(now - request_time) > self._replay_window:
            logger.warning(
                "TX_REQUEST timestamp too far from current time: request=%d now=%d",
                request_time, now,
            )
            self._send_nack(
                header.msg_id, ErrorCode.INVALID_TX,
                "Request expired or timestamp invalid", sender_id,
            )
            return

        # Check for replay (deduplication by signature)
        sig_key = bytes(req["signature"])
        if sig_key in self._seen_requests:
            logger.warning("Duplicate TX_REQUEST detected (replay), ignoring")
            self._send_nack(
                header.msg_id, ErrorCode.INVALID_TX,
                "Duplicate request (replay rejected)", sender_id,
            )
            return

        # Verify secp256k1 signature to prove keypair ownership
        # Signed data includes timestamp for replay protection
        sender_address = bytes_to_address(req["sender_addr"])
        signed_data = (req["sender_addr"] + req["dest_addr"]
                       + struct.pack("!Q", req["amount_wei"]) + req["token_addr"]
                       + struct.pack("!I", request_time))
        if not verify_payload(sender_address, signed_data, req["signature"]):
            logger.warning("Invalid signature on TX_REQUEST from %s", sender_id)
            self._send_nack(
                header.msg_id, ErrorCode.UNAUTHORIZED,
                "Invalid signature", sender_id,
            )
            return

        # Record this signature to prevent replays
        self._seen_requests[sig_key] = time.time() + self._replay_window

        # Authorize by Ethereum address (not mesh ID, which is spoofable)
        if self._config.allowed_requesters:
            if sender_address.lower() not in [a.lower() for a in self._config.allowed_requesters]:
                logger.warning(
                    "Unauthorized TX_REQUEST: address %s not in allowed list",
                    sender_address,
                )
                self._send_nack(
                    header.msg_id, ErrorCode.UNAUTHORIZED,
                    "Not in allowed requesters", sender_id,
                )
                return

        # Check amount limit (only applies to native ETH transfers)
        token_addr = req["token_addr"]
        is_erc20 = token_addr != NATIVE_ETH_ADDRESS

        if not is_erc20:
            max_wei = int(Decimal(str(self._config.max_transfer_eth)) * Decimal(WEI_PER_ETH))
            if req["amount_wei"] > max_wei:
                logger.warning(
                    "TX_REQUEST amount %d exceeds limit %d",
                    req["amount_wei"], max_wei,
                )
                self._send_nack(
                    header.msg_id, ErrorCode.AMOUNT_EXCEEDED,
                    f"Max {self._config.max_transfer_eth} ETH", sender_id,
                )
                return
        else:
            max_token = self._config.max_transfer_token_units
            if max_token > 0 and req["amount_wei"] > max_token:
                logger.warning(
                    "ERC-20 TX_REQUEST amount %d exceeds token limit %d",
                    req["amount_wei"], max_token,
                )
                self._send_nack(
                    header.msg_id, ErrorCode.AMOUNT_EXCEEDED,
                    f"Max {max_token} token units per transfer", sender_id,
                )
                return
            logger.info(
                "ERC-20 transfer request: amount=%d token_limit=%s",
                req["amount_wei"],
                max_token if max_token > 0 else "unlimited",
            )

        dest_address = bytes_to_address(req["dest_addr"])

        # Verify hot wallet has sufficient balance before spending
        try:
            hot_checksum = Web3.to_checksum_address(self._hot_address)
            if is_erc20:
                token_address = bytes_to_address(token_addr)
                contract = self._w3.eth.contract(
                    address=Web3.to_checksum_address(token_address),
                    abi=ERC20_ABI,
                )
                hot_balance = contract.functions.balanceOf(hot_checksum).call()
                if hot_balance < req["amount_wei"]:
                    logger.warning(
                        "Insufficient token balance: have %d, need %d",
                        hot_balance, req["amount_wei"],
                    )
                    self._send_nack(
                        header.msg_id, ErrorCode.INSUFFICIENT_BALANCE,
                        "Insufficient token balance in hot wallet", sender_id,
                    )
                    return
            else:
                hot_balance = self._w3.eth.get_balance(hot_checksum)
                # Need amount + gas cost (estimate gas_price * 21000)
                gas_estimate = req["amount_wei"] + (self._w3.eth.gas_price * 21_000)
                if hot_balance < gas_estimate:
                    logger.warning(
                        "Insufficient ETH balance: have %d, need ~%d (including gas)",
                        hot_balance, gas_estimate,
                    )
                    self._send_nack(
                        header.msg_id, ErrorCode.INSUFFICIENT_BALANCE,
                        "Insufficient ETH balance in hot wallet", sender_id,
                    )
                    return
        except Exception as e:
            logger.error("Failed to check hot wallet balance: %s", e)
            self._send_nack(
                header.msg_id, ErrorCode.RPC_ERROR,
                f"Balance check failed: {e}", sender_id,
            )
            return

        try:
            nonce = self._get_next_nonce()
            gas_price = self._w3.eth.gas_price
        except Exception as e:
            logger.error("Failed to fetch tx params: %s", e)
            self._send_nack(
                header.msg_id, ErrorCode.RPC_ERROR,
                f"TX params fetch failed: {e}", sender_id,
            )
            return

        try:
            if is_erc20:
                from basemesh.wallet import create_erc20_transfer
                if not isinstance(token_address, str):
                    token_address = bytes_to_address(token_addr)
                tx_bytes = create_erc20_transfer(
                    self._hot_private_key, token_address,
                    dest_address, req["amount_wei"],
                    nonce, gas_price, self._chain_id,
                )
            else:
                from basemesh.wallet import create_eth_transfer
                tx_bytes = create_eth_transfer(
                    self._hot_private_key, dest_address,
                    req["amount_wei"], nonce, gas_price, self._chain_id,
                )
        except Exception as e:
            logger.error("Failed to create transaction: %s", e)
            self._send_nack(
                header.msg_id, ErrorCode.RPC_ERROR,
                f"TX creation failed: {e}", sender_id,
            )
            return

        # Broadcast
        success, result = self._broadcast_to_base(tx_bytes)
        self._send_tx_result(header.msg_id, success, result, sender_id)

    def _handle_balance_req(self, header: BaseMeshHeader, payload: bytes,
                            sender_id: str) -> None:
        """Handle BALANCE_REQ messages. Query RPC and respond."""
        if not self._check_rate_limit(sender_id, header.msg_id):
            return

        logger.info("BALANCE_REQ from %s", sender_id)

        try:
            req = decode_balance_req(payload)
        except ValueError as e:
            logger.error("Invalid BALANCE_REQ: %s", e)
            self._send_nack(
                header.msg_id, ErrorCode.INVALID_TX,
                f"Invalid balance request: {e}", sender_id,
            )
            return

        address = bytes_to_address(req["address"])
        token_addr = req["token_addr"]
        is_erc20 = token_addr != NATIVE_ETH_ADDRESS

        try:
            if is_erc20:
                token_address = bytes_to_address(token_addr)
                contract = self._w3.eth.contract(
                    address=Web3.to_checksum_address(token_address),
                    abi=ERC20_ABI,
                )
                amount = contract.functions.balanceOf(
                    Web3.to_checksum_address(address)
                ).call()
            else:
                amount = self._w3.eth.get_balance(
                    Web3.to_checksum_address(address)
                )
        except Exception as e:
            logger.error("Balance query failed: %s", e)
            self._send_nack(
                header.msg_id, ErrorCode.RPC_ERROR,
                f"Balance query failed: {e}", sender_id,
            )
            return

        resp_payload = encode_balance_resp(req["address"], amount, token_addr)
        resp_msg = pack_message(
            MsgType.BALANCE_RESP, generate_msg_id(), 0, 1, resp_payload
        )
        self._mesh.send(resp_msg, destination_id=sender_id)

    def _handle_nonce_req(self, header: BaseMeshHeader, payload: bytes,
                          sender_id: str) -> None:
        """Handle NONCE_REQ messages. Query RPC for account nonce."""
        if not self._check_rate_limit(sender_id, header.msg_id):
            return

        logger.info("NONCE_REQ from %s", sender_id)

        try:
            req = decode_nonce_req(payload)
        except ValueError as e:
            logger.error("Invalid NONCE_REQ: %s", e)
            return

        address = bytes_to_address(req["address"])
        try:
            nonce = self._w3.eth.get_transaction_count(
                Web3.to_checksum_address(address)
            )
        except Exception as e:
            logger.error("Nonce query failed: %s", e)
            self._send_nack(
                header.msg_id, ErrorCode.RPC_ERROR,
                f"Nonce fetch failed: {e}", sender_id,
            )
            return

        resp_payload = encode_nonce_resp(nonce)
        resp_msg = pack_message(
            MsgType.NONCE_RESP, generate_msg_id(), 0, 1, resp_payload
        )
        self._mesh.send(resp_msg, destination_id=sender_id)

    def _handle_gas_req(self, header: BaseMeshHeader, payload: bytes,
                        sender_id: str) -> None:
        """Handle GAS_REQ messages. Query RPC for gas price."""
        if not self._check_rate_limit(sender_id, header.msg_id):
            return

        logger.info("GAS_REQ from %s", sender_id)

        try:
            gas_price = self._w3.eth.gas_price
        except Exception as e:
            logger.error("Gas price query failed: %s", e)
            self._send_nack(
                header.msg_id, ErrorCode.GAS_ESTIMATION_FAILED,
                f"Gas price fetch failed: {e}", sender_id,
            )
            return

        resp_payload = encode_gas_resp(gas_price, self._chain_id)
        resp_msg = pack_message(
            MsgType.GAS_RESP, generate_msg_id(), 0, 1, resp_payload
        )
        self._mesh.send(resp_msg, destination_id=sender_id)

    def _handle_addr_share(self, header: BaseMeshHeader, payload: bytes,
                           sender_id: str) -> None:
        """Handle ADDR_SHARE messages. Store mesh-to-Ethereum address mapping."""
        try:
            data = decode_addr_share(payload)
        except ValueError as e:
            logger.error("Invalid ADDR_SHARE: %s", e)
            return

        self._known_addresses[sender_id] = data["address"]
        address = bytes_to_address(data["address"])
        label = data["label"] or sender_id
        logger.info("Address registered: %s -> %s", label, address)

        # Send ACK
        ack_payload = encode_ack(header.msg_id, 0)
        ack_msg = pack_message(
            MsgType.ACK, generate_msg_id(), 0, 1, ack_payload
        )
        self._mesh.send(ack_msg, destination_id=sender_id, want_ack=False)

    def _broadcast_to_base(self, tx_bytes: bytes) -> tuple[bool, str]:
        """Send raw transaction bytes to Base RPC."""
        try:
            tx_hash = self._w3.eth.send_raw_transaction(tx_bytes)
            tx_hash_hex = tx_hash.hex()
            logger.info("Transaction broadcast success: 0x%s", tx_hash_hex)
            return True, "0x" + tx_hash_hex
        except Exception as e:
            logger.error("Transaction broadcast failed: %s", e)
            return False, str(e)

    def _send_tx_result(self, original_msg_id: int, success: bool,
                        hash_or_error: str, destination_id: str) -> None:
        """Send a TX_RESULT message back to the requesting node."""
        data = hash_or_error.encode("utf-8")
        result_payload = encode_tx_result(original_msg_id, success, data)
        result_msg = pack_message(
            MsgType.TX_RESULT, generate_msg_id(), 0, 1, result_payload
        )
        self._mesh.send(result_msg, destination_id=destination_id)

    def _send_nack(self, original_msg_id: int, error_code: int,
                   error_msg: str, destination_id: str) -> None:
        """Send a NACK message back to the requesting node."""
        nack_payload = encode_nack(original_msg_id, error_code, error_msg)
        nack_msg = pack_message(
            MsgType.NACK, generate_msg_id(), 0, 1, nack_payload
        )
        self._mesh.send(nack_msg, destination_id=destination_id)
