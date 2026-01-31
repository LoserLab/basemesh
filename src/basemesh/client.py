"""Client node logic for BaseMesh.

The offline client node signs transactions locally and sends them
over the Meshtastic mesh to a gateway for broadcasting to Base.
"""

from __future__ import annotations
from decimal import Decimal
import logging
import struct
import threading
import time
from typing import Callable, Optional

from basemesh.chunker import chunk_payload, generate_msg_id
from basemesh.constants import (
    ACK_TIMEOUT,
    WEI_PER_ETH,
    MAX_RETRIES,
    NATIVE_ETH_ADDRESS,
    MsgType,
    RETRY_DELAY,
    DEFAULT_DISCOVERY_TIMEOUT,
    DEFAULT_NONCE_TIMEOUT,
    DEFAULT_GAS_TIMEOUT,
    DEFAULT_RESULT_TIMEOUT,
    DEFAULT_BALANCE_TIMEOUT,
)
from basemesh.crypto import sign_payload
from basemesh.mesh import MeshInterface
from basemesh.protocol import (
    BaseMeshHeader,
    decode_ack,
    decode_addr_share,
    decode_balance_resp,
    decode_nonce_resp,
    decode_gas_resp,
    decode_gateway_beacon,
    decode_tx_result,
    encode_addr_share,
    encode_balance_req,
    encode_nonce_req,
    encode_gas_req,
    encode_tx_request,
    pack_message,
)
from basemesh.wallet import (
    WalletManager,
    create_eth_transfer,
    create_erc20_transfer,
    address_to_bytes,
    bytes_to_address,
)

logger = logging.getLogger(__name__)


def _to_raw_amount(amount: float, decimals: int) -> int:
    """Convert a human-readable amount to raw integer units using Decimal for precision."""
    return int(Decimal(str(amount)) * Decimal(10 ** decimals))


class ClientNode:
    """Offline client node that sends Base transactions over the mesh.

    Supports Mode 1 (relay signed TX), Mode 2 (wallet-to-wallet),
    and Mode 3 (request gateway to send).
    """

    def __init__(self, mesh: MeshInterface,
                 wallet_manager: WalletManager,
                 gateway_node_id: Optional[str] = None,
                 discovery_timeout: float = DEFAULT_DISCOVERY_TIMEOUT,
                 nonce_timeout: float = DEFAULT_NONCE_TIMEOUT,
                 gas_timeout: float = DEFAULT_GAS_TIMEOUT,
                 result_timeout: float = DEFAULT_RESULT_TIMEOUT,
                 balance_timeout: float = DEFAULT_BALANCE_TIMEOUT):
        self._mesh = mesh
        self._wallet_mgr = wallet_manager
        self._gateway_id = gateway_node_id
        self._discovery_timeout = discovery_timeout
        self._nonce_timeout = nonce_timeout
        self._gas_timeout = gas_timeout
        self._result_timeout = result_timeout
        self._balance_timeout = balance_timeout
        self._acked_chunks: dict[int, set[int]] = {}
        self._chunk_lock = threading.Lock()
        self._results: dict[int, dict] = {}
        self._balances: dict[int, dict] = {}
        self._received_addresses: dict[str, dict] = {}
        self._discovered_gateways: dict[str, dict] = {}
        self._nonce: Optional[int] = None
        self._gas_info: Optional[dict] = None
        self._result_cond = threading.Condition()
        self._balance_cond = threading.Condition()
        self._nonce_cond = threading.Condition()
        self._gas_cond = threading.Condition()
        self._gateway_cond = threading.Condition()

    def connect(self) -> None:
        """Connect to mesh and register handlers."""
        self._mesh.register_handler(MsgType.ACK, self._handle_ack)
        self._mesh.register_handler(MsgType.NACK, self._handle_nack)
        self._mesh.register_handler(MsgType.TX_RESULT, self._handle_tx_result)
        self._mesh.register_handler(MsgType.BALANCE_RESP, self._handle_balance_resp)
        self._mesh.register_handler(MsgType.NONCE_RESP, self._handle_nonce_resp)
        self._mesh.register_handler(MsgType.GAS_RESP, self._handle_gas_resp)
        self._mesh.register_handler(MsgType.GATEWAY_BEACON, self._handle_gateway_beacon)
        self._mesh.register_handler(MsgType.ADDR_SHARE, self._handle_addr_share)
        self._mesh.connect()

    def close(self) -> None:
        """Close the mesh connection."""
        self._mesh.close()

    # --- Mode 1: Relay pre-signed transaction ---

    def relay_signed_tx(self, wallet_name: str, recipient: str,
                        amount: float, token_address: Optional[str] = None,
                        token_decimals: int = 18,
                        nonce: Optional[int] = None,
                        gas_price: Optional[int] = None,
                        chain_id: Optional[int] = None,
                        passphrase: str = "",
                        on_result: Optional[Callable] = None) -> int:
        """Create, sign, and relay a transaction over mesh to gateway.

        Args:
            wallet_name: Name of the local wallet.
            recipient: Destination Ethereum address (0x...).
            amount: Human-readable amount (e.g. 0.5 ETH, 10.0 USDC).
            token_address: ERC-20 contract address, or None for native ETH.
            token_decimals: Decimal places for conversion (18 for ETH, 6 for USDC, etc.).
            nonce: Account nonce (fetched from gateway if None).
            gas_price: Gas price in wei (fetched from gateway if None).
            chain_id: Chain ID (fetched from gateway if None).
            passphrase: Wallet encryption passphrase.
            on_result: Optional callback for result.

        Returns the msg_id for tracking.
        The private key NEVER leaves this device.
        """
        private_key = self._wallet_mgr.load_private_key(wallet_name, passphrase=passphrase)
        address = self._wallet_mgr.get_address(wallet_name)

        # Fetch nonce from gateway if not provided
        if nonce is None:
            logger.info("Fetching nonce from gateway...")
            nonce = self.fetch_nonce(address)
            if nonce is None:
                raise TimeoutError("Failed to fetch nonce from gateway")

        # Fetch gas price from gateway if not provided
        if gas_price is None or chain_id is None:
            logger.info("Fetching gas info from gateway...")
            gas_info = self.fetch_gas_info()
            if gas_info is None:
                raise TimeoutError("Failed to fetch gas info from gateway")
            if gas_price is None:
                gas_price = gas_info["gas_price"]
            if chain_id is None:
                chain_id = gas_info["chain_id"]

        # Convert human-readable amount to raw units using correct decimals
        amount_raw = _to_raw_amount(amount, token_decimals)

        if token_address and token_address != "0x" + "00" * 20:
            tx_bytes = create_erc20_transfer(
                private_key, token_address, recipient,
                amount_raw, nonce, gas_price, chain_id,
            )
            logger.info(
                "ERC-20 transaction signed locally (%d bytes): %s -> %s (token: %s)",
                len(tx_bytes), amount, recipient, token_address,
            )
        else:
            tx_bytes = create_eth_transfer(
                private_key, recipient,
                amount_raw, nonce, gas_price, chain_id,
            )
            logger.info(
                "ETH transaction signed locally (%d bytes): %.6f ETH -> %s",
                len(tx_bytes), amount, recipient,
            )

        return self.relay_raw_tx(tx_bytes, on_result=on_result)

    def relay_raw_tx(self, tx_bytes: bytes,
                     on_result: Optional[Callable] = None) -> int:
        """Send an already-serialized signed transaction over mesh.

        Returns the msg_id for tracking.
        """
        msg_id = generate_msg_id()
        chunks = chunk_payload(tx_bytes, MsgType.TX_CHUNK, msg_id=msg_id)
        logger.info(
            "Sending transaction: %d bytes in %d chunks (msg_id=%d)",
            len(tx_bytes), len(chunks), msg_id,
        )

        with self._chunk_lock:
            self._acked_chunks[msg_id] = set()
        thread = threading.Thread(
            target=self._retry_loop, args=(chunks, msg_id), daemon=True
        )
        thread.start()

        return msg_id

    # --- Mode 2: Wallet-to-wallet ---

    def share_address(self, wallet_name: str, label: str = "") -> bool:
        """Broadcast this node's Ethereum address over mesh with ACK retry.

        Returns True if ACK received, False if all retries exhausted.
        """
        address = self._wallet_mgr.get_address(wallet_name)
        addr_bytes = address_to_bytes(address)
        payload = encode_addr_share(addr_bytes, label=label)
        msg_id = generate_msg_id()
        msg = pack_message(MsgType.ADDR_SHARE, msg_id, 0, 1, payload)

        with self._chunk_lock:
            self._acked_chunks[msg_id] = set()
        display_label = label or wallet_name

        for attempt in range(MAX_RETRIES + 1):
            self._mesh.send(msg)
            logger.info("Shared address '%s': %s (attempt %d)", display_label, address, attempt + 1)

            time.sleep(ACK_TIMEOUT)
            with self._chunk_lock:
                if 0 in self._acked_chunks.get(msg_id, set()):
                    logger.info("Address share ACK received for '%s'", display_label)
                    del self._acked_chunks[msg_id]
                    return True

            if attempt < MAX_RETRIES:
                logger.warning("No ACK for address share, retrying...")

        with self._chunk_lock:
            self._acked_chunks.pop(msg_id, None)
        logger.warning("Address share not ACKed after %d retries", MAX_RETRIES)
        return False

    def get_received_addresses(self) -> dict[str, dict]:
        """Return all addresses received from other nodes."""
        return dict(self._received_addresses)

    # --- Gateway discovery ---

    def discover_gateway(self, timeout: Optional[float] = None) -> Optional[str]:
        """Wait for a gateway beacon and auto-set gateway ID.

        Returns the gateway mesh node ID, or None on timeout.
        """
        if timeout is None:
            timeout = self._discovery_timeout
        deadline = time.time() + timeout
        with self._gateway_cond:
            while not self._discovered_gateways:
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None
                self._gateway_cond.wait(timeout=remaining)

            best_id = max(
                self._discovered_gateways,
                key=lambda k: self._discovered_gateways[k]["last_seen"],
            )
            if not self._gateway_id:
                self._gateway_id = best_id
                logger.info("Auto-discovered gateway: %s", best_id)
            return best_id

    def is_gateway_online(self, max_stale_seconds: float = 180) -> bool:
        """Check if the current gateway has sent a recent beacon."""
        if not self._gateway_id:
            return False
        info = self._discovered_gateways.get(self._gateway_id)
        if not info:
            return False
        return (time.time() - info["last_seen"]) < max_stale_seconds

    # --- Mode 3: Request gateway transfer ---

    def request_transfer(self, wallet_name: str, destination: str,
                         amount: float, token_address: Optional[str] = None,
                         token_decimals: int = 18,
                         passphrase: str = "") -> int:
        """Send a signed TX_REQUEST to the gateway.

        The request is signed with the sender's key to prove identity
        (but the gateway's hot wallet pays for the transfer).

        Args:
            wallet_name: Name of the local wallet.
            destination: Destination Ethereum address (0x...).
            amount: Human-readable amount (e.g. 0.5 ETH, 10.0 USDC).
            token_address: ERC-20 contract address, or None for native ETH.
            token_decimals: Decimal places for conversion (18 for ETH, 6 for USDC, etc.).
            passphrase: Wallet encryption passphrase.

        Returns msg_id for tracking.
        """
        if not self._gateway_id:
            raise ValueError("Gateway node ID not set")

        private_key = self._wallet_mgr.load_private_key(wallet_name, passphrase=passphrase)
        sender_address = self._wallet_mgr.get_address(wallet_name)
        sender_addr_bytes = address_to_bytes(sender_address)
        dest_addr_bytes = address_to_bytes(destination)
        amount_raw = _to_raw_amount(amount, token_decimals)

        # Determine token address
        if token_address:
            token_addr_bytes = address_to_bytes(token_address)
        else:
            token_addr_bytes = NATIVE_ETH_ADDRESS

        # Sign the request payload for authentication (includes timestamp for replay protection)
        request_timestamp = int(time.time())
        signed_data = (sender_addr_bytes + dest_addr_bytes
                       + struct.pack("!Q", amount_raw) + token_addr_bytes
                       + struct.pack("!I", request_timestamp))
        sig = sign_payload(private_key, signed_data)

        payload = encode_tx_request(
            sender_addr_bytes, dest_addr_bytes, amount_raw, sig,
            token_addr=token_addr_bytes,
            timestamp=request_timestamp,
        )
        msg_id = generate_msg_id()
        msg = pack_message(MsgType.TX_REQUEST, msg_id, 0, 1, payload)

        if token_address:
            logger.info(
                "Requesting gateway transfer: %.6f (token %s) -> %s",
                amount, token_address, destination,
            )
        else:
            logger.info(
                "Requesting gateway transfer: %.6f ETH -> %s",
                amount, destination,
            )
        self._mesh.send(msg, destination_id=self._gateway_id)
        return msg_id

    def fetch_nonce(self, address: str, timeout: Optional[float] = None) -> Optional[int]:
        """Request the account nonce from the gateway.

        Returns nonce value or None on timeout.
        """
        if timeout is None:
            timeout = self._nonce_timeout
        if not self._gateway_id:
            raise ValueError("Gateway node ID not set")

        addr_bytes = address_to_bytes(address)
        payload = encode_nonce_req(addr_bytes)
        msg_id = generate_msg_id()
        msg = pack_message(MsgType.NONCE_REQ, msg_id, 0, 1, payload)

        with self._nonce_cond:
            self._nonce = None
        self._mesh.send(msg, destination_id=self._gateway_id)
        logger.info("Requested nonce from gateway for %s", address)

        deadline = time.time() + timeout
        with self._nonce_cond:
            while self._nonce is None:
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None
                self._nonce_cond.wait(timeout=remaining)
            return self._nonce

    def fetch_gas_info(self, timeout: Optional[float] = None) -> Optional[dict]:
        """Request gas price and chain ID from the gateway.

        Returns dict with 'gas_price' and 'chain_id', or None on timeout.
        """
        if timeout is None:
            timeout = self._gas_timeout
        if not self._gateway_id:
            raise ValueError("Gateway node ID not set")

        payload = encode_gas_req()
        msg_id = generate_msg_id()
        msg = pack_message(MsgType.GAS_REQ, msg_id, 0, 1, payload)

        with self._gas_cond:
            self._gas_info = None
        self._mesh.send(msg, destination_id=self._gateway_id)
        logger.info("Requested gas info from gateway")

        deadline = time.time() + timeout
        with self._gas_cond:
            while self._gas_info is None:
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None
                self._gas_cond.wait(timeout=remaining)
            return self._gas_info

    def check_balance(self, address: str,
                      token_address: Optional[str] = None) -> int:
        """Request balance of an address from the gateway.

        Returns the msg_id. Listen for the result via wait_for_balance().
        """
        if not self._gateway_id:
            raise ValueError("Gateway node ID not set")

        addr_bytes = address_to_bytes(address)
        if token_address:
            token_addr_bytes = address_to_bytes(token_address)
        else:
            token_addr_bytes = NATIVE_ETH_ADDRESS

        payload = encode_balance_req(addr_bytes, token_addr=token_addr_bytes)
        msg_id = generate_msg_id()
        msg = pack_message(MsgType.BALANCE_REQ, msg_id, 0, 1, payload)

        self._mesh.send(msg, destination_id=self._gateway_id)
        logger.info("Requested balance for %s", address)
        return msg_id

    def wait_for_result(self, msg_id: int, timeout: Optional[float] = None) -> Optional[dict]:
        """Block until a TX_RESULT is received for the given msg_id."""
        if timeout is None:
            timeout = self._result_timeout
        deadline = time.time() + timeout
        with self._result_cond:
            while msg_id not in self._results:
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None
                self._result_cond.wait(timeout=remaining)
            return self._results.pop(msg_id)

    def wait_for_balance(self, msg_id: Optional[int] = None,
                         timeout: Optional[float] = None) -> Optional[dict]:
        """Block until a BALANCE_RESP is received.

        If msg_id is provided, waits for that specific response.
        Otherwise waits for any balance response (backwards compatible).
        """
        if timeout is None:
            timeout = self._balance_timeout
        deadline = time.time() + timeout
        with self._balance_cond:
            while True:
                if msg_id is not None and msg_id in self._balances:
                    return self._balances.pop(msg_id)
                elif msg_id is None and self._balances:
                    key = max(self._balances.keys())
                    return self._balances.pop(key)
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None
                self._balance_cond.wait(timeout=remaining)

    def preflight_balance_check(self, address: str, amount_raw: int,
                                token_address: Optional[str] = None,
                                gas_estimate_wei: int = 0) -> Optional[bool]:
        """Check if sender has sufficient balance for the intended transfer.

        Returns True if sufficient, False if insufficient, None on timeout.
        This is advisory only -- the transaction will still proceed.
        """
        msg_id = self.check_balance(address, token_address=token_address)
        result = self.wait_for_balance(msg_id=msg_id)
        if result is None:
            logger.warning("Pre-flight balance check timed out")
            return None

        if token_address:
            available = result["amount"]
            needed = amount_raw
            if available < needed:
                logger.warning(
                    "Pre-flight check: insufficient token balance. "
                    "Have %d, need %d (token: %s)",
                    available, needed, token_address,
                )
                return False
        else:
            available = result["amount"]
            needed = amount_raw + gas_estimate_wei
            if available < needed:
                logger.warning(
                    "Pre-flight check: insufficient ETH balance. "
                    "Have %d wei, need ~%d wei (amount + gas)",
                    available, needed,
                )
                return False

        logger.info("Pre-flight balance check passed")
        return True

    # --- Handlers ---

    def _handle_ack(self, header: BaseMeshHeader, payload: bytes,
                    sender_id: str) -> None:
        """Track which chunks have been acknowledged."""
        ack = decode_ack(payload)
        msg_id = ack["acked_msg_id"]
        chunk_num = ack["acked_chunk"]

        with self._chunk_lock:
            if msg_id in self._acked_chunks:
                self._acked_chunks[msg_id].add(chunk_num)
                logger.debug("ACK received: msg_id=%d chunk=%d", msg_id, chunk_num)

    def _handle_nack(self, header: BaseMeshHeader, payload: bytes,
                     sender_id: str) -> None:
        """Handle NACK from gateway."""
        from basemesh.protocol import decode_nack
        nack = decode_nack(payload)
        logger.warning(
            "NACK received: msg_id=%d error=0x%02x %s",
            nack["nacked_msg_id"], nack["error_code"], nack["error_msg"],
        )
        with self._result_cond:
            self._results[nack["nacked_msg_id"]] = {
                "success": False,
                "error": nack["error_msg"],
            }
            self._result_cond.notify_all()

    def _handle_tx_result(self, header: BaseMeshHeader, payload: bytes,
                          sender_id: str) -> None:
        """Process transaction result from gateway."""
        result = decode_tx_result(payload)
        msg_id = result["orig_msg_id"]

        with self._result_cond:
            if result["success"]:
                tx_hash = result["data"].decode("utf-8", errors="replace")
                logger.info("Transaction confirmed: %s", tx_hash)
                self._results[msg_id] = {"success": True, "tx_hash": tx_hash}
            else:
                error = result["data"].decode("utf-8", errors="replace")
                logger.error("Transaction failed: %s", error)
                self._results[msg_id] = {"success": False, "error": error}

            self._result_cond.notify_all()

    def _handle_balance_resp(self, header: BaseMeshHeader, payload: bytes,
                             sender_id: str) -> None:
        """Process balance response from gateway."""
        resp = decode_balance_resp(payload)
        address = bytes_to_address(resp["address"])
        token_addr = resp["token_addr"]
        amount = resp["amount"]

        if token_addr == NATIVE_ETH_ADDRESS:
            eth = amount / WEI_PER_ETH
            logger.info("Balance for %s: %.18f ETH", address, eth)
            with self._balance_cond:
                self._balances[header.msg_id] = {
                    "address": address,
                    "amount": amount,
                    "eth": eth,
                    "token_addr": None,
                }
                self._balance_cond.notify_all()
        else:
            token = bytes_to_address(token_addr)
            logger.info("Token balance for %s: %d (token %s)", address, amount, token)
            with self._balance_cond:
                self._balances[header.msg_id] = {
                    "address": address,
                    "amount": amount,
                    "token_addr": token,
                }
                self._balance_cond.notify_all()

    def _handle_nonce_resp(self, header: BaseMeshHeader, payload: bytes,
                           sender_id: str) -> None:
        """Process nonce response from gateway."""
        resp = decode_nonce_resp(payload)
        logger.info("Received nonce from gateway: %d", resp["nonce"])
        with self._nonce_cond:
            self._nonce = resp["nonce"]
            self._nonce_cond.notify_all()

    def _handle_gas_resp(self, header: BaseMeshHeader, payload: bytes,
                         sender_id: str) -> None:
        """Process gas price response from gateway."""
        resp = decode_gas_resp(payload)
        logger.info(
            "Received gas info: price=%d chain_id=%d",
            resp["gas_price"], resp["chain_id"],
        )
        with self._gas_cond:
            self._gas_info = resp
            self._gas_cond.notify_all()

    def _handle_gateway_beacon(self, header: BaseMeshHeader, payload: bytes,
                               sender_id: str) -> None:
        """Process gateway beacon and track discovered gateways."""
        beacon = decode_gateway_beacon(payload)
        with self._gateway_cond:
            self._discovered_gateways[sender_id] = {
                **beacon,
                "last_seen": time.time(),
            }
            if not self._gateway_id:
                self._gateway_id = sender_id
                logger.info("Auto-discovered gateway: %s", sender_id)
            self._gateway_cond.notify_all()
        logger.debug(
            "Gateway beacon from %s: v%d caps=0x%02x uptime=%ds",
            sender_id, beacon["version"], beacon["capabilities"],
            beacon["uptime_seconds"],
        )

    def _handle_addr_share(self, header: BaseMeshHeader, payload: bytes,
                           sender_id: str) -> None:
        """Store received address associations."""
        data = decode_addr_share(payload)
        address = bytes_to_address(data["address"])
        self._received_addresses[sender_id] = {
            "address": address,
            "label": data["label"],
        }
        label = data["label"] or sender_id
        logger.info("Received address from %s: %s", label, address)

    # --- Retry logic ---

    def _retry_loop(self, chunks: list[bytes], msg_id: int) -> None:
        """Send chunks with ACK tracking and retry logic (runs in background thread)."""
        from basemesh.protocol import unpack_message

        chunk_info = []
        for chunk_raw in chunks:
            hdr, _ = unpack_message(chunk_raw)
            chunk_info.append(hdr.chunk_num)

        self._mesh.send_chunks(chunks, destination_id=self._gateway_id)

        for attempt in range(MAX_RETRIES):
            time.sleep(ACK_TIMEOUT)

            with self._chunk_lock:
                acked = self._acked_chunks.get(msg_id, set()).copy()
            unacked = [i for i, cn in enumerate(chunk_info) if cn not in acked]

            if not unacked:
                logger.info("All %d chunks acknowledged", len(chunks))
                with self._chunk_lock:
                    self._acked_chunks.pop(msg_id, None)
                return

            logger.warning(
                "Retry %d/%d: %d chunks unacked",
                attempt + 1, MAX_RETRIES, len(unacked),
            )

            for idx in unacked:
                self._mesh.send(chunks[idx], destination_id=self._gateway_id)
                time.sleep(RETRY_DELAY)

        with self._chunk_lock:
            acked = self._acked_chunks.get(msg_id, set()).copy()
            self._acked_chunks.pop(msg_id, None)
        unacked_count = sum(1 for cn in chunk_info if cn not in acked)
        if unacked_count > 0:
            logger.error(
                "Failed to deliver %d/%d chunks after %d retries",
                unacked_count, len(chunks), MAX_RETRIES,
            )
            with self._result_cond:
                self._results[msg_id] = {
                    "success": False,
                    "error": f"Failed to deliver {unacked_count}/{len(chunks)} chunks",
                }
                self._result_cond.notify_all()
