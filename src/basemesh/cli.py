"""Click CLI for BaseMesh."""

import json as json_mod
import logging
import random
import sys
from decimal import Decimal
from pathlib import Path
from typing import Optional

import click

from basemesh.config import BaseMeshConfig, get_rpc_url, get_chain_id, load_config
from basemesh.constants import WEI_PER_ETH, USDC_ADDRESSES, USDC_DECIMALS
from basemesh.mesh import MeshInterface
from basemesh.wallet import WalletManager


class _JsonFormatter(logging.Formatter):
    """Structured JSON log formatter."""

    def format(self, record):
        return json_mod.dumps({
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        })


def resolve_token(token, usdc: bool, network: str):
    """Resolve --usdc flag or --token to a token contract address.

    Returns (token_address, decimals) tuple.
    token_address is None for native ETH.
    """
    if usdc and token:
        raise click.UsageError("Cannot use --usdc and --token together.")
    if usdc:
        addr = USDC_ADDRESSES.get(network)
        if not addr:
            raise click.UsageError(
                f"No USDC address configured for network '{network}'. "
                f"Use --token with the contract address instead."
            )
        return addr, USDC_DECIMALS
    return token, 18


def setup_logging(level: str, json_log: bool = False) -> None:
    if json_log:
        handler = logging.StreamHandler()
        handler.setFormatter(_JsonFormatter())
        logging.basicConfig(
            level=getattr(logging, level.upper(), logging.INFO),
            handlers=[handler],
        )
    else:
        logging.basicConfig(
            level=getattr(logging, level.upper(), logging.INFO),
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )


def build_mesh(config: BaseMeshConfig) -> MeshInterface:
    return MeshInterface(
        connection_type=config.mesh.connection_type,
        device_path=config.mesh.device_path,
        hostname=config.mesh.hostname,
    )


@click.group()
@click.option("--config", "-c", "config_path", type=click.Path(exists=True),
              default=None, help="Path to config YAML file")
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
@click.option("--json-log", is_flag=True, help="Output logs in structured JSON format")
@click.pass_context
def cli(ctx, config_path, verbose, json_log):
    """BaseMesh: Base (Ethereum L2) transactions over Meshtastic mesh networks."""
    ctx.ensure_object(dict)

    if config_path:
        config = load_config(Path(config_path))
    else:
        config = BaseMeshConfig()

    if verbose:
        config.log_level = "DEBUG"

    setup_logging(config.log_level, json_log=json_log)
    ctx.obj["config"] = config


# --- Gateway command ---

@cli.command()
@click.option("--rpc-url", help="Base RPC URL (overrides config)")
@click.option("--chain-id", type=int, default=None, help="Chain ID (default: from network)")
@click.option("--hot-wallet", help="Wallet name for Mode 3 gateway transfers")
@click.option("--passphrase", prompt=False, hide_input=True, default="",
              help="Passphrase for hot wallet (prompted if hot-wallet is set)")
@click.option("--beacon-interval", type=int, default=None,
              help="Beacon broadcast interval in seconds (default: 60)")
@click.pass_context
def gateway(ctx, rpc_url, chain_id, hot_wallet, passphrase, beacon_interval):
    """Run as a gateway node (internet-connected, relays to Base)."""
    from basemesh.gateway import GatewayNode

    config = ctx.obj["config"]

    if rpc_url:
        config.base.rpc_url = rpc_url
    if chain_id is not None:
        config.base.chain_id = chain_id
    if hot_wallet:
        config.gateway.hot_wallet = hot_wallet
    if beacon_interval is not None:
        config.gateway.beacon_interval = beacon_interval

    # Prompt for passphrase if hot wallet is set but passphrase wasn't provided
    if config.gateway.hot_wallet and not passphrase:
        passphrase = click.prompt("Hot wallet passphrase", hide_input=True, default="")

    resolved_rpc = get_rpc_url(config.base)
    resolved_chain_id = get_chain_id(config.base)
    mesh = build_mesh(config)
    wm = WalletManager()

    gw = GatewayNode(
        mesh=mesh,
        rpc_url=resolved_rpc,
        chain_id=resolved_chain_id,
        wallet_manager=wm,
        gateway_config=config.gateway,
    )

    click.echo(f"Starting gateway node...")
    click.echo(f"  Base RPC:   {resolved_rpc}")
    click.echo(f"  Chain ID:   {resolved_chain_id}")
    click.echo(f"  Network:    {config.base.network}")
    if config.gateway.hot_wallet:
        click.echo(f"  Hot wallet: {config.gateway.hot_wallet}")
        click.echo(f"  Max transfer: {config.gateway.max_transfer_eth} ETH")
        if config.gateway.max_transfer_token_units > 0:
            click.echo(f"  Max token transfer: {config.gateway.max_transfer_token_units} units")
    click.echo()

    gw.start(hot_wallet_passphrase=passphrase)


# --- Send commands ---

@cli.group()
@click.pass_context
def send(ctx):
    """Send Base transactions over the mesh."""
    pass


@send.command("relay")
@click.option("--wallet", "-w", required=True, help="Local wallet name")
@click.option("--to", "recipient", required=True, help="Recipient Ethereum address (0x...)")
@click.option("--amount", "-a", required=True, type=float, help="Amount in ETH (or token units)")
@click.option("--token", default=None, help="ERC-20 token contract address (omit for native ETH)")
@click.option("--usdc", is_flag=True, help="Send USDC (auto-resolves contract address for current network)")
@click.option("--decimals", type=int, default=None,
              help="Token decimal places (default: 18 for ETH, 6 for USDC, auto for --usdc)")
@click.option("--gateway-node", "-g", help="Gateway mesh node ID (e.g., !aabbccdd)")
@click.option("--auto-discover", is_flag=True, help="Auto-discover gateway via beacon")
@click.option("--passphrase", prompt=True, hide_input=True, default="",
              help="Wallet passphrase")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
@click.option("--check-balance", "do_preflight", is_flag=True,
              help="Check sender balance before sending")
@click.option("--ack-timeout", type=float, default=None,
              help="Result wait timeout in seconds (default: 120)")
@click.option("--discovery-timeout", type=float, default=None,
              help="Gateway discovery timeout in seconds (default: 120)")
@click.pass_context
def send_relay(ctx, wallet, recipient, amount, token, usdc, decimals,
               gateway_node, auto_discover, passphrase, yes, do_preflight,
               ack_timeout, discovery_timeout):
    """Mode 1: Sign locally and relay signed TX over mesh to gateway."""
    from basemesh.client import ClientNode, _to_raw_amount

    config = ctx.obj["config"]
    token, resolved_decimals = resolve_token(token, usdc, config.base.network)
    if decimals is not None:
        resolved_decimals = decimals
    mesh = build_mesh(config)
    wm = WalletManager()

    client_kwargs = {}
    if ack_timeout is not None:
        client_kwargs["result_timeout"] = ack_timeout
    if discovery_timeout is not None:
        client_kwargs["discovery_timeout"] = discovery_timeout

    client = ClientNode(mesh=mesh, wallet_manager=wm,
                        gateway_node_id=gateway_node, **client_kwargs)
    client.connect()

    if auto_discover and not gateway_node:
        click.echo("Discovering gateway via beacon...")
        gw = client.discover_gateway()
        if not gw:
            click.echo("No gateway found. Specify --gateway-node or try again.", err=True)
            client.close()
            sys.exit(1)
        click.echo(f"  Found gateway: {gw}")

    if token:
        label = "USDC" if usdc else token
    else:
        label = "ETH"

    click.echo(f"Signing transaction locally...")
    click.echo(f"  From:   {wallet}")
    click.echo(f"  To:     {recipient}")
    click.echo(f"  Amount: {amount} {label}")
    click.echo(f"  Fetching nonce + gas from gateway...")
    click.echo()

    if not yes:
        if not click.confirm(f"Send {amount} {label} to {recipient} via relay?", default=False):
            click.echo("Cancelled.")
            client.close()
            return

    if do_preflight:
        address = wm.get_address(wallet)
        click.echo("Checking sender balance...")
        amount_raw = _to_raw_amount(amount, resolved_decimals)
        sufficient = client.preflight_balance_check(
            address=address,
            amount_raw=amount_raw,
            token_address=token,
        )
        if sufficient is False:
            click.echo("WARNING: Sender balance appears insufficient. Proceeding anyway.", err=True)
        elif sufficient is None:
            click.echo("WARNING: Could not verify balance (timeout). Proceeding anyway.", err=True)

    try:
        msg_id = client.relay_signed_tx(
            wallet_name=wallet,
            recipient=recipient,
            amount=amount,
            token_address=token,
            token_decimals=resolved_decimals,
            passphrase=passphrase,
        )
        click.echo(f"Transaction sent (msg_id={msg_id}). Waiting for result...")

        result = client.wait_for_result(msg_id)
        if result and result.get("success"):
            click.echo(f"Success! TX hash: {result['tx_hash']}")
        elif result:
            click.echo(f"Failed: {result.get('error', 'Unknown error')}")
        else:
            click.echo("Timed out waiting for result from gateway.")
    finally:
        client.close()


@send.command("request")
@click.option("--wallet", "-w", required=True, help="Your wallet name (for auth)")
@click.option("--to", "recipient", required=True, help="Recipient Ethereum address (0x...)")
@click.option("--amount", "-a", required=True, type=float, help="Amount in ETH (or token units)")
@click.option("--token", default=None, help="ERC-20 token contract address (omit for native ETH)")
@click.option("--usdc", is_flag=True, help="Send USDC (auto-resolves contract address for current network)")
@click.option("--decimals", type=int, default=None,
              help="Token decimal places (default: 18 for ETH, 6 for USDC, auto for --usdc)")
@click.option("--gateway-node", "-g", default=None, help="Gateway mesh node ID")
@click.option("--auto-discover", is_flag=True, help="Auto-discover gateway via beacon")
@click.option("--passphrase", prompt=True, hide_input=True, default="",
              help="Wallet passphrase")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
@click.option("--check-balance", "do_preflight", is_flag=True,
              help="Check sender balance before sending")
@click.option("--ack-timeout", type=float, default=None,
              help="Result wait timeout in seconds (default: 120)")
@click.option("--discovery-timeout", type=float, default=None,
              help="Gateway discovery timeout in seconds (default: 120)")
@click.pass_context
def send_request(ctx, wallet, recipient, amount, token, usdc, decimals,
                 gateway_node, auto_discover, passphrase, yes, do_preflight,
                 ack_timeout, discovery_timeout):
    """Mode 3: Request gateway to send ETH/tokens from its hot wallet."""
    from basemesh.client import ClientNode, _to_raw_amount

    config = ctx.obj["config"]
    token, resolved_decimals = resolve_token(token, usdc, config.base.network)
    if decimals is not None:
        resolved_decimals = decimals
    mesh = build_mesh(config)
    wm = WalletManager()

    client_kwargs = {}
    if ack_timeout is not None:
        client_kwargs["result_timeout"] = ack_timeout
    if discovery_timeout is not None:
        client_kwargs["discovery_timeout"] = discovery_timeout

    client = ClientNode(mesh=mesh, wallet_manager=wm,
                        gateway_node_id=gateway_node, **client_kwargs)
    client.connect()

    if auto_discover and not gateway_node:
        click.echo("Discovering gateway via beacon...")
        gw = client.discover_gateway()
        if not gw:
            click.echo("No gateway found. Specify --gateway-node or try again.", err=True)
            client.close()
            sys.exit(1)
        click.echo(f"  Found gateway: {gw}")

    if token:
        label = "USDC" if usdc else token
    else:
        label = "ETH"

    click.echo(f"Requesting gateway transfer...")
    click.echo(f"  To:     {recipient}")
    click.echo(f"  Amount: {amount} {label}")
    click.echo()

    if not yes:
        if not click.confirm(f"Send {amount} {label} to {recipient} via gateway request?",
                             default=False):
            click.echo("Cancelled.")
            client.close()
            return

    if do_preflight:
        address = wm.get_address(wallet)
        click.echo("Checking sender balance...")
        amount_raw = _to_raw_amount(amount, resolved_decimals)
        sufficient = client.preflight_balance_check(
            address=address,
            amount_raw=amount_raw,
            token_address=token,
        )
        if sufficient is False:
            click.echo("WARNING: Sender balance appears insufficient. Proceeding anyway.", err=True)
        elif sufficient is None:
            click.echo("WARNING: Could not verify balance (timeout). Proceeding anyway.", err=True)

    try:
        msg_id = client.request_transfer(
            wallet_name=wallet,
            destination=recipient,
            amount=amount,
            token_address=token,
            token_decimals=resolved_decimals,
            passphrase=passphrase,
        )
        click.echo(f"Request sent (msg_id={msg_id}). Waiting for result...")

        result = client.wait_for_result(msg_id)
        if result and result.get("success"):
            click.echo(f"Success! TX hash: {result['tx_hash']}")
        elif result:
            click.echo(f"Failed: {result.get('error', 'Unknown error')}")
        else:
            click.echo("Timed out waiting for result from gateway.")
    finally:
        client.close()


@send.command("deferred")
@click.option("--wallet", "-w", required=True, help="Local wallet name")
@click.option("--to", "recipient", required=True, help="Recipient Ethereum address (0x...)")
@click.option("--amount", "-a", required=True, type=float, help="Amount in ETH (or token units)")
@click.option("--mode", "-m", type=click.Choice(["1", "3"]), default="3",
              help="Transfer mode: 1 (relay) or 3 (gateway request, default)")
@click.option("--token", default=None, help="ERC-20 token contract address (omit for native ETH)")
@click.option("--usdc", is_flag=True, help="Send USDC (auto-resolves contract address for current network)")
@click.option("--decimals", type=int, default=None,
              help="Token decimal places (default: 18 for ETH, 6 for USDC, auto for --usdc)")
@click.option("--passphrase", prompt=True, hide_input=True, default="",
              help="Wallet passphrase (validated, then cached in memory)")
@click.pass_context
def send_deferred(ctx, wallet, recipient, amount, mode, token, usdc, decimals, passphrase):
    """Queue a transaction for sending when a gateway becomes available.

    The intent is stored locally. Use 'basemesh queue flush' or
    'basemesh listen' to send when a gateway is in range.
    """
    from basemesh.store import IntentStore

    config = ctx.obj["config"]
    token, resolved_decimals = resolve_token(token, usdc, config.base.network)
    if decimals is not None:
        resolved_decimals = decimals

    wm = WalletManager()
    store = IntentStore()

    if token:
        label = "USDC" if usdc else token
    else:
        label = "ETH"

    try:
        # Validate wallet and passphrase (no mesh connection needed)
        wm.load_private_key(wallet, passphrase=passphrase)
    except FileNotFoundError:
        click.echo(f"Error: Wallet '{wallet}' not found.", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error: Failed to decrypt wallet: {e}", err=True)
        sys.exit(1)

    try:
        intent = store.add(
            mode=int(mode),
            wallet_name=wallet,
            recipient=recipient,
            amount=amount,
            token_address=token,
            token_decimals=resolved_decimals,
        )
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    click.echo(f"Queued intent {intent.id}: {amount} {label} -> {recipient} (mode {mode})")
    click.echo("Use 'basemesh queue list' to see pending intents.")
    click.echo("Use 'basemesh queue flush' or 'basemesh listen' to send.")


# --- Queue management ---

@cli.group()
def queue():
    """Manage the store-and-forward intent queue."""
    pass


@queue.command("list")
@click.option("--status", type=click.Choice(["pending", "sending", "sent", "failed"]),
              default=None, help="Filter by status")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def queue_list(status, as_json):
    """List queued transaction intents."""
    from basemesh.store import IntentStore
    from datetime import datetime

    store = IntentStore()
    intents = store.list_intents(status=status)

    if as_json:
        from dataclasses import asdict
        click.echo(json_mod.dumps([asdict(i) for i in intents], indent=2))
        return

    if not intents:
        click.echo("No intents in queue.")
        return

    click.echo(f"{'ID':<10} {'Mode':<6} {'Status':<9} {'Wallet':<14} "
               f"{'To':<14} {'Amount':<12} {'Created'}")
    click.echo("-" * 85)
    for i in intents:
        to_short = i.recipient[:8] + "..." + i.recipient[-4:]
        ts = datetime.fromtimestamp(i.created_at).strftime("%Y-%m-%d %H:%M")
        token_label = ""
        if i.token_address:
            token_label = " (ERC20)"
        click.echo(f"{i.id:<10} {i.mode:<6} {i.status:<9} {i.wallet_name:<14} "
                   f"{to_short:<14} {i.amount}{token_label:<12} {ts}")


@queue.command("flush")
@click.option("--passphrase", prompt=True, hide_input=True, default="",
              help="Wallet passphrase for re-signing")
@click.option("--wallet", "-w", default=None,
              help="Only flush intents for this wallet")
@click.option("--gateway-node", "-g", default=None, help="Gateway mesh node ID")
@click.option("--auto-discover", is_flag=True, help="Auto-discover gateway via beacon")
@click.option("--discovery-timeout", type=float, default=None,
              help="Gateway discovery timeout in seconds (default: 120)")
@click.pass_context
def queue_flush(ctx, passphrase, wallet, gateway_node, auto_discover, discovery_timeout):
    """Send pending intents to a gateway (requires mesh connection)."""
    from basemesh.client import ClientNode
    from basemesh.store import IntentStore

    config = ctx.obj["config"]
    store = IntentStore()
    pending = store.pending_intents()

    if wallet:
        pending = [i for i in pending if i.wallet_name == wallet]

    if not pending:
        click.echo("No pending intents to flush.")
        return

    click.echo(f"Found {len(pending)} pending intent(s).")

    mesh = build_mesh(config)
    wm = WalletManager()

    client_kwargs = {}
    if discovery_timeout is not None:
        client_kwargs["discovery_timeout"] = discovery_timeout

    client = ClientNode(
        mesh=mesh, wallet_manager=wm,
        gateway_node_id=gateway_node,
        intent_store=store,
        **client_kwargs,
    )
    client.connect()

    if auto_discover and not gateway_node:
        click.echo("Discovering gateway via beacon...")
        gw = client.discover_gateway()
        if not gw:
            click.echo("No gateway found.", err=True)
            client.close()
            sys.exit(1)
        click.echo(f"  Found gateway: {gw}")

    # Build passphrase map for all wallets in the queue
    wallet_names = set(i.wallet_name for i in pending)
    pp_map = {wn: passphrase for wn in wallet_names}

    try:
        results = client.flush_all_pending(passphrase_map=pp_map)
        for r in results:
            res = r["result"]
            if res and res.get("success"):
                click.echo(f"  {r['intent_id']}: Success! TX: {res.get('tx_hash', 'N/A')}")
            elif res:
                click.echo(f"  {r['intent_id']}: Failed: {res.get('error', 'Unknown')}")
            else:
                click.echo(f"  {r['intent_id']}: Timeout (will retry later)")

        still_pending = len(store.pending_intents())
        if still_pending:
            click.echo(f"{still_pending} intent(s) still pending.")
        else:
            click.echo("All intents processed.")
    finally:
        client.close()


@queue.command("clear")
@click.option("--status", type=click.Choice(["pending", "sent", "failed"]),
              default=None, help="Only clear intents with this status (default: all)")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
def queue_clear(status, yes):
    """Remove intents from the queue."""
    from basemesh.store import IntentStore

    store = IntentStore()

    if not yes:
        label = f"all '{status}'" if status else "ALL"
        if not click.confirm(f"Remove {label} intents from the queue?", default=False):
            click.echo("Cancelled.")
            return

    removed = store.clear(status=status)
    click.echo(f"Removed {removed} intent(s).")


@queue.command("remove")
@click.argument("intent_id")
def queue_remove(intent_id):
    """Remove a specific intent by ID."""
    from basemesh.store import IntentStore

    store = IntentStore()
    if store.remove(intent_id):
        click.echo(f"Removed intent {intent_id}.")
    else:
        click.echo(f"Intent '{intent_id}' not found.", err=True)
        sys.exit(1)


# --- Listen (auto-flush daemon) ---

@cli.command("listen")
@click.option("--wallet", "-w", required=True, help="Wallet name (for passphrase caching)")
@click.option("--passphrase", prompt=True, hide_input=True, default="",
              help="Wallet passphrase (held in memory for auto-signing)")
@click.option("--gateway-node", "-g", default=None, help="Gateway mesh node ID (optional)")
@click.pass_context
def listen(ctx, wallet, passphrase, gateway_node):
    """Listen for gateway beacons and auto-send queued intents.

    Runs as a long-lived process. When a gateway beacon is received,
    all pending intents are automatically signed and sent.
    Press Ctrl+C to stop.
    """
    from basemesh.client import ClientNode
    from basemesh.store import IntentStore

    config = ctx.obj["config"]
    mesh = build_mesh(config)
    wm = WalletManager()
    store = IntentStore()

    # Validate passphrase
    try:
        wm.load_private_key(wallet, passphrase=passphrase)
    except FileNotFoundError:
        click.echo(f"Error: Wallet '{wallet}' not found.", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error: Failed to decrypt wallet: {e}", err=True)
        sys.exit(1)

    client = ClientNode(
        mesh=mesh, wallet_manager=wm,
        gateway_node_id=gateway_node,
        intent_store=store,
        auto_flush=True,
    )
    client.cache_passphrase(wallet, passphrase)
    client.connect()

    pending_count = len(store.pending_intents())
    click.echo(f"Listening for gateway beacons (auto-flush enabled)...")
    click.echo(f"  Wallet: {wallet}")
    click.echo(f"  Pending intents: {pending_count}")
    if gateway_node:
        click.echo(f"  Gateway: {gateway_node}")
    else:
        click.echo("  Gateway: auto-discover")
    click.echo("  Press Ctrl+C to stop.")
    click.echo()

    try:
        mesh.run()
    except KeyboardInterrupt:
        click.echo("\nStopping listener...")
    finally:
        client.close()


# --- Address sharing ---

@cli.command("share-address")
@click.option("--wallet", "-w", required=True, help="Wallet name")
@click.option("--label", "-l", default="", help="Optional label for your address")
@click.pass_context
def share_address(ctx, wallet, label):
    """Mode 2: Share your Ethereum address over mesh."""
    from basemesh.client import ClientNode

    config = ctx.obj["config"]
    mesh = build_mesh(config)
    wm = WalletManager()

    client = ClientNode(mesh=mesh, wallet_manager=wm)
    client.connect()

    try:
        client.share_address(wallet_name=wallet, label=label)
        address = wm.get_address(wallet)
        click.echo(f"Address broadcast: {address}")
    finally:
        client.close()


# --- Balance check ---

@cli.command("balance")
@click.option("--address", "-a", required=True, help="Ethereum address to check (0x...)")
@click.option("--token", default=None, help="ERC-20 token contract address (omit for ETH)")
@click.option("--usdc", is_flag=True, help="Check USDC balance (auto-resolves contract address)")
@click.option("--gateway-node", "-g", default=None, help="Gateway mesh node ID")
@click.option("--auto-discover", is_flag=True, help="Auto-discover gateway via beacon")
@click.option("--discovery-timeout", type=float, default=None,
              help="Gateway discovery timeout in seconds (default: 120)")
@click.pass_context
def check_balance(ctx, address, token, usdc, gateway_node, auto_discover,
                  discovery_timeout):
    """Query ETH or ERC-20 token balance via gateway."""
    from basemesh.client import ClientNode

    config = ctx.obj["config"]
    token, _ = resolve_token(token, usdc, config.base.network)
    mesh = build_mesh(config)
    wm = WalletManager()

    client_kwargs = {}
    if discovery_timeout is not None:
        client_kwargs["discovery_timeout"] = discovery_timeout

    client = ClientNode(mesh=mesh, wallet_manager=wm,
                        gateway_node_id=gateway_node, **client_kwargs)
    client.connect()

    if auto_discover and not gateway_node:
        click.echo("Discovering gateway via beacon...")
        gw = client.discover_gateway()
        if not gw:
            click.echo("No gateway found. Specify --gateway-node or try again.", err=True)
            client.close()
            sys.exit(1)
        click.echo(f"  Found gateway: {gw}")

    try:
        client.check_balance(address, token_address=token)
        click.echo(f"Balance request sent. Waiting for response...")

        result = client.wait_for_balance()
        if result:
            click.echo(f"Address: {result['address']}")
            if result.get("token_addr"):
                click.echo(f"Token:   {result['token_addr']}")
                click.echo(f"Balance: {result['amount']}")
            else:
                click.echo(f"Balance: {result['eth']:.18f} ETH ({result['amount']} wei)")
        else:
            click.echo("Timed out waiting for balance response.")
    finally:
        client.close()


# --- Wallet management ---

@cli.group()
def wallet():
    """Manage local Ethereum wallets."""
    pass


@wallet.command("create")
@click.option("--name", "-n", required=True, help="Wallet name")
@click.option("--no-mnemonic", is_flag=True, help="Skip mnemonic generation (random keypair)")
@click.option("--passphrase", prompt=True, hide_input=True,
              confirmation_prompt=True,
              help="Encryption passphrase (required)")
@click.option("--skip-backup-check", is_flag=True,
              help="Skip mnemonic backup verification prompt")
def wallet_create(name, no_mnemonic, passphrase, skip_backup_check):
    """Create a new Ethereum wallet (BIP39 mnemonic by default)."""
    if not passphrase:
        click.echo("Error: A passphrase is required to protect your private key.", err=True)
        sys.exit(1)
    wm = WalletManager()
    try:
        if no_mnemonic:
            address = wm.create_wallet(name, passphrase=passphrase)
            click.echo(f"Wallet created: {name}")
            click.echo(f"Address:        {address}")
        else:
            address, mnemonic = wm.create_wallet_with_mnemonic(name, passphrase=passphrase)
            click.echo(f"Wallet created: {name}")
            click.echo(f"Address:        {address}")
            click.echo()
            click.echo("RECOVERY PHRASE (write this down and store securely!):")
            click.echo(f"  {mnemonic}")
            click.echo()
            click.echo("WARNING: This phrase will NOT be shown again.")
            click.echo("         Anyone with this phrase can access your funds.")

            if not skip_backup_check:
                words = mnemonic.split()
                idx = random.randint(0, len(words) - 1)
                word_num = idx + 1
                click.echo()
                typed = click.prompt(
                    f"Please type word #{word_num} from your mnemonic to confirm backup"
                )
                if typed.strip().lower() == words[idx].lower():
                    click.echo("Backup confirmed.")
                else:
                    click.echo(
                        f"WARNING: You entered '{typed}' but word #{word_num} is "
                        f"'{words[idx]}'. Make sure you have written down your "
                        f"mnemonic correctly!",
                        err=True,
                    )
    except FileExistsError:
        click.echo(f"Error: Wallet '{name}' already exists.", err=True)
        sys.exit(1)


@wallet.command("recover")
@click.option("--name", "-n", required=True, help="Wallet name")
@click.option("--mnemonic", "mnemonic_phrase", prompt=True, hide_input=True,
              help="BIP39 recovery phrase (12 or 24 words)")
@click.option("--passphrase", prompt=True, hide_input=True,
              confirmation_prompt=True,
              help="Encryption passphrase for the recovered wallet")
def wallet_recover(name, mnemonic_phrase, passphrase):
    """Recover a wallet from a BIP39 mnemonic phrase."""
    if not passphrase:
        click.echo("Error: A passphrase is required to protect your private key.", err=True)
        sys.exit(1)
    wm = WalletManager()
    try:
        address = wm.recover_wallet(name, mnemonic_phrase, passphrase=passphrase)
        click.echo(f"Wallet recovered: {name}")
        click.echo(f"Address:          {address}")
    except FileExistsError:
        click.echo(f"Error: Wallet '{name}' already exists.", err=True)
        sys.exit(1)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@wallet.command("import")
@click.option("--name", "-n", required=True, help="Wallet name")
@click.option("--private-key", prompt=True, hide_input=True,
              help="Hex-encoded private key (with or without 0x prefix)")
@click.option("--passphrase", prompt=True, hide_input=True,
              confirmation_prompt=True, default="",
              help="Encryption passphrase")
def wallet_import(name, private_key, passphrase):
    """Import an existing Ethereum wallet from a private key."""
    wm = WalletManager()
    try:
        address = wm.import_wallet(name, private_key, passphrase=passphrase)
        click.echo(f"Wallet imported: {name}")
        click.echo(f"Address:         {address}")
    except FileExistsError:
        click.echo(f"Error: Wallet '{name}' already exists.", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@wallet.command("list")
def wallet_list():
    """List all local wallets."""
    wm = WalletManager()
    wallets = wm.list_wallets()
    if not wallets:
        click.echo("No wallets found. Create one with: basemesh wallet create --name <name>")
        return

    click.echo(f"{'Name':<20} {'Address':<44} {'Encrypted'}")
    click.echo("-" * 75)
    for w in wallets:
        enc = "yes" if w["encrypted"] else "no"
        click.echo(f"{w['name']:<20} {w['address']:<44} {enc}")


@wallet.command("delete")
@click.option("--name", "-n", required=True, help="Wallet name")
@click.confirmation_option(prompt="Are you sure you want to delete this wallet?")
def wallet_delete(name):
    """Delete a local wallet."""
    wm = WalletManager()
    try:
        wm.delete_wallet(name)
        click.echo(f"Wallet '{name}' deleted.")
    except FileNotFoundError:
        click.echo(f"Error: Wallet '{name}' not found.", err=True)
        sys.exit(1)


def main():
    cli(obj={})


if __name__ == "__main__":
    main()
