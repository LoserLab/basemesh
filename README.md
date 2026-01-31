# BaseMesh

Send Base (Ethereum L2) transactions over Meshtastic/LoRa mesh networks.

BaseMesh enables cryptocurrency transfers in off-grid environments using LoRa radio. Transactions are signed locally (private keys never leave your device), chunked to fit within LoRa's bandwidth constraints, and relayed through a gateway node to the Base network. Supports native ETH and ERC-20 token transfers (including USDC).

## Operating Modes

### Mode 1: Offline Sign + Relay
Sign an Ethereum transaction on your local device, send the signed transaction over the mesh to an internet-connected gateway that broadcasts it to Base. The gateway provides nonce and gas price on request so your transaction is built with current chain state.

### Mode 2: Wallet-to-Wallet
Exchange Ethereum addresses with other mesh nodes over LoRa. Address sharing includes ACK-based delivery confirmation with automatic retry.

### Mode 3: Full Gateway
A gateway node holds a hot wallet. Remote offline nodes send authenticated transfer requests, and the gateway signs and broadcasts on their behalf. Requests are authorized by secp256k1 ECDSA signature verification against an Ethereum address allowlist.

## Installation

```bash
pip install -e .
```

Or with dev dependencies:

```bash
pip install -e ".[dev]"
```

To enable the HTTP API (for Mirra Resource registration):

```bash
pip install -e ".[http]"
```

## Quick Start

### 1. Create a wallet

```bash
basemesh wallet create --name mywallet
```

You will be prompted to type back one word from your mnemonic to confirm you have written it down. Use `--skip-backup-check` to skip this verification (e.g., for scripting).

This generates a BIP39 mnemonic (12 words) and derives an Ethereum keypair using the standard BIP-44 path (`m/44'/60'/0'/0/0`). The mnemonic is displayed once -- write it down and store it safely. The mnemonic is **not** stored on disk.

To create a wallet without a mnemonic:

```bash
basemesh wallet create --name mywallet --no-mnemonic
```

### 2. Recover a wallet from mnemonic

```bash
basemesh wallet recover --name restored
```

You will be prompted for the mnemonic phrase and encryption passphrase. Compatible with MetaMask, Ledger, and other BIP-44 wallets using the standard Ethereum derivation path.

### 3. Run a gateway (internet-connected node)

```bash
basemesh gateway --rpc-url https://sepolia.base.org
```

The gateway validates the RPC connection and chain ID at startup. If the RPC is unreachable or the chain ID doesn't match your configuration, the gateway will exit with a clear error message.

The gateway broadcasts periodic beacons so clients can auto-discover it. Configure the beacon interval:

```bash
basemesh gateway --rpc-url https://sepolia.base.org --beacon-interval 120
```

To enable Mode 3 (hot wallet transfers):

```bash
basemesh gateway --rpc-url https://sepolia.base.org --hot-wallet mywallet
```

### 4. Send ETH (offline node)

**Mode 1** - Sign locally and relay:
```bash
basemesh send relay \
  --wallet mywallet \
  --to 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18 \
  --amount 0.01 \
  --gateway-node '!aabbccdd'
```

You will be prompted to confirm before sending. Use `--yes` / `-y` to skip confirmation (for scripting).

The nonce and gas price are fetched automatically from the gateway.

With gateway auto-discovery (no need to know the gateway node ID):
```bash
basemesh send relay \
  --wallet mywallet \
  --to 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18 \
  --amount 0.01 \
  --auto-discover
```

**Mode 3** - Request gateway to send from its hot wallet:
```bash
basemesh send request \
  --wallet mywallet \
  --to 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18 \
  --amount 0.1 \
  --gateway-node '!aabbccdd'
```

### 5. Send ERC-20 tokens

Send USDC (auto-resolves contract address for the configured network):
```bash
basemesh send relay \
  --wallet mywallet \
  --to 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18 \
  --amount 10.0 \
  --usdc \
  --auto-discover
```

Send any ERC-20 token by contract address:
```bash
basemesh send relay \
  --wallet mywallet \
  --to 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18 \
  --amount 100.0 \
  --token 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 \
  --decimals 6 \
  --auto-discover
```

The `--decimals` flag specifies the token's decimal places (default: 18). For `--usdc`, this is automatically set to 6.

### 6. Check balance

```bash
basemesh balance --address 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18 --auto-discover
```

ERC-20 token balance:
```bash
basemesh balance --address 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18 --usdc --auto-discover
```

### 7. Share your address

```bash
basemesh share-address --wallet mywallet --label "Field Node Alpha"
```

### 8. Store-and-forward (deferred transactions)

Queue a transaction when no gateway is available:
```bash
basemesh send deferred \
  --wallet mywallet \
  --to 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18 \
  --amount 0.5 \
  --mode 3
```

The intent is stored locally at `~/.basemesh/queue.json`. No mesh connection is needed. The passphrase is validated at queue time but **not** persisted to disk.

View pending intents:
```bash
basemesh queue list
basemesh queue list --status pending --json
```

Manually flush when a gateway is available:
```bash
basemesh queue flush --auto-discover
```

Or run a long-lived listener that auto-sends when a gateway beacon is detected:
```bash
basemesh listen --wallet mywallet
```

The listener caches your passphrase in memory and automatically signs and sends all pending intents whenever a gateway comes into range. Mode 3 intents are re-signed with a fresh timestamp at send time. Mode 1 intents fetch fresh nonce and gas price from the gateway before signing.

Remove intents:
```bash
basemesh queue remove <intent-id>
basemesh queue clear --yes
basemesh queue clear --status sent --yes
```

### 9. HTTP API (Mirra Resource)

The gateway can expose a REST API for external integrations such as [Mirra](https://getmirra.app) Resource registration. The API auto-generates an OpenAPI 3.0 spec at `/openapi.json`.

```bash
basemesh gateway --rpc-url https://sepolia.base.org --http-port 8420 --api-key your-secret-key
```

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/status` | Gateway info (uptime, chain, capabilities) |
| GET | `/v1/balance/{address}?token=` | ETH or ERC-20 balance |
| GET | `/v1/gas` | Current gas price and chain ID |
| GET | `/v1/nonce/{address}` | Account nonce (transaction count) |
| POST | `/v1/transfer` | Submit transfer from gateway hot wallet |

All endpoints require an `X-API-Key` header. Rate limiting is applied per API key.

```bash
# Check gateway status
curl -H "X-API-Key: your-secret-key" http://localhost:8420/v1/status

# Query balance
curl -H "X-API-Key: your-secret-key" http://localhost:8420/v1/balance/0x742d...

# Get OpenAPI spec (no auth required)
curl http://localhost:8420/openapi.json
```

The HTTP API requires optional dependencies: `pip install basemesh[http]`

## Configuration

Copy `config.example.yaml` to `config.yaml` and edit:

```bash
cp config.example.yaml config.yaml
```

Then run with:

```bash
basemesh -c config.yaml gateway
```

### Rate Limiting

The gateway rate-limits requests per sender using a token bucket algorithm:

```yaml
max_requests_per_minute: 10.0
rate_limit_burst: 3
```

### Gateway Beacon

The gateway periodically broadcasts a beacon advertising its capabilities and uptime:

```yaml
beacon_interval: 60  # seconds
```

### Transfer Authorization

Mode 3 requests are authorized by verifying the secp256k1 signature against the sender's Ethereum address. The `allowed_requesters` list contains checksummed Ethereum addresses:

```yaml
allowed_requesters:
  - "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18"
  - "0x9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
```

An empty list allows all authenticated requesters.

### Transfer Limits

The `max_transfer_eth` setting limits the maximum ETH amount per Mode 3 request:

```yaml
max_transfer_eth: 0.1  # per-request limit in ETH
```

For ERC-20 token transfers, use `max_transfer_token_units` (raw token units, 0 = no limit):

```yaml
max_transfer_token_units: 1000000000  # e.g., 1000 USDC (6 decimals)
```

If both limits are unset, native ETH uses the `max_transfer_eth` default (0.1 ETH) and ERC-20 has no limit. Use the `allowed_requesters` allowlist for additional access control.

### CLI Options

**Global flags** (apply to all commands):
- `--verbose` / `-v`: Enable DEBUG-level logging
- `--json-log`: Output logs in structured JSON format (useful for production monitoring)
- `--config` / `-c`: Path to YAML config file

**Send flags** (`send relay` and `send request`):
- `--yes` / `-y`: Skip the confirmation prompt before sending
- `--check-balance`: Check sender balance before sending (advisory warning only)
- `--ack-timeout`: Result wait timeout in seconds (default: 120)
- `--discovery-timeout`: Gateway discovery timeout in seconds (default: 120)

**Wallet flags** (`wallet create`):
- `--skip-backup-check`: Skip mnemonic backup verification prompt

**Deferred send flags** (`send deferred`):
- `--mode` / `-m`: Transfer mode: `1` (relay) or `3` (gateway request, default)

**Queue flags** (`queue flush`):
- `--wallet` / `-w`: Only flush intents for this wallet
- `--auto-discover`: Auto-discover gateway via beacon
- `--discovery-timeout`: Gateway discovery timeout in seconds (default: 120)

**Listen flags** (`listen`):
- `--wallet` / `-w`: Wallet name (required for passphrase caching)
- `--gateway-node` / `-g`: Gateway mesh node ID (optional, auto-discovers otherwise)

**Gateway HTTP flags** (`gateway`):
- `--http-port`: Port for HTTP API server (enables REST API for Mirra)
- `--api-key`: API key for HTTP API authentication (required if `--http-port` is set)

**Balance flags** (`balance`):
- `--discovery-timeout`: Gateway discovery timeout in seconds (default: 120)

## Supported Networks

| Network | Chain ID | RPC URL |
|---------|----------|---------|
| Base Mainnet | 8453 | https://mainnet.base.org |
| Base Sepolia (testnet) | 84532 | https://sepolia.base.org |

## Known USDC Addresses

| Network | USDC Address | Decimals |
|---------|-------------|----------|
| Base Mainnet | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` | 6 |
| Base Sepolia | `0x036CbD53842c5426634e7929541eC2318f3dCF7e` | 6 |

## Protocol

BaseMesh uses a compact binary protocol designed for LoRa's ~233-byte message limit:

- **10-byte header**: magic (2B) + version (1B) + message type (1B) + message ID (2B) + chunk number (1B) + total chunks (1B) + payload length (1B) + CRC-8 (1B)
- **Up to 210 bytes payload per chunk**
- **Magic bytes**: `0x42 0x4D` ("BM") -- independent from SolMesh ("SM")
- **Addresses**: 20-byte Ethereum addresses (saves 12 bytes vs Solana's 32-byte pubkeys)
- **Signatures**: 65-byte secp256k1 ECDSA (r + s + v) with EIP-191 personal sign
- A typical ETH transfer fits in 2 chunks

Message types: `TX_CHUNK`, `TX_REQUEST`, `ADDR_SHARE`, `ACK`, `NACK`, `BALANCE_REQ`, `BALANCE_RESP`, `NONCE_REQ`, `NONCE_RESP`, `GAS_REQ`, `GAS_RESP`, `TX_RESULT`, `GATEWAY_BEACON`

## Security

- Private keys are **never** transmitted over LoRa
- Wallet files are encrypted with AES-256-GCM (PBKDF2-derived key, 480K iterations)
- Wallet files are created with `0600` permissions (owner read/write only)
- Wallet names are validated to prevent path traversal attacks
- BIP39 mnemonic backup -- recovery phrase displayed once, never stored
- Standard BIP-44 derivation path: `m/44'/60'/0'/0/0` (compatible with MetaMask, Ledger, etc.)
- Mode 3 requests are authenticated via secp256k1 signatures using EIP-191 personal sign, verified against the sender's Ethereum address (not the spoofable mesh node ID)
- Gateway enforces an allowlist of authorized Ethereum addresses and per-transfer ETH limits
- Per-sender token bucket rate limiting protects the gateway from abuse
- Stale rate limiter entries are automatically cleaned up
- CRC-8 integrity check on all protocol messages (on top of LoRa's FEC)
- Chunk reassembly is keyed by `(sender_id, msg_id)` to prevent cross-sender collisions
- Chunk bounds validation prevents out-of-range chunk injection
- Gateway uses a local nonce counter with thread-safe locking to prevent nonce race conditions
- Amount conversion uses `Decimal` arithmetic to prevent floating-point precision errors
- Balance query failures return explicit error NACKs (not silent zero balances)
- Gateway validates RPC connection and chain ID at startup (fails fast on misconfiguration)
- ERC-20 transfer limits configurable via `max_transfer_token_units`
- Transaction confirmation prompts prevent accidental sends
- Mnemonic backup verification during wallet creation
- TX_REQUEST replay protection via 4-byte timestamp (5-minute window) and signature deduplication
- Hot wallet balance verified before spending (includes gas estimate for ETH)
- Store-and-forward queue contains **no secrets** (wallet names and public addresses only, no keys or passphrases)
- Queue file created with `0600` permissions, atomic writes via write-tmp-rename
- Passphrases for auto-flush are held in memory only (never written to disk)
- Deferred intents are re-signed at send time (no stale pre-signed transactions stored)
- HTTP API requires API key authentication on all endpoints
- HTTP API rate limiting uses separate token buckets from mesh senders
- HTTP API enforces the same transfer limits (`max_transfer_eth` / `max_transfer_token_units`) as mesh Mode 3

## Disclaimer

**IMPORTANT: READ THIS BEFORE USING BASEMESH**

BaseMesh is experimental software provided "as-is" without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement.

**Loss of Funds Risk**: Cryptocurrency transactions are irreversible. Errors in transaction construction, network configuration, or software bugs may result in permanent loss of funds. The authors and contributors are not responsible for any loss of cryptocurrency, tokens, or other digital assets resulting from the use of this software.

**Self-Custody**: BaseMesh is a self-custody tool -- keys are generated and stored locally on your device and are never sent to any server or transmitted over LoRa. You are solely responsible for your own wallets, private keys, mnemonic phrases, and funds. If you lose your private key or mnemonic phrase, your funds cannot be recovered by anyone.

**Hot Wallet Risk**: Mode 3 gateway operation involves holding a hot wallet with real funds. The gateway operator is solely responsible for securing the hot wallet, configuring appropriate transfer limits and allowlists, and monitoring for unauthorized activity. The authors bear no responsibility for funds lost from hot wallets.

**No Financial Advice**: This software does not constitute financial advice. The authors make no recommendations regarding the purchase, sale, or transfer of any cryptocurrency or token.

**Network Risks**: LoRa mesh radio communication is subject to interference, range limitations, and potential eavesdropping. While transaction data is signed and integrity-checked, the mesh transport layer is not encrypted. Protocol messages (addresses, amounts, transaction hashes) are visible to any node on the same mesh network.

**Liability Limitation**: The authors and contributors shall not be held liable for any loss of funds, lost keys, failed transactions, security breaches, hacks, or any other damages arising from the use of this software. By using BaseMesh, you agree to hold the authors and contributors harmless from any and all claims, losses, or liabilities.

**Regulatory Compliance**: You are solely responsible for compliance with all applicable laws and regulations in your jurisdiction, including but not limited to sanctions, export controls, tax obligations, money transmission laws, and financial regulations. The authors make no representations regarding the legality of using this software in any jurisdiction.

**Testing Recommendation**: Always test on Base Sepolia (testnet) before using real funds on Base Mainnet. Verify wallet creation, transaction signing, and end-to-end relay flow with testnet ETH before risking any real assets.

Use at your own risk.

## Development

```bash
pip install -e ".[dev,http]"
PYTHONPATH=src python3 -m pytest tests/ -v
```

## Requirements

- Python 3.9+
- Meshtastic device (USB or WiFi connected)
- `meshtastic`, `web3`, `eth-account`, `click`, `pyyaml`, `cryptography`, `mnemonic` Python libraries

## License

MIT
