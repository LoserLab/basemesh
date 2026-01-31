# BaseMesh

**Send crypto when there's no internet.**

BaseMesh lets you send ETH and USDC on Base (Ethereum L2) through Meshtastic LoRa radio mesh networks. No cell towers, no WiFi, no satellite -- just long-range radio.

---

## The Problem

Billions of people live in areas with unreliable or no internet access. Natural disasters, remote fieldwork, authoritarian censorship, and infrastructure failures can cut off connectivity at any moment. When that happens, access to digital money stops.

Existing crypto wallets require an internet connection to broadcast transactions. If you're off-grid, your funds are frozen.

## The Solution

BaseMesh bridges the gap between offline devices and the blockchain using **Meshtastic** -- an open-source, long-range mesh networking platform built on LoRa radio.

A single internet-connected gateway node can serve an entire mesh network of offline users. Transactions are signed locally on each user's device (private keys never leave the device), transmitted over LoRa radio to the gateway, and broadcast to the Base network.

**One gateway. Unlimited offline users. Up to 10+ km range per hop.**

---

## How It Works

```
  Offline User A                    Gateway Node                     Base Network
  (no internet)                  (internet-connected)                (Ethereum L2)

  Sign TX locally   ──LoRa──>   Receive & validate   ──RPC──>   Broadcast to chain
  Private key stays              Rate limit, verify               Confirm on-chain
  on device                      Relay to Base                    Return TX hash
                    <──LoRa──   Send confirmation     <──RPC──
```

### Three Operating Modes

**Mode 1: Offline Sign + Relay**
Sign a transaction on your device. The signed bytes are chunked, sent over LoRa to the gateway, reassembled, and broadcast. You control your keys. The gateway is just a relay.

**Mode 2: Address Exchange**
Share your Ethereum address with other nodes on the mesh. Useful for field coordination -- know where to send payments before you need to.

**Mode 3: Gateway Transfers**
The gateway holds a funded hot wallet. Offline users send authenticated transfer requests (signed with their Ethereum key), and the gateway executes the transfer on their behalf. Ideal for aid distribution, field payments, or group operations.

---

## Key Features

### Works Anywhere LoRa Reaches
- **10+ km line-of-sight range** per hop (further with mesh relaying)
- No cell towers, WiFi, or satellite required
- Works in disaster zones, remote areas, at sea, in conflict zones

### Built on Base
- **Low fees**: Base L2 transactions cost fractions of a cent
- **Fast finality**: Transactions confirm in seconds
- **Full EVM compatibility**: Works with any ERC-20 token
- **USDC support built in**: First-class support for the most widely-used stablecoin

### Security-First Design
- **Private keys never leave your device** -- transactions are signed locally
- **AES-256-GCM encrypted wallet storage** with PBKDF2 key derivation (480K iterations)
- **BIP39/BIP44 standard wallets** -- compatible with MetaMask, Ledger, and hardware wallets
- **Cryptographic authentication** -- Mode 3 requests verified via secp256k1 ECDSA signatures
- **Replay protection** -- timestamped requests with signature deduplication
- **Rate limiting** -- per-sender token bucket algorithm protects gateways from abuse
- **Allowlisting** -- gateway operators control who can request transfers
- **Transfer caps** -- configurable per-transaction limits for ETH and ERC-20 tokens

### Compact Binary Protocol
Purpose-built for LoRa's ~233-byte message limit:
- 10-byte header with CRC-8 integrity checking
- 20-byte Ethereum addresses (compact vs 32-byte alternatives)
- Automatic chunking and reassembly for larger transactions
- A typical ETH transfer fits in just 2 radio packets

### Open Source
MIT licensed. Fully auditable. No vendor lock-in. No accounts. No servers. No tracking.

---

## Use Cases

### Humanitarian Aid & Disaster Relief
Distribute funds to field workers in areas where infrastructure has been destroyed. One gateway at a command post can serve dozens of aid workers spread across a disaster zone, each sending and receiving payments via radio.

### Remote & Rural Payments
Enable digital payments in areas with no banking infrastructure and limited connectivity. Farmers, remote workers, and rural communities can transact using stablecoins like USDC without needing internet access.

### Maritime & Offshore
Vessels at sea can send transactions through a coastal or shipboard gateway. Crew payments, port fee settlements, or emergency fund transfers -- all without satellite internet.

### Expeditions & Fieldwork
Research teams, conservation groups, or mining operations in remote locations can manage budgets and payments through a single gateway node connected via satellite backhaul.

### Censorship Resistance
In environments where internet access is restricted or monitored, LoRa radio provides an alternative communication channel for financial transactions. Mesh topology means no single point of failure.

### Off-Grid Events & Festivals
Temporary events in areas without cell coverage can deploy a BaseMesh gateway and let attendees transact freely using USDC or ETH.

---

## Technical Specs

| Spec | Value |
|------|-------|
| Blockchain | Base (Ethereum L2) |
| Native currency | ETH |
| Supported tokens | Any ERC-20 (USDC built-in) |
| Radio | LoRa via Meshtastic |
| Range | 10+ km per hop (line-of-sight) |
| Protocol overhead | 10 bytes per packet |
| Max payload | 210 bytes per chunk |
| Signing | secp256k1 ECDSA (EIP-191) |
| Wallet encryption | AES-256-GCM |
| Key derivation | PBKDF2 (480K iterations) |
| HD wallet path | BIP-44 m/44'/60'/0'/0/0 |
| Wallet compatibility | MetaMask, Ledger, Trezor |
| Networks | Base Mainnet (8453), Base Sepolia (84532) |
| Language | Python 3.9+ |
| License | MIT |
| Tests | 221 passing |

---

## Getting Started

### What You Need
1. **Two or more Meshtastic devices** (e.g., Heltec V3, T-Beam, RAK WisBlock) -- ~$25-35 each
2. **One internet-connected computer** for the gateway (Raspberry Pi works great)
3. **Python 3.9+**

### Five Minutes to First Transaction

```bash
# Install
pip install -e .

# Create a wallet
basemesh wallet create --name alice

# Run a gateway (on the internet-connected node)
basemesh gateway --rpc-url https://sepolia.base.org --hot-wallet gateway-wallet

# Send ETH from an offline node
basemesh send relay --wallet alice --to 0x... --amount 0.01 --auto-discover

# Send USDC
basemesh send relay --wallet alice --to 0x... --amount 10 --usdc --auto-discover
```

---

## Architecture

```
                    LoRa Mesh Network

    [Offline Node]  ~~~  [Relay Node]  ~~~  [Gateway Node] --- Internet --- [Base L2]
         |                    |                   |
    Local wallet         Forwards msgs      Validates, relays
    Signs locally        Extends range       RPC to Base
    No internet          No internet         Internet required
```

- **Offline nodes**: Run `basemesh` CLI, sign transactions locally, send over LoRa
- **Relay nodes**: Standard Meshtastic devices that extend mesh range (no BaseMesh software needed)
- **Gateway node**: Runs `basemesh gateway`, bridges mesh traffic to Base RPC

The gateway is the only node that needs internet. Everything else works over radio.

---

## Comparison

| Feature | BaseMesh | Traditional Mobile Wallet | Hardware Wallet |
|---------|----------|--------------------------|-----------------|
| Works without internet | Yes | No | No (needs broadcast) |
| Range | 10+ km (LoRa) | Cell coverage | USB cable |
| Keys stay on device | Yes | Depends | Yes |
| Supports stablecoins | Yes (USDC, any ERC-20) | Yes | Yes |
| Open source | Yes (MIT) | Varies | Varies |
| Cost per node | ~$30 radio | $200+ phone | $60-150 |
| Multi-user per gateway | Yes | N/A | N/A |

---

## About

BaseMesh is a companion project to [SolMesh](https://github.com/me) (Solana over Meshtastic). While SolMesh targets Solana, BaseMesh targets Base -- Coinbase's Ethereum L2 -- offering lower fees, ERC-20 token support, and compatibility with the broader Ethereum ecosystem.

Built for the real world. Built for the worst conditions. Built to work when nothing else does.

---

*BaseMesh is experimental open-source software. Use at your own risk. See [README.md](README.md) for full disclaimer and liability limitations.*
