# @unconfirmed/ika

Typed query helpers and transaction builders for [Ika](https://ika.xyz) dWallets on Sui.

## Install

```bash
bun add @unconfirmed/ika @mysten/sui
```

`@mysten/sui` is a peer dependency — bring your own version (^2.5.0).

## Quick Start

```ts
import { SuiGrpcClient } from "@mysten/sui/grpc";
import { ika, getNetworkConfig } from "@unconfirmed/ika";

// Create a Sui client extended with Ika
const client = new SuiGrpcClient({ network: "testnet" })
  .$extend(ika({ config: getNetworkConfig("testnet") }));

// Query a dWallet
const dwallet = await client.ika.getDWallet("0x...");

// Poll until a dWallet reaches a specific state
const activeDWallet = await client.ika.getDWalletInParticularState(
  "0x...",
  "Active",
  { timeout: 300_000 },
);
```

## Transaction Builders

Every operation is a standalone function that accepts a `Transaction` and returns the result:

```ts
import { Transaction } from "@mysten/sui/transactions";
import {
  requestDWalletDKG,
  requestPresign,
  requestGlobalPresign,
  approveMessage,
  requestSign,
} from "@unconfirmed/ika/transactions";

const tx = new Transaction();

// Request a presign
const presignCap = requestGlobalPresign({
  config: client.ika.ikaConfig,
  tx,
  curve: "SECP256K1",
  signatureAlgorithm: "ECDSASecp256k1",
  dwalletNetworkEncryptionKeyId: "0x...",
  ikaCoin,
  suiCoin: tx.gas,
});
```

## Subpath Exports

```ts
import { ika, IkaClient }       from "@unconfirmed/ika/client";
import { requestDWalletDKG }     from "@unconfirmed/ika/transactions";
import { Curve, Hash }           from "@unconfirmed/ika/types";
import { UserShareEncryptionKeys } from "@unconfirmed/ika/crypto";
import { validateHashSignatureCombination } from "@unconfirmed/ika/validation";
import { initializeWasm }        from "@unconfirmed/ika/wasm";
```

Or import everything from the barrel:

```ts
import { ika, Curve, requestDWalletDKG, UserShareEncryptionKeys } from "@unconfirmed/ika";
```

## Architecture

| Module | Contents |
|--------|----------|
| `client.ts` | `ika()` $extend factory, `IkaClient` class with caching and queries |
| `transactions.ts` | Standalone transaction builders (DKG, presign, sign, system ops) |
| `crypto.ts` | DKG preparation, signing helpers, `UserShareEncryptionKeys` |
| `types.ts` | Interfaces, const enums (`Curve`, `Hash`, `SignatureAlgorithm`), BCS types |
| `validation.ts` | Curve/hash/signature combination validation |
| `wasm.ts` | WASM lazy loader for `@unconfirmed/ika-wasm` |
| `errors.ts` | `IkaClientError` hierarchy |
| `network-configs.ts` | Testnet and mainnet configurations |

## Changes from @ika.xyz/sdk

This SDK is a ground-up rewrite of `@ika.xyz/sdk` v0.4.0, restructured to follow [Mysten's SDK patterns](https://docs.sui.io/guides/developer/sui-101/using-sui-sdk):

| Aspect | @ika.xyz/sdk | @unconfirmed/ika |
|--------|-------------|------------------|
| Client pattern | Standalone `IkaClient` class | `$extend()` registration on `SuiGrpcClient` / `SuiJsonRpcClient` |
| Transaction building | `IkaTransaction` class wrapping `Transaction` | Standalone functions accepting `Transaction` as a parameter |
| `@mysten/sui` | Regular dependency | Peer dependency |
| Network transport | JSON-RPC (`SuiJsonRpcClient`) | gRPC-first (`ClientWithCoreApi` — works with both) |
| Module format | Dual CJS/ESM build (`dist/`) | Ships TypeScript source directly |
| Exports | Single entry point | Subpath exports (`/client`, `/transactions`, `/types`, etc.) |
| Crypto + keys | Separate `cryptography.ts` and `user-share-encryption-keys.ts` | Merged into `crypto.ts` |
| Validation | `hash-signature-validation.ts` | `validation.ts` |
| Transaction helpers | `tx/coordinator.ts` + `tx/system.ts` as separate modules | Inlined into `transactions.ts` |

### Feature Parity

All functionality from `@ika.xyz/sdk` v0.4.0 is preserved:

- DKG (distributed key generation) for all curves (secp256k1, secp256r1, ed25519, ristretto)
- Zero-trust, shared, and imported-key dWallet creation
- Presign and global presign operations
- Signing with all supported signature algorithms and hash schemes
- Future sign (two-transaction signing flow)
- Encryption key registration and user share management
- dWallet transfer via re-encryption
- Protocol public parameter caching
- State polling with exponential backoff
- System/validator operations

## Supported Curves and Algorithms

| Curve | Algorithms | Hashes |
|-------|-----------|--------|
| SECP256K1 | ECDSASecp256k1 | KECCAK256, SHA256, DoubleSHA256 |
| SECP256K1 | Taproot | SHA256 |
| SECP256R1 | ECDSASecp256r1 | SHA256 |
| ED25519 | EdDSA | SHA512 |
| RISTRETTO | SchnorrkelSubstrate | Merlin |

## Testing

```bash
# Unit tests (no network required)
bun run test:unit

# Integration tests (requires Ika localnet)
bun run test:integration
```

### Running Localnet

```bash
# Terminal 1 — Sui
RUST_LOG="off,sui_node=info" sui start --with-faucet --force-regenesis --epoch-duration-ms 1000000000000000

# Terminal 2 — Ika
cd path/to/ika && cargo run --bin ika --release --no-default-features -- start
```

## License

BSD-3-Clause-Clear
