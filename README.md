# BIP32 Derived

**A Rust library for hierarchical deterministic (HD) key derivation** per BIP-32 — the standard for deriving hierarchical cryptocurrency key pairs from a single master seed.

## Why It Matters

BIP-32 (Bitcoin Improvement Proposal 32) solved a fundamental problem in cryptocurrency wallet design: managing thousands of addresses without storing thousands of private keys. Instead, a single master seed deterministically generates an entire tree of key pairs.

Key innovations:
- **Hierarchical derivation**: Keys are organized in a tree. Parent keys derive child keys, which derive grandchildren, enabling organized account structures (e.g., `m/44'/0'/0'/0/0` for the first Bitcoin address).
- **Hardened vs. non-hardened**: Hardened derivation (index ≥ 2³¹) requires the private key; non-hardened can derive from just the public key, enabling watch-only wallets.
- **Account separation**: Standard derivation paths (BIP-44) organize keys by coin type, account, change, and address index.

The derivation path `m/44'/0'/0'/0/0` means: purpose 44 (BIP-44) → coin 0 (Bitcoin) → account 0 → external chain → address 0.

## How It Works

**Extended keys**: An `ExtendedPrivateKey` bundles a 32-byte private key with a 32-byte chain code. The chain code provides the "extra entropy" that makes child keys unpredictable even if one child key is compromised.

**Non-hardened derivation** (index < 2³¹): Computes `HMAC-SHA512(chain_code, parent_pubkey || index)`. The first 32 bytes are added to the parent private key to produce the child private key; the last 32 bytes become the child chain code. Because this uses the parent *public* key, anyone with the parent public key and chain code can derive child public keys.

**Hardened derivation** (index ≥ 2³¹): Uses `HMAC-SHA512(chain_code, parent_private_key || index)` instead. This requires the private key and prevents the chain from being extended by observers with only the public key.

**Path derivation**: The `derive_path("m/44'/0'/0'/0/0")` method parses the path string, splits on `/`, identifies hardened indices (suffix `'` or `h`), and chains child derivations.

**Fingerprint**: A 4-byte identifier computed from the parent key, used in human-readable key representations (xpub/xprv).

## Quick Start

```rust
use bip32_derived::ExtendedPrivateKey;

let master = ExtendedPrivateKey::new([0xAB; 32], [0xCD; 32]);

// Derive standard BIP-44 path: m/44'/0'/0'
let account = master.derive_path("m/44'/0'/0'").unwrap();

// Non-hardened child (external chain, first address)
let address_key = account.derive_child(0).unwrap().derive_child(0).unwrap();

println!("Master depth: {}", master.depth());
println!("Address depth: {}", address_key.depth());
println!("Key: {:02X?}", &address_key.key()[..8]);
```

## API

- **`ExtendedPrivateKey`** — 32-byte key + 32-byte chain code + depth + parent fingerprint
  - `new(key, chain_code)` — Create master key at depth 0
  - `derive_child(index)` — Non-hardened child derivation
  - `derive_child_hardened(index)` — Hardened child derivation
  - `derive_path("m/44'/0'/0'/0/0")` — Full path derivation
  - `fingerprint()` → `[u8; 4]` — Key fingerprint
  - `depth()` → `u8` — Depth in derivation tree

## Architecture Notes

Provides HD wallet key derivation for SuperInstance blockchain tooling. The simplified HMAC (using XOR instead of real HMAC-SHA512) is for demonstration — production use requires a cryptographic HMAC-SHA512 implementation. See the [architecture overview](https://github.com/SuperInstance/SuperInstance/blob/main/ARCHITECTURE.md).

## License

MIT
