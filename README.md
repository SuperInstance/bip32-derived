# bip32-derived

**BIP-32 hierarchical deterministic (HD) key derivation — master key generation, child key derivation, and path-based wallet tree construction.**

BIP-32 defines a tree structure for deriving cryptographic keys from a single master seed. Each node in the tree produces child keys via HMAC-SHA512, enabling unlimited addresses from one backup. The derivation supports both **normal** (non-hardened) children — which can be derived from extended public keys — and **hardened** children — which require the private key and break the parent-to-child link for security.

## Why It Matters

HD wallets are the backbone of modern cryptocurrency infrastructure:

- **BIP-44 wallet structure** — `m/44'/0'/0'/0/0` defines account hierarchies used by every major wallet (Ledger, Trezor, Electrum, MetaMask).
- **Address privacy** — Each transaction uses a fresh address derived from the tree, preventing address reuse and linking.
- **Hierarchical delegation** — A parent xpub can generate child public keys for watch-only wallets, without exposing private keys.
- **Multi-currency** — One seed generates keys for Bitcoin, Ethereum, and any BIP-44-compatible coin via different purpose/account branches.
- **Hardware wallets** — Secure enclaves store the seed and derive keys on-device, never exposing the master key.

The cryptographic guarantee: deriving child keys is computationally cheap (one HMAC-SHA512), but reversing derivation (child → parent) is as hard as breaking ECDSA.

## How It Works

### Master Key Generation

From a random seed S (128–512 bits, typically 256):

> I = HMAC-SHA512(key = "Bitcoin seed", data = S)  
> master_key = I[0:32]  
> master_chain_code = I[32:64]

### Child Key Derivation

For a parent key K_p with chain code C_p, deriving child at index i:

**Normal (i < 2³¹):**

> I = HMAC-SHA512(key = C_p, data = point(K_p) || ser32(i))  
> child_key = (parse256(I[0:32]) + K_p) mod n  
> child_chain = I[32:64]

**Hardened (i ≥ 2³¹):**

> I = HMAC-SHA512(key = C_p, data = 0x00 || ser256(K_p) || ser32(i))  
> child_key = (parse256(I[0:32]) + K_p) mod n  
> child_chain = I[32:64]

where n = 1.158 × 10⁷⁷ (the order of the secp256k1 curve).

Key differences:
- **Normal**: Uses the compressed public key point(K_p) → can be derived from xpub alone
- **Hardened**: Uses the raw private key ser256(K_p) → requires the private key, breaking upward derivation

### Index Encoding

- **Normal indices**: 0 to 2³¹ - 1 (0x00000000 to 0x7FFFFFFF)
- **Hardened indices**: 2³¹ to 2³² - 1 (0x80000000 to 0xFFFFFFFF), often written as i' or iH

Path notation: `m/44'/0'/0'/0/0`

| Component | Meaning | Index |
|-----------|---------|-------|
| m | Master key | — |
| 44' | Purpose (BIP-44) | 44 + 2³¹ |
| 0' | Coin type (Bitcoin) | 0 + 2³¹ |
| 0' | Account | 0 + 2³¹ |
| 0 | External chain (receiving) | 0 |
| 0 | Address index | 0 |

### Fingerprint

The 4-byte parent fingerprint identifies the parent key in serialized extended keys:

> fingerprint = HASH160(compressed_pubkey)[0:4]

where HASH160 = RIPEMD160(SHA256(pubkey)).

### Security Properties

1. **Forward secrecy**: Knowing a parent key reveals all normal children. Hardened children remain secret.
2. **Backward secrecy**: Knowing a child key does NOT reveal the parent (ECDSA hardness).
3. **Cross-branch secrecy**: Siblings are independent under HMAC — knowing one child reveals nothing about another.

### Complexity

| Operation | Time | Notes |
|-----------|------|-------|
| Master key from seed | O(1) | One HMAC-SHA512 |
| Child derivation (normal) | O(1) | HMAC + EC point add |
| Child derivation (hardened) | O(1) | HMAC + EC scalar add |
| Path derivation (depth d) | O(d) | d sequential derivations |
| Fingerprint | O(1) | HASH160 of pubkey |

## Quick Start

```rust
// This crate runs as a binary demo
// Run: cargo run

use bip32_derived::ExtendedPrivateKey;

let master = ExtendedPrivateKey::new([0xABu8; 32], [0xCDu8; 32]);
println!("Master depth: {}", master.depth());

// Derive m/44'/0'/0' (BIP-44 account)
let account = master.derive_path("m/44'/0'/0'").unwrap();
println!("Account depth: {}", account.depth());

// Derive external chain address 0
let external = account.derive_child(0).unwrap();
let address = external.derive_child(0).unwrap();
println!("Address depth: {}", address.depth());
println!("Address key[:8]: {:02X?}", &address.key()[..8]);
```

## API

- **`ExtendedPrivateKey`** — { key: [u8; 32], chain_code: [u8; 32], depth, parent_fingerprint, child_index }
  - `new(key, chain_code)` — Create master key (depth = 0)
  - `derive_child(index) → Result<Self, &str>` — Normal derivation (index < 2³¹)
  - `derive_child_hardened(index) → Result<Self, &str>` — Hardened derivation
  - `derive_path("m/44'/0'/0'/0/0") → Result<Self, &str>` — Full path derivation
  - `fingerprint() → [u8; 4]` — Parent fingerprint
  - `depth() → u8`, `key() → &[u8; 32]`

## Architecture Notes

The γ+η=C identity: γ (generative capacity) is the size of the derivable key space — 2³² children per node, unlimited depth. η (evaluative depth) is the cryptographic security — HMAC-SHA512 + secp256k1 ensure child keys are indistinguishable from random without the chain code. C = wallet utility: a system that can derive unlimited keys (high γ) while maintaining cryptographic unlinkability (high η) enables practical self-custody at scale. The hardened/normal distinction is the γ/η tradeoff knob: hardened reduces γ (can't derive from xpub) but increases η (stronger isolation).

## References

1. Wuille, P. (2012). BIP-32: "Hierarchical Deterministic Wallets." — Core specification.
2. Wuille, P. (2014). BIP-44: "Multi-Account Hierarchy for Deterministic Wallets." — Wallet structure.
3. Antonopoulos, A. (2014). *Mastering Bitcoin*, Ch. 5. — HD wallet walkthrough.
4. RFC 5869 (2010). "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)." — HMAC-SHA512 design rationale.

## License

MIT
