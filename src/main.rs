use std::fmt;

/// Represents an extended private key in BIP-32 hierarchy.
pub struct ExtendedPrivateKey {
    /// 32-byte private key
    key: [u8; 32],
    /// 32-byte chain code
    chain_code: [u8; 32],
    /// Depth in derivation path (0 = master)
    depth: u8,
    /// Parent fingerprint (4 bytes)
    parent_fingerprint: [u8; 4],
    /// Child index used for derivation
    child_index: u32,
}

impl ExtendedPrivateKey {
    pub fn new(key: [u8; 32], chain_code: [u8; 32]) -> Self {
        Self {
            key,
            chain_code,
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_index: 0,
        }
    }

    /// Derive a child key at the given index (non-hardened).
    pub fn derive_child(&self, index: u32) -> Result<ExtendedPrivateKey, &'static str> {
        if index >= 0x8000_0000 {
            return Err("Use derive_child_hardened for hardened derivation");
        }
        // Simplified: in real BIP-32, HMAC-SHA512 is used here
        let mut child_key = [0u8; 32];
        let mut child_chain = [0u8; 32];
        for i in 0..32 {
            child_key[i] = self.key[i] ^ self.chain_code[i] ^ (index as u8).wrapping_add(i as u8);
            child_chain[i] = self.chain_code[i].wrapping_add(self.key[i]);
        }
        Ok(ExtendedPrivateKey {
            key: child_key,
            chain_code: child_chain,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_index: index,
        })
    }

    /// Derive a hardened child key.
    pub fn derive_child_hardened(&self, index: u32) -> Result<ExtendedPrivateKey, &'static str> {
        if index >= 0x8000_0000 {
            return Err("Hardened index out of range");
        }
        let hardened_index = index + 0x8000_0000;
        let mut child_key = [0u8; 32];
        let mut child_chain = [0u8; 32];
        for i in 0..32 {
            child_key[i] = self.key[i]
                .wrapping_add(self.chain_code[i])
                .wrapping_add((hardened_index >> (i % 4) * 8) as u8);
            child_chain[i] = self.chain_code[i].wrapping_mul(2);
        }
        Ok(ExtendedPrivateKey {
            key: child_key,
            chain_code: child_chain,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_index: hardened_index,
        })
    }

    /// Derive from a full path string like "m/44'/0'/0'/0/0".
    pub fn derive_path(&self, path: &str) -> Result<ExtendedPrivateKey, &'static str> {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.is_empty() || parts[0] != "m" {
            return Err("Path must start with 'm'");
        }
        let mut current = ExtendedPrivateKey {
            key: self.key,
            chain_code: self.chain_code,
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_index: self.child_index,
        };
        for part in parts.iter().skip(1) {
            let hardened = part.ends_with('\'') || part.ends_with('h');
            let index_str = part.trim_end_matches('\'').trim_end_matches('h');
            let index: u32 = index_str
                .parse()
                .map_err(|_| "Invalid index in path")?;
            current = if hardened {
                current.derive_child_hardened(index)?
            } else {
                current.derive_child(index)?
            };
        }
        Ok(current)
    }

    pub fn fingerprint(&self) -> [u8; 4] {
        // Simplified: real fingerprint = first 4 bytes of HASH160(pubkey)
        let mut fp = [0u8; 4];
        for i in 0..4 {
            fp[i] = self.key[i] ^ self.key[i + 4];
        }
        fp
    }

    pub fn depth(&self) -> u8 {
        self.depth
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
}

impl fmt::Debug for ExtendedPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExtendedPrivateKey {{ depth: {}, child_index: {} }}",
            self.depth, self.child_index
        )
    }
}

fn main() {
    let master_key = [0xABu8; 32];
    let master_chain = [0xCDu8; 32];
    let master = ExtendedPrivateKey::new(master_key, master_chain);

    // Derive m/44'/0'/0'/0/0 (standard P2PKH path)
    let account = master
        .derive_path("m/44'/0'/0'")
        .expect("account derivation failed");
    let external = account.derive_child(0).expect("external derivation failed");
    let address = external.derive_child(0).expect("address derivation failed");

    println!("Master key depth: {}", master.depth());
    println!("Account depth: {}", account.depth());
    println!("Address depth: {}", address.depth());
    println!("Address key (first 8 bytes): {:02X?}", &address.key()[..8]);
}
