//! Vault file format and operations.
//!
//! A vault file is: MAGIC (8) | nonce (12) | ciphertext | tag (32).
//! The ciphertext is the plaintext encrypted with AES-256-CTR under the
//! encryption key; the tag is HMAC-SHA256(nonce || ciphertext) under the
//! MAC key. A key file holds exactly 64 bytes: 32 encryption key, then
//! 32 MAC key. Verifying the tag happens before any plaintext is released.

use crate::aes::Aes256;
use crate::rand::fill_random;
use crate::sha256::hmac_sha256;
use std::fs;
use std::path::Path;

pub const MAGIC: [u8; 8] = *b"DENVLT01";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 32;

/// The two halves of a key file.
#[derive(Clone, Copy)]
pub struct VaultKey {
    pub enc: [u8; 32],
    pub mac: [u8; 32],
}

pub const KEY_FILE_LEN: usize = 64;

/// Read and sanity-check a key file.
pub fn load_key(path: &Path) -> Result<VaultKey, String> {
    let raw = fs::read(path).map_err(|e| format!("cannot read key file {}: {}", path.display(), e))?;
    if raw.len() != KEY_FILE_LEN {
        return Err(format!(
            "key file {} must be exactly {} bytes of raw key material (got {})",
            path.display(),
            KEY_FILE_LEN,
            raw.len()
        ));
    }
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    enc.copy_from_slice(&raw[..32]);
    mac.copy_from_slice(&raw[32..]);
    Ok(VaultKey { enc, mac })
}

/// Write a fresh 64-byte key file. Fails if the file already exists, so a
/// rotation never clobbers the current key by accident.
pub fn create_key(path: &Path) -> Result<VaultKey, String> {
    if path.exists() {
        return Err(format!(
            "key file {} already exists; refusing to overwrite (use a new path)",
            path.display()
        ));
    }
    let mut key = VaultKey { enc: [0; 32], mac: [0; 32] };
    fill_random(&mut key.enc)?;
    fill_random(&mut key.mac)?;
    let mut raw = [0u8; KEY_FILE_LEN];
    raw[..32].copy_from_slice(&key.enc);
    raw[32..].copy_from_slice(&key.mac);
    fs::write(path, raw).map_err(|e| format!("cannot write key file {}: {}", path.display(), e))?;
    Ok(key)
}

/// Encrypt plaintext under the key and return the vault file bytes.
pub fn encrypt(key: &VaultKey, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    let cipher = Aes256::new(&key.enc);
    let mut ciphertext = plaintext.to_vec();
    cipher.ctr_xor(&nonce, &mut ciphertext);

    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len() + TAG_LEN);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    let tag = hmac_sha256(&key.mac, &out[MAGIC.len()..]);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Decrypt and verify a vault file. The tag is checked before the
/// plaintext is returned, so tampered files yield an error, not garbage.
pub fn decrypt(key: &VaultKey, vault: &[u8]) -> Result<Vec<u8>, String> {
    let min_len = MAGIC.len() + NONCE_LEN + TAG_LEN;
    if vault.len() < min_len {
        return Err(format!("vault too short: {} bytes, minimum {}", vault.len(), min_len));
    }
    if vault[..MAGIC.len()] != MAGIC {
        return Err("not a dotenv-vault file (bad magic)".to_string());
    }
    let body_len = vault.len() - TAG_LEN;
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&vault[body_len..]);
    let expected = hmac_sha256(&key.mac, &vault[MAGIC.len()..body_len]);
    // constant-time-ish comparison
    let mut diff = 0u8;
    for (a, b) in tag.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err("authentication failed: file was modified or the key is wrong".to_string());
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&vault[MAGIC.len()..MAGIC.len() + NONCE_LEN]);
    let mut ciphertext = vault[MAGIC.len() + NONCE_LEN..body_len].to_vec();
    let cipher = Aes256::new(&key.enc);
    cipher.ctr_xor(&nonce, &mut ciphertext);
    Ok(ciphertext)
}

/// Re-encrypt a vault under a new key: decrypt with `old`, encrypt the
/// plaintext with `new`. Returns the new vault bytes.
pub fn rotate(old: &VaultKey, new: &VaultKey, vault: &[u8]) -> Result<Vec<u8>, String> {
    let plaintext = decrypt(old, vault)?;
    encrypt(new, &plaintext)
}

/// Write a vault file with owner-only permissions (best effort on platforms
/// that support the mode bits).
pub fn write_vault(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(seed: u8) -> VaultKey {
        VaultKey {
            enc: [seed; 32],
            mac: [seed.wrapping_add(1); 32],
        }
    }

    #[test]
    fn round_trip() {
        let key = test_key(1);
        let vault = encrypt(&key, b"API_KEY=secret\n").unwrap();
        assert_eq!(decrypt(&key, &vault).unwrap(), b"API_KEY=secret\n");
        assert_eq!(&vault[..8], &MAGIC);
    }

    #[test]
    fn empty_and_large_payloads() {
        let key = test_key(2);
        let empty = encrypt(&key, b"").unwrap();
        assert!(decrypt(&key, &empty).unwrap().is_empty());
        let big: Vec<u8> = (0..100_000u32).map(|i| (i * 31 % 251) as u8).collect();
        let vault = encrypt(&key, &big).unwrap();
        assert_eq!(decrypt(&key, &vault).unwrap(), big);
    }

    #[test]
    fn every_flipped_byte_is_detected() {
        let key = test_key(3);
        let plaintext = b"DB_PASSWORD=hunter2\nSERVER=prod\n";
        let vault = encrypt(&key, plaintext).unwrap();
        // flip each byte of nonce/ciphertext/tag in turn
        for i in MAGIC.len()..vault.len() {
            let mut tampered = vault.clone();
            tampered[i] ^= 0x01;
            assert!(
                decrypt(&key, &tampered).is_err(),
                "flip at byte {} must be caught",
                i
            );
        }
    }

    #[test]
    fn wrong_key_fails() {
        let vault = encrypt(&test_key(4), b"secret").unwrap();
        assert!(decrypt(&test_key(5), &vault).is_err());
    }

    #[test]
    fn truncated_vault_fails() {
        let vault = encrypt(&test_key(6), b"secret").unwrap();
        assert!(decrypt(&test_key(6), &vault[..vault.len() - 1]).is_err());
        assert!(decrypt(&test_key(6), &vault[..10]).is_err());
    }

    #[test]
    fn same_plaintext_different_vaults() {
        let key = test_key(7);
        let a = encrypt(&key, b"same").unwrap();
        let b = encrypt(&key, b"same").unwrap();
        assert_ne!(a, b, "fresh nonce must produce different vault bytes");
    }

    #[test]
    fn rotation_reencrypts() {
        let old = test_key(8);
        let new = test_key(9);
        let vault = encrypt(&old, b"TOKEN=abc").unwrap();
        let rotated = rotate(&old, &new, &vault).unwrap();
        assert_eq!(decrypt(&new, &rotated).unwrap(), b"TOKEN=abc");
        assert!(decrypt(&old, &rotated).is_err());
    }
}
