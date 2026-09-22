//! Random key generation from the OS entropy pool.

use std::fs::File;
use std::io::Read;

/// Fill the buffer with cryptographically secure random bytes from
/// /dev/urandom (non-blocking after first boot on every supported OS).
pub fn fill_random(buf: &mut [u8]) -> Result<(), String> {
    let mut file = File::open("/dev/urandom").map_err(|e| format!("cannot open /dev/urandom: {}", e))?;
    file.read_exact(buf)
        .map_err(|e| format!("cannot read /dev/urandom: {}", e))
}

/// Generate a fresh 32-byte key.
pub fn generate_key() -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    fill_random(&mut key)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_random_and_unique() {
        let a = generate_key().unwrap();
        let b = generate_key().unwrap();
        assert_ne!(a, b, "two generated keys must never collide");
        assert!(a.iter().any(|&x| x != 0));
    }
}
