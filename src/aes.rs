//! AES-256 block cipher and CTR mode, implemented from FIPS-197.

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
    0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
    0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
    0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
    0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
    0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
    0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
    0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
    0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
    0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
    0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
    0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
    0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
    0x16,
];

const RCON: [u8; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

fn xtime(a: u8) -> u8 {
    // multiply by x in GF(2^8)
    (a << 1) ^ if a & 0x80 != 0 { 0x1b } else { 0 }
}

/// Expanded AES-256 round keys: 15 * 16 bytes.
pub struct Aes256 {
    round_keys: [[u8; 16]; 15],
}

impl Aes256 {
    pub fn new(key: &[u8; 32]) -> Aes256 {
        // Key expansion: 8 words initial, 7 rounds of expansion to 60 words.
        let mut words = [[0u8; 4]; 60];
        for (i, word) in words.iter_mut().enumerate().take(8) {
            *word = [
                key[4 * i],
                key[4 * i + 1],
                key[4 * i + 2],
                key[4 * i + 3],
            ];
        }
        for i in 8..60 {
            let mut temp = words[i - 1];
            if i % 8 == 0 {
                temp.rotate_left(1); // RotWord
                for byte in temp.iter_mut() {
                    *byte = SBOX[*byte as usize]; // SubWord
                }
                temp[0] ^= RCON[i / 8 - 1];
            } else if i % 8 == 4 {
                for byte in temp.iter_mut() {
                    *byte = SBOX[*byte as usize];
                }
            }
            for j in 0..4 {
                temp[j] ^= words[i - 8][j];
            }
            words[i] = temp;
        }
        let mut round_keys = [[0u8; 16]; 15];
        for (rk, chunk) in round_keys.iter_mut().zip(words.as_chunks::<4>().0) {
            for w in 0..4 {
                rk[w * 4..w * 4 + 4].copy_from_slice(&chunk[w]);
            }
        }
        Aes256 { round_keys }
    }

    /// Encrypt one 16-byte block in place.
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        add_round_key(block, &self.round_keys[0]);
        for round in 1..14 {
            sub_bytes(block);
            shift_rows(block);
            mix_columns(block);
            add_round_key(block, &self.round_keys[round]);
        }
        sub_bytes(block);
        shift_rows(block);
        add_round_key(block, &self.round_keys[14]);
    }

    /// CTR mode: XOR `data` with the keystream from `nonce` (12 bytes) and
    /// a big-endian 32-bit block counter. Encryption and decryption are
    /// the same operation.
    pub fn ctr_xor(&self, nonce: &[u8; 12], data: &mut [u8]) {
        let mut counter: u32 = 0;
        for chunk in data.chunks_mut(16) {
            let mut block = [0u8; 16];
            block[..12].copy_from_slice(nonce);
            block[12..].copy_from_slice(&counter.to_be_bytes());
            self.encrypt_block(&mut block);
            for (byte, keystream) in chunk.iter_mut().zip(block.iter()) {
                *byte ^= keystream;
            }
            counter = counter.wrapping_add(1);
        }
    }
}

fn add_round_key(block: &mut [u8; 16], key: &[u8; 16]) {
    for i in 0..16 {
        block[i] ^= key[i];
    }
}

fn sub_bytes(block: &mut [u8; 16]) {
    for byte in block.iter_mut() {
        *byte = SBOX[*byte as usize];
    }
}

fn shift_rows(block: &mut [u8; 16]) {
    // state is column-major: block[r + 4c]; row r rotates left by r.
    let old = *block;
    for r in 1..4 {
        for c in 0..4 {
            block[r + 4 * c] = old[r + 4 * ((c + r) % 4)];
        }
    }
}

fn mix_columns(block: &mut [u8; 16]) {
    for c in 0..4 {
        let col = [
            block[4 * c],
            block[4 * c + 1],
            block[4 * c + 2],
            block[4 * c + 3],
        ];
        block[4 * c] = gmul(col[0], 2) ^ gmul(col[1], 3) ^ col[2] ^ col[3];
        block[4 * c + 1] = col[0] ^ gmul(col[1], 2) ^ gmul(col[2], 3) ^ col[3];
        block[4 * c + 2] = col[0] ^ col[1] ^ gmul(col[2], 2) ^ gmul(col[3], 3);
        block[4 * c + 3] = gmul(col[0], 3) ^ col[1] ^ col[2] ^ gmul(col[3], 2);
    }
}

/// GF(2^8) multiply with the AES reduction polynomial.
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    product
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS-197 Appendix C.3: AES-256 known-answer vector.
    #[test]
    fn fips197_aes256_vector() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let mut block = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        Aes256::new(&key).encrypt_block(&mut block);
        let expected: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ];
        assert_eq!(block, expected);
    }

    #[test]
    fn ctr_is_symmetric() {
        let key: [u8; 32] = core::array::from_fn(|i| (i * 13 + 5) as u8);
        let nonce = [7u8; 12];
        let mut data: Vec<u8> = (0..100u8).collect();
        let original = data.clone();
        let cipher = Aes256::new(&key);
        cipher.ctr_xor(&nonce, &mut data);
        assert_ne!(data, original);
        cipher.ctr_xor(&nonce, &mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn different_nonces_diverge() {
        let key = [1u8; 32];
        let cipher = Aes256::new(&key);
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        cipher.ctr_xor(&[0; 12], &mut a);
        cipher.ctr_xor(&[1; 12], &mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn ctr_long_data_uses_all_counters() {
        let key = [9u8; 32];
        let cipher = Aes256::new(&key);
        // 40 bytes: three keystream blocks, the last one partial
        let mut data = [0u8; 40];
        cipher.ctr_xor(&[2; 12], &mut data);
        assert!(data[..16] != data[16..32], "counter blocks must differ");
    }
}
