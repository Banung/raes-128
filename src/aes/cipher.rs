//! FIPS 197 AES-128 block cipher and key expansion.

use super::AesError;
use super::tables::{INV_SBOX, RCON, SBOX, gf_mul};

/// AES block size in bytes (128 bits).
pub const BLOCK_SIZE: usize = 16;

/// AES-128 key size in bytes (128 bits).
pub const KEY_SIZE: usize = 16;

const NUM_ROUNDS: usize = 10;

/// Core AES-128 block cipher storing the 11 expanded 128-bit round keys.
#[derive(Debug, Clone)]
pub struct Aes128 {
    round_keys: [[u8; BLOCK_SIZE]; NUM_ROUNDS + 1],
}

impl Aes128 {
    /// Creates an [`Aes128`] instance by expanding the 16-byte cipher key per FIPS 197 Section 5.2.
    pub fn new(key: [u8; KEY_SIZE]) -> Self {
        Self {
            round_keys: expand_key(key),
        }
    }

    /// Creates an [`Aes128`] instance from a byte slice after validating its 16-byte length.
    pub fn from_slice(key: &[u8]) -> Result<Self, AesError> {
        let key_bytes: [u8; KEY_SIZE] = key.try_into().map_err(|_| AesError::InvalidKeyLength {
            expected: KEY_SIZE,
            actual: key.len(),
        })?;
        Ok(Self::new(key_bytes))
    }

    /// Encrypts a single 16-byte block using AES-128 (FIPS 197 Section 5.1).
    pub fn encrypt_block(&self, block: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        let mut state = block;
        add_round_key(&mut state, &self.round_keys[0]);

        for round in 1..NUM_ROUNDS {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            add_round_key(&mut state, &self.round_keys[round]);
        }

        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, &self.round_keys[NUM_ROUNDS]);
        state
    }

    /// Decrypts a single 16-byte block using AES-128 (FIPS 197 Section 5.3).
    pub fn decrypt_block(&self, block: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        let mut state = block;
        add_round_key(&mut state, &self.round_keys[NUM_ROUNDS]);

        for round in (1..NUM_ROUNDS).rev() {
            inv_shift_rows(&mut state);
            inv_sub_bytes(&mut state);
            add_round_key(&mut state, &self.round_keys[round]);
            inv_mix_columns(&mut state);
        }

        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, &self.round_keys[0]);
        state
    }
}

fn expand_key(key: [u8; KEY_SIZE]) -> [[u8; BLOCK_SIZE]; NUM_ROUNDS + 1] {
    let mut words = [[0u8; 4]; 4 * (NUM_ROUNDS + 1)];

    for (i, chunk) in key.chunks_exact(4).enumerate() {
        words[i] = [chunk[0], chunk[1], chunk[2], chunk[3]];
    }

    for i in 4..words.len() {
        let mut temp = words[i - 1];
        if i % 4 == 0 {
            temp = sub_word(rot_word(temp));
            temp[0] ^= RCON[(i / 4) - 1];
        }
        let prev = words[i - 4];
        words[i] = [
            prev[0] ^ temp[0],
            prev[1] ^ temp[1],
            prev[2] ^ temp[2],
            prev[3] ^ temp[3],
        ];
    }

    let mut round_keys = [[0u8; BLOCK_SIZE]; NUM_ROUNDS + 1];
    for (round, rk) in round_keys.iter_mut().enumerate() {
        for col in 0..4 {
            let word = words[round * 4 + col];
            rk[col * 4..col * 4 + 4].copy_from_slice(&word);
        }
    }
    round_keys
}

#[inline]
fn rot_word(word: [u8; 4]) -> [u8; 4] {
    [word[1], word[2], word[3], word[0]]
}

#[inline]
fn sub_word(word: [u8; 4]) -> [u8; 4] {
    [
        SBOX[word[0] as usize],
        SBOX[word[1] as usize],
        SBOX[word[2] as usize],
        SBOX[word[3] as usize],
    ]
}

#[inline]
fn add_round_key(state: &mut [u8; BLOCK_SIZE], round_key: &[u8; BLOCK_SIZE]) {
    for (s, &k) in state.iter_mut().zip(round_key.iter()) {
        *s ^= k;
    }
}

#[inline]
fn sub_bytes(state: &mut [u8; BLOCK_SIZE]) {
    for byte in state.iter_mut() {
        *byte = SBOX[*byte as usize];
    }
}

#[inline]
fn inv_sub_bytes(state: &mut [u8; BLOCK_SIZE]) {
    for byte in state.iter_mut() {
        *byte = INV_SBOX[*byte as usize];
    }
}

// Column-major layout: element at (row r, col c) is state[4 * c + r].
#[inline]
fn shift_rows(state: &mut [u8; BLOCK_SIZE]) {
    // Row 1: cyclic left shift by 1.
    let tmp1 = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = tmp1;

    // Row 2: cyclic left shift by 2.
    state.swap(2, 10);
    state.swap(6, 14);

    // Row 3: cyclic left shift by 3 (right shift by 1).
    let tmp3 = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = tmp3;
}

#[inline]
fn inv_shift_rows(state: &mut [u8; BLOCK_SIZE]) {
    // Row 1: cyclic right shift by 1.
    let tmp1 = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = tmp1;

    // Row 2: cyclic right shift by 2.
    state.swap(2, 10);
    state.swap(6, 14);

    // Row 3: cyclic right shift by 3 (left shift by 1).
    let tmp3 = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = tmp3;
}

fn mix_columns(state: &mut [u8; BLOCK_SIZE]) {
    for col in 0..4 {
        let base = col * 4;
        let s0 = state[base];
        let s1 = state[base + 1];
        let s2 = state[base + 2];
        let s3 = state[base + 3];

        state[base] = gf_mul(0x02, s0) ^ gf_mul(0x03, s1) ^ s2 ^ s3;
        state[base + 1] = s0 ^ gf_mul(0x02, s1) ^ gf_mul(0x03, s2) ^ s3;
        state[base + 2] = s0 ^ s1 ^ gf_mul(0x02, s2) ^ gf_mul(0x03, s3);
        state[base + 3] = gf_mul(0x03, s0) ^ s1 ^ s2 ^ gf_mul(0x02, s3);
    }
}

fn inv_mix_columns(state: &mut [u8; BLOCK_SIZE]) {
    for col in 0..4 {
        let base = col * 4;
        let s0 = state[base];
        let s1 = state[base + 1];
        let s2 = state[base + 2];
        let s3 = state[base + 3];

        state[base] = gf_mul(0x0e, s0) ^ gf_mul(0x0b, s1) ^ gf_mul(0x0d, s2) ^ gf_mul(0x09, s3);
        state[base + 1] =
            gf_mul(0x09, s0) ^ gf_mul(0x0e, s1) ^ gf_mul(0x0b, s2) ^ gf_mul(0x0d, s3);
        state[base + 2] =
            gf_mul(0x0d, s0) ^ gf_mul(0x09, s1) ^ gf_mul(0x0e, s2) ^ gf_mul(0x0b, s3);
        state[base + 3] =
            gf_mul(0x0b, s0) ^ gf_mul(0x0d, s1) ^ gf_mul(0x09, s2) ^ gf_mul(0x0e, s3);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips_197_appendix_b_vector() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let plaintext: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];
        let expected_ciphertext: [u8; 16] = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
            0x0b, 0x32,
        ];

        let cipher = Aes128::new(key);
        let ciphertext = cipher.encrypt_block(plaintext);
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(cipher.decrypt_block(ciphertext), plaintext);
    }

    #[test]
    fn fips_197_appendix_c1_vector() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected_ciphertext: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];

        let cipher = Aes128::new(key);
        let ciphertext = cipher.encrypt_block(plaintext);
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(cipher.decrypt_block(ciphertext), plaintext);
    }

    #[test]
    fn from_slice_validates_key_length() {
        assert!(Aes128::from_slice(&[0u8; 16]).is_ok());

        for bad_len in [0, 15, 17, 32] {
            let err = Aes128::from_slice(&vec![0u8; bad_len]).unwrap_err();
            assert_eq!(
                err,
                AesError::InvalidKeyLength {
                    expected: 16,
                    actual: bad_len,
                }
            );
        }
    }
}
