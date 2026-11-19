//! PKCS#7 padding and constant-time-style unpadding for 16-byte AES blocks.

use super::AesError;
use super::cipher::BLOCK_SIZE;

/// Appends PKCS#7 padding bytes so the output is a non-zero multiple of 16 bytes.
pub fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let pad_len = BLOCK_SIZE - (data.len() % BLOCK_SIZE);
    let mut padded = Vec::with_capacity(data.len() + pad_len);
    padded.extend_from_slice(data);
    padded.resize(data.len() + pad_len, pad_len as u8);
    padded
}

/// Validates and strips PKCS#7 padding from a block-aligned byte slice.
///
/// Inspects every byte of the final 16-byte block without early returns to avoid
/// short-circuiting padding validation.
pub fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>, AesError> {
    if data.is_empty() || data.len() % BLOCK_SIZE != 0 {
        return Err(AesError::InvalidPadding);
    }

    let last_block = &data[data.len() - BLOCK_SIZE..];
    let pad_byte = last_block[BLOCK_SIZE - 1];
    let pad_len = pad_byte as usize;

    let mut diff = u8::from(pad_len == 0 || pad_len > BLOCK_SIZE);
    let pad_start = BLOCK_SIZE.saturating_sub(pad_len);

    for (idx, &byte) in last_block.iter().enumerate() {
        let mask = 0u8.wrapping_sub(u8::from(idx >= pad_start));
        diff |= mask & (byte ^ pad_byte);
    }

    if diff != 0 {
        return Err(AesError::InvalidPadding);
    }

    Ok(data[..data.len() - pad_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_boundary_lengths() {
        for len in [0usize, 1, 15, 16, 17, 32] {
            let input: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7).wrapping_add(3)).collect();
            let padded = pkcs7_pad(&input);

            assert_ne!(padded.len(), 0);
            assert_eq!(padded.len() % BLOCK_SIZE, 0);

            let expected_pad = BLOCK_SIZE - (len % BLOCK_SIZE);
            assert_eq!(padded.len(), len + expected_pad);
            assert!(padded[len..].iter().all(|&b| b == expected_pad as u8));

            let unpadded = pkcs7_unpad(&padded).expect("valid padding should unpad");
            assert_eq!(unpadded, input);
        }
    }

    #[test]
    fn rejects_empty_and_unaligned_inputs() {
        assert_eq!(pkcs7_unpad(&[]), Err(AesError::InvalidPadding));
        for len in [1usize, 15, 17, 31] {
            let buf = vec![0x01u8; len];
            assert_eq!(pkcs7_unpad(&buf), Err(AesError::InvalidPadding));
        }
    }

    #[test]
    fn rejects_out_of_range_pad_bytes() {
        let mut zero_pad = [0x41u8; BLOCK_SIZE];
        zero_pad[BLOCK_SIZE - 1] = 0x00;
        assert_eq!(pkcs7_unpad(&zero_pad), Err(AesError::InvalidPadding));

        let mut seventeen_pad = [0x11u8; BLOCK_SIZE * 2];
        seventeen_pad[BLOCK_SIZE * 2 - 1] = 0x11;
        assert_eq!(pkcs7_unpad(&seventeen_pad), Err(AesError::InvalidPadding));

        let mut ff_pad = [0xffu8; BLOCK_SIZE];
        ff_pad[BLOCK_SIZE - 1] = 0xff;
        assert_eq!(pkcs7_unpad(&ff_pad), Err(AesError::InvalidPadding));
    }

    #[test]
    fn rejects_corrupted_multi_byte_pad() {
        let mut padded = pkcs7_pad(b"hello world"); // 11 bytes -> 5 bytes of 0x05
        assert_eq!(padded.len(), BLOCK_SIZE);
        // Corrupt the first padding byte while leaving the trailing byte intact.
        padded[11] = 0x04;
        assert_eq!(pkcs7_unpad(&padded), Err(AesError::InvalidPadding));

        // Corrupt an interior padding byte in a 2-block full-block padding case.
        let mut full_block_pad = pkcs7_pad(&[0xaa; 16]);
        assert_eq!(full_block_pad.len(), 32);
        full_block_pad[20] ^= 0x01;
        assert_eq!(pkcs7_unpad(&full_block_pad), Err(AesError::InvalidPadding));
    }

    #[test]
    fn rejects_non_lsb_corrupted_pad_bytes() {
        // 11 bytes -> 5 bytes of 0x05; flipping bits 1 or 7 preserves bit 0.
        let base_odd = pkcs7_pad(b"hello world");
        for bit_mask in [0x02u8, 0x80u8] {
            let mut corrupted = base_odd.clone();
            corrupted[11] ^= bit_mask;
            assert_eq!(pkcs7_unpad(&corrupted), Err(AesError::InvalidPadding));
        }

        // 12 bytes -> 4 bytes of 0x04 (even); zeroing an earlier pad byte preserves bit 0.
        let mut base_even = pkcs7_pad(&[0x42; 12]);
        assert_eq!(base_even[15], 0x04);
        base_even[12] = 0x00;
        assert_eq!(pkcs7_unpad(&base_even), Err(AesError::InvalidPadding));
    }
}
