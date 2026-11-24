//! AES-128 block cipher modes of operation: ECB, CBC, PCBC, CFB, OFB, and CTR.

use super::AesError;
use super::cipher::{Aes128, BLOCK_SIZE};
use super::padding::{pkcs7_pad, pkcs7_unpad};
use super::trace::{BlockTrace, FirstBlockModeTrace, TraceDirection};

/// Supported AES-128 modes of operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMode {
    Ecb,
    Cbc,
    Pcbc,
    Cfb,
    Ofb,
    Ctr,
}

impl CipherMode {
    /// All six supported cipher modes in canonical order.
    pub const ALL: [CipherMode; 6] = [
        Self::Ecb,
        Self::Cbc,
        Self::Pcbc,
        Self::Cfb,
        Self::Ofb,
        Self::Ctr,
    ];

    /// Returns `true` if this mode requires a 16-byte initialization vector / counter block.
    pub const fn requires_iv(self) -> bool {
        !matches!(self, Self::Ecb)
    }

    /// Returns the uppercase standard name of this cipher mode.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ecb => "ECB",
            Self::Cbc => "CBC",
            Self::Pcbc => "PCBC",
            Self::Cfb => "CFB",
            Self::Ofb => "OFB",
            Self::Ctr => "CTR",
        }
    }
}

/// Encrypts `plaintext` with AES-128 under the specified [`CipherMode`].
///
/// `Ecb`, `Cbc`, and `Pcbc` apply PKCS#7 padding; `Cfb`, `Ofb`, and `Ctr` operate
/// on arbitrary byte lengths without padding.
pub fn encrypt(
    mode: CipherMode,
    key: &[u8],
    iv: Option<&[u8]>,
    plaintext: &[u8],
) -> Result<Vec<u8>, AesError> {
    encrypt_inner(mode, key, iv, plaintext, false).map(|(out, _)| out)
}

/// Encrypts `plaintext` with AES-128 under `mode` and captures a first-block trace.
pub fn encrypt_with_trace(
    mode: CipherMode,
    key: &[u8],
    iv: Option<&[u8]>,
    plaintext: &[u8],
) -> Result<(Vec<u8>, Option<FirstBlockModeTrace>), AesError> {
    encrypt_inner(mode, key, iv, plaintext, true)
}

/// Decrypts `ciphertext` with AES-128 under the specified [`CipherMode`].
///
/// `Ecb`, `Cbc`, and `Pcbc` require a non-empty multiple-of-16 ciphertext length
/// and verify/strip PKCS#7 padding; `Cfb`, `Ofb`, and `Ctr` accept arbitrary byte lengths.
pub fn decrypt(
    mode: CipherMode,
    key: &[u8],
    iv: Option<&[u8]>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, AesError> {
    decrypt_inner(mode, key, iv, ciphertext, false).map(|(out, _)| out)
}

/// Decrypts `ciphertext` with AES-128 under `mode` and captures a first-block trace.
pub fn decrypt_with_trace(
    mode: CipherMode,
    key: &[u8],
    iv: Option<&[u8]>,
    ciphertext: &[u8],
) -> Result<(Vec<u8>, Option<FirstBlockModeTrace>), AesError> {
    decrypt_inner(mode, key, iv, ciphertext, true)
}

fn encrypt_inner(
    mode: CipherMode,
    key: &[u8],
    iv: Option<&[u8]>,
    plaintext: &[u8],
    capture_trace: bool,
) -> Result<(Vec<u8>, Option<FirstBlockModeTrace>), AesError> {
    let cipher = Aes128::from_slice(key)?;

    match mode {
        CipherMode::Ecb => {
            let (out, bt) = encrypt_ecb(&cipher, plaintext, capture_trace);
            let trace = bt.map(|block_trace| FirstBlockModeTrace {
                mode,
                operation: TraceDirection::Encrypt,
                note: "ECB encrypts PKCS#7-padded block 0 directly without an IV (C0 = E_K(P0))."
                    .to_string(),
                source_block: pkcs7_pad(&plaintext[..plaintext.len().min(BLOCK_SIZE)])
                    [..BLOCK_SIZE]
                    .to_vec(),
                iv: None,
                result_block: out[..BLOCK_SIZE].to_vec(),
                block_trace,
            });
            Ok((out, trace))
        }
        CipherMode::Cbc => {
            let iv_arr = require_iv(iv)?;
            let (out, bt) = encrypt_cbc(&cipher, iv_arr, plaintext, capture_trace);
            let trace = bt.map(|block_trace| FirstBlockModeTrace {
                mode,
                operation: TraceDirection::Encrypt,
                note: "CBC XORs PKCS#7-padded block 0 with IV before AES encryption (C0 = E_K(P0 XOR IV))."
                    .to_string(),
                source_block: pkcs7_pad(&plaintext[..plaintext.len().min(BLOCK_SIZE)])
                    [..BLOCK_SIZE]
                    .to_vec(),
                iv: Some(iv_arr),
                result_block: out[..BLOCK_SIZE].to_vec(),
                block_trace,
            });
            Ok((out, trace))
        }
        CipherMode::Pcbc => {
            let iv_arr = require_iv(iv)?;
            let (out, bt) = encrypt_pcbc(&cipher, iv_arr, plaintext, capture_trace);
            let trace = bt.map(|block_trace| FirstBlockModeTrace {
                mode,
                operation: TraceDirection::Encrypt,
                note: "PCBC XORs block 0 with IV (C0 = E_K(P0 XOR IV)) and propagates P_i XOR C_i to subsequent blocks."
                    .to_string(),
                source_block: pkcs7_pad(&plaintext[..plaintext.len().min(BLOCK_SIZE)])
                    [..BLOCK_SIZE]
                    .to_vec(),
                iv: Some(iv_arr),
                result_block: out[..BLOCK_SIZE].to_vec(),
                block_trace,
            });
            Ok((out, trace))
        }
        CipherMode::Cfb => {
            let iv_arr = require_iv(iv)?;
            if plaintext.is_empty() {
                return Ok((Vec::new(), None));
            }
            let (out, bt) = encrypt_cfb(&cipher, iv_arr, plaintext, capture_trace);
            let trace = stream_mode_trace(
                mode,
                TraceDirection::Encrypt,
                "CFB encrypts IV via AES-Encrypt to produce Keystream0, then XORs block 0 with Keystream0 (C0 = P0 XOR E_K(IV)).",
                plaintext,
                iv_arr,
                &out,
                bt,
            );
            Ok((out, trace))
        }
        CipherMode::Ofb => {
            let iv_arr = require_iv(iv)?;
            if plaintext.is_empty() {
                return Ok((Vec::new(), None));
            }
            let (out, bt) = apply_ofb(&cipher, iv_arr, plaintext, capture_trace);
            let trace = stream_mode_trace(
                mode,
                TraceDirection::Encrypt,
                "OFB encrypts IV via AES-Encrypt to produce Keystream0, then XORs block 0 with Keystream0 (C0 = P0 XOR E_K(IV)).",
                plaintext,
                iv_arr,
                &out,
                bt,
            );
            Ok((out, trace))
        }
        CipherMode::Ctr => {
            let counter_arr = require_iv(iv)?;
            if plaintext.is_empty() {
                return Ok((Vec::new(), None));
            }
            let (out, bt) = apply_ctr(&cipher, counter_arr, plaintext, capture_trace);
            let trace = stream_mode_trace(
                mode,
                TraceDirection::Encrypt,
                "CTR encrypts Counter0 via AES-Encrypt to produce Keystream0, then XORs block 0 with Keystream0 (C0 = P0 XOR E_K(Counter0)).",
                plaintext,
                counter_arr,
                &out,
                bt,
            );
            Ok((out, trace))
        }
    }
}

fn decrypt_inner(
    mode: CipherMode,
    key: &[u8],
    iv: Option<&[u8]>,
    ciphertext: &[u8],
    capture_trace: bool,
) -> Result<(Vec<u8>, Option<FirstBlockModeTrace>), AesError> {
    let cipher = Aes128::from_slice(key)?;

    match mode {
        CipherMode::Ecb => {
            let (out, bt) = decrypt_ecb(&cipher, ciphertext, capture_trace)?;
            let trace = bt.map(|block_trace| FirstBlockModeTrace {
                mode,
                operation: TraceDirection::Decrypt,
                note: "ECB decrypts ciphertext block 0 directly without an IV (P0 = D_K(C0))."
                    .to_string(),
                source_block: ciphertext[..BLOCK_SIZE].to_vec(),
                iv: None,
                result_block: out[..out.len().min(BLOCK_SIZE)].to_vec(),
                block_trace,
            });
            Ok((out, trace))
        }
        CipherMode::Cbc => {
            let iv_arr = require_iv(iv)?;
            let (out, bt) = decrypt_cbc(&cipher, iv_arr, ciphertext, capture_trace)?;
            let trace = bt.map(|block_trace| FirstBlockModeTrace {
                mode,
                operation: TraceDirection::Decrypt,
                note: "CBC decrypts C0 with AES then XORs with IV to recover block 0 (P0 = D_K(C0) XOR IV)."
                    .to_string(),
                source_block: ciphertext[..BLOCK_SIZE].to_vec(),
                iv: Some(iv_arr),
                result_block: out[..out.len().min(BLOCK_SIZE)].to_vec(),
                block_trace,
            });
            Ok((out, trace))
        }
        CipherMode::Pcbc => {
            let iv_arr = require_iv(iv)?;
            let (out, bt) = decrypt_pcbc(&cipher, iv_arr, ciphertext, capture_trace)?;
            let trace = bt.map(|block_trace| FirstBlockModeTrace {
                mode,
                operation: TraceDirection::Decrypt,
                note: "PCBC decrypts C0 then XORs with IV (P0 = D_K(C0) XOR IV) and propagates P_i XOR C_i to subsequent blocks."
                    .to_string(),
                source_block: ciphertext[..BLOCK_SIZE].to_vec(),
                iv: Some(iv_arr),
                result_block: out[..out.len().min(BLOCK_SIZE)].to_vec(),
                block_trace,
            });
            Ok((out, trace))
        }
        CipherMode::Cfb => {
            let iv_arr = require_iv(iv)?;
            if ciphertext.is_empty() {
                return Ok((Vec::new(), None));
            }
            let (out, bt) = decrypt_cfb(&cipher, iv_arr, ciphertext, capture_trace);
            let trace = stream_mode_trace(
                mode,
                TraceDirection::Decrypt,
                "CFB decrypts by encrypting IV via AES-Encrypt to produce Keystream0, then XORing ciphertext block 0 with Keystream0 (P0 = C0 XOR E_K(IV)).",
                ciphertext,
                iv_arr,
                &out,
                bt,
            );
            Ok((out, trace))
        }
        CipherMode::Ofb => {
            let iv_arr = require_iv(iv)?;
            if ciphertext.is_empty() {
                return Ok((Vec::new(), None));
            }
            let (out, bt) = apply_ofb(&cipher, iv_arr, ciphertext, capture_trace);
            let trace = stream_mode_trace(
                mode,
                TraceDirection::Decrypt,
                "OFB decrypts by encrypting IV via AES-Encrypt to produce Keystream0, then XORing ciphertext block 0 with Keystream0 (P0 = C0 XOR E_K(IV)).",
                ciphertext,
                iv_arr,
                &out,
                bt,
            );
            Ok((out, trace))
        }
        CipherMode::Ctr => {
            let counter_arr = require_iv(iv)?;
            if ciphertext.is_empty() {
                return Ok((Vec::new(), None));
            }
            let (out, bt) = apply_ctr(&cipher, counter_arr, ciphertext, capture_trace);
            let trace = stream_mode_trace(
                mode,
                TraceDirection::Decrypt,
                "CTR decrypts by encrypting Counter0 via AES-Encrypt to produce Keystream0, then XORing ciphertext block 0 with Keystream0 (P0 = C0 XOR E_K(Counter0)).",
                ciphertext,
                counter_arr,
                &out,
                bt,
            );
            Ok((out, trace))
        }
    }
}

fn stream_mode_trace(
    mode: CipherMode,
    operation: TraceDirection,
    note: &str,
    input: &[u8],
    iv: [u8; BLOCK_SIZE],
    output: &[u8],
    block_trace: Option<BlockTrace>,
) -> Option<FirstBlockModeTrace> {
    let first_len = input.len().min(BLOCK_SIZE);
    block_trace.map(|bt| FirstBlockModeTrace {
        mode,
        operation,
        note: note.to_string(),
        source_block: input[..first_len].to_vec(),
        iv: Some(iv),
        result_block: output[..first_len].to_vec(),
        block_trace: bt,
    })
}

fn require_iv(iv: Option<&[u8]>) -> Result<[u8; BLOCK_SIZE], AesError> {
    let slice = iv.ok_or(AesError::MissingIv)?;
    slice.try_into().map_err(|_| AesError::InvalidIvLength {
        expected: BLOCK_SIZE,
        actual: slice.len(),
    })
}

fn ensure_block_aligned(ciphertext: &[u8]) -> Result<(), AesError> {
    if ciphertext.is_empty() || ciphertext.len() % BLOCK_SIZE != 0 {
        return Err(AesError::InvalidCiphertextLength {
            actual: ciphertext.len(),
        });
    }
    Ok(())
}

fn xor_block(a: [u8; BLOCK_SIZE], b: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut out = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn to_block(slice: &[u8]) -> [u8; BLOCK_SIZE] {
    let mut block = [0u8; BLOCK_SIZE];
    block.copy_from_slice(slice);
    block
}

fn xor_stream_chunk(input: &[u8], keystream: &[u8; BLOCK_SIZE], out: &mut Vec<u8>) {
    for (&b, &k) in input.iter().zip(keystream.iter()) {
        out.push(b ^ k);
    }
}

fn encrypt_block_maybe_trace(
    cipher: &Aes128,
    block: [u8; BLOCK_SIZE],
    capture: bool,
    trace_slot: &mut Option<BlockTrace>,
) -> [u8; BLOCK_SIZE] {
    if capture && trace_slot.is_none() {
        let (out, bt) = cipher.encrypt_block_with_trace(block);
        *trace_slot = Some(bt);
        out
    } else {
        cipher.encrypt_block(block)
    }
}

fn decrypt_block_maybe_trace(
    cipher: &Aes128,
    block: [u8; BLOCK_SIZE],
    capture: bool,
    trace_slot: &mut Option<BlockTrace>,
) -> [u8; BLOCK_SIZE] {
    if capture && trace_slot.is_none() {
        let (out, bt) = cipher.decrypt_block_with_trace(block);
        *trace_slot = Some(bt);
        out
    } else {
        cipher.decrypt_block(block)
    }
}

fn encrypt_ecb(
    cipher: &Aes128,
    plaintext: &[u8],
    capture_trace: bool,
) -> (Vec<u8>, Option<BlockTrace>) {
    let padded = pkcs7_pad(plaintext);
    let mut out = Vec::with_capacity(padded.len());
    let mut trace = None;
    for chunk in padded.chunks_exact(BLOCK_SIZE) {
        let encrypted =
            encrypt_block_maybe_trace(cipher, to_block(chunk), capture_trace, &mut trace);
        out.extend_from_slice(&encrypted);
    }
    (out, trace)
}

fn decrypt_ecb(
    cipher: &Aes128,
    ciphertext: &[u8],
    capture_trace: bool,
) -> Result<(Vec<u8>, Option<BlockTrace>), AesError> {
    ensure_block_aligned(ciphertext)?;
    let mut padded = Vec::with_capacity(ciphertext.len());
    let mut trace = None;
    for chunk in ciphertext.chunks_exact(BLOCK_SIZE) {
        let decrypted =
            decrypt_block_maybe_trace(cipher, to_block(chunk), capture_trace, &mut trace);
        padded.extend_from_slice(&decrypted);
    }
    let unpadded = pkcs7_unpad(&padded)?;
    Ok((unpadded, trace))
}

fn encrypt_cbc(
    cipher: &Aes128,
    iv: [u8; BLOCK_SIZE],
    plaintext: &[u8],
    capture_trace: bool,
) -> (Vec<u8>, Option<BlockTrace>) {
    let padded = pkcs7_pad(plaintext);
    let mut out = Vec::with_capacity(padded.len());
    let mut prev = iv;
    let mut trace = None;

    for chunk in padded.chunks_exact(BLOCK_SIZE) {
        let block = xor_block(to_block(chunk), prev);
        let encrypted = encrypt_block_maybe_trace(cipher, block, capture_trace, &mut trace);
        out.extend_from_slice(&encrypted);
        prev = encrypted;
    }
    (out, trace)
}

fn decrypt_cbc(
    cipher: &Aes128,
    iv: [u8; BLOCK_SIZE],
    ciphertext: &[u8],
    capture_trace: bool,
) -> Result<(Vec<u8>, Option<BlockTrace>), AesError> {
    ensure_block_aligned(ciphertext)?;
    let mut padded = Vec::with_capacity(ciphertext.len());
    let mut prev = iv;
    let mut trace = None;

    for chunk in ciphertext.chunks_exact(BLOCK_SIZE) {
        let c = to_block(chunk);
        let decrypted = decrypt_block_maybe_trace(cipher, c, capture_trace, &mut trace);
        let p = xor_block(decrypted, prev);
        padded.extend_from_slice(&p);
        prev = c;
    }
    let unpadded = pkcs7_unpad(&padded)?;
    Ok((unpadded, trace))
}

fn encrypt_pcbc(
    cipher: &Aes128,
    iv: [u8; BLOCK_SIZE],
    plaintext: &[u8],
    capture_trace: bool,
) -> (Vec<u8>, Option<BlockTrace>) {
    let padded = pkcs7_pad(plaintext);
    let mut out = Vec::with_capacity(padded.len());
    let mut prev_mask = iv;
    let mut trace = None;

    for chunk in padded.chunks_exact(BLOCK_SIZE) {
        let p = to_block(chunk);
        let c = encrypt_block_maybe_trace(
            cipher,
            xor_block(p, prev_mask),
            capture_trace,
            &mut trace,
        );
        out.extend_from_slice(&c);
        prev_mask = xor_block(p, c);
    }
    (out, trace)
}

#[cfg(test)]
fn decrypt_pcbc_raw(
    cipher: &Aes128,
    iv: [u8; BLOCK_SIZE],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AesError> {
    decrypt_pcbc_raw_inner(cipher, iv, ciphertext, false).map(|(padded, _)| padded)
}

fn decrypt_pcbc_raw_inner(
    cipher: &Aes128,
    iv: [u8; BLOCK_SIZE],
    ciphertext: &[u8],
    capture_trace: bool,
) -> Result<(Vec<u8>, Option<BlockTrace>), AesError> {
    ensure_block_aligned(ciphertext)?;
    let mut padded = Vec::with_capacity(ciphertext.len());
    let mut prev_mask = iv;
    let mut trace = None;

    for chunk in ciphertext.chunks_exact(BLOCK_SIZE) {
        let c = to_block(chunk);
        let decrypted = decrypt_block_maybe_trace(cipher, c, capture_trace, &mut trace);
        let p = xor_block(decrypted, prev_mask);
        padded.extend_from_slice(&p);
        prev_mask = xor_block(p, c);
    }
    Ok((padded, trace))
}

fn decrypt_pcbc(
    cipher: &Aes128,
    iv: [u8; BLOCK_SIZE],
    ciphertext: &[u8],
    capture_trace: bool,
) -> Result<(Vec<u8>, Option<BlockTrace>), AesError> {
    let (padded, trace) = decrypt_pcbc_raw_inner(cipher, iv, ciphertext, capture_trace)?;
    let unpadded = pkcs7_unpad(&padded)?;
    Ok((unpadded, trace))
}

fn encrypt_cfb(
    cipher: &Aes128,
    iv: [u8; BLOCK_SIZE],
    plaintext: &[u8],
    capture_trace: bool,
) -> (Vec<u8>, Option<BlockTrace>) {
    let mut out = Vec::with_capacity(plaintext.len());
    let mut feedback = iv;
    let mut trace = None;

    for chunk in plaintext.chunks(BLOCK_SIZE) {
        let keystream = encrypt_block_maybe_trace(cipher, feedback, capture_trace, &mut trace);
        let start = out.len();
        xor_stream_chunk(chunk, &keystream, &mut out);
        if chunk.len() == BLOCK_SIZE {
            feedback.copy_from_slice(&out[start..]);
        }
    }
    (out, trace)
}

fn decrypt_cfb(
    cipher: &Aes128,
    iv: [u8; BLOCK_SIZE],
    ciphertext: &[u8],
    capture_trace: bool,
) -> (Vec<u8>, Option<BlockTrace>) {
    let mut out = Vec::with_capacity(ciphertext.len());
    let mut feedback = iv;
    let mut trace = None;

    for chunk in ciphertext.chunks(BLOCK_SIZE) {
        let keystream = encrypt_block_maybe_trace(cipher, feedback, capture_trace, &mut trace);
        xor_stream_chunk(chunk, &keystream, &mut out);
        if chunk.len() == BLOCK_SIZE {
            feedback.copy_from_slice(chunk);
        }
    }
    (out, trace)
}

fn apply_ofb(
    cipher: &Aes128,
    iv: [u8; BLOCK_SIZE],
    input: &[u8],
    capture_trace: bool,
) -> (Vec<u8>, Option<BlockTrace>) {
    let mut out = Vec::with_capacity(input.len());
    let mut feedback = iv;
    let mut trace = None;

    for chunk in input.chunks(BLOCK_SIZE) {
        feedback = encrypt_block_maybe_trace(cipher, feedback, capture_trace, &mut trace);
        xor_stream_chunk(chunk, &feedback, &mut out);
    }
    (out, trace)
}

fn apply_ctr(
    cipher: &Aes128,
    initial_counter: [u8; BLOCK_SIZE],
    input: &[u8],
    capture_trace: bool,
) -> (Vec<u8>, Option<BlockTrace>) {
    let mut out = Vec::with_capacity(input.len());
    let mut counter = initial_counter;
    let mut trace = None;

    for chunk in input.chunks(BLOCK_SIZE) {
        let keystream = encrypt_block_maybe_trace(cipher, counter, capture_trace, &mut trace);
        xor_stream_chunk(chunk, &keystream, &mut out);
        counter = u128::from_be_bytes(counter).wrapping_add(1).to_be_bytes();
    }
    (out, trace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::encoding::hex_decode;

    const NIST_KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
    const NIST_PLAINTEXT: &str = concat!(
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "f69f2445df4f9b17ad2b417be66c3710"
    );
    const NIST_IV: &str = "000102030405060708090a0b0c0d0e0f";

    #[test]
    fn mode_metadata() {
        assert!(!CipherMode::Ecb.requires_iv());
        assert!(CipherMode::Cbc.requires_iv());
        assert!(CipherMode::Pcbc.requires_iv());
        assert!(CipherMode::Cfb.requires_iv());
        assert!(CipherMode::Ofb.requires_iv());
        assert!(CipherMode::Ctr.requires_iv());

        assert_eq!(
            CipherMode::ALL.map(CipherMode::name),
            ["ECB", "CBC", "PCBC", "CFB", "OFB", "CTR"]
        );
    }

    #[test]
    fn nist_sp800_38a_ecb_f1_1() {
        let key = hex_decode(NIST_KEY).unwrap();
        let pt = hex_decode(NIST_PLAINTEXT).unwrap();
        let expected_first_64 = hex_decode(concat!(
            "3ad77bb40d7a3660a89ecaf32466ef97",
            "f5d3d58503b9699de785895a96fdbaaf",
            "43b1cd7f598ece23881b00e3ed030688",
            "7b0c785e27e8ad3f8223207104725dd4"
        ))
        .unwrap();

        let ct = encrypt(CipherMode::Ecb, &key, None, &pt).unwrap();
        assert_eq!(ct.len(), 80); // 64 bytes + 16-byte PKCS#7 padding block
        assert_eq!(&ct[..64], expected_first_64.as_slice());

        let recovered = decrypt(CipherMode::Ecb, &key, None, &ct).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn nist_sp800_38a_cbc_f2_1() {
        let key = hex_decode(NIST_KEY).unwrap();
        let iv = hex_decode(NIST_IV).unwrap();
        let pt = hex_decode(NIST_PLAINTEXT).unwrap();
        let expected_first_64 = hex_decode(concat!(
            "7649abac8119b246cee98e9b12e9197d",
            "5086cb9b507219ee95db113a917678b2",
            "73bed6b8e3c1743b7116e69e22229516",
            "3ff1caa1681fac09120eca307586e1a7"
        ))
        .unwrap();

        let ct = encrypt(CipherMode::Cbc, &key, Some(&iv), &pt).unwrap();
        assert_eq!(ct.len(), 80);
        assert_eq!(&ct[..64], expected_first_64.as_slice());

        let recovered = decrypt(CipherMode::Cbc, &key, Some(&iv), &ct).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn nist_sp800_38a_cfb128_f3_13() {
        let key = hex_decode(NIST_KEY).unwrap();
        let iv = hex_decode(NIST_IV).unwrap();
        let pt = hex_decode(NIST_PLAINTEXT).unwrap();
        let expected = hex_decode(concat!(
            "3b3fd92eb72dad20333449f8e83cfb4a",
            "c8a64537a0b3a93fcde3cdad9f1ce58b",
            "26751f67a3cbb140b1808cf187a4f4df",
            "c04b05357c5d1c0eeac4c66f9ff7f2e6"
        ))
        .unwrap();

        let ct = encrypt(CipherMode::Cfb, &key, Some(&iv), &pt).unwrap();
        assert_eq!(ct, expected);

        let recovered = decrypt(CipherMode::Cfb, &key, Some(&iv), &ct).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn nist_sp800_38a_ofb_f4_1() {
        let key = hex_decode(NIST_KEY).unwrap();
        let iv = hex_decode(NIST_IV).unwrap();
        let pt = hex_decode(NIST_PLAINTEXT).unwrap();
        let expected = hex_decode(concat!(
            "3b3fd92eb72dad20333449f8e83cfb4a",
            "7789508d16918f03f53c52dac54ed825",
            "9740051e9c5fecf64344f7a82260edcc",
            "304c6528f659c77866a510d9c1d6ae5e"
        ))
        .unwrap();

        let ct = encrypt(CipherMode::Ofb, &key, Some(&iv), &pt).unwrap();
        assert_eq!(ct, expected);

        let recovered = decrypt(CipherMode::Ofb, &key, Some(&iv), &ct).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn nist_sp800_38a_ctr_f5_1() {
        let key = hex_decode(NIST_KEY).unwrap();
        let counter = hex_decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
        let pt = hex_decode(NIST_PLAINTEXT).unwrap();
        let expected = hex_decode(concat!(
            "874d6191b620e3261bef6864990db6ce",
            "9806f66b7970fdff8617187bb9fffdff",
            "5ae4df3edbd5d35e5b4f09020db03eab",
            "1e031dda2fbe03d1792170a0f3009cee"
        ))
        .unwrap();

        let ct = encrypt(CipherMode::Ctr, &key, Some(&counter), &pt).unwrap();
        assert_eq!(ct, expected);

        let recovered = decrypt(CipherMode::Ctr, &key, Some(&counter), &ct).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn pcbc_round_trip_and_error_propagation() {
        let key = hex_decode(NIST_KEY).unwrap();
        let iv_bytes = hex_decode(NIST_IV).unwrap();
        let iv: [u8; BLOCK_SIZE] = iv_bytes.as_slice().try_into().unwrap();
        let pt = b"Block zero 16 B!Block one  16 B!Block two"; // 41 bytes -> 3 padded blocks (48 bytes)

        let ct = encrypt(CipherMode::Pcbc, &key, Some(&iv), pt).unwrap();
        assert_eq!(ct.len(), 48);
        assert_eq!(decrypt(CipherMode::Pcbc, &key, Some(&iv), &ct).unwrap(), pt);

        // Flip 1 bit in ciphertext block 0.
        let mut tampered = ct.clone();
        tampered[0] ^= 0x01;

        // With padding check, propagation into the trailing block fails PKCS#7 validation.
        assert_eq!(
            decrypt(CipherMode::Pcbc, &key, Some(&iv), &tampered),
            Err(AesError::InvalidPadding)
        );

        // Inspect raw decrypted blocks to confirm error propagates into block 0, block 1, and block 2.
        let cipher = Aes128::from_slice(&key).unwrap();
        let orig_padded = pkcs7_pad(pt);
        let raw_dec = decrypt_pcbc_raw(&cipher, iv, &tampered).unwrap();
        assert_ne!(&raw_dec[0..16], &orig_padded[0..16]);
        assert_ne!(&raw_dec[16..32], &orig_padded[16..32]);
        assert_ne!(&raw_dec[32..48], &orig_padded[32..48]);
    }

    #[test]
    fn round_trip_all_modes_various_lengths() {
        let key = hex_decode(NIST_KEY).unwrap();
        let iv = hex_decode(NIST_IV).unwrap();

        for mode in CipherMode::ALL {
            let mode_iv = if mode.requires_iv() {
                Some(iv.as_slice())
            } else {
                None
            };

            for len in [0usize, 1, 15, 16, 17, 50] {
                let pt: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(13).wrapping_add(5))
                    .collect();
                let ct = encrypt(mode, &key, mode_iv, &pt).unwrap();
                let recovered = decrypt(mode, &key, mode_iv, &ct).unwrap();
                assert_eq!(
                    recovered, pt,
                    "round-trip failed for mode {} at length {len}",
                    mode.name()
                );
            }
        }
    }

    #[test]
    fn ctr_counter_wraps_around_from_max_u128() {
        let key = hex_decode(NIST_KEY).unwrap();
        let max_counter = [0xffu8; BLOCK_SIZE];
        let zero_counter = [0x00u8; BLOCK_SIZE];
        let pt = vec![0xa5u8; 32]; // block 0 uses 0xff..ff, block 1 uses 0x00..00

        let ct = encrypt(CipherMode::Ctr, &key, Some(&max_counter), &pt).unwrap();
        let block1_only_ct = encrypt(CipherMode::Ctr, &key, Some(&zero_counter), &pt[16..]).unwrap();

        assert_eq!(&ct[16..32], block1_only_ct.as_slice());
        assert_eq!(
            decrypt(CipherMode::Ctr, &key, Some(&max_counter), &ct).unwrap(),
            pt
        );
    }

    #[test]
    fn error_handling_across_modes() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];

        // Bad key length
        assert_eq!(
            encrypt(CipherMode::Ecb, &[0u8; 15], None, b"abc"),
            Err(AesError::InvalidKeyLength {
                expected: 16,
                actual: 15
            })
        );
        assert_eq!(
            decrypt(CipherMode::Ctr, &[0u8; 32], Some(&iv), b"abc"),
            Err(AesError::InvalidKeyLength {
                expected: 16,
                actual: 32
            })
        );

        // Missing and invalid IV lengths on all 5 IV-requiring modes
        for mode in [
            CipherMode::Cbc,
            CipherMode::Pcbc,
            CipherMode::Cfb,
            CipherMode::Ofb,
            CipherMode::Ctr,
        ] {
            assert_eq!(encrypt(mode, &key, None, b"hello"), Err(AesError::MissingIv));
            assert_eq!(decrypt(mode, &key, None, b"hello"), Err(AesError::MissingIv));

            assert_eq!(
                encrypt(mode, &key, Some(&[0u8; 15]), b"hello"),
                Err(AesError::InvalidIvLength {
                    expected: 16,
                    actual: 15
                })
            );
            assert_eq!(
                decrypt(mode, &key, Some(&[0u8; 17]), b"hello"),
                Err(AesError::InvalidIvLength {
                    expected: 16,
                    actual: 17
                })
            );
        }

        // Empty or unaligned ciphertext on padded block modes
        for mode in [CipherMode::Ecb, CipherMode::Cbc, CipherMode::Pcbc] {
            let mode_iv = if mode.requires_iv() {
                Some(iv.as_slice())
            } else {
                None
            };

            assert_eq!(
                decrypt(mode, &key, mode_iv, &[]),
                Err(AesError::InvalidCiphertextLength { actual: 0 })
            );
            assert_eq!(
                decrypt(mode, &key, mode_iv, &[0u8; 15]),
                Err(AesError::InvalidCiphertextLength { actual: 15 })
            );

            // Corrupted padding on valid-length ciphertext
            let mut ct = encrypt(mode, &key, mode_iv, b"secret").unwrap();
            let last = ct.len() - 1;
            ct[last] ^= 0x01;
            assert_eq!(
                decrypt(mode, &key, mode_iv, &ct),
                Err(AesError::InvalidPadding)
            );
        }
    }
}
