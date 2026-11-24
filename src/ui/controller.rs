//! GPUI-independent controller logic for AES-128 UI operations.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::aes::{
    AesError, BLOCK_SIZE, CipherMode, FirstBlockModeTrace, base64_decode, base64_encode,
    decrypt_with_trace, encrypt_with_trace, hex_decode, hex_encode,
};

/// Input representation for 16-byte AES-128 keys and initialization vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    Utf8,
    Hex,
}

impl KeyFormat {
    /// Returns the human-readable UI label for this key/IV format.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Utf8 => "UTF-8 (16 B)",
            Self::Hex => "Hex (32 chars)",
        }
    }
}

/// Text encoding format for ciphertext input/output in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiphertextFormat {
    Hex,
    Base64,
}

impl CiphertextFormat {
    /// Returns the human-readable UI label for this ciphertext format.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Hex => "Hex",
            Self::Base64 => "Base64",
        }
    }
}

/// Parameters collected from the UI to execute an encrypt or decrypt operation.
#[derive(Debug, Clone, Copy)]
pub struct CryptoRequest<'a> {
    pub mode: CipherMode,
    pub key_format: KeyFormat,
    pub key_text: &'a str,
    pub iv_format: KeyFormat,
    pub iv_text: &'a str,
    pub ciphertext_format: CiphertextFormat,
    pub input_text: &'a str,
}

/// Output and metadata returned by [`run_encrypt`] and [`run_decrypt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoSuccess {
    pub output: String,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub utf8_fallback_hex: bool,
    pub trace: Option<FirstBlockModeTrace>,
}

/// Parses a 16-byte key or initialization vector according to `format`.
pub fn parse_fixed_16(text: &str, format: KeyFormat, is_iv: bool) -> Result<[u8; 16], AesError> {
    match format {
        KeyFormat::Utf8 => slice_to_16(text.as_bytes(), is_iv),
        KeyFormat::Hex => {
            let decoded = hex_decode(text)?;
            slice_to_16(&decoded, is_iv)
        }
    }
}

fn slice_to_16(bytes: &[u8], is_iv: bool) -> Result<[u8; 16], AesError> {
    bytes.try_into().map_err(|_| {
        if is_iv {
            AesError::InvalidIvLength {
                expected: BLOCK_SIZE,
                actual: bytes.len(),
            }
        } else {
            AesError::InvalidKeyLength {
                expected: BLOCK_SIZE,
                actual: bytes.len(),
            }
        }
    })
}

/// Validates and parses the key and optional initialization vector for a cipher mode.
pub(crate) fn parse_key_and_iv_fields(
    mode: CipherMode,
    key_format: KeyFormat,
    key_text: &str,
    iv_format: KeyFormat,
    iv_text: &str,
) -> Result<([u8; 16], Option<[u8; 16]>), AesError> {
    let key = parse_fixed_16(key_text, key_format, false)?;
    let iv = if mode.requires_iv() {
        let is_empty = match iv_format {
            KeyFormat::Utf8 => iv_text.is_empty(),
            KeyFormat::Hex => iv_text.trim().is_empty(),
        };
        if is_empty {
            return Err(AesError::MissingIv);
        }
        Some(parse_fixed_16(iv_text, iv_format, true)?)
    } else {
        None
    };
    Ok((key, iv))
}

fn parse_key_and_iv(req: &CryptoRequest<'_>) -> Result<([u8; 16], Option<[u8; 16]>), AesError> {
    parse_key_and_iv_fields(
        req.mode,
        req.key_format,
        req.key_text,
        req.iv_format,
        req.iv_text,
    )
}

/// Validates inputs, encrypts UTF-8 `input_text`, and formats the resulting ciphertext.
pub fn run_encrypt(req: &CryptoRequest<'_>) -> Result<CryptoSuccess, AesError> {
    let (key, iv) = parse_key_and_iv(req)?;
    let (ciphertext, trace) = encrypt_with_trace(
        req.mode,
        &key,
        iv.as_ref().map(|b| b.as_slice()),
        req.input_text.as_bytes(),
    )?;
    let output = match req.ciphertext_format {
        CiphertextFormat::Hex => hex_encode(&ciphertext),
        CiphertextFormat::Base64 => base64_encode(&ciphertext),
    };

    Ok(CryptoSuccess {
        output,
        input_bytes: req.input_text.len(),
        output_bytes: ciphertext.len(),
        utf8_fallback_hex: false,
        trace,
    })
}

/// Validates inputs, decodes ciphertext, decrypts it, and converts plaintext to UTF-8 or hex.
pub fn run_decrypt(req: &CryptoRequest<'_>) -> Result<CryptoSuccess, AesError> {
    let (key, iv) = parse_key_and_iv(req)?;
    let ciphertext = match req.ciphertext_format {
        CiphertextFormat::Hex => hex_decode(req.input_text)?,
        CiphertextFormat::Base64 => base64_decode(req.input_text)?,
    };
    let input_bytes = ciphertext.len();
    let (plaintext, trace) = decrypt_with_trace(
        req.mode,
        &key,
        iv.as_ref().map(|b| b.as_slice()),
        &ciphertext,
    )?;
    let output_bytes = plaintext.len();

    let (output, utf8_fallback_hex) = match String::from_utf8(plaintext) {
        Ok(text) => (text, false),
        Err(err) => (hex_encode(err.as_bytes()), true),
    };

    Ok(CryptoSuccess {
        output,
        input_bytes,
        output_bytes,
        utf8_fallback_hex,
        trace,
    })
}

/// Generates 16 random bytes using `/dev/urandom` on Unix, with a `std` entropy fallback.
pub fn generate_random_16_bytes() -> [u8; 16] {
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut buf = [0u8; 16];
        if let Ok(mut file) = std::fs::File::open("/dev/urandom")
            && file.read_exact(&mut buf).is_ok()
        {
            return buf;
        }
    }
    fallback_random_16_bytes()
}

fn fallback_random_16_bytes() -> [u8; 16] {
    static COUNTER: AtomicU64 = AtomicU64::new(1);

    let mut out = [0u8; 16];
    for chunk in out.chunks_exact_mut(8) {
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u64(seq);
        hasher.write_u64(nanos);
        chunk.copy_from_slice(&hasher.finish().to_le_bytes());
    }
    out
}

/// Generates 16 random bytes encoded as 32 lowercase hexadecimal characters.
pub fn generate_random_hex_16() -> String {
    hex_encode(&generate_random_16_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::encrypt;

    const UTF8_KEY: &str = "0123456789abcdef";
    const HEX_KEY: &str = "000102030405060708090a0b0c0d0e0f";
    const UTF8_IV: &str = "fedcba9876543210";
    const HEX_IV: &str = "101112131415161718191a1b1c1d1e1f";

    #[test]
    fn round_trip_all_modes_formats() {
        let plaintext = "Hello, RAES-128 controller! Multi-block UTF-8: αβγδ.";

        for mode in CipherMode::ALL {
            for (key_format, key_text) in [
                (KeyFormat::Utf8, UTF8_KEY),
                (KeyFormat::Hex, HEX_KEY),
            ] {
                for (iv_format, iv_text) in [
                    (KeyFormat::Utf8, UTF8_IV),
                    (KeyFormat::Hex, HEX_IV),
                ] {
                    for ciphertext_format in [CiphertextFormat::Hex, CiphertextFormat::Base64] {
                        let enc_req = CryptoRequest {
                            mode,
                            key_format,
                            key_text,
                            iv_format,
                            iv_text,
                            ciphertext_format,
                            input_text: plaintext,
                        };
                        let enc = run_encrypt(&enc_req).expect("encrypt should succeed");
                        assert_eq!(enc.input_bytes, plaintext.len());
                        assert!(!enc.utf8_fallback_hex);

                        let dec_req = CryptoRequest {
                            mode,
                            key_format,
                            key_text,
                            iv_format,
                            iv_text,
                            ciphertext_format,
                            input_text: &enc.output,
                        };
                        let dec = run_decrypt(&dec_req).expect("decrypt should succeed");
                        assert_eq!(dec.output, plaintext);
                        assert_eq!(dec.input_bytes, enc.output_bytes);
                        assert_eq!(dec.output_bytes, plaintext.len());
                        assert!(!dec.utf8_fallback_hex);
                    }
                }
            }
        }
    }

    #[test]
    fn ecb_ignores_empty_iv_while_other_modes_require_it() {
        for mode in CipherMode::ALL {
            for iv_format in [KeyFormat::Utf8, KeyFormat::Hex] {
                let iv_text = match iv_format {
                    KeyFormat::Utf8 => "",
                    KeyFormat::Hex => "   ",
                };
                let enc_req = CryptoRequest {
                    mode,
                    key_format: KeyFormat::Utf8,
                    key_text: UTF8_KEY,
                    iv_format,
                    iv_text,
                    ciphertext_format: CiphertextFormat::Hex,
                    input_text: "secret",
                };
                let dec_req = CryptoRequest {
                    input_text: "00112233445566778899aabbccddeeff",
                    ..enc_req
                };

                if mode.requires_iv() {
                    assert_eq!(run_encrypt(&enc_req), Err(AesError::MissingIv));
                    assert_eq!(run_decrypt(&dec_req), Err(AesError::MissingIv));
                } else {
                    let enc = run_encrypt(&enc_req).expect("ECB encrypt should ignore empty IV");
                    let dec = run_decrypt(&CryptoRequest {
                        input_text: &enc.output,
                        ..enc_req
                    })
                    .expect("ECB decrypt should ignore empty IV");
                    assert_eq!(dec.output, "secret");
                }
            }
        }
    }

    #[test]
    fn non_utf8_plaintext_falls_back_to_hex() {
        let key = parse_fixed_16(HEX_KEY, KeyFormat::Hex, false).unwrap();
        let iv = parse_fixed_16(HEX_IV, KeyFormat::Hex, true).unwrap();
        let raw_bytes = [0xff, 0xfe, 0x00, 0x80];
        let ciphertext = encrypt(CipherMode::Cbc, &key, Some(&iv), &raw_bytes).unwrap();
        let ciphertext_hex = hex_encode(&ciphertext);

        let res = run_decrypt(&CryptoRequest {
            mode: CipherMode::Cbc,
            key_format: KeyFormat::Hex,
            key_text: HEX_KEY,
            iv_format: KeyFormat::Hex,
            iv_text: HEX_IV,
            ciphertext_format: CiphertextFormat::Hex,
            input_text: &ciphertext_hex,
        })
        .expect("decrypt should succeed with hex fallback");

        assert!(res.utf8_fallback_hex);
        assert_eq!(res.output, "fffe0080");
        assert_eq!(res.input_bytes, ciphertext.len());
        assert_eq!(res.output_bytes, raw_bytes.len());
    }

    #[test]
    fn validation_errors_match_expected_aes_errors() {
        assert_eq!(
            parse_fixed_16("short", KeyFormat::Utf8, false),
            Err(AesError::InvalidKeyLength {
                expected: 16,
                actual: 5,
            })
        );
        assert_eq!(
            parse_fixed_16("00112233", KeyFormat::Hex, false),
            Err(AesError::InvalidKeyLength {
                expected: 16,
                actual: 4,
            })
        );
        assert_eq!(
            parse_fixed_16("short-iv", KeyFormat::Utf8, true),
            Err(AesError::InvalidIvLength {
                expected: 16,
                actual: 8,
            })
        );
        assert_eq!(
            parse_fixed_16("0011", KeyFormat::Hex, true),
            Err(AesError::InvalidIvLength {
                expected: 16,
                actual: 2,
            })
        );
        assert!(matches!(
            parse_fixed_16("zzzz", KeyFormat::Hex, false),
            Err(AesError::InvalidHex(_))
        ));

        let bad_hex = CryptoRequest {
            mode: CipherMode::Ecb,
            key_format: KeyFormat::Utf8,
            key_text: UTF8_KEY,
            iv_format: KeyFormat::Utf8,
            iv_text: "",
            ciphertext_format: CiphertextFormat::Hex,
            input_text: "not-hex!",
        };
        assert!(matches!(run_decrypt(&bad_hex), Err(AesError::InvalidHex(_))));

        let bad_b64 = CryptoRequest {
            ciphertext_format: CiphertextFormat::Base64,
            input_text: "not*valid*base64",
            ..bad_hex
        };
        assert!(matches!(
            run_decrypt(&bad_b64),
            Err(AesError::InvalidBase64(_))
        ));
    }

    #[test]
    fn random_hex_generates_distinct_32_char_lowercase_hex() {
        let first = generate_random_hex_16();
        let second = generate_random_hex_16();

        assert_eq!(first.len(), 32);
        assert_eq!(second.len(), 32);
        assert!(first
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        assert!(second
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        assert_eq!(hex_decode(&first).unwrap().len(), 16);
        assert_eq!(hex_decode(&second).unwrap().len(), 16);
        assert_ne!(first, second);
    }

    #[test]
    fn format_labels_match_spec() {
        assert_eq!(KeyFormat::Utf8.label(), "UTF-8 (16 B)");
        assert_eq!(KeyFormat::Hex.label(), "Hex (32 chars)");
        assert_eq!(CiphertextFormat::Hex.label(), "Hex");
        assert_eq!(CiphertextFormat::Base64.label(), "Base64");
    }
}
