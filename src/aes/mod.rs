//! Pure-Rust AES-128 block cipher implementation (FIPS 197).

pub mod cipher;
pub mod encoding;
pub mod modes;
pub mod padding;
mod tables;

pub use cipher::{Aes128, BLOCK_SIZE, KEY_SIZE};
pub use encoding::{base64_decode, base64_encode, hex_decode, hex_encode};
pub use modes::{CipherMode, decrypt, encrypt};
pub use padding::{pkcs7_pad, pkcs7_unpad};

/// Errors returned by AES-128 key, block, mode, padding, and encoding operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AesError {
    /// Provided key slice length did not match the required 16-byte AES-128 key size.
    InvalidKeyLength { expected: usize, actual: usize },
    /// Initialization vector is required for the selected cipher mode.
    MissingIv,
    /// Provided initialization vector length did not match the 16-byte block size.
    InvalidIvLength { expected: usize, actual: usize },
    /// Ciphertext length is not a valid multiple of the 16-byte block size.
    InvalidCiphertextLength { actual: usize },
    /// Decrypted plaintext failed PKCS#7 padding validation.
    InvalidPadding,
    /// Input was not valid hexadecimal text.
    InvalidHex(String),
    /// Input was not valid Base64 text.
    InvalidBase64(String),
}

impl std::fmt::Display for AesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeyLength { expected, actual } => {
                write!(f, "invalid key length: expected {expected} bytes, got {actual}")
            }
            Self::MissingIv => write!(f, "missing initialization vector (IV)"),
            Self::InvalidIvLength { expected, actual } => {
                write!(f, "invalid IV length: expected {expected} bytes, got {actual}")
            }
            Self::InvalidCiphertextLength { actual } => {
                write!(
                    f,
                    "invalid ciphertext length: {actual} bytes is not a non-zero multiple of 16"
                )
            }
            Self::InvalidPadding => write!(f, "invalid PKCS#7 padding"),
            Self::InvalidHex(msg) => write!(f, "invalid hex input: {msg}"),
            Self::InvalidBase64(msg) => write!(f, "invalid base64 input: {msg}"),
        }
    }
}

impl std::error::Error for AesError {}
