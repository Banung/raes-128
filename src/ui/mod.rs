//! UI support modules and GPUI-independent controllers.

pub mod app;
pub mod controller;
pub mod file_crypto;

pub use app::RaesApp;
pub use controller::{
    CiphertextFormat, CryptoRequest, CryptoSuccess, KeyFormat, generate_random_16_bytes,
    generate_random_hex_16, parse_fixed_16, run_decrypt, run_encrypt,
};
pub use file_crypto::{
    FileCryptoError, FileCryptoRequest, FileCryptoSuccess, MAX_FILE_SIZE_BYTES, decrypt_file,
    encrypt_file, suggested_output_path,
};
