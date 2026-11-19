//! UI support modules and GPUI-independent controllers.

pub mod app;
pub mod controller;

pub use app::RaesApp;
pub use controller::{
    CiphertextFormat, CryptoRequest, CryptoSuccess, KeyFormat, generate_random_16_bytes,
    generate_random_hex_16, parse_fixed_16, run_decrypt, run_encrypt,
};
