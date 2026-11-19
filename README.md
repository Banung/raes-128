# raes-128

A pure-Rust AES-128 encryption and decryption desktop application built with [`gpui-kit`](https://crates.io/crates/gpui-kit) and zero external cryptography dependencies.

## Features

- **Pure-Rust AES-128 (FIPS 197)**: Implements SubBytes, ShiftRows, MixColumns, AddRoundKey, 128-bit key expansion, and inverse round transformations from scratch in `src/aes/`.
- **6 Modes of Operation**: Supports **ECB**, **CBC**, **PCBC**, **CFB**, **OFB**, and **CTR** (with PKCS#7 padding for block modes ECB/CBC/PCBC and stream operation for CFB/OFB/CTR).
- **Flexible Key & IV Inputs**:
  - Toggle Key and IV/Counter inputs between **UTF-8 (16 B)** and **Hex (32 chars)** with live length indicators.
  - Built-in **Random** 128-bit generator for keys and IVs.
  - IV controls automatically disable when **ECB** mode is selected.
- **Ciphertext Encoding**: Encode and decode ciphertext in **Hex** or **Base64** (with automatic hex fallback display when decrypted bytes are non-UTF-8).
- **Interactive Desktop UI**: Encrypt, Decrypt, Use Output as Input (swap), Copy Output to clipboard, Clear, and an accessible live status bar.

## Commands

Build the project:

```bash
cargo build
```

Run the desktop application:

```bash
cargo run
```

Run all unit and headless UI integration tests:

```bash
cargo test
```

Run Clippy across all targets:

```bash
cargo clippy --all-targets
```
