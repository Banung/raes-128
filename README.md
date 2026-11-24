# raes-128

A pure-Rust AES-128 encryption and decryption desktop application built with [`gpui-kit`](https://crates.io/crates/gpui-kit) and zero external cryptography dependencies.

## Features

- **Pure-Rust AES-128 (FIPS 197)**: Implements SubBytes, ShiftRows, MixColumns, AddRoundKey, 128-bit key expansion, and inverse round transformations from scratch in `src/aes/`.
- **6 Modes of Operation**: Supports **ECB**, **CBC**, **PCBC**, **CFB**, **OFB**, and **CTR**, with selectable **PKCS#7** or **None (Raw)** block padding for ECB/CBC/PCBC (automatically disabled for stream modes CFB/OFB/CTR).
- **Flexible Key & IV Inputs**:
  - Toggle Key and IV/Counter inputs between **UTF-8 (16 B)** and **Hex (32 chars)** with live length indicators.
  - Built-in **Random** 128-bit generator for keys and IVs.
  - IV controls automatically disable when **ECB** mode is selected.
- **Plaintext & Ciphertext Encoding**: Toggle Plaintext input/output between **UTF-8** and **Hex**, and Ciphertext between **Hex** and **Base64** (with automatic hex fallback display when UTF-8 decrypted bytes are non-UTF-8).
- **1-Click NIST Test Vector Presets**: Load **FIPS 197 App. B**, **FIPS 197 App. C.1**, or **NIST CBC F.2.1** directly in the Text workspace for instant GUI and Step-by-Step Trace verification.
- **Text, File & Trace Workspaces**:
  - Switch between **Text**, **File**, and **Trace** tabs while keeping Cipher Mode, Key, and IV/Counter configuration synchronized.
  - **Disk File Encryption & Decryption**: Encrypt and decrypt arbitrary binary files up to **128 MiB** directly from disk using native **Browse...** and **Save As...** file picker dialogs or editable path inputs.
  - **Smart Output Paths & Safety**: Leaving the output path blank auto-suggests `.enc` on encryption and strips `.enc` (or appends `.dec`) on decryption. Input files are never overwritten in place, and writes are performed atomically via a temporary file.
- **Step-by-Step Trace**:
  - Automatically captures the AES-128 block-0 trace from both **Text** and **File** Encrypt/Decrypt operations across all 6 cipher modes.
  - Defaults to the summary view (**Initial / R1 / Final**): **Initial Round**, complete **Round 1** (`SubBytes`, `ShiftRows`, `MixColumns`, `AddRoundKey` or their inverse equivalents), and **Final Round** with 4x4 column-major hexadecimal state matrices.
  - Toggle **All 10 Rounds** to inspect every round (`0..=10`) and all 11 round keys (`K0..=K10`), or click **Copy Trace** to copy the monospace report to the clipboard.
- **Interactive Desktop UI**: Encrypt, Decrypt, Use Output as Input (swap), Copy Output / Copy Trace to clipboard, Clear / Clear Paths, and an accessible live status bar.

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
