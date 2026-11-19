# raes-128

A desktop application for AES-128 encryption and decryption built with Rust and [`gpui-kit`](https://crates.io/crates/gpui-kit).

## Overview

- **Custom AES-128 implementation**: AES-128 encryption and decryption will be implemented from scratch in Rust without external cryptography libraries in upcoming stages.
- **Current stage**: Provides the minimal runnable `gpui-kit` desktop shell (`RaesApp`) and headless UI smoke test; no encryption or decryption functionality is implemented yet.

## Commands

Build the project:

```bash
cargo build
```

Run the desktop application:

```bash
cargo run
```

Run tests (including the headless `gpui-kit` UI smoke test):

```bash
cargo test
```

Run Clippy across all targets:

```bash
cargo clippy --all-targets
```
