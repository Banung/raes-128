use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use gpui_kit::test::{TestQueryExt, TestWindowExt};
use gpui_kit::{
    AnyWindowHandle, AppContext, Bounds, Point, TestAppContext, Window, WindowBounds,
    WindowOptions, px, size,
};

struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn new(label: &str) -> Self {
        static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);
        let pid = std::process::id();
        loop {
            let seq = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("raes_128_smoke_{label}_{pid}_{seq}"));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
                Err(err) => panic!("failed to create temp dir {}: {err}", path.display()),
            }
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn open_test_app(cx: &mut TestAppContext) -> AnyWindowHandle {
    cx.update(gpui_kit::init);

    let (handle, _) = cx.update(|cx| {
        gpui_kit::open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(Bounds {
                    origin: Point::default(),
                    size: size(px(960.), px(900.)),
                })),
                ..Default::default()
            },
            cx,
            |window, cx| cx.new(|cx| raes_128::RaesApp::new(window, cx)),
        )
        .expect("open test window")
    });

    cx.update_window(handle, |_, window, cx| {
        window.render_frame(cx);
    })
    .expect("render initial frame");

    handle
}

fn output_text_value(window: &Window) -> String {
    window
        .find_by_label("Output Text")
        .value()
        .expect("output textarea should expose a value")
        .to_string()
}

fn trace_text_value(window: &Window) -> String {
    window
        .find_by_label("Step-by-Step Trace")
        .value()
        .expect("trace textarea should expose a value")
        .to_string()
}

fn status_text(window: &Window) -> String {
    window
        .find("status-message")
        .label()
        .expect("status label should be set")
        .to_string()
}

#[gpui_kit::test]
fn renders_raes_app_shell(cx: &mut TestAppContext) {
    let handle = open_test_app(cx);

    cx.update_window(handle, |_, window, _| {
        let title = window.find("app-title");
        assert!(title.visible());
        assert_eq!(title.label(), Some("RAES-128"));
    })
    .expect("update test window");
}

#[gpui_kit::test]
fn encrypts_and_decrypts_cbc_through_ui(cx: &mut TestAppContext) {
    let handle = open_test_app(cx);

    cx.update_window(handle, |_, window, cx| {
        window.click("key-input", cx);
        window.input("0123456789abcdef", cx);

        window.click("iv-input", cx);
        window.input("000102030405060708090a0b0c0d0e0f", cx);

        window.click("input-text", cx);
        window.input("Hello RAES-128!", cx);

        window.click("btn-encrypt", cx);

        let ciphertext = output_text_value(window);
        assert!(!ciphertext.is_empty(), "ciphertext should not be empty");
        assert!(
            ciphertext.bytes().all(|b| b.is_ascii_hexdigit()),
            "ciphertext should be valid hex, got {ciphertext:?}"
        );

        let status = status_text(window);
        assert!(
            status.starts_with("Encrypted"),
            "expected Encrypted status, got {status:?}"
        );

        window.click("btn-swap", cx);
        window.click("btn-decrypt", cx);

        assert_eq!(output_text_value(window), "Hello RAES-128!");
        let status = status_text(window);
        assert!(
            status.starts_with("Decrypted"),
            "expected Decrypted status, got {status:?}"
        );
    })
    .expect("run cbc ui test");
}

#[gpui_kit::test]
fn encrypts_ecb_without_iv_through_ui(cx: &mut TestAppContext) {
    let handle = open_test_app(cx);

    cx.update_window(handle, |_, window, cx| {
        window.click("mode-ecb", cx);
        assert_eq!(window.find("btn-gen-iv").disabled(), Some(true));
        window.click("iv-input", cx);
        window.input("ignored", cx);
        assert_eq!(window.find("iv-input").value(), Some(""));

        window.click("key-input", cx);
        window.input("0123456789abcdef", cx);

        window.click("input-text", cx);
        window.input("ECB mode test", cx);

        window.click("btn-encrypt", cx);

        let ciphertext = output_text_value(window);
        assert!(!ciphertext.is_empty(), "ECB ciphertext should not be empty");
        let status = status_text(window);
        assert!(
            status.starts_with("Encrypted"),
            "expected Encrypted status, got {status:?}"
        );

        window.click("btn-swap", cx);
        window.click("btn-decrypt", cx);

        assert_eq!(output_text_value(window), "ECB mode test");
    })
    .expect("run ecb ui test");
}

#[gpui_kit::test]
fn shows_error_on_invalid_key_length(cx: &mut TestAppContext) {
    let handle = open_test_app(cx);

    cx.update_window(handle, |_, window, cx| {
        window.click("key-input", cx);
        window.input("short", cx);

        window.click("input-text", cx);
        window.input("hello", cx);

        window.click("btn-encrypt", cx);

        let status = status_text(window);
        assert!(
            status.contains("invalid key length"),
            "expected invalid key length error, got {status:?}"
        );
    })
    .expect("run invalid key length ui test");
}

#[gpui_kit::test]
fn encrypts_and_decrypts_file_through_ui(cx: &mut TestAppContext) {
    let dir = TempDirGuard::new("file_round_trip");
    let source_path = dir.path().join("payload.bin");
    let enc_path = dir.path().join("payload.bin.enc");
    let restored_path = dir.path().join("payload.bin.restored");

    let original_bytes = b"\x00\x01\xffHello binary RAES-128!\xfe\x80";
    std::fs::write(&source_path, original_bytes).expect("write source file");

    let source_str = source_path.to_string_lossy().into_owned();
    let enc_str = enc_path.to_string_lossy().into_owned();
    let restored_str = restored_path.to_string_lossy().into_owned();

    let handle = open_test_app(cx);

    cx.update_window(handle, |_, window, cx| {
        window.click("tab-file", cx);

        window.click("key-input", cx);
        window.input("0123456789abcdef", cx);

        window.click("iv-input", cx);
        window.input("000102030405060708090a0b0c0d0e0f", cx);

        window.click("file-input-path", cx);
        window.input(&source_str, cx);

        window.click("file-output-path", cx);
        window.input(&enc_str, cx);

        window.click("btn-file-encrypt", cx);

        let status = status_text(window);
        assert!(
            status.starts_with("Encrypted file"),
            "expected Encrypted file status, got {status:?}"
        );
        assert!(enc_path.exists(), "encrypted output file should exist");
        let encrypted_bytes = std::fs::read(&enc_path).expect("read encrypted file");
        assert_ne!(
            encrypted_bytes.as_slice(),
            original_bytes,
            "encrypted file bytes should differ from plaintext"
        );

        window.click("btn-file-swap", cx);
        window.click("file-output-path", cx);
        window.input(&restored_str, cx);

        window.click("btn-file-decrypt", cx);

        let status = status_text(window);
        assert!(
            status.starts_with("Decrypted file"),
            "expected Decrypted file status, got {status:?}"
        );
        let restored_bytes = std::fs::read(&restored_path).expect("read restored file");
        assert_eq!(
            restored_bytes.as_slice(),
            original_bytes,
            "decrypted file bytes should match original bytes"
        );
    })
    .expect("run file encrypt/decrypt ui test");
}

#[gpui_kit::test]
fn shows_error_when_file_input_and_output_paths_match(cx: &mut TestAppContext) {
    let dir = TempDirGuard::new("file_same_path");
    let file_path = dir.path().join("do_not_clobber.bin");
    let original_bytes = b"preserve-original-file-contents";
    std::fs::write(&file_path, original_bytes).expect("write source file");

    let file_str = file_path.to_string_lossy().into_owned();
    let handle = open_test_app(cx);

    cx.update_window(handle, |_, window, cx| {
        window.click("tab-file", cx);

        window.click("key-input", cx);
        window.input("0123456789abcdef", cx);

        window.click("iv-input", cx);
        window.input("000102030405060708090a0b0c0d0e0f", cx);

        window.click("file-input-path", cx);
        window.input(&file_str, cx);

        window.click("file-output-path", cx);
        window.input(&file_str, cx);

        window.click("btn-file-encrypt", cx);

        let status = status_text(window);
        assert!(
            status.starts_with("Error:") && status.contains("same file"),
            "expected same-file error status, got {status:?}"
        );
        let after_bytes = std::fs::read(&file_path).expect("read original file");
        assert_eq!(
            after_bytes.as_slice(),
            original_bytes,
            "original file bytes should remain untouched"
        );
    })
    .expect("run same-path error ui test");
}

#[gpui_kit::test]
fn shows_step_by_step_trace_after_encrypt_and_toggles_all_rounds(cx: &mut TestAppContext) {
    let handle = open_test_app(cx);

    cx.update_window(handle, |_, window, cx| {
        window.click("key-input", cx);
        window.input("0123456789abcdef", cx);

        window.click("iv-input", cx);
        window.input("000102030405060708090a0b0c0d0e0f", cx);

        window.click("input-text", cx);
        window.input("Hello RAES-128!", cx);

        window.click("btn-encrypt", cx);
        window.click("tab-trace", cx);

        assert_eq!(status_text(window), "Switched to Step-by-Step Trace view");

        let summary_trace = trace_text_value(window);
        assert!(summary_trace.contains("AES-128-CBC"));
        assert!(summary_trace.contains("Initial Round"));
        assert!(summary_trace.contains("Round 1"));
        assert!(summary_trace.contains("SubBytes"));
        assert!(summary_trace.contains("ShiftRows"));
        assert!(summary_trace.contains("MixColumns"));
        assert!(summary_trace.contains("AddRoundKey"));
        assert!(summary_trace.contains("Final Round"));
        assert!(!summary_trace.contains("Round 5"));

        window.click("trace-mode-all", cx);
        let full_trace = trace_text_value(window);
        assert!(full_trace.contains("Round 5"));
        assert!(full_trace.contains("K5"));

        window.click("trace-mode-summary", cx);
        let back_to_summary = trace_text_value(window);
        assert!(!back_to_summary.contains("Round 5"));
    })
    .expect("run trace encrypt and toggle ui test");
}

#[gpui_kit::test]
fn captures_trace_for_decrypt_and_file_operations(cx: &mut TestAppContext) {
    let dir = TempDirGuard::new("trace_file_ops");
    let source_path = dir.path().join("trace_input.bin");
    let enc_path = dir.path().join("trace_input.bin.enc");
    std::fs::write(&source_path, b"Trace file payload!").expect("write source file");

    let source_str = source_path.to_string_lossy().into_owned();
    let enc_str = enc_path.to_string_lossy().into_owned();
    let handle = open_test_app(cx);

    cx.update_window(handle, |_, window, cx| {
        window.click("key-input", cx);
        window.input("0123456789abcdef", cx);

        window.click("iv-input", cx);
        window.input("000102030405060708090a0b0c0d0e0f", cx);

        window.click("input-text", cx);
        window.input("Hello RAES-128!", cx);

        window.click("btn-encrypt", cx);
        window.click("btn-swap", cx);
        window.click("btn-decrypt", cx);
        window.click("tab-trace", cx);

        let dec_trace = trace_text_value(window);
        assert!(dec_trace.contains("Operation:             Decrypt"));
        assert!(dec_trace.contains("InvSubBytes"));
        assert!(dec_trace.contains("InvShiftRows"));
        assert!(dec_trace.contains("InvMixColumns"));

        window.click("tab-file", cx);
        window.click("file-input-path", cx);
        window.input(&source_str, cx);
        window.click("file-output-path", cx);
        window.input(&enc_str, cx);
        window.click("btn-file-encrypt", cx);
        window.click("tab-trace", cx);

        let file_enc_trace = trace_text_value(window);
        assert!(file_enc_trace.contains("Operation:             Encrypt"));
        assert!(file_enc_trace.contains("SubBytes"));
    })
    .expect("run trace decrypt and file ui test");
}

#[gpui_kit::test]
fn verifies_fips_197_appendix_b_preset_and_raw_block_round_trip(cx: &mut TestAppContext) {
    let handle = open_test_app(cx);

    cx.update_window(handle, |_, window, cx| {
        window.click("preset-fips197-app-b", cx);
        window.click("btn-encrypt", cx);

        assert_eq!(output_text_value(window), "3925841d02dc09fbdc118597196a0b32");

        window.click("tab-trace", cx);
        let trace = trace_text_value(window);
        assert!(trace.contains("AES-128-ECB"));
        assert!(trace.contains("3243f6a8885a308d313198a2e0370734"));
        assert!(trace.contains("3925841d02dc09fbdc118597196a0b32"));
        assert!(trace.contains("d4 e0 b8 1e"));
        assert!(trace.contains("d4bf5d30e0b452aeb84111f11e2798e5"));

        window.click("tab-text", cx);
        window.click("btn-swap", cx);
        window.click("btn-decrypt", cx);

        assert_eq!(output_text_value(window), "3243f6a8885a308d313198a2e0370734");
        let status = status_text(window);
        assert!(
            status.starts_with("Decrypted"),
            "expected Decrypted status, got {status:?}"
        );
        assert!(
            !status.contains("non-UTF-8"),
            "expected hex plaintext decrypt without non-UTF-8 fallback wording, got {status:?}"
        );
    })
    .expect("run fips 197 appendix b preset ui test");
}

#[gpui_kit::test]
fn rejects_unaligned_plaintext_in_none_padding_mode_and_disables_padding_for_ctr(
    cx: &mut TestAppContext,
) {
    let handle = open_test_app(cx);

    cx.update_window(handle, |_, window, cx| {
        window.click("mode-ctr", cx);
        assert_eq!(window.find("pad-pkcs7").disabled(), Some(true));
        assert_eq!(window.find("pad-none").disabled(), Some(true));

        window.click("mode-ecb", cx);
        assert_eq!(window.find("pad-none").disabled(), None);
        window.click("pad-none", cx);

        window.click("key-input", cx);
        window.input("0123456789abcdef", cx);

        window.click("input-text", cx);
        window.input("short", cx);

        window.click("btn-encrypt", cx);

        let status = status_text(window);
        assert!(
            status.starts_with("Error:") && status.contains("invalid plaintext length"),
            "expected invalid plaintext length error, got {status:?}"
        );
    })
    .expect("run none padding error and ctr disable ui test");
}
