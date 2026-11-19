use gpui_kit::test::{TestQueryExt, TestWindowExt};
use gpui_kit::{
    AnyWindowHandle, AppContext, Bounds, Point, TestAppContext, Window, WindowBounds,
    WindowOptions, px, size,
};

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
