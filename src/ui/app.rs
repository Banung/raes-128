use gpui_kit::{
    AppContext, ClipboardItem, Context, Entity, IntoElement, ParentElement, Render, Role,
    SharedString, Styled, TestSupportExt, Window, div, prelude::*, px,
};
use gpui_kit::component::{
    ActiveTheme, Disableable, StyledExt,
    button::{Button, ButtonVariants as _},
    h_flex,
    input::{Input, InputState, Textarea, TextareaState},
    label::Label,
    v_flex,
};

use crate::aes::CipherMode;
use crate::ui::controller::{
    CiphertextFormat, CryptoRequest, KeyFormat, generate_random_hex_16, run_decrypt, run_encrypt,
};

/// Interactive desktop application view for pure-Rust AES-128 encryption and decryption.
pub struct RaesApp {
    mode: CipherMode,
    key_format: KeyFormat,
    iv_format: KeyFormat,
    ciphertext_format: CiphertextFormat,
    key_input: Entity<InputState>,
    iv_input: Entity<InputState>,
    input_text: Entity<TextareaState>,
    output_text: Entity<TextareaState>,
    status_message: SharedString,
    status_is_error: bool,
}

impl RaesApp {
    /// Creates a new `RaesApp` view with default CBC mode and initialized text inputs.
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let key_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("16-byte UTF-8 key or 32-char hex"));
        let iv_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("32-char hex IV or 16-byte UTF-8"));
        let input_text = cx.new(|cx| {
            TextareaState::new(window, cx)
                .placeholder("Enter plaintext to encrypt or ciphertext to decrypt...")
                .rows(5)
        });
        let output_text = cx.new(|cx| {
            TextareaState::new(window, cx)
                .placeholder("Result will appear here...")
                .rows(5)
        });

        Self {
            mode: CipherMode::Cbc,
            key_format: KeyFormat::Utf8,
            iv_format: KeyFormat::Hex,
            ciphertext_format: CiphertextFormat::Hex,
            key_input,
            iv_input,
            input_text,
            output_text,
            status_message: "Ready".into(),
            status_is_error: false,
        }
    }

    fn set_status(&mut self, message: impl Into<SharedString>, is_error: bool) {
        self.status_message = message.into();
        self.status_is_error = is_error;
    }

    fn run_operation(&mut self, encrypt_op: bool, window: &mut Window, cx: &mut Context<Self>) {
        let key_text = self.key_input.read(cx).value();
        let iv_text = self.iv_input.read(cx).value();
        let input_text = self.input_text.read(cx).value();

        let req = CryptoRequest {
            mode: self.mode,
            key_format: self.key_format,
            key_text: key_text.as_ref(),
            iv_format: self.iv_format,
            iv_text: iv_text.as_ref(),
            ciphertext_format: self.ciphertext_format,
            input_text: input_text.as_ref(),
        };

        let result = if encrypt_op {
            run_encrypt(&req)
        } else {
            run_decrypt(&req)
        };

        match result {
            Ok(res) => {
                let output = res.output;
                self.output_text
                    .update(cx, |state, cx| state.set_value(output, window, cx));
                let status = if encrypt_op {
                    format!(
                        "Encrypted {} bytes -> {} bytes ({}, {})",
                        res.input_bytes,
                        res.output_bytes,
                        self.mode.name(),
                        self.ciphertext_format.label()
                    )
                } else if res.utf8_fallback_hex {
                    format!(
                        "Decrypted {} bytes -> {} bytes ({}, non-UTF-8 shown as hex)",
                        res.input_bytes,
                        res.output_bytes,
                        self.mode.name()
                    )
                } else {
                    format!(
                        "Decrypted {} bytes -> {} bytes ({})",
                        res.input_bytes,
                        res.output_bytes,
                        self.mode.name()
                    )
                };
                self.set_status(status, false);
            }
            Err(err) => {
                self.set_status(format!("Error: {err}"), true);
            }
        }
        cx.notify();
    }
}

const fn mode_button_id(mode: CipherMode) -> &'static str {
    match mode {
        CipherMode::Ecb => "mode-ecb",
        CipherMode::Cbc => "mode-cbc",
        CipherMode::Pcbc => "mode-pcbc",
        CipherMode::Cfb => "mode-cfb",
        CipherMode::Ofb => "mode-ofb",
        CipherMode::Ctr => "mode-ctr",
    }
}

fn format_length_indicator(text: &str, format: KeyFormat) -> String {
    match format {
        KeyFormat::Utf8 => format!("{} / 16 bytes", text.len()),
        KeyFormat::Hex => format!("{} / 32 hex chars", text.trim().len()),
    }
}

fn toggle_button(id: &'static str, label: &'static str, active: bool, disabled: bool) -> Button {
    let btn = Button::new(id).label(label).disabled(disabled);
    if active { btn.primary() } else { btn.outline() }
}

impl Render for RaesApp {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        let requires_iv = self.mode.requires_iv();

        let key_len_text = format_length_indicator(self.key_input.read(cx).value().as_ref(), self.key_format);
        let iv_len_text = if requires_iv {
            format_length_indicator(self.iv_input.read(cx).value().as_ref(), self.iv_format)
        } else {
            "Not required".to_string()
        };

        let status_border = if self.status_is_error {
            theme.danger
        } else {
            theme.border
        };
        let status_text_color = if self.status_is_error {
            theme.danger
        } else {
            theme.muted_foreground
        };

        v_flex()
            .size_full()
            .px_5()
            .py_4()
            .gap_2p5()
            .bg(theme.background)
            .text_color(theme.foreground)
            // Header
            .child(
                v_flex()
                    .gap_0p5()
                    .child(
                        div()
                            .id("app-title")
                            .test_support()
                            .aria_label("RAES-128")
                            .text_size(px(24.0))
                            .font_semibold()
                            .child("RAES-128"),
                    )
                    .child(
                        Label::new("Pure-Rust AES-128 Encryption & Decryption (FIPS 197)")
                            .text_color(theme.muted_foreground),
                    ),
            )
            // Cipher Mode Bar
            .child(
                v_flex()
                    .p_3()
                    .gap_2()
                    .rounded(px(8.0))
                    .bg(theme.secondary)
                    .border_1()
                    .border_color(theme.border)
                    .child(
                        h_flex()
                            .justify_between()
                            .items_center()
                            .child(Label::new("Cipher Mode").font_semibold())
                            .child(
                                Label::new(if requires_iv {
                                    "128-bit IV / Counter required"
                                } else {
                                    "No IV used in ECB mode"
                                })
                                .text_color(theme.muted_foreground),
                            ),
                    )
                    .child(
                        h_flex()
                            .gap_2()
                            .children(CipherMode::ALL.into_iter().map(|mode| {
                                toggle_button(
                                    mode_button_id(mode),
                                    mode.name(),
                                    self.mode == mode,
                                    false,
                                )
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.mode = mode;
                                    this.set_status(format!("Mode set to {}", mode.name()), false);
                                    cx.notify();
                                }))
                            })),
                    ),
            )
            // Key Configuration Section
            .child(
                v_flex()
                    .p_3()
                    .gap_2()
                    .rounded(px(8.0))
                    .bg(theme.secondary)
                    .border_1()
                    .border_color(theme.border)
                    .child(
                        h_flex()
                            .justify_between()
                            .items_center()
                            .child(
                                h_flex()
                                    .gap_2()
                                    .items_center()
                                    .child(Label::new("Key").font_semibold())
                                    .child(Label::new(key_len_text).text_color(theme.muted_foreground)),
                            )
                            .child(
                                h_flex()
                                    .gap_2()
                                    .child(
                                        toggle_button(
                                            "key-fmt-utf8",
                                            KeyFormat::Utf8.label(),
                                            self.key_format == KeyFormat::Utf8,
                                            false,
                                        )
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.key_format = KeyFormat::Utf8;
                                            this.set_status("Key format set to UTF-8 (16 B)", false);
                                            cx.notify();
                                        })),
                                    )
                                    .child(
                                        toggle_button(
                                            "key-fmt-hex",
                                            KeyFormat::Hex.label(),
                                            self.key_format == KeyFormat::Hex,
                                            false,
                                        )
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.key_format = KeyFormat::Hex;
                                            this.set_status("Key format set to Hex (32 chars)", false);
                                            cx.notify();
                                        })),
                                    ),
                            ),
                    )
                    .child(
                        h_flex()
                            .gap_2()
                            .items_center()
                            .child(
                                Input::new(&self.key_input)
                                    .id("key-input")
                                    .aria_label("AES-128 Key")
                                    .flex_1(),
                            )
                            .child(
                                Button::new("btn-gen-key")
                                    .outline()
                                    .label("Random")
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.key_format = KeyFormat::Hex;
                                        let hex = generate_random_hex_16();
                                        this.key_input
                                            .update(cx, |state, cx| state.set_value(hex, window, cx));
                                        this.set_status("Generated random 128-bit key (Hex)", false);
                                        cx.notify();
                                    })),
                            ),
                    ),
            )
            // IV / Counter Configuration Section
            .child(
                v_flex()
                    .p_3()
                    .gap_2()
                    .rounded(px(8.0))
                    .bg(theme.secondary)
                    .border_1()
                    .border_color(theme.border)
                    .child(
                        h_flex()
                            .justify_between()
                            .items_center()
                            .child(
                                h_flex()
                                    .gap_2()
                                    .items_center()
                                    .child(
                                        Label::new(if requires_iv {
                                            "IV / Counter"
                                        } else {
                                            "IV / Counter (Not used in ECB mode)"
                                        })
                                        .font_semibold(),
                                    )
                                    .child(Label::new(iv_len_text).text_color(theme.muted_foreground)),
                            )
                            .child(
                                h_flex()
                                    .gap_2()
                                    .child(
                                        toggle_button(
                                            "iv-fmt-hex",
                                            KeyFormat::Hex.label(),
                                            self.iv_format == KeyFormat::Hex,
                                            !requires_iv,
                                        )
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.iv_format = KeyFormat::Hex;
                                            this.set_status("IV format set to Hex (32 chars)", false);
                                            cx.notify();
                                        })),
                                    )
                                    .child(
                                        toggle_button(
                                            "iv-fmt-utf8",
                                            KeyFormat::Utf8.label(),
                                            self.iv_format == KeyFormat::Utf8,
                                            !requires_iv,
                                        )
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.iv_format = KeyFormat::Utf8;
                                            this.set_status("IV format set to UTF-8 (16 B)", false);
                                            cx.notify();
                                        })),
                                    ),
                            ),
                    )
                    .child(
                        h_flex()
                            .gap_2()
                            .items_center()
                            .child(
                                Input::new(&self.iv_input)
                                    .id("iv-input")
                                    .aria_label("Initialization Vector")
                                    .disabled(!requires_iv)
                                    .flex_1(),
                            )
                            .child(
                                Button::new("btn-gen-iv")
                                    .outline()
                                    .label("Random")
                                    .disabled(!requires_iv)
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.iv_format = KeyFormat::Hex;
                                        let hex = generate_random_hex_16();
                                        this.iv_input
                                            .update(cx, |state, cx| state.set_value(hex, window, cx));
                                        this.set_status("Generated random 128-bit IV (Hex)", false);
                                        cx.notify();
                                    })),
                            ),
                    ),
            )
            // Ciphertext Format Row
            .child(
                h_flex()
                    .justify_between()
                    .items_center()
                    .child(Label::new("Ciphertext Format").font_semibold())
                    .child(
                        h_flex()
                            .gap_2()
                            .child(
                                toggle_button(
                                    "ct-fmt-hex",
                                    CiphertextFormat::Hex.label(),
                                    self.ciphertext_format == CiphertextFormat::Hex,
                                    false,
                                )
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.ciphertext_format = CiphertextFormat::Hex;
                                    this.set_status("Ciphertext format set to Hex", false);
                                    cx.notify();
                                })),
                            )
                            .child(
                                toggle_button(
                                    "ct-fmt-base64",
                                    CiphertextFormat::Base64.label(),
                                    self.ciphertext_format == CiphertextFormat::Base64,
                                    false,
                                )
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.ciphertext_format = CiphertextFormat::Base64;
                                    this.set_status("Ciphertext format set to Base64", false);
                                    cx.notify();
                                })),
                            ),
                    ),
            )
            // Input Textarea
            .child(
                v_flex()
                    .gap_1()
                    .child(Label::new("Input (Plaintext / Ciphertext)").font_semibold())
                    .child(
                        div()
                            .id("input-text")
                            .test_support()
                            .w_full()
                            .child(
                                Textarea::new(&self.input_text)
                                    .accessibility_id("input-text")
                                    .aria_label("Input Text")
                                    .h(px(120.0)),
                            ),
                    ),
            )
            // Action Bar
            .child(
                h_flex()
                    .gap_2()
                    .items_center()
                    .child(
                        Button::new("btn-encrypt")
                            .primary()
                            .label("Encrypt")
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.run_operation(true, window, cx);
                            })),
                    )
                    .child(
                        Button::new("btn-decrypt")
                            .primary()
                            .label("Decrypt")
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.run_operation(false, window, cx);
                            })),
                    )
                    .child(
                        Button::new("btn-swap")
                            .outline()
                            .label("Use Output as Input")
                            .on_click(cx.listener(|this, _, window, cx| {
                                let output = this.output_text.read(cx).value();
                                this.input_text
                                    .update(cx, |state, cx| state.set_value(output, window, cx));
                                this.output_text
                                    .update(cx, |state, cx| state.set_value("", window, cx));
                                this.set_status("Moved output to input", false);
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("btn-copy")
                            .outline()
                            .label("Copy Output")
                            .on_click(cx.listener(|this, _, _, cx| {
                                let text = this.output_text.read(cx).value();
                                if text.is_empty() {
                                    this.set_status("Nothing to copy", false);
                                } else {
                                    cx.write_to_clipboard(ClipboardItem::new_string(text.to_string()));
                                    this.set_status("Copied output to clipboard", false);
                                }
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("btn-clear")
                            .outline()
                            .label("Clear")
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.input_text
                                    .update(cx, |state, cx| state.set_value("", window, cx));
                                this.output_text
                                    .update(cx, |state, cx| state.set_value("", window, cx));
                                this.set_status("Cleared", false);
                                cx.notify();
                            })),
                    ),
            )
            // Output Textarea
            .child(
                v_flex()
                    .gap_1()
                    .child(Label::new("Output").font_semibold())
                    .child(
                        div()
                            .id("output-text")
                            .test_support()
                            .w_full()
                            .child(
                                Textarea::new(&self.output_text)
                                    .accessibility_id("output-text")
                                    .aria_label("Output Text")
                                    .readonly(true)
                                    .h(px(120.0)),
                            ),
                    ),
            )
            // Status Bar
            .child(
                div()
                    .id("status-message")
                    .role(Role::Status)
                    .test_support()
                    .aria_label(self.status_message.clone())
                    .w_full()
                    .px_3()
                    .py_2()
                    .rounded(px(6.0))
                    .bg(theme.secondary)
                    .border_1()
                    .border_color(status_border)
                    .text_color(status_text_color)
                    .child(self.status_message.clone()),
            )
    }
}
