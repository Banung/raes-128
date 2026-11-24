use std::path::{Path, PathBuf};

use gpui_kit::{
    AppContext, ClipboardItem, Context, Entity, IntoElement, ParentElement, PathPromptOptions,
    Render, Role, SharedString, Styled, TestSupportExt, Window, div, prelude::*, px,
};
use gpui_kit::component::{
    ActiveTheme, Disableable, StyledExt,
    button::{Button, ButtonVariants as _},
    h_flex,
    input::{Input, InputState, Textarea, TextareaState},
    label::Label,
    v_flex,
};

use crate::aes::{CipherMode, FirstBlockModeTrace, PaddingMode, format_trace_text};
use crate::ui::controller::{
    CiphertextFormat, CryptoRequest, KeyFormat, PlaintextFormat, generate_random_hex_16,
    run_decrypt, run_encrypt,
};
use crate::ui::file_crypto::{
    FileCryptoRequest, decrypt_file, encrypt_file, suggested_output_path,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkspaceTab {
    Text,
    File,
    Trace,
}

/// Interactive desktop application view for pure-Rust AES-128 encryption and decryption.
pub struct RaesApp {
    active_tab: WorkspaceTab,
    mode: CipherMode,
    key_format: KeyFormat,
    iv_format: KeyFormat,
    ciphertext_format: CiphertextFormat,
    key_input: Entity<InputState>,
    iv_input: Entity<InputState>,
    input_text: Entity<TextareaState>,
    output_text: Entity<TextareaState>,
    file_input_path: Entity<InputState>,
    file_output_path: Entity<InputState>,
    last_trace: Option<FirstBlockModeTrace>,
    trace_show_all_rounds: bool,
    trace_output: Entity<TextareaState>,
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
        let file_input_path = cx.new(|cx| {
            InputState::new(window, cx).placeholder("Path to input file on disk...")
        });
        let file_output_path = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Path to output file (leave blank to auto-suggest)...")
        });
        let trace_output = cx.new(|cx| {
            TextareaState::new(window, cx)
                .placeholder(
                    "Run Encrypt or Decrypt (Text or File) to inspect the AES-128 Step-by-Step Trace...",
                )
                .rows(14)
        });

        Self {
            active_tab: WorkspaceTab::Text,
            mode: CipherMode::Cbc,
            key_format: KeyFormat::Utf8,
            iv_format: KeyFormat::Hex,
            ciphertext_format: CiphertextFormat::Hex,
            key_input,
            iv_input,
            input_text,
            output_text,
            file_input_path,
            file_output_path,
            last_trace: None,
            trace_show_all_rounds: false,
            trace_output,
            status_message: "Ready".into(),
            status_is_error: false,
        }
    }

    fn set_status(&mut self, message: impl Into<SharedString>, is_error: bool) {
        self.status_message = message.into();
        self.status_is_error = is_error;
    }

    fn refresh_trace_view(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let formatted = match &self.last_trace {
            Some(trace) => format_trace_text(trace, self.trace_show_all_rounds),
            None => String::new(),
        };
        self.trace_output
            .update(cx, |state, cx| state.set_value(formatted, window, cx));
    }

    fn run_operation(&mut self, encrypt_op: bool, window: &mut Window, cx: &mut Context<Self>) {
        let key_text = self.key_input.read(cx).value();
        let iv_text = self.iv_input.read(cx).value();
        let input_text = self.input_text.read(cx).value();

        let req = CryptoRequest {
            mode: self.mode,
            padding: PaddingMode::Pkcs7,
            key_format: self.key_format,
            key_text: key_text.as_ref(),
            iv_format: self.iv_format,
            iv_text: iv_text.as_ref(),
            plaintext_format: PlaintextFormat::Utf8,
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
                self.last_trace = res.trace;
                self.refresh_trace_view(window, cx);
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

    fn run_file_operation(
        &mut self,
        encrypt_op: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let key_text = self.key_input.read(cx).value();
        let iv_text = self.iv_input.read(cx).value();
        let in_val = self.file_input_path.read(cx).value();
        let out_val = self.file_output_path.read(cx).value();

        let in_raw = in_val.trim();
        let out_raw = out_val.trim();

        let output_path = if !in_raw.is_empty() && out_raw.is_empty() {
            let suggested = suggested_output_path(Path::new(in_raw), encrypt_op);
            let suggested_str = suggested.to_string_lossy().into_owned();
            self.file_output_path
                .update(cx, |state, cx| state.set_value(suggested_str, window, cx));
            suggested
        } else {
            PathBuf::from(out_raw)
        };

        let req = FileCryptoRequest {
            mode: self.mode,
            key_format: self.key_format,
            key_text: key_text.as_ref(),
            iv_format: self.iv_format,
            iv_text: iv_text.as_ref(),
            input_path: Path::new(in_raw),
            output_path: &output_path,
        };

        let result = if encrypt_op {
            encrypt_file(&req)
        } else {
            decrypt_file(&req)
        };

        match result {
            Ok(res) => {
                self.last_trace = res.trace;
                self.refresh_trace_view(window, cx);
                let verb = if encrypt_op {
                    "Encrypted file"
                } else {
                    "Decrypted file"
                };
                self.set_status(
                    format!(
                        "{verb}: {} bytes -> {} bytes ({}) -> {}",
                        res.input_bytes,
                        res.output_bytes,
                        self.mode.name(),
                        res.output_path.display()
                    ),
                    false,
                );
            }
            Err(err) => {
                self.set_status(format!("Error: {err}"), true);
            }
        }
        cx.notify();
    }

    fn browse_input_file(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let receiver = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("Select input file".into()),
        });

        cx.spawn_in(window, async move |this, cx| {
            let Ok(result) = receiver.await else {
                return;
            };

            match result {
                Ok(Some(paths)) => {
                    let Some(selected) = paths.into_iter().next() else {
                        return;
                    };
                    let _ = this.update_in(cx, |this, window, cx| {
                        let selected_str = selected.to_string_lossy().into_owned();
                        this.file_input_path
                            .update(cx, |state, cx| state.set_value(selected_str, window, cx));
                        if this.file_output_path.read(cx).value().trim().is_empty() {
                            let suggested = suggested_output_path(&selected, true)
                                .to_string_lossy()
                                .into_owned();
                            this.file_output_path
                                .update(cx, |state, cx| state.set_value(suggested, window, cx));
                        }
                        this.set_status(
                            format!("Selected input file: {}", selected.display()),
                            false,
                        );
                        cx.notify();
                    });
                }
                Ok(None) => {}
                Err(err) => {
                    let _ = this.update_in(cx, |this, _window, cx| {
                        this.set_status(
                            format!("Error: failed to open file picker: {err}"),
                            true,
                        );
                        cx.notify();
                    });
                }
            }
        })
        .detach();
    }

    fn browse_output_file(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let out_val = self.file_output_path.read(cx).value();
        let in_val = self.file_input_path.read(cx).value();
        let out_trimmed = out_val.trim();
        let in_trimmed = in_val.trim();

        let dir = non_empty_parent(out_trimmed)
            .or_else(|| non_empty_parent(in_trimmed))
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

        let suggested_name = if !out_trimmed.is_empty() {
            Path::new(out_trimmed)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
        } else if !in_trimmed.is_empty() {
            suggested_output_path(Path::new(in_trimmed), true)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
        } else {
            None
        };

        let receiver = cx.prompt_for_new_path(&dir, suggested_name.as_deref());

        cx.spawn_in(window, async move |this, cx| {
            let Ok(result) = receiver.await else {
                return;
            };

            match result {
                Ok(Some(selected)) => {
                    let _ = this.update_in(cx, |this, window, cx| {
                        let selected_str = selected.to_string_lossy().into_owned();
                        this.file_output_path
                            .update(cx, |state, cx| state.set_value(selected_str, window, cx));
                        this.set_status(
                            format!("Selected output file: {}", selected.display()),
                            false,
                        );
                        cx.notify();
                    });
                }
                Ok(None) => {}
                Err(err) => {
                    let _ = this.update_in(cx, |this, _window, cx| {
                        this.set_status(
                            format!("Error: failed to open save dialog: {err}"),
                            true,
                        );
                        cx.notify();
                    });
                }
            }
        })
        .detach();
    }
}

fn non_empty_parent(raw: &str) -> Option<PathBuf> {
    if raw.is_empty() {
        return None;
    }
    Path::new(raw)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
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

impl RaesApp {
    fn render_text_workspace(&self, cx: &mut Context<Self>) -> impl IntoElement {
        v_flex()
            .gap_2p5()
            .w_full()
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
    }

    fn render_file_workspace(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();

        v_flex()
            .gap_2p5()
            .w_full()
            // Disk File Encryption & Decryption Card
            .child(
                v_flex()
                    .p_3()
                    .gap_2p5()
                    .rounded(px(8.0))
                    .bg(theme.secondary)
                    .border_1()
                    .border_color(theme.border)
                    .child(
                        Label::new("Disk File Encryption & Decryption").font_semibold(),
                    )
                    .child(
                        h_flex()
                            .gap_2()
                            .items_center()
                            .child(
                                div()
                                    .w(px(92.0))
                                    .child(Label::new("Input File").font_semibold()),
                            )
                            .child(
                                Input::new(&self.file_input_path)
                                    .id("file-input-path")
                                    .aria_label("Input File Path")
                                    .flex_1(),
                            )
                            .child(
                                Button::new("btn-browse-input")
                                    .outline()
                                    .label("Browse...")
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.browse_input_file(window, cx);
                                    })),
                            ),
                    )
                    .child(
                        h_flex()
                            .gap_2()
                            .items_center()
                            .child(
                                div()
                                    .w(px(92.0))
                                    .child(Label::new("Output File").font_semibold()),
                            )
                            .child(
                                Input::new(&self.file_output_path)
                                    .id("file-output-path")
                                    .aria_label("Output File Path")
                                    .flex_1(),
                            )
                            .child(
                                Button::new("btn-browse-output")
                                    .outline()
                                    .label("Save As...")
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.browse_output_file(window, cx);
                                    })),
                            ),
                    )
                    .child(
                        Label::new(
                            "Supports arbitrary binary files up to 128 MiB. Input files are never overwritten in place.",
                        )
                        .text_color(theme.muted_foreground),
                    ),
            )
            // File Action Bar
            .child(
                h_flex()
                    .gap_2()
                    .items_center()
                    .child(
                        Button::new("btn-file-encrypt")
                            .primary()
                            .label("Encrypt File")
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.run_file_operation(true, window, cx);
                            })),
                    )
                    .child(
                        Button::new("btn-file-decrypt")
                            .primary()
                            .label("Decrypt File")
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.run_file_operation(false, window, cx);
                            })),
                    )
                    .child(
                        Button::new("btn-file-swap")
                            .outline()
                            .label("Use Output as Input")
                            .on_click(cx.listener(|this, _, window, cx| {
                                let output = this.file_output_path.read(cx).value();
                                this.file_input_path
                                    .update(cx, |state, cx| state.set_value(output, window, cx));
                                this.file_output_path
                                    .update(cx, |state, cx| state.set_value("", window, cx));
                                this.set_status("Moved output file path to input", false);
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("btn-file-clear")
                            .outline()
                            .label("Clear Paths")
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.file_input_path
                                    .update(cx, |state, cx| state.set_value("", window, cx));
                                this.file_output_path
                                    .update(cx, |state, cx| state.set_value("", window, cx));
                                this.set_status("Cleared file paths", false);
                                cx.notify();
                            })),
                    ),
            )
    }

    fn render_trace_workspace(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        let summary_text = match &self.last_trace {
            Some(trace) => format!(
                "AES-128-{} • {} (Core: {})",
                trace.mode.name(),
                trace.operation.label(),
                trace.block_trace.direction.label()
            ),
            None => "No trace captured yet — run Encrypt or Decrypt in Text or File tab".to_string(),
        };

        v_flex()
            .gap_2p5()
            .w_full()
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
                            .gap_2()
                            .child(Label::new("Step-by-Step Trace (Block 0)").font_semibold())
                            .child(
                                Label::new(summary_text).text_color(theme.muted_foreground),
                            ),
                    )
                    .child(
                        h_flex()
                            .gap_2()
                            .items_center()
                            .child(
                                toggle_button(
                                    "trace-mode-summary",
                                    "Initial / R1 / Final",
                                    !self.trace_show_all_rounds,
                                    false,
                                )
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.trace_show_all_rounds = false;
                                    this.refresh_trace_view(window, cx);
                                    this.set_status(
                                        "Showing summary trace (Initial Round, Round 1, Final Round)",
                                        false,
                                    );
                                    cx.notify();
                                })),
                            )
                            .child(
                                toggle_button(
                                    "trace-mode-all",
                                    "All 10 Rounds",
                                    self.trace_show_all_rounds,
                                    false,
                                )
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.trace_show_all_rounds = true;
                                    this.refresh_trace_view(window, cx);
                                    this.set_status(
                                        "Showing full 10-round trace and all 11 round keys",
                                        false,
                                    );
                                    cx.notify();
                                })),
                            )
                            .child(
                                Button::new("btn-copy-trace")
                                    .outline()
                                    .label("Copy Trace")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        let text = this.trace_output.read(cx).value();
                                        if text.is_empty() {
                                            this.set_status("No trace to copy", false);
                                        } else {
                                            cx.write_to_clipboard(ClipboardItem::new_string(
                                                text.to_string(),
                                            ));
                                            this.set_status("Copied trace to clipboard", false);
                                        }
                                        cx.notify();
                                    })),
                            ),
                    ),
            )
            .child(
                div()
                    .id("trace-output")
                    .test_support()
                    .w_full()
                    .font_family(theme.mono_font_family.clone())
                    .child(
                        Textarea::new(&self.trace_output)
                            .accessibility_id("trace-output")
                            .aria_label("Step-by-Step Trace")
                            .readonly(true)
                            .h(px(480.0)),
                    ),
            )
    }
}

impl Render for RaesApp {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let workspace_content = match self.active_tab {
            WorkspaceTab::Text => self.render_text_workspace(cx).into_any_element(),
            WorkspaceTab::File => self.render_file_workspace(cx).into_any_element(),
            WorkspaceTab::Trace => self.render_trace_workspace(cx).into_any_element(),
        };

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

        let mut root = v_flex()
            .size_full()
            .px_5()
            .py_4()
            .gap_2p5()
            .bg(theme.background)
            .text_color(theme.foreground)
            // Header + Workspace Switcher
            .child(
                h_flex()
                    .justify_between()
                    .items_center()
                    .gap_3()
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
                    .child(
                        h_flex()
                            .gap_2()
                            .items_center()
                            .child(
                                toggle_button(
                                    "tab-text",
                                    "Text",
                                    self.active_tab == WorkspaceTab::Text,
                                    false,
                                )
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.active_tab = WorkspaceTab::Text;
                                    this.set_status("Switched to Text mode", false);
                                    cx.notify();
                                })),
                            )
                            .child(
                                toggle_button(
                                    "tab-file",
                                    "File",
                                    self.active_tab == WorkspaceTab::File,
                                    false,
                                )
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.active_tab = WorkspaceTab::File;
                                    this.set_status("Switched to File mode", false);
                                    cx.notify();
                                })),
                            )
                            .child(
                                toggle_button(
                                    "tab-trace",
                                    "Trace",
                                    self.active_tab == WorkspaceTab::Trace,
                                    false,
                                )
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.active_tab = WorkspaceTab::Trace;
                                    this.set_status("Switched to Step-by-Step Trace view", false);
                                    cx.notify();
                                })),
                            ),
                    ),
            );

        if self.active_tab != WorkspaceTab::Trace {
            root = root
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
                                        this.set_status(
                                            format!("Mode set to {}", mode.name()),
                                            false,
                                        );
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
                                        .child(
                                            Label::new(key_len_text)
                                                .text_color(theme.muted_foreground),
                                        ),
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
                                                this.set_status(
                                                    "Key format set to UTF-8 (16 B)",
                                                    false,
                                                );
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
                                                this.set_status(
                                                    "Key format set to Hex (32 chars)",
                                                    false,
                                                );
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
                                            this.key_input.update(cx, |state, cx| {
                                                state.set_value(hex, window, cx)
                                            });
                                            this.set_status(
                                                "Generated random 128-bit key (Hex)",
                                                false,
                                            );
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
                                        .child(
                                            Label::new(iv_len_text)
                                                .text_color(theme.muted_foreground),
                                        ),
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
                                                this.set_status(
                                                    "IV format set to Hex (32 chars)",
                                                    false,
                                                );
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
                                                this.set_status(
                                                    "IV format set to UTF-8 (16 B)",
                                                    false,
                                                );
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
                                            this.iv_input.update(cx, |state, cx| {
                                                state.set_value(hex, window, cx)
                                            });
                                            this.set_status(
                                                "Generated random 128-bit IV (Hex)",
                                                false,
                                            );
                                            cx.notify();
                                        })),
                                ),
                        ),
                );
        }

        root
            // Active Workspace (Text, File, or Trace)
            .child(workspace_content)
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
