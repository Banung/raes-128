pub mod aes;

use gpui_kit::{
    Context, IntoElement, ParentElement, Render, Styled, TestSupportExt, Window,
    component::{ActiveTheme, StyledExt, label::Label},
    div, prelude::*, px,
};

pub struct RaesApp;

impl RaesApp {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RaesApp {
    fn default() -> Self {
        Self::new()
    }
}

impl Render for RaesApp {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();

        div()
            .size_full()
            .flex()
            .flex_col()
            .items_center()
            .justify_center()
            .gap_2()
            .p_6()
            .bg(theme.background)
            .text_color(theme.foreground)
            .child(
                div()
                    .id("app-title")
                    .test_support()
                    .aria_label("RAES-128")
                    .text_size(px(28.0))
                    .font_semibold()
                    .child("RAES-128"),
            )
            .child(
                Label::new("GPUI Kit desktop shell ready.")
                    .text_color(theme.muted_foreground),
            )
    }
}
