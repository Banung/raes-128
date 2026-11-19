use gpui_kit::{
    AppContext, TitlebarOptions, WindowBounds, WindowOptions, assets::Assets, px, size,
};

fn main() {
    gpui_kit::application().with_assets(Assets).run(|cx| {
        gpui_kit::init(cx);

        let options = WindowOptions {
            window_bounds: Some(WindowBounds::centered(size(px(800.0), px(600.0)), cx)),
            titlebar: Some(TitlebarOptions {
                title: Some("RAES-128".into()),
                ..Default::default()
            }),
            ..Default::default()
        };

        gpui_kit::open_window(options, cx, |_, cx| cx.new(|_| raes_128::RaesApp::new()))
            .expect("failed to open main window");

        cx.activate(true);
    });
}
