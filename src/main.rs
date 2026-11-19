use gpui_kit::{
    AppContext, TitlebarOptions, WindowBounds, WindowOptions, assets::Assets, px, size,
};

fn main() {
    gpui_kit::application().with_assets(Assets).run(|cx| {
        gpui_kit::init(cx);

        let options = WindowOptions {
            window_bounds: Some(WindowBounds::centered(size(px(960.0), px(780.0)), cx)),
            titlebar: Some(TitlebarOptions {
                title: Some("RAES-128".into()),
                ..Default::default()
            }),
            ..Default::default()
        };

        gpui_kit::open_window(options, cx, |window, cx| {
            cx.new(|cx| raes_128::RaesApp::new(window, cx))
        })
        .expect("failed to open main window");

        cx.activate(true);
    });
}
