use gpui_kit::test::TestWindowExt;
use gpui_kit::{
    AppContext, Bounds, Point, TestAppContext, WindowBounds, WindowOptions, px, size,
};

#[gpui_kit::test]
fn renders_raes_app_shell(cx: &mut TestAppContext) {
    cx.update(gpui_kit::init);

    let (handle, _) = cx.update(|cx| {
        gpui_kit::open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(Bounds {
                    origin: Point::default(),
                    size: size(px(800.), px(600.)),
                })),
                ..Default::default()
            },
            cx,
            |_, cx| cx.new(|_| raes_128::RaesApp::new()),
        )
        .expect("open test window")
    });

    cx.update_window(handle, |_, window, cx| {
        window.render_frame(cx);
        let title = window.find("app-title");
        assert!(title.visible());
        assert_eq!(title.label(), Some("RAES-128"));
    })
    .expect("update test window");
}
