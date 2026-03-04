fn main() {
    let mut res = winres::WindowsResource::new();
    res.set_manifest_file("app.manifest");
    res.compile()
        .expect("failed to embed Windows manifest resource");
}
