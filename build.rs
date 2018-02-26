extern crate gcc;

fn main() {
    gcc::Build::new()
        .file("src/nlmsg_ext.c")
        .static_flag(true)
        .compile("libmnl_ext.a");
}
