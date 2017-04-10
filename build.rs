extern crate gcc;

fn main() {
    gcc::compile_library("libmnl_ext.a", &["src/nlmsg_ext.c"]);
}
