fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        println!("cargo:rustc-link-lib=c++abi");
        println!("cargo:rustc-cdylib-link-arg=-Wl,-z,defs");
        println!("cargo:rustc-cdylib-link-arg=-Wl,--pack-dyn-relocs=android");
        println!("cargo:rustc-cdylib-link-arg=-Wl,--icf=all");
    }
}
