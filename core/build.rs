use std::env;
use std::path::PathBuf;

fn main() {
    // Only generate C bindings if the "ffi" feature is enabled
    if env::var("CARGO_FEATURE_FFI").is_ok() {
        generate_c_bindings();
    }
    
    // Set linking configuration
    println!("cargo:rustc-link-lib=static=secure_protocol");
    println!("cargo:rerun-if-changed=src/ffi");
    println!("cargo:rerun-if-changed=cbindgen.toml");
}

fn generate_c_bindings() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    
    // We need to handle the case where "bindings/c" might not exist yet if not created by mkdir
    // But assuming the user followed instructions or mkdir was run.
    // We'll target a specific path.
    let output_file = PathBuf::from(&crate_dir)
        .join("..")
        .join("bindings")
        .join("c")
        .join("secure_protocol.h");
    
    let config = cbindgen::Config::from_file("cbindgen.toml")
        .unwrap_or_else(|_| cbindgen::Config::default());

    if let Ok(bindings) = cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(config)
        .generate() 
    {
        bindings.write_to_file(output_file);
    }
}
