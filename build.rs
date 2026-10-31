fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Server stubs for the service; the client is only used by tests.
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&["proto/kms.proto"], &["proto"])?;
    println!("cargo:rerun-if-changed=proto/kms.proto");
    Ok(())
}
