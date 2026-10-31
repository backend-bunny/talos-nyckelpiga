//! Write a self-signed `tls.crt`/`tls.key` for `localhost` into a directory.
//! Used by hack/test.sh to smoke-test the image; never for real deployments
//! (Talos needs a publicly trusted certificate).
//!
//! Usage: cargo run --example selfsigned -- <dir>

fn main() {
    let dir = std::env::args().nth(1).expect("usage: selfsigned <dir>");
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(format!("{dir}/tls.crt"), ck.cert.pem()).unwrap();
    std::fs::write(format!("{dir}/tls.key"), ck.signing_key.serialize_pem()).unwrap();
}
