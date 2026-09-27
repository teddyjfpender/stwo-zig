#![no_main]
ziskos::entrypoint!(main);
use sha2::{Digest, Sha256};
fn main() {
    let input = ziskos::io::read_slice();
    let n = u32::from_le_bytes(input[..4].try_into().unwrap());
    assert!(n <= 4096);
    let mut output = [0u8; 32];
    for _ in 0..n { output = Sha256::digest(output).into(); }
    ziskos::io::commit_slice(&output);
}
