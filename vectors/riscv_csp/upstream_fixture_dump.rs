//! Source-isolated adapter for CSP generators not exposed by the upstream CLI.
//!
//! Compile this file against the pinned checkout's already locked `utils`
//! library. It deliberately contains no RNG, curve, or field implementation of
//! its own; the emitted bytes come directly from the upstream generator.

use std::env;

fn hex(bytes: impl IntoIterator<Item = u8>) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.into_iter();
    let mut encoded = String::with_capacity(bytes.size_hint().0 * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn ecdsa_secp256k1() {
    let (digest, (x, y), signature) = utils::generate_ecdsa_k256_input();
    let mut input = Vec::with_capacity(32 + 65 + 64);
    input.extend_from_slice(&digest);
    input.push(0x04);
    input.extend_from_slice(&x);
    input.extend_from_slice(&y);
    input.extend_from_slice(&signature);
    println!("{}", hex(input));
    println!("{}", hex(digest));
}

fn poseidon2_m31(size: usize) {
    let values = utils::generate_poseidon_input_m31(size);
    let mut input = Vec::with_capacity(4 + values.len() * 4);
    input.extend_from_slice(&(values.len() as u32).to_le_bytes());
    for value in values {
        input.extend_from_slice(&value.to_le_bytes());
    }
    println!("{}", hex(input));
}

fn main() {
    let mut arguments = env::args().skip(1);
    match arguments.next().as_deref() {
        Some("ecdsa-secp256k1") if arguments.next().is_none() => {
            ecdsa_secp256k1();
        }
        Some("poseidon2-m31") => {
            let size = arguments
                .next()
                .expect("poseidon2-m31 requires a size")
                .parse()
                .expect("poseidon2-m31 size must be an integer");
            assert!(arguments.next().is_none(), "unexpected trailing argument");
            poseidon2_m31(size);
        }
        _ => panic!(
            "usage: upstream_fixture_dump \
             <ecdsa-secp256k1 | poseidon2-m31 SIZE>"
        ),
    }
}
