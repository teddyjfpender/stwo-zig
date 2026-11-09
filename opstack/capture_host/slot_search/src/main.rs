//! Offline bounded secure-trie prefix search; output remains untrusted advice.
use sha3::{Digest, Keccak256};
use std::time::{Duration, Instant};
fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 3);
    let prefix = &args[1];
    assert!(!prefix.is_empty() && prefix.len() <= 6 && prefix.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
    let seconds: u64 = args[2].parse().unwrap();
    assert!((1..=60).contains(&seconds));
    let wanted = u32::from_str_radix(prefix, 16).unwrap();
    let shift = 32 - 4 * prefix.len();
    let started = Instant::now();
    let mut slot = [0u8; 32];
    for candidate in 0u64..(1 << 28) {
        if candidate & 4095 == 0 && started.elapsed() >= Duration::from_secs(seconds) { std::process::exit(2); }
        slot[24..].copy_from_slice(&candidate.to_be_bytes());
        let hash = Keccak256::digest(slot);
        if u32::from_be_bytes(hash[..4].try_into().unwrap()) >> shift == wanted {
            println!("{{\"candidate\":{candidate},\"attempts\":{},\"seconds\":{}}}",candidate + 1,started.elapsed().as_secs_f64());
            return;
        }
    }
    std::process::exit(2);
}
