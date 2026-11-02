//! Runs the Rust guest's validation entry point natively on canonical SSZ
//! inputs: `stwo-eest-rust-host FILE...` prints `<file> <output hex|ABORT>` per
//! input. A panic (the guest's illegal-instruction path) prints ABORT.
use std::{fs, panic};

fn main() {
    panic::set_hook(Box::new(|_| {}));
    for path in std::env::args().skip(1) {
        let input = match fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                println!("{path} READ_ERROR {e}");
                continue;
            }
        };
        let r = panic::catch_unwind(|| stateless_validator_reth::guest::run_stateless_guest(&input));
        match r {
            Ok(out) if out.len() == 43 && out[32] == 1 => {
                let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
                println!("{path} {hex}");
            }
            Ok(out) => {
                let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
                println!("{path} REJECT {hex}");
            }
            Err(_) => println!("{path} ABORT"),
        }
    }
}
