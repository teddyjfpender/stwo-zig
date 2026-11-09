mod common;
mod config;
mod examples;
mod fri;
mod generator;
mod model;
mod pcs;
mod proof;
mod vcs;

use std::env;
use std::fs;
use std::path::PathBuf;

use crate::config::DEFAULT_COUNT;
use crate::generator::generate_vectors;

const UPSTREAM_COMMIT: &str = "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2";

fn main() {
    let (out_path, sample_count) = parse_args();
    let mut state = config::VECTOR_SEED;
    let vectors = generate_vectors(&mut state, sample_count);

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).expect("failed to create vector output directory");
    }

    let serialized = serde_json::to_string_pretty(&vectors).expect("failed to serialize vectors");
    fs::write(&out_path, serialized).expect("failed to write vectors");
}

fn parse_args() -> (PathBuf, usize) {
    let mut out = PathBuf::from("vectors/waist/fields.json");
    let mut sample_count = DEFAULT_COUNT;
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => {
                let path = args.next().expect("--out requires a path");
                out = PathBuf::from(path);
            }
            "--count" => {
                let raw = args.next().expect("--count requires a number");
                sample_count = raw.parse::<usize>().expect("--count must be a usize");
            }
            "--help" | "-h" => {
                eprintln!("Usage: stwo-vector-gen [--out <path>] [--count <n>]");
                std::process::exit(0);
            }
            _ => {
                panic!("unknown argument: {arg}");
            }
        }
    }

    (out, sample_count)
}
