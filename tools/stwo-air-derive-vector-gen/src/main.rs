use serde::Serialize;
use std::env;
use std::fs;
use std::path::PathBuf;

const DEFAULT_COUNT: usize = 32;
const VECTOR_SCHEMA_VERSION: u32 = 1;
const VECTOR_SEED: u64 = 0x7f4a_7c15_39de_2b11u64;

#[derive(Debug, Clone, Serialize)]
struct Meta {
    schema_version: u32,
    seed: u64,
    sample_count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct MixedRowUpdateVector {
    len: usize,
    initial_a: Vec<u32>,
    initial_b: [Vec<u16>; 2],
    expected_a: Vec<u32>,
    expected_b: [Vec<u16>; 2],
}

#[derive(Debug, Clone, Serialize)]
struct InvalidShapeVector {
    len: usize,
    a_len: usize,
    b_lens: [usize; 2],
    expected: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct VectorFile {
    meta: Meta,
    mixed_row_updates: Vec<MixedRowUpdateVector>,
    invalid_shape_cases: Vec<InvalidShapeVector>,
}

fn main() {
    let (out_path, sample_count) = parse_args();
    let mut state = VECTOR_SEED;
    let vectors = generate_vectors(&mut state, sample_count);

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).expect("failed to create vector output directory");
    }
    let rendered = serde_json::to_string_pretty(&vectors).expect("failed to serialize vectors");
    fs::write(out_path, format!("{rendered}\n")).expect("failed to write vectors");
}

fn parse_args() -> (PathBuf, usize) {
    let mut out = PathBuf::from("vectors/air_derive.json");
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
                eprintln!("Usage: stwo-air-derive-vector-gen [--out <path>] [--count <n>]");
                std::process::exit(0);
            }
            _ => panic!("unknown argument: {arg}"),
        }
    }

    (out, sample_count)
}

fn generate_vectors(state: &mut u64, sample_count: usize) -> VectorFile {
    let mut mixed_row_updates = Vec::with_capacity(sample_count);
    for _ in 0..sample_count {
        let len = 1 + ((next_u64(state) as usize) % 24);

        let mut initial_a = Vec::with_capacity(len);
        let mut initial_b0 = Vec::with_capacity(len);
        let mut initial_b1 = Vec::with_capacity(len);
        for _ in 0..len {
            initial_a.push(next_u64(state) as u32);
            initial_b0.push((next_u64(state) & 0xffff) as u16);
            initial_b1.push((next_u64(state) & 0xffff) as u16);
        }

        let mut expected_a = initial_a.clone();
        let mut expected_b0 = initial_b0.clone();
        let mut expected_b1 = initial_b1.clone();
        for i in 0..len {
            expected_a[i] ^= (i as u32).wrapping_mul(7);
            expected_b0[i] = expected_b0[i].wrapping_add(i as u16);
            expected_b1[i] ^= ((i as u16).wrapping_mul(3)).wrapping_add(1);
        }

        mixed_row_updates.push(MixedRowUpdateVector {
            len,
            initial_a,
            initial_b: [initial_b0, initial_b1],
            expected_a,
            expected_b: [expected_b0, expected_b1],
        });
    }

    let invalid_shape_cases = vec![
        InvalidShapeVector {
            len: 8,
            a_len: 8,
            b_lens: [8, 7],
            expected: "ShapeMismatch",
        },
        InvalidShapeVector {
            len: 5,
            a_len: 4,
            b_lens: [5, 5],
            expected: "ShapeMismatch",
        },
    ];

    VectorFile {
        meta: Meta {
            schema_version: VECTOR_SCHEMA_VERSION,
            seed: VECTOR_SEED,
            sample_count,
        },
        mixed_row_updates,
        invalid_shape_cases,
    }
}

fn next_u64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    x.wrapping_mul(0x2545_f491_4f6c_dd1d)
}
