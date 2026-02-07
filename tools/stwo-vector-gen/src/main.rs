use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use stwo::core::fields::cm31::CM31;
use stwo::core::fields::m31::{M31, P};
use stwo::core::fields::qm31::QM31;
use stwo::core::fields::FieldExpOps;

const UPSTREAM_COMMIT: &str = "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2";
const DEFAULT_COUNT: usize = 256;

#[derive(Debug, Clone, Serialize)]
struct Meta {
    upstream_commit: &'static str,
    sample_count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct M31Vector {
    a: u32,
    b: u32,
    add: u32,
    sub: u32,
    mul: u32,
    inv_a: u32,
    div_ab: u32,
}

#[derive(Debug, Clone, Serialize)]
struct CM31Vector {
    a: [u32; 2],
    b: [u32; 2],
    add: [u32; 2],
    sub: [u32; 2],
    mul: [u32; 2],
    inv_a: [u32; 2],
    div_ab: [u32; 2],
}

#[derive(Debug, Clone, Serialize)]
struct QM31Vector {
    a: [u32; 4],
    b: [u32; 4],
    add: [u32; 4],
    sub: [u32; 4],
    mul: [u32; 4],
    inv_a: [u32; 4],
    div_ab: [u32; 4],
}

#[derive(Debug, Clone, Serialize)]
struct FieldVectors {
    meta: Meta,
    m31: Vec<M31Vector>,
    cm31: Vec<CM31Vector>,
    qm31: Vec<QM31Vector>,
}

fn main() {
    let (out_path, sample_count) = parse_args();
    let mut state = 0x243f_6a88_85a3_08d3u64;
    let vectors = generate_vectors(&mut state, sample_count);

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).expect("failed to create vector output directory");
    }

    let serialized = serde_json::to_string_pretty(&vectors).expect("failed to serialize vectors");
    fs::write(&out_path, serialized).expect("failed to write vectors");
}

fn parse_args() -> (PathBuf, usize) {
    let mut out = PathBuf::from("vectors/fields.json");
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

fn generate_vectors(state: &mut u64, sample_count: usize) -> FieldVectors {
    let mut m31 = Vec::with_capacity(sample_count);
    let mut cm31 = Vec::with_capacity(sample_count);
    let mut qm31 = Vec::with_capacity(sample_count);

    for _ in 0..sample_count {
        let a = sample_m31(state, true);
        let b = sample_m31(state, true);
        m31.push(M31Vector {
            a: encode_m31(a),
            b: encode_m31(b),
            add: encode_m31(a + b),
            sub: encode_m31(a - b),
            mul: encode_m31(a * b),
            inv_a: encode_m31(a.inverse()),
            div_ab: encode_m31(a / b),
        });
    }

    for _ in 0..sample_count {
        let a = sample_cm31(state, true);
        let b = sample_cm31(state, true);
        cm31.push(CM31Vector {
            a: encode_cm31(a),
            b: encode_cm31(b),
            add: encode_cm31(a + b),
            sub: encode_cm31(a - b),
            mul: encode_cm31(a * b),
            inv_a: encode_cm31(a.inverse()),
            div_ab: encode_cm31(a / b),
        });
    }

    for _ in 0..sample_count {
        let a = sample_qm31(state, true);
        let b = sample_qm31(state, true);
        qm31.push(QM31Vector {
            a: encode_qm31(a),
            b: encode_qm31(b),
            add: encode_qm31(a + b),
            sub: encode_qm31(a - b),
            mul: encode_qm31(a * b),
            inv_a: encode_qm31(a.inverse()),
            div_ab: encode_qm31(a / b),
        });
    }

    FieldVectors {
        meta: Meta {
            upstream_commit: UPSTREAM_COMMIT,
            sample_count,
        },
        m31,
        cm31,
        qm31,
    }
}

fn encode_m31(x: M31) -> u32 {
    x.0
}

fn encode_cm31(x: CM31) -> [u32; 2] {
    [x.0 .0, x.1 .0]
}

fn encode_qm31(x: QM31) -> [u32; 4] {
    [x.0 .0 .0, x.0 .1 .0, x.1 .0 .0, x.1 .1 .0]
}

fn sample_m31(state: &mut u64, non_zero: bool) -> M31 {
    loop {
        let candidate = (next_u64(state) as u32) & 0x7fff_ffff;
        if candidate == P {
            continue;
        }
        if non_zero && candidate == 0 {
            continue;
        }
        return M31::from_u32_unchecked(candidate);
    }
}

fn sample_cm31(state: &mut u64, non_zero: bool) -> CM31 {
    loop {
        let out = CM31(sample_m31(state, false), sample_m31(state, false));
        if non_zero && out.0 .0 == 0 && out.1 .0 == 0 {
            continue;
        }
        return out;
    }
}

fn sample_qm31(state: &mut u64, non_zero: bool) -> QM31 {
    loop {
        let out = QM31(
            CM31(sample_m31(state, false), sample_m31(state, false)),
            CM31(sample_m31(state, false), sample_m31(state, false)),
        );
        if non_zero && encode_qm31(out) == [0, 0, 0, 0] {
            continue;
        }
        return out;
    }
}

fn next_u64(state: &mut u64) -> u64 {
    // Xorshift64* (deterministic, non-cryptographic).
    let mut x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    x.wrapping_mul(0x2545_f491_4f6c_dd1d)
}

#[allow(dead_code)]
fn _assert_relative(path: &Path) {
    let _ = path;
}
