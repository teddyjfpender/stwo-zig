use std::{env, fs, path::PathBuf};

fn q(token: &str) -> u16 {
    token.strip_prefix('q').unwrap().parse::<u16>().unwrap()
}

fn main() {
    println!("cargo:rerun-if-changed=iadd256.kmx");
    let circuit = fs::read_to_string("iadd256.kmx").unwrap();
    let mut gates = Vec::new();
    let mut counts = [0usize; 4];
    for line in circuit.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        match words.as_slice() {
            ["APPEND_TO_REGISTER", qbit, reg] => {
                let qi = q(qbit) as usize;
                let ri = reg.strip_prefix('r').unwrap().parse::<usize>().unwrap();
                assert_eq!(qi, counts[0]);
                assert_eq!(ri, qi / 256);
                counts[0] += 1;
            }
            ["REGISTER", reg] => {
                let ri = reg.strip_prefix('r').unwrap().parse::<usize>().unwrap();
                assert_eq!(ri, counts[1]);
                counts[1] += 1;
            }
            ["CX", control, target] => {
                let (c, t) = (q(control), q(target));
                assert!(c < 512 && t < 512 && c != t);
                gates.push(format!("Gate {{ a: {c}, b: 0, target: {t}, ccx: false }},"));
                counts[2] += 1;
            }
            ["CCX", control1, control2, target] => {
                let (a, b, t) = (q(control1), q(control2), q(target));
                assert!(a < 512 && b < 512 && t < 512 && a != b && a != t && b != t);
                gates.push(format!(
                    "Gate {{ a: {a}, b: {b}, target: {t}, ccx: true }},"
                ));
                counts[3] += 1;
            }
            _ => panic!("unsupported fixture line: {line}"),
        }
    }
    assert_eq!(counts, [512, 2, 2038, 509]);
    let output = format!("const GATES: [Gate; 2547] = [\n{}\n];\n", gates.join("\n"));
    let path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("gates.rs");
    fs::write(path, output).unwrap();
}
