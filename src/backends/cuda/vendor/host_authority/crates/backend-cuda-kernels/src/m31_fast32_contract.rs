//! Host-independent qualification contract for the narrow M31 candidate.
//!
//! AOT generators and terminal sinks share these exact vectors and algebra.
//! Production inputs are canonical (`0..P`): source evaluations and twiddles
//! start canonical, and every candidate add/sub/mul below returns canonical.
//! The device implementation additionally maps the legacy `P` zero alias to 0.

pub const P: u32 = 0x7fff_ffff;
pub const BOUNDARY_WORDS: [u32; 6] = [0, 1, 2, P / 2, P - 2, P - 1];
pub const RANDOM_SEED: u64 = 0xd1b5_4a32_d192_ed03;
pub const RANDOM_MULTIPLIER: u64 = 6_364_136_223_846_793_005;
pub const RANDOM_PAIRS: usize = 1_000_000;

pub const fn candidate_mul(left: u32, right: u32) -> u32 {
    let product = left as u64 * right as u64;
    let lo = product as u32;
    let hi = (product >> 32) as u32;
    let quotient = (hi << 1) | (lo >> 31);
    let first = (lo & P) + quotient;
    let reduced = (first & P) + (first >> 31);
    if reduced == P {
        0
    } else {
        reduced
    }
}

pub const fn candidate_add(left: u32, right: u32) -> u32 {
    let sum = left + right;
    let reduced = (sum & P) + (sum >> 31);
    if reduced == P {
        0
    } else {
        reduced
    }
}

pub const fn candidate_sub(left: u32, right: u32) -> u32 {
    let difference = if left >= right {
        left - right
    } else {
        left + P - right
    };
    if difference == P {
        0
    } else {
        difference
    }
}

pub const fn reference_mul(left: u32, right: u32) -> u32 {
    (left as u64 * right as u64 % P as u64) as u32
}

pub const fn reference_add(left: u32, right: u32) -> u32 {
    ((left as u64 + right as u64) % P as u64) as u32
}

pub const fn reference_sub(left: u32, right: u32) -> u32 {
    ((left as u64 + P as u64 - right as u64) % P as u64) as u32
}

pub struct DeterministicPairs {
    seed: u64,
    remaining: usize,
}

impl Iterator for DeterministicPairs {
    type Item = (u32, u32);

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.seed = self.seed.wrapping_mul(RANDOM_MULTIPLIER).wrapping_add(1);
        let left = (self.seed % P as u64) as u32;
        self.seed = self.seed.wrapping_mul(RANDOM_MULTIPLIER).wrapping_add(1);
        self.remaining -= 1;
        Some((left, (self.seed % P as u64) as u32))
    }
}

pub const fn deterministic_pairs(count: usize) -> DeterministicPairs {
    DeterministicPairs {
        seed: RANDOM_SEED,
        remaining: count,
    }
}

#[cfg(test)]
const fn small_mersenne_mul(bits: u32, left: u32, right: u32) -> u32 {
    let modulus = (1u32 << bits) - 1;
    let product = left as u64 * right as u64;
    let first = (product as u32 & modulus) + (product >> bits) as u32;
    let reduced = (first & modulus) + (first >> bits);
    if reduced == modulus {
        0
    } else {
        reduced
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Cm31 = [u32; 2];
    type Qm31 = [u32; 4];

    #[derive(Clone, Copy)]
    struct Ops {
        add: fn(u32, u32) -> u32,
        sub: fn(u32, u32) -> u32,
        mul: fn(u32, u32) -> u32,
    }

    const CANDIDATE: Ops = Ops {
        add: candidate_add,
        sub: candidate_sub,
        mul: candidate_mul,
    };
    const REFERENCE: Ops = Ops {
        add: reference_add,
        sub: reference_sub,
        mul: reference_mul,
    };

    fn pow2k(ops: Ops, squarings: u32, mut value: u32) -> u32 {
        for _ in 0..squarings {
            value = (ops.mul)(value, value);
        }
        value
    }

    fn inv(ops: Ops, value: u32) -> u32 {
        let t0 = (ops.mul)(pow2k(ops, 2, value), value);
        let t1 = (ops.mul)(pow2k(ops, 1, t0), t0);
        let t2 = (ops.mul)(pow2k(ops, 3, t1), t0);
        let t3 = (ops.mul)(pow2k(ops, 1, t2), t0);
        let t4 = (ops.mul)(pow2k(ops, 8, t3), t3);
        let t5 = (ops.mul)(pow2k(ops, 8, t4), t3);
        (ops.mul)(pow2k(ops, 7, t5), t2)
    }

    fn cm_add(ops: Ops, left: Cm31, right: Cm31) -> Cm31 {
        [(ops.add)(left[0], right[0]), (ops.add)(left[1], right[1])]
    }

    fn cm_sub(ops: Ops, left: Cm31, right: Cm31) -> Cm31 {
        [(ops.sub)(left[0], right[0]), (ops.sub)(left[1], right[1])]
    }

    fn cm_neg(ops: Ops, value: Cm31) -> Cm31 {
        [(ops.sub)(0, value[0]), (ops.sub)(0, value[1])]
    }

    fn cm_mul(ops: Ops, left: Cm31, right: Cm31) -> Cm31 {
        [
            (ops.sub)((ops.mul)(left[0], right[0]), (ops.mul)(left[1], right[1])),
            (ops.add)((ops.mul)(left[0], right[1]), (ops.mul)(left[1], right[0])),
        ]
    }

    fn cm_inv(ops: Ops, value: Cm31) -> Cm31 {
        let factor = inv(
            ops,
            (ops.add)((ops.mul)(value[0], value[0]), (ops.mul)(value[1], value[1])),
        );
        [
            (ops.mul)(value[0], factor),
            (ops.sub)(0, (ops.mul)(value[1], factor)),
        ]
    }

    fn qm_add(ops: Ops, left: Qm31, right: Qm31) -> Qm31 {
        let a = cm_add(ops, [left[0], left[1]], [right[0], right[1]]);
        let b = cm_add(ops, [left[2], left[3]], [right[2], right[3]]);
        [a[0], a[1], b[0], b[1]]
    }

    fn qm_sub(ops: Ops, left: Qm31, right: Qm31) -> Qm31 {
        let a = cm_sub(ops, [left[0], left[1]], [right[0], right[1]]);
        let b = cm_sub(ops, [left[2], left[3]], [right[2], right[3]]);
        [a[0], a[1], b[0], b[1]]
    }

    fn qm_mul(ops: Ops, left: Qm31, right: Qm31) -> Qm31 {
        let left_a = [left[0], left[1]];
        let left_b = [left[2], left[3]];
        let right_a = [right[0], right[1]];
        let right_b = [right[2], right[3]];
        let v0 = cm_mul(ops, left_a, right_a);
        let v1 = cm_mul(ops, left_b, right_b);
        let v2 = cm_mul(
            ops,
            cm_add(ops, left_a, left_b),
            cm_add(ops, right_a, right_b),
        );
        let a = cm_add(ops, v0, cm_mul(ops, [2, 1], v1));
        let b = cm_sub(ops, v2, cm_add(ops, v0, v1));
        [a[0], a[1], b[0], b[1]]
    }

    fn qm_inv(ops: Ops, value: Qm31) -> Qm31 {
        let a = [value[0], value[1]];
        let b = [value[2], value[3]];
        let b2 = cm_mul(ops, b, b);
        let ib2 = [(ops.sub)(0, b2[1]), b2[0]];
        let denom = cm_sub(
            ops,
            cm_mul(ops, a, a),
            cm_add(ops, cm_add(ops, b2, b2), ib2),
        );
        let denom_inv = cm_inv(ops, denom);
        let out_a = cm_mul(ops, a, denom_inv);
        let out_b = cm_neg(ops, cm_mul(ops, b, denom_inv));
        [out_a[0], out_a[1], out_b[0], out_b[1]]
    }

    fn assert_canonical(words: impl IntoIterator<Item = u32>) {
        for word in words {
            assert!(word < P, "non-canonical M31 word: {word}");
        }
    }

    #[test]
    fn boundary_cartesian_and_one_million_random_pairs_match_reference() {
        let mut checked = 0;
        for left in BOUNDARY_WORDS {
            for right in BOUNDARY_WORDS {
                assert_eq!(candidate_mul(left, right), reference_mul(left, right));
                assert_eq!(candidate_add(left, right), reference_add(left, right));
                assert_eq!(candidate_sub(left, right), reference_sub(left, right));
                checked += 1;
            }
        }
        assert_eq!(checked, 36);
        for alias in [0, 1, 2, P - 1, P] {
            assert_eq!(candidate_mul(P, alias), 0);
            assert_eq!(candidate_add(P, alias), alias % P);
            assert_eq!(candidate_sub(P, alias), reference_sub(0, alias % P));
        }
        for (left, right) in deterministic_pairs(RANDOM_PAIRS) {
            assert_eq!(candidate_mul(left, right), reference_mul(left, right));
            assert_eq!(candidate_add(left, right), reference_add(left, right));
            assert_eq!(candidate_sub(left, right), reference_sub(left, right));
            assert!(candidate_mul(left, right) < P);
            assert!(candidate_add(left, right) < P);
            assert!(candidate_sub(left, right) < P);
        }
    }

    #[test]
    fn reduction_is_exhaustive_for_small_mersenne_fields() {
        for bits in 2..=10 {
            let modulus = (1u32 << bits) - 1;
            for left in 0..modulus {
                for right in 0..modulus {
                    assert_eq!(
                        small_mersenne_mul(bits, left, right),
                        (left as u64 * right as u64 % modulus as u64) as u32,
                        "bits={bits}, left={left}, right={right}",
                    );
                }
            }
        }
    }

    #[test]
    fn inverse_cm31_and_qm31_operations_match_current_arithmetic() {
        let boundary_vectors = (0..BOUNDARY_WORDS.len())
            .map(|index| {
                [
                    BOUNDARY_WORDS[index],
                    BOUNDARY_WORDS[(index + 1) % BOUNDARY_WORDS.len()],
                    BOUNDARY_WORDS[(index + 2) % BOUNDARY_WORDS.len()],
                    BOUNDARY_WORDS[(index + 3) % BOUNDARY_WORDS.len()],
                ]
            })
            .collect::<Vec<_>>();
        for &left in &boundary_vectors {
            assert_eq!(inv(CANDIDATE, left[0]), inv(REFERENCE, left[0]));
            assert_eq!(
                cm_inv(CANDIDATE, [left[0], left[1]]),
                cm_inv(REFERENCE, [left[0], left[1]])
            );
            assert_eq!(qm_inv(CANDIDATE, left), qm_inv(REFERENCE, left));
            for &right in &boundary_vectors {
                assert_eq!(
                    cm_add(CANDIDATE, [left[0], left[1]], [right[0], right[1]]),
                    cm_add(REFERENCE, [left[0], left[1]], [right[0], right[1]])
                );
                assert_eq!(
                    cm_sub(CANDIDATE, [left[0], left[1]], [right[0], right[1]]),
                    cm_sub(REFERENCE, [left[0], left[1]], [right[0], right[1]])
                );
                assert_eq!(
                    cm_mul(CANDIDATE, [left[0], left[1]], [right[0], right[1]]),
                    cm_mul(REFERENCE, [left[0], left[1]], [right[0], right[1]])
                );
                assert_eq!(
                    qm_add(CANDIDATE, left, right),
                    qm_add(REFERENCE, left, right)
                );
                assert_eq!(
                    qm_sub(CANDIDATE, left, right),
                    qm_sub(REFERENCE, left, right)
                );
                assert_eq!(
                    qm_mul(CANDIDATE, left, right),
                    qm_mul(REFERENCE, left, right)
                );
            }
        }

        let mut pairs = deterministic_pairs(16_384);
        for _ in 0..4_096 {
            let first = pairs.next().unwrap();
            let second = pairs.next().unwrap();
            let third = pairs.next().unwrap();
            let fourth = pairs.next().unwrap();
            let left = [first.0, first.1, second.0, second.1];
            let right = [third.0, third.1, fourth.0, fourth.1];
            let candidate_cm = cm_mul(CANDIDATE, [left[0], left[1]], [right[0], right[1]]);
            let candidate_cm_inv = cm_inv(CANDIDATE, [left[0], left[1]]);
            let candidate_qm = qm_mul(CANDIDATE, left, right);
            let candidate_qm_inv = qm_inv(CANDIDATE, left);
            assert_eq!(
                candidate_cm,
                cm_mul(REFERENCE, [left[0], left[1]], [right[0], right[1]])
            );
            assert_eq!(candidate_cm_inv, cm_inv(REFERENCE, [left[0], left[1]]));
            assert_eq!(
                cm_add(CANDIDATE, [left[0], left[1]], [right[0], right[1]]),
                cm_add(REFERENCE, [left[0], left[1]], [right[0], right[1]])
            );
            assert_eq!(
                cm_sub(CANDIDATE, [left[0], left[1]], [right[0], right[1]]),
                cm_sub(REFERENCE, [left[0], left[1]], [right[0], right[1]])
            );
            assert_eq!(candidate_qm, qm_mul(REFERENCE, left, right));
            assert_eq!(candidate_qm_inv, qm_inv(REFERENCE, left));
            assert_canonical(candidate_cm);
            assert_canonical(candidate_cm_inv);
            assert_canonical(candidate_qm);
            assert_canonical(candidate_qm_inv);
        }
    }
}
