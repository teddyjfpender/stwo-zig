//! Independent equations; exact accumulator order includes identically-zero families.
use super::layout::*;
use num_traits::{One, Zero};
use stwo::core::{air::accumulation::PointEvaluationAccumulator, fields::qm31::SecureField as Q};
pub struct Sink {
    pub accumulator: PointEvaluationAccumulator,
    pub inverse: Q,
    pub count: usize,
}
impl Sink {
    pub fn emit(&mut self, x: Q) {
        self.accumulator.accumulate(x * self.inverse);
        self.count += 1;
    }
    pub fn zeros(&mut self, n: usize) {
        for _ in 0..n {
            self.emit(Q::zero());
        }
    }
    pub fn boolean(&mut self, x: Q) {
        self.emit(x * (x - Q::one()));
    }
}
pub fn evaluate(f: &[Q], m: &[Q], s: &mut Sink) {
    let one = Q::one();
    let z = Q::zero();
    for w in 0..22 {
        for i in 0..8 {
            let mut value = z;
            for j in 0..8 {
                let b = m[bit(w, 8 * i + j)];
                s.boolean(b);
                value += b * q(1 << j);
            }
            s.emit(m[byte(w, i)] - value);
            s.emit((one - f[119 + w]) * m[byte(w, i)]);
        }
    }
    for i in 0..88 {
        s.boolean(m[1584 + i]);
        s.emit((one - f[141 + i]) * m[1584 + i]);
    }
    for slot in 0..4 {
        let enabled = f[71 + slot];
        for start in [prev(slot), gap(slot)] {
            let mut value = z;
            for i in 0..12 {
                let b = m[start + 1 + i];
                s.boolean(b);
                value += b * q(1 << i);
            }
            s.emit(m[start] - value);
            s.emit((one - enabled) * m[start]);
        }
        s.emit(enabled * (m[prev(slot)] + m[gap(slot)] + one - f[75 + slot]));
    }
    for c in [2360, 2361, 2362, 2364, 2365, 2366, 2367, 2368, 2370] {
        s.boolean(m[c]);
    }
    assert_eq!(s.count, 2061);
    let add = opcode(f, 0) + opcode(f, 10);
    let immediate = opcode(f, 10);
    let address = opcode(f, 31) + opcode(f, 38);
    let mut squares = z;
    for i in 0..8 {
        let a = m[byte(0, i)];
        let rhs = m[byte(7, i)];
        let result = m[byte(2, i)];
        s.emit(
            add * (a + rhs + if i == 0 { z } else { m[carry(0, i - 1)] }
                - result
                - q(256) * m[carry(0, i)]),
        );
        s.emit(z);
        s.emit(rhs - immediate * f[79 + i] - opcode(f, 0) * m[byte(1, i)]);
        s.emit(z);
        s.emit(
            address
                * (a + f[79 + i] + if i == 0 { z } else { m[carry(2, i - 1)] }
                    - m[byte(6, i)]
                    - q(256) * m[carry(2, i)]),
        );
        if i >= 4 {
            s.emit(z)
        }
        s.zeros(3);
        squares += (a - rhs) * (a - rhs);
    }
    s.emit(m[2368] * squares);
    s.emit(squares * m[2369] + m[2368]);
    s.emit(m[2369]);
    s.emit(m[2368]);
    s.emit(m[2368] * m[2369]);
    s.zeros(16);
    s.emit(m[2370]);
    for i in 0..8 {
        s.emit(f[0] * (f[95 + i] - f[103 + i]));
        s.zeros(3);
    }
    s.emit(z);
    s.zeros(192);
    assert_eq!(s.count, 2376);
    s.zeros(2528);
    super::memory::evaluate(f, m, s);
    assert_eq!(s.count, 5058);
    s.zeros(285);
    // For this admitted program, every division word/carry is identically zero.
    let zero = m[2362];
    let inv = m[2363];
    for x in [
        m[2364],
        m[2365],
        m[2366],
        m[2367] - m[2366],
        z,
        zero,
        zero * inv,
        zero,
        inv,
    ] {
        s.emit(x)
    }
    s.zeros(143);
    assert_eq!(s.count, 5495);
}
