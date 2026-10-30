use super::{layout::*, local::Sink};
use num_traits::{One, Zero};
use stwo::core::fields::qm31::SecureField as Q;
pub fn evaluate(f: &[Q], m: &[Q], s: &mut Sink) {
    let loads = [
        (28, 1, true),
        (32, 1, false),
        (29, 2, true),
        (33, 2, false),
        (30, 4, true),
        (34, 4, false),
        (31, 8, false),
    ];
    let stores = [(35, 1), (36, 2), (37, 4), (38, 8)];
    let load: Q = loads.iter().map(|(op, _, _)| opcode(f, *op)).sum();
    let store: Q = stores.iter().map(|(op, _)| opcode(f, *op)).sum();
    let memory = load + store;
    let mut offsets = Q::zero();
    let mut value = Q::zero();
    for i in 0..8 {
        let x = m[OFFSET + i];
        s.boolean(x);
        offsets += x;
        value += x * q(i as u32);
    }
    s.emit(offsets - memory);
    s.emit(memory * (value - m[bit(6, 0)] - q(2) * m[bit(6, 1)] - q(4) * m[bit(6, 2)]));
    s.emit(load * (m[2360] - Q::one()));
    s.emit(store * (m[2361] - Q::one()));
    s.emit((Q::one() - memory) * m[2360]);
    s.emit((Q::one() - memory) * m[2361]);
    for i in 0..8 {
        s.emit(load * (m[byte(5, i)] - m[byte(4, i)]));
    }
    for (op, width, signed) in loads {
        for offset in 0..8 {
            if offset % width != 0 || offset + width > 8 {
                s.emit(opcode(f, op) * m[OFFSET + offset]);
            }
        }
        for i in 0..8 {
            let mut expected = Q::zero();
            for offset in 0..8 {
                if offset + width > 8 {
                    continue;
                }
                let v = if i < width {
                    m[byte(4, offset + i)]
                } else if signed {
                    m[bit(4, (offset + width) * 8 - 1)] * q(255)
                } else {
                    Q::zero()
                };
                expected += m[OFFSET + offset] * v;
            }
            s.emit(opcode(f, op) * (m[byte(2, i)] - expected));
        }
    }
    for (op, width) in stores {
        for offset in 0..8 {
            if offset % width != 0 || offset + width > 8 {
                s.emit(opcode(f, op) * m[OFFSET + offset]);
            }
        }
        for i in 0..8 {
            let mut expected = Q::zero();
            for offset in 0..8 {
                if offset + width > 8 {
                    continue;
                }
                let v = if i >= offset && i - offset < width {
                    m[byte(1, i - offset)]
                } else {
                    m[byte(4, i)]
                };
                expected += m[OFFSET + offset] * v;
            }
            s.emit(opcode(f, op) * (m[byte(5, i)] - expected));
        }
    }
}
