//! Synthetic non-cyclotomic square followed by dense multiplication.
//! DP framing never asserts OP or pairing validity.
use ark_bn254::{Fq, Fq12, Fq2, Fq6};
use ark_ff::{Field, PrimeField};
pub fn run() -> [u8; 43] {
    fn value(offset: u64) -> Fq12 {
        let p = |i| Fq::from(offset + i);
        let q = |i| Fq2::new(p(i), p(i + 1));
        Fq12::new(Fq6::new(q(0), q(2), q(4)), Fq6::new(q(6), q(8), q(10)))
    }
    let mut a = value(1);
    let b = value(21);
    #[cfg(feature = "pairing-dense-service")]
    {
        super::dense::square(&mut a);
        super::dense::multiply(&mut a, &b);
    }
    #[cfg(not(feature = "pairing-dense-service"))]
    {
        a.square_in_place();
        a *= &b;
    }
    let fields = [
        a.c0.c0.c0, a.c0.c0.c1, a.c0.c1.c0, a.c0.c1.c1, a.c0.c2.c0, a.c0.c2.c1, a.c1.c0.c0,
        a.c1.c0.c1, a.c1.c1.c0, a.c1.c1.c1, a.c1.c2.c0, a.c1.c2.c1,
    ];
    let mut bytes = [0u8; 384];
    for (i, f) in fields.iter().enumerate() {
        for (j, v) in f.into_bigint().0.iter().enumerate() {
            bytes[i * 32 + j * 8..i * 32 + j * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
    }
    let mut out = [0; 43];
    out[..11].copy_from_slice(b"OPDENSE0001");
    out[11..].copy_from_slice(alloy_primitives::keccak256(bytes).as_slice());
    out
}
