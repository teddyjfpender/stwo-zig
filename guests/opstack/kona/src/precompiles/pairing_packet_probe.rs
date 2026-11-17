//! Small reproducible RV64 service probe. Coefficients are synthetic ABI inputs;
//! this does not assert valid curve preparation or an Ethereum pairing result.
use alloc::{sync::Arc, vec};
use ark_bn254::{Fq, Fq2, Fq6, Fq12, G1Affine};
use ark_ff::{AdditiveGroup, Field, PrimeField};

pub fn run() -> [u8; 43] {
    let f = |v| Fq::from(v);
    let q = |v| Fq2::new(f(v), f(v + 1));
    let prepared = Arc::new(super::PreparedG2 {
        ell_coeffs: vec![(q(21), q(23), q(25)), (q(27), q(29), q(31))],
        infinity: false,
    });
    let groups = vec![
        (G1Affine::new_unchecked(f(2), f(3)), None, prepared.clone()),
        (G1Affine::identity(), None, prepared.clone()),
        (G1Affine::new_unchecked(f(5), f(7)), None, prepared.clone()),
        (G1Affine::new_unchecked(f(11), f(13)), None, prepared),
    ];
    let seed = Fq12::new(Fq6::new(q(1), q(3), q(5)), Fq6::new(q(7), q(9), q(11)));
    let mut value = seed;
    super::sparse::miller_lines(&mut value, &groups, 0, 0);
    value.square_in_place();
    super::sparse::miller_lines(&mut value, &groups, 1, 1 << 2);
    // These paths must not index the invalid line or emit any service.
    super::sparse::miller_lines(&mut value, &groups, usize::MAX, 0xffff);
    super::sparse::miller_lines(&mut value, &[], usize::MAX, 0);
    assert_ne!(value, Fq12::ZERO);
    let mut words = [0u8; 384];
    for (i, coordinate) in [
        value.c0.c0.c0,
        value.c0.c0.c1,
        value.c0.c1.c0,
        value.c0.c1.c1,
        value.c0.c2.c0,
        value.c0.c2.c1,
        value.c1.c0.c0,
        value.c1.c0.c1,
        value.c1.c1.c0,
        value.c1.c1.c1,
        value.c1.c2.c0,
        value.c1.c2.c1,
    ]
    .iter()
    .enumerate()
    {
        for (j, limb) in coordinate.into_bigint().0.iter().enumerate() {
            words[i * 32 + j * 8..i * 32 + j * 8 + 8].copy_from_slice(&limb.to_le_bytes());
        }
    }
    let digest = alloy_primitives::keccak256(words);
    let mut output = [0u8; 43];
    output[..11].copy_from_slice(b"OPPACKET001");
    output[11..].copy_from_slice(digest.as_slice());
    output
}

#[cfg(test)]
mod tests {
    #[test]
    fn diagnostic_uses_ordinary_host_arithmetic() {
        let output = super::run();
        extern crate std;
        std::println!("{}", alloy_primitives::hex::encode(output));
        assert_eq!(
            alloy_primitives::hex::encode(output),
            "4f505041434b4554303031700505a8aeffcb67a24146da8cba7e9b974e9969dbcb5b70324a9b295893c610"
        );
    }
}
