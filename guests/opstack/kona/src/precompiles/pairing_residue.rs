//! Positive pairing witnesses based on the residue check in ePrint 2024/640.
//! For p = Fq modulus, r = Fr modulus, x = BN seed, let
//! L = p^3 - p^2 + p + 6x + 2. Since r divides L and r is coprime
//! to p^6 - 1, any nonzero z with z c w^L = 1 and c in Fq6 has
//! z^((p^12 - 1)/r) = 1. The guest checks the equation, even for a
//! malicious hint. Missing or invalid hints use ordinary final exponentiation.
use ark_bn254::{Fq, Fq2, Fq6, Fq12};
use ark_ff::{AdditiveGroup, BigInt, Field, One, PrimeField};
#[cfg(any(feature = "host", test))]
#[path = "pairing_residue_exponents.rs"]
mod exponents;

pub(super) const BYTES: usize = 30 * 32;
pub(super) struct Hint {
    pub(super) seed: Fq12,
    pub(super) inverse: Fq12,
    pub(super) scale: Fq6,
}
impl Hint {
    pub(super) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != BYTES {
            return None;
        }
        let mut words = bytes.chunks_exact(32);
        let mut fq = || {
            let word = words.next()?;
            Fq::from_bigint(BigInt(core::array::from_fn(|i| {
                u64::from_le_bytes(word[8 * i..8 * (i + 1)].try_into().unwrap())
            })))
        };
        let mut fq2 = || Some(Fq2::new(fq()?, fq()?));
        let mut fq6 = || Some(Fq6::new(fq2()?, fq2()?, fq2()?));
        Some(Self {
            seed: Fq12::new(fq6()?, fq6()?),
            inverse: Fq12::new(fq6()?, fq6()?),
            scale: fq6()?,
        })
    }

    pub(super) fn valid_seed(&self) -> bool {
        (self.seed * self.inverse).is_one()
    }

    pub(super) fn check_tail(&self, mut seeded_miller: Fq12) -> bool {
        let mut power = self.seed;
        power.frobenius_map_in_place(3);
        let mut inverse_square = self.inverse;
        inverse_square.frobenius_map_in_place(2);
        power *= inverse_square;
        let mut first = self.seed;
        first.frobenius_map_in_place(1);
        power *= first;
        seeded_miller *= power;
        seeded_miller *= Fq12::new(self.scale, Fq6::ZERO);
        seeded_miller.is_one()
    }

    #[cfg(any(feature = "host", test))]
    pub(super) fn from_positive_miller(value: Fq12) -> Option<Self> {
        // The caller checked final exponentiation. Project away the 27-part of
        // the kernel into Fq6, then extract the negative L-th root in the
        // remaining subgroup, whose order is coprime to L.
        let scale = value.pow(exponents::REMOVE_27_PART);
        if scale.c1 != Fq6::ZERO {
            return None;
        }
        let seed = (value * scale).pow(exponents::NEGATIVE_LAMBDA_ROOT);
        Some(Self {
            seed,
            inverse: seed.inverse()?,
            scale: scale.c0,
        })
    }

    #[cfg(any(feature = "host", test))]
    pub(super) fn encode(&self) -> [u8; BYTES] {
        let mut out = [0; BYTES];
        let mut words = out.chunks_exact_mut(32);
        for plane in [
            self.seed.c0,
            self.seed.c1,
            self.inverse.c0,
            self.inverse.c1,
            self.scale,
        ] {
            for coord in [plane.c0, plane.c1, plane.c2] {
                for fq in [coord.c0, coord.c1] {
                    let word = words.next().expect("fixed hint width");
                    for (dst, limb) in word.chunks_exact_mut(8).zip(fq.into_bigint().0) {
                        dst.copy_from_slice(&limb.to_le_bytes());
                    }
                }
            }
        }
        out
    }
}
