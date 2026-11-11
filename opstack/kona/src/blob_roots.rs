//! Fixed EIP-4844 domain, authenticated by the program image.
//!
//! `opstack/tools/blob_roots.py --check` reproduces the bytes using Python
//! integer arithmetic. Decode at compile time: no heap, runtime field
//! multiplications, unsafe layout casts, or witness-controlled constants.
use ark_bls12_381::Fr;
use ark_ff::{BigInt, MontConfig};

pub(super) const SIZE: usize = 4096;
const ENCODED: &[u8; SIZE * 32] = if ark_bls12_381::FrConfig::CANONICAL_REPRESENTATION {
    include_bytes!("blob_roots/canonical.bin")
} else {
    include_bytes!("blob_roots/montgomery.bin")
};
pub(super) static ROOTS: [Fr; SIZE] = decode();

const fn decode() -> [Fr; SIZE] {
    let mut roots = [Fr::new_unchecked(BigInt([0; 4])); SIZE];
    let mut i = 0;
    while i < SIZE {
        let mut limbs = [0; 4];
        let mut limb = 0;
        while limb < 4 {
            let mut byte = 0;
            while byte < 8 {
                limbs[limb] |= (ENCODED[i * 32 + limb * 8 + byte] as u64) << (byte * 8);
                byte += 1;
            }
            limb += 1;
        }
        roots[i] = Fr::new_unchecked(BigInt(limbs));
        i += 1;
    }
    roots
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{FftField, Field, PrimeField};

    #[test]
    fn every_root_matches_arkworks_and_is_canonical() {
        let step = Fr::get_root_of_unity(SIZE as u64).unwrap();
        assert_eq!(step.pow([SIZE as u64]), Fr::ONE);
        assert_ne!(step.pow([(SIZE / 2) as u64]), Fr::ONE);
        let mut expected = Fr::ONE;
        for root in ROOTS {
            assert!(root.0 < Fr::MODULUS);
            assert_eq!(root, expected);
            expected *= step;
        }
        assert_eq!(expected, Fr::ONE);
    }
}
