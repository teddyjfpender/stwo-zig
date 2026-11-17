use super::*;
use alloy_primitives::{U256, uint};

#[test]
fn modular_exponentiation_matches_reference_including_even_and_zero_moduli() {
    let mut seed = 0x9e3779b97f4a7c15u64;
    for len in 0..=32 {
        for boundary in [0u8, 1, 2, 255] {
            let modulus = alloc::vec![boundary; len];
            let base = alloc::vec![255; len];
            for exp in [&[][..], &[0], &[1], &[2], &[255], &[0, 0, 1, 0]] {
                assert_eq!(
                    Services.modexp(&base, exp, &modulus),
                    DefaultCrypto.modexp(&base, exp, &modulus)
                );
            }
        }
        let mut base = [0; 32];
        let mut modulus = [0; 32];
        for (a, b) in base.iter_mut().zip(&mut modulus) {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *a = seed as u8;
            *b = (seed >> 32) as u8;
        }
        // More than 256 exponent bits must survive, and leading zeros in the
        // modulus must retain the requested output width.
        let exponent = [0x81; 65];
        assert_eq!(
            Services.modexp(&base[..len], &exponent, &modulus[..len]),
            DefaultCrypto.modexp(&base[..len], &exponent, &modulus[..len])
        );
    }
    for len in [33, 48, 64] {
        assert_eq!(
            Services.modexp(&alloc::vec![7;len], &[3], &alloc::vec![10;len]),
            DefaultCrypto.modexp(&alloc::vec![7;len], &[3], &alloc::vec![10;len])
        );
    }
}

fn generator() -> [u8; 64] {
    let mut p = [0; 64];
    p[31] = 1;
    p[63] = 2;
    p
}

#[test]
fn bn254_window_and_exceptional_cases_match_arkworks() {
    let g = generator();
    let zero = [0; 64];
    let order = uint!(0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001_U256);
    for k in [
        U256::ZERO,
        U256::from(1),
        U256::from(2),
        U256::from(15),
        U256::from(16),
        U256::from(255),
        order - U256::from(1),
        order,
        order + U256::from(1),
        U256::MAX,
    ] {
        let scalar = k.to_be_bytes::<32>();
        assert_eq!(
            Services.bn254_g1_mul(&g, &scalar),
            DefaultCrypto.bn254_g1_mul(&g, &scalar)
        );
        assert_eq!(
            Services.bn254_g1_mul(&zero, &scalar),
            DefaultCrypto.bn254_g1_mul(&zero, &scalar)
        );
    }
    let minus_g = DefaultCrypto
        .bn254_g1_mul(&g, &(order - U256::from(1)).to_be_bytes::<32>())
        .unwrap();
    for p in [g, zero, minus_g] {
        for q in [g, zero, minus_g] {
            assert_eq!(
                Services.bn254_g1_add(&p, &q),
                DefaultCrypto.bn254_g1_add(&p, &q)
            );
        }
    }
    let mut seed = 0xd1b54a32d192ed03u64;
    for _ in 0..12 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let scalar = U256::from_limbs([
            seed,
            seed.rotate_left(13),
            seed.rotate_left(29),
            seed.rotate_left(47),
        ])
        .to_be_bytes::<32>();
        let p = DefaultCrypto.bn254_g1_mul(&g, &scalar).unwrap();
        assert_eq!(
            Services.bn254_g1_mul(&p, &scalar),
            DefaultCrypto.bn254_g1_mul(&p, &scalar)
        );
        assert_eq!(
            Services.bn254_g1_add(&p, &g),
            DefaultCrypto.bn254_g1_add(&p, &g)
        );
    }
}

#[test]
fn bn254_rejects_bad_points_even_with_zero_scalar_or_infinity_peer() {
    let zero = [0; 64];
    let p = uint!(0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47_U256);
    let mut noncanonical = generator();
    noncanonical[..32].copy_from_slice(&p.to_be_bytes::<32>());
    let mut offcurve = generator();
    offcurve[63] = 3;
    for bad in [noncanonical, offcurve, [255; 64]] {
        assert_eq!(
            Services.bn254_g1_add(&bad, &zero),
            DefaultCrypto.bn254_g1_add(&bad, &zero)
        );
        assert_eq!(
            Services.bn254_g1_mul(&bad, &[0; 32]),
            DefaultCrypto.bn254_g1_mul(&bad, &[0; 32])
        );
    }
}

#[test]
fn sha_provider_matches_software_at_padding_boundaries() {
    for len in [0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 1024] {
        let data = alloc::vec![0xa5;len];
        assert_eq!(Services.sha256(&data), DefaultCrypto.sha256(&data));
    }
}
