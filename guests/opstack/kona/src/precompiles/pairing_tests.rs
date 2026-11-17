use super::*;
use ark_bn254::{Fr, G1Projective, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};

fn fq(x: Fq) -> [u8; 32] {
    U256::from_limbs(x.into_bigint().0).to_be_bytes::<32>()
}
fn g1(p: G1Affine) -> [u8; 64] {
    let mut out = [0; 64];
    if !p.is_zero() {
        out[..32].copy_from_slice(&fq(p.x));
        out[32..].copy_from_slice(&fq(p.y));
    }
    out
}
fn g2(p: G2Affine) -> [u8; 128] {
    let mut out = [0; 128];
    if !p.is_zero() {
        for (i, x) in [p.x.c1, p.x.c0, p.y.c1, p.y.c0].into_iter().enumerate() {
            out[i * 32..(i + 1) * 32].copy_from_slice(&fq(x));
        }
    }
    out
}

#[test]
fn cached_pairings_match_reference_for_true_false_infinity_and_eviction() {
    let mut cache = Cache::new();
    let p = g1(G1Affine::generator());
    let n = g1(-G1Affine::generator());
    let q = g2(G2Affine::generator());
    for pairs in [
        alloc::vec![],
        alloc::vec![(&p[..], &q[..])],
        alloc::vec![(&p[..], &q[..]), (&n[..], &q[..])],
        alloc::vec![(&[0; 64][..], &q[..])],
    ] {
        let want = DefaultCrypto.bn254_pairing_check(&pairs);
        assert_eq!(cache.check(&pairs), want);
        assert_eq!(cache.check(&pairs), want);
    }
    assert_eq!(cache.hits, 4);
    for i in 2..30u64 {
        let p = g1((G1Projective::generator() * Fr::from(i)).into_affine());
        let pairs = [(&p[..], &q[..])];
        assert_eq!(
            cache.check(&pairs),
            DefaultCrypto.bn254_pairing_check(&pairs)
        );
    }
    assert!(cache.point_hits > 20);
    assert_eq!(
        cache.prepared_builds, 1,
        "one reusable G2 preparation across distinct G1 requests"
    );
    assert!(cache.points.len() <= POINTS);
    assert_eq!(cache.results.len(), RESULTS);
    assert!(
        cache.results.iter().map(|x| x.bytes.len()).sum::<usize>() <= RESULTS * MAX_PAIRS * 192
    );
    let pairs = alloc::vec![(&p[..],&q[..]);MAX_PAIRS+1];
    assert_eq!(
        cache.check(&pairs),
        DefaultCrypto.bn254_pairing_check(&pairs)
    );
}

#[test]
fn invalid_points_are_not_hidden_by_infinity_or_admitted_into_cache() {
    let mut cache = Cache::new();
    let p = g1(G1Affine::generator());
    let q = g2(G2Affine::generator());
    assert_eq!(cache.check(&[(&p, &q)]), Ok(false));
    let mut bad = q;
    bad[..32].fill(255);
    for a in [&p[..], &[0; 64][..]] {
        let pairs = [(a, &bad[..])];
        assert_eq!(
            cache.check(&pairs),
            DefaultCrypto.bn254_pairing_check(&pairs)
        );
    }
    let old = cache.points.len();
    let non_subgroup = (1..100u64)
        .find_map(|i| {
            G2Affine::get_point_from_x_unchecked(Fq2::new(Fq::from(i), Fq::from(1)), false)
                .filter(|p| !p.is_in_correct_subgroup_assuming_on_curve())
        })
        .unwrap();
    let bad = g2(non_subgroup);
    let pairs = [(&[0; 64][..], &bad[..])];
    assert_eq!(
        cache.check(&pairs),
        DefaultCrypto.bn254_pairing_check(&pairs)
    );
    assert!(cache.check(&pairs).is_err());
    assert_eq!(cache.points.len(), old);
    for i in 2..22u64 {
        let q = g2((G2Projective::generator() * Fr::from(i)).into_affine());
        let pairs = [(&p[..], &q[..])];
        assert_eq!(
            cache.check(&pairs),
            DefaultCrypto.bn254_pairing_check(&pairs)
        );
    }
    assert_eq!(cache.points.len(), POINTS);
}

#[test]
fn borrowed_miller_checks_multi_chunk_cancellation_and_pins_evicted_lines() {
    let mut cache = Cache::new();
    let p = g1(G1Affine::generator());
    let n = g1(-G1Affine::generator());
    let points: Vec<_> = (1..=24u64)
        .map(|i| g2((G2Projective::generator() * Fr::from(i)).into_affine()))
        .collect();
    for q in &points[..16] {
        assert_eq!(cache.check(&[(&p, q)]), Ok(false));
    }
    let mut pairs = alloc::vec![(&p[..], &points[0][..])];
    // New points replace older slots while borrowed coefficient owners stay live.
    for q in &points[16..22] {
        pairs.push((&p, q));
    }
    assert_eq!(
        cache.check(&pairs),
        DefaultCrypto.bn254_pairing_check(&pairs)
    );
    for q in &points[16..22] {
        pairs.push((&n, q));
    }
    pairs.push((&n, &points[0]));
    assert_eq!(cache.check(&pairs), Ok(true));
    assert_eq!(
        cache.check(&pairs),
        DefaultCrypto.bn254_pairing_check(&pairs)
    );
}

#[cfg(feature = "pairing-hints")]
#[test]
fn residue_witness_checks_true_pairing_and_rejects_replay_for_false_pairing() {
    use ark_bn254::Fq12;
    use ark_ff::{AdditiveGroup, Field, One};
    let p = G1Affine::generator();
    let q = G2Affine::generator();
    let q2 = (G2Projective::generator() * Fr::from(2)).into_affine();
    let p2 = (G1Projective::generator() * Fr::from(2)).into_affine();
    let groups = [
        (p2, None, Arc::new(PreparedG2::from(q))),
        (-p, None, Arc::new(PreparedG2::from(q2))),
    ];
    assert!(miller::check(&groups));
    let value = miller::run(&groups, None);
    assert!(!value.is_one(), "test needs a nontrivial Miller residue");
    let hint = residue::Hint::from_positive_miller(value).unwrap();
    let decoded = residue::Hint::decode(&hint.encode()).unwrap();
    assert!(decoded.valid_seed());
    let fused = miller::run(&groups, Some((&decoded.seed, &decoded.inverse)));
    assert_eq!(
        fused,
        value * decoded.seed.pow([29793968203157093288u128 as u64, 1])
    );
    assert!(decoded.check_tail(fused));
    assert!(!miller::check(&groups[..1]));
    assert!(!decoded.check_tail(miller::run(
        &groups[..1],
        Some((&decoded.seed, &decoded.inverse))
    )));
    assert!(
        !residue::Hint {
            seed: Fq12::ZERO,
            ..decoded
        }
        .valid_seed()
    );
    let mut malformed = hint.encode();
    malformed[..32].fill(255);
    assert!(residue::Hint::decode(&malformed).is_none());
}

#[test]
fn frequent_g2_owners_survive_one_shot_points_and_clock_wrap() {
    let mut cache = Cache::new();
    cache.point_clock = u64::MAX - 20;
    let fixed: Vec<_> = (1..=3u64)
        .map(|i| g2((G2Projective::generator() * Fr::from(i)).into_affine()))
        .collect();
    let owners: Vec<_> = fixed
        .iter()
        .map(|bytes| {
            let index = cache.g2(bytes).unwrap();
            cache.prepared(index)
        })
        .collect();
    for i in 4..40u64 {
        let transient = g2((G2Projective::generator() * Fr::from(i)).into_affine());
        cache.g2(&transient).unwrap();
        for (bytes, owner) in fixed.iter().zip(&owners) {
            let index = cache.g2(bytes).unwrap();
            assert!(
                Arc::ptr_eq(owner, &cache.prepared(index)),
                "a frequently used prepared point was discarded"
            );
        }
    }
    assert_eq!(cache.prepared_builds, 3);
    assert_eq!(cache.points.len(), POINTS);
    assert!(cache.point_clock < 200, "test must cross counter wrap");
}
