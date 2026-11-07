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
    // New points evict the first slot, while its coefficient owner must live.
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
