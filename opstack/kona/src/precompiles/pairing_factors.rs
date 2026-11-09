//! Exact reuse of a guest-computed single-pair Miller factor across requests.
//! The field product of the individual loops is the multi-Miller loop. The
//! shared squaring and every sparse line multiplication distribute over it.
use super::super::PreparedG2;
use super::miller;
use alloc::{sync::Arc, vec::Vec};
use ark_bn254::{Fq12, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::Field;

const ENTRIES: usize = 16;

struct Entry {
    point: G1Affine,
    lines: Arc<PreparedG2>,
    repeated: bool,
    factor: Option<Fq12>,
    last_use: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fr, G2Affine};
    use ark_ec::CurveGroup;

    #[test]
    fn recurrent_factor_preserves_seeded_and_unseeded_miller_products() {
        let p = G1Affine::generator();
        let q = G2Affine::generator();
        let fixed = Arc::new(PreparedG2::from(q));
        let varying = Arc::new(PreparedG2::from((q * Fr::from(7)).into_affine()));
        let seed = Fq12::from(23u64);
        let inverse = seed.inverse().unwrap();
        let mut cache = Factors::new();
        for i in 1..=20u64 {
            let groups = [
                (p, None, Arc::clone(&fixed)),
                ((p * Fr::from(i)).into_affine(), None, Arc::clone(&varying)),
            ];
            let (mask, factor) = cache.collect(&groups);
            assert_eq!(mask, if i >= 3 { 1 } else { 0 });
            for seed_pair in [None, Some((&seed, &inverse))] {
                assert_eq!(
                    miller::run(&groups, seed_pair),
                    miller::run_skipping(&groups, seed_pair, mask) * factor
                );
            }
        }
    }

    #[test]
    fn stale_computed_factors_do_not_starve_a_new_repeated_pair() {
        let p = G1Affine::generator();
        let q = Arc::new(PreparedG2::from(G2Affine::generator()));
        let mut cache = Factors::new();
        let old: Vec<_> = (1..=16u64)
            .map(|i| ((p * Fr::from(i)).into_affine(), None, Arc::clone(&q)))
            .collect();
        for _ in 0..3 {
            for pair in old.chunks(2) {
                cache.collect(pair);
            }
        }
        assert_eq!(
            cache.entries.iter().filter(|e| e.factor.is_some()).count(),
            ENTRIES
        );
        let fixed = (p * Fr::from(101)).into_affine();
        for i in 0..8u64 {
            let groups = [
                (fixed, None, Arc::clone(&q)),
                ((p * Fr::from(1000 + i)).into_affine(), None, Arc::clone(&q)),
            ];
            let (mask, _) = cache.collect(&groups);
            assert_eq!(mask & 1 != 0, i >= 2, "new hot pair never matures");
        }
        assert!(
            cache
                .entries
                .iter()
                .find(|e| e.point == fixed)
                .unwrap()
                .factor
                .is_some()
        );
        assert!(cache.entries.len() <= ENTRIES);
    }
}

pub(super) struct Factors {
    entries: Vec<Entry>,
    clock: u64,
    #[cfg(feature = "host")]
    pub(super) census: [u64; 4],
}

impl Factors {
    pub(super) const fn new() -> Self {
        Self {
            entries: Vec::new(),
            clock: 0,
            #[cfg(feature = "host")]
            census: [0; 4],
        }
    }

    pub(super) fn collect(&mut self, groups: &[miller::Group]) -> (u16, Fq12) {
        let mut mask = 0;
        let mut product = Fq12::ONE;
        if groups.len() < 2 {
            return (mask, product);
        }
        self.clock = self.clock.wrapping_add(1);
        for (ordinal, group) in groups.iter().enumerate() {
            let (point, _, lines) = group;
            if point.is_zero() {
                continue;
            }
            if let Some(entry) = self
                .entries
                .iter_mut()
                .find(|entry| entry.point == *point && Arc::ptr_eq(&entry.lines, lines))
            {
                entry.last_use = self.clock;
                #[cfg(feature = "host")]
                {
                    self.census[0] += 1;
                }
                if !entry.repeated {
                    entry.repeated = true;
                    continue;
                }
                // Wait until the third sighting. Computing one independent
                // factor incurs a separate loop of squarings once.
                #[cfg(feature = "host")]
                if entry.factor.is_none() {
                    self.census[1] += 1;
                }
                let factor = *entry
                    .factor
                    .get_or_insert_with(|| miller::run(core::slice::from_ref(group), None));
                if mask == 0 {
                    product = factor;
                } else {
                    product *= factor;
                }
                mask |= 1 << ordinal;
                continue;
            }
            #[cfg(feature = "host")]
            {
                self.census[2] += 1;
            }
            let entry = Entry {
                point: *point,
                lines: Arc::clone(lines),
                repeated: false,
                factor: None,
                last_use: self.clock,
            };
            if self.entries.len() < ENTRIES {
                self.entries.push(entry);
            } else {
                #[cfg(feature = "host")]
                {
                    self.census[3] += 1;
                }
                let oldest = self
                    .entries
                    .iter_mut()
                    .max_by_key(|entry| self.clock.wrapping_sub(entry.last_use))
                    .expect("full factor cache");
                *oldest = entry;
            }
        }
        (mask, product)
    }
}
