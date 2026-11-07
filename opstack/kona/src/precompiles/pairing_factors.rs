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
}

pub(super) struct Factors {
    entries: Vec<Entry>,
    clock: u64,
}

impl Factors {
    pub(super) const fn new() -> Self {
        Self {
            entries: Vec::new(),
            clock: 0,
        }
    }

    pub(super) fn collect(&mut self, groups: &[miller::Group]) -> (u16, Fq12) {
        let mut mask = 0;
        let mut product = Fq12::ONE;
        if groups.len() < 2 {
            return (mask, product);
        }
        self.clock += 1;
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
                if !entry.repeated {
                    entry.repeated = true;
                    continue;
                }
                // Wait until the third sighting. Computing one independent
                // factor incurs a separate loop of squarings once.
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
                let oldest = self
                    .entries
                    .iter_mut()
                    .min_by_key(|entry| (entry.factor.is_some(), entry.last_use))
                    .expect("full factor cache");
                *oldest = entry;
            }
        }
        (mask, product)
    }
}
