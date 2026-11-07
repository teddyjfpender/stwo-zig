//! Bounded, exact-byte reuse of results and validated G2 points. Every entry
//! originates from computations in this execution; no host-supplied hint or
//! digest-only equality can create an admitted result. VM RAM binds reuse.
use alloc::{sync::Arc, vec::Vec};
use alloy_primitives::U256;
use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
type PreparedG2 = <Bn254 as Pairing>::G2Prepared;
#[cfg(feature = "pairing-hints")]
#[path = "pairing_hint_stream.rs"]
mod hints;
#[path = "pairing_miller.rs"]
mod miller;
#[cfg(feature = "pairing-hints")]
#[path = "pairing_residue.rs"]
mod residue;
use ark_ec::{AffineRepr, pairing::Pairing};
use ark_ff::{BigInt, PrimeField, Zero};
use revm_precompile::{Crypto, DefaultCrypto, PrecompileHalt};

const RESULTS: usize = 8;
const POINTS: usize = 16;
const MAX_PAIRS: usize = 16;
struct ResultEntry {
    bytes: Vec<u8>,
    result: bool,
}
struct PointEntry {
    bytes: [u8; 128],
    point: G2Affine,
    prepared: Option<Arc<PreparedG2>>,
}
struct Cache {
    results: Vec<ResultEntry>,
    points: Vec<PointEntry>,
    next_result: usize,
    #[cfg(feature = "pairing-hints")]
    hints: hints::Stream,
    next_point: usize,
    hits: usize,
    point_hits: usize,
    #[cfg(test)]
    prepared_builds: usize,
}
impl Cache {
    const fn new() -> Self {
        Self {
            results: Vec::new(),
            points: Vec::new(),
            next_result: 0,
            #[cfg(feature = "pairing-hints")]
            hints: hints::Stream::new(),
            next_point: 0,
            hits: 0,
            point_hits: 0,
            #[cfg(test)]
            prepared_builds: 0,
        }
    }
    fn g2(&mut self, bytes: &[u8]) -> Result<usize, PrecompileHalt> {
        for (index, entry) in self.points.iter().enumerate() {
            if entry.bytes == bytes {
                self.point_hits += 1;
                return Ok(index);
            }
        }
        let x = Fq2::new(field(&bytes[32..64])?, field(&bytes[..32])?);
        let y = Fq2::new(field(&bytes[96..])?, field(&bytes[64..96])?);
        let point = if x.is_zero() && y.is_zero() {
            G2Affine::zero()
        } else {
            let p = G2Affine::new_unchecked(x, y);
            if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
                return Err(PrecompileHalt::Bn254AffineGFailedToCreate);
            }
            p
        };
        let entry = PointEntry {
            bytes: bytes.try_into().expect("checked pair width"),
            point,
            prepared: None,
        };
        let index = if self.points.len() < POINTS {
            self.points.push(entry);
            self.points.len() - 1
        } else {
            let index = self.next_point;
            self.points[index] = entry;
            self.next_point = (index + 1) % POINTS;
            index
        };
        Ok(index)
    }
    fn prepared(&mut self, index: usize) -> Arc<PreparedG2> {
        let entry = &mut self.points[index];
        if entry.prepared.is_none() {
            entry.prepared = Some(Arc::new(PreparedG2::from(entry.point)));
            #[cfg(test)]
            {
                self.prepared_builds += 1;
            }
        }
        // The caller borrows the lines through this owner. Cache eviction
        // during the same request cannot invalidate a previous pair.
        Arc::clone(entry.prepared.as_ref().unwrap())
    }

    fn check(&mut self, pairs: &[(&[u8], &[u8])]) -> Result<bool, PrecompileHalt> {
        #[cfg(feature = "pairing-hints")]
        let hint = self.hints.next();
        // Keep large requests on the pinned implementation with bounded cache
        // work. Wrong-width direct trait calls retain its original behavior.
        if pairs.len() > MAX_PAIRS || pairs.iter().any(|(a, b)| a.len() != 64 || b.len() != 128) {
            return DefaultCrypto.bn254_pairing_check(pairs);
        }
        for entry in &self.results {
            if entry.bytes.len() == pairs.len() * 192
                && entry
                    .bytes
                    .chunks_exact(192)
                    .zip(pairs)
                    .all(|(cached, (a, b))| &cached[..64] == *a && &cached[64..] == *b)
            {
                self.hits += 1;
                return Ok(entry.result);
            }
        }
        let mut groups: Vec<miller::Group> = Vec::with_capacity(pairs.len());
        for (a, b) in pairs {
            let x = field(&a[..32])?;
            let y = field(&a[32..])?;
            let p = if x.is_zero() && y.is_zero() {
                G1Affine::zero()
            } else {
                let p = G1Affine::new_unchecked(x, y);
                if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
                    return Err(PrecompileHalt::Bn254AffineGFailedToCreate);
                }
                p
            };
            // Validate G2 even when G1 is infinity; invalid pairs cannot be
            // hidden behind a zero pairing contribution.
            let q = self.g2(b)?;
            if !p.is_zero() && !self.points[q].point.is_zero() {
                let prepared = self.prepared(q);
                if let Some((first, sum, _)) = groups
                    .iter_mut()
                    .find(|(_, _, q)| Arc::ptr_eq(q, &prepared))
                {
                    *sum.get_or_insert_with(|| first.into_group()) += p;
                } else {
                    groups.push((p, None, prepared));
                }
            }
        }
        let result = if !miller::normalize(&mut groups) {
            true
        } else {
            #[cfg(feature = "pairing-hints")]
            {
                self.hints.check(&groups, hint)
            }
            #[cfg(not(feature = "pairing-hints"))]
            {
                miller::check(&groups)
            }
        };
        let mut bytes = Vec::with_capacity(pairs.len() * 192);
        for (a, b) in pairs {
            bytes.extend_from_slice(a);
            bytes.extend_from_slice(b);
        }
        let entry = ResultEntry { bytes, result };
        if self.results.len() < RESULTS {
            self.results.push(entry);
        } else {
            self.results[self.next_result] = entry;
            self.next_result = (self.next_result + 1) % RESULTS;
        }
        Ok(result)
    }
}
fn field(bytes: &[u8]) -> Result<Fq, PrecompileHalt> {
    let x = U256::from_be_slice(bytes);
    Fq::from_bigint(BigInt(*x.as_limbs())).ok_or(PrecompileHalt::Bn254FieldPointNotAMember)
}
static CACHE: spin::Mutex<Cache> = spin::Mutex::new(Cache::new());
pub(super) fn check(pairs: &[(&[u8], &[u8])]) -> Result<bool, PrecompileHalt> {
    CACHE.lock().check(pairs)
}

#[cfg(test)]
#[path = "pairing_tests.rs"]
mod tests;

#[cfg(feature = "pairing-hints")]
pub(super) fn install_hints(input: &'static [u8]) -> Option<&'static [u8]> {
    CACHE.lock().hints.install(input)
}

#[cfg(all(feature = "pairing-hints", feature = "host"))]
pub(super) fn start_hint_collection() {
    CACHE.lock().hints.collect = Some(Vec::new());
}

#[cfg(all(feature = "pairing-hints", feature = "host"))]
pub(super) fn finish_hint_collection(input: Vec<u8>) -> Option<Vec<u8>> {
    CACHE.lock().hints.finish(input)
}
