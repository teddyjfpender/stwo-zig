//! Bounded, exact-byte reuse of results and validated G2 points. Every entry
//! originates from computations in this execution; no host-supplied hint or
//! digest-only equality can create an admitted result. VM RAM binds reuse.
use alloc::vec::Vec;
use alloy_primitives::U256;
use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ec::{AffineRepr, pairing::Pairing};
use ark_ff::{BigInt, One, PrimeField, Zero};
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
}
struct Cache {
    results: Vec<ResultEntry>,
    points: Vec<PointEntry>,
    next_result: usize,
    next_point: usize,
    hits: usize,
    point_hits: usize,
}
impl Cache {
    const fn new() -> Self {
        Self {
            results: Vec::new(),
            points: Vec::new(),
            next_result: 0,
            next_point: 0,
            hits: 0,
            point_hits: 0,
        }
    }
    fn g2(&mut self, bytes: &[u8]) -> Result<G2Affine, PrecompileHalt> {
        for entry in &self.points {
            if entry.bytes == bytes {
                self.point_hits += 1;
                return Ok(entry.point);
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
        };
        if self.points.len() < POINTS {
            self.points.push(entry);
        } else {
            self.points[self.next_point] = entry;
            self.next_point = (self.next_point + 1) % POINTS;
        }
        Ok(point)
    }
    fn check(&mut self, pairs: &[(&[u8], &[u8])]) -> Result<bool, PrecompileHalt> {
        // Keep large requests on the pinned implementation with bounded cache
        // work. Wrong-width direct trait calls retain its original behavior.
        if pairs.len() > MAX_PAIRS || pairs.iter().any(|(a, b)| a.len() != 64 || b.len() != 128) {
            return DefaultCrypto.bn254_pairing_check(pairs);
        }
        let mut bytes = Vec::with_capacity(pairs.len() * 192);
        for (a, b) in pairs {
            bytes.extend_from_slice(a);
            bytes.extend_from_slice(b);
        }
        for entry in &self.results {
            if entry.bytes == bytes {
                self.hits += 1;
                return Ok(entry.result);
            }
        }
        let mut g1 = Vec::with_capacity(pairs.len());
        let mut g2 = Vec::with_capacity(pairs.len());
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
            if !p.is_zero() && !q.is_zero() {
                g1.push(p);
                g2.push(q);
            }
        }
        let result = g1.is_empty() || Bn254::multi_pairing(g1, g2).0.is_one();
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
