//! EIP-4844 blob admission for hashes supplied by the anchored L1 source.
use crate::statement_sha2::{Digest, Sha256};
use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec::Vec};
use alloy_eips::eip4844::Blob;
use alloy_primitives::B256;
#[cfg(test)]
use alloy_primitives::hex;
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AdditiveGroup, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInt, BigInteger, Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use async_trait::async_trait;
use kona_derive::{BlobProvider, PipelineError, PipelineErrorKind};
use kona_protocol::BlockInfo;
use spin::Mutex;

const FIELD_ELEMENTS: usize = 4096;
// 4096^-1 in the EIP-4844 scalar field; checked by qualification below.
const INV_DOMAIN: Fr = ark_ff::MontFp!(
    "52423073447788513186850219087163459498374710080483563692275874603576291491841"
);
const MAX_SIDECARS: usize = 256;
#[cfg(test)]
const SCALAR_MODULUS: [u8; 32] =
    hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");

#[derive(Debug, Clone, Copy)]
pub struct BlobSidecar<'a> {
    pub blob: &'a Blob,
    pub commitment: [u8; 48],
    pub proof: [u8; 48],
}

#[derive(Debug, Clone)]
pub(crate) struct AnchoredBlobs<'a> {
    sidecars: BTreeMap<B256, BlobSidecar<'a>>,
    verified: Arc<Mutex<bool>>,
}

fn invalid(reason: &'static str) -> PipelineErrorKind {
    PipelineError::Provider(reason.into()).crit()
}

impl<'a> AnchoredBlobs<'a> {
    pub(crate) fn new(sidecars: &[BlobSidecar<'a>]) -> Result<Self, PipelineErrorKind> {
        if sidecars.len() > MAX_SIDECARS {
            return Err(invalid("blob witness exceeds sidecar limit"));
        }
        let mut index = BTreeMap::new();
        for sidecar in sidecars {
            if index
                .insert(versioned_hash(&sidecar.commitment), *sidecar)
                .is_some()
            {
                return Err(invalid("duplicate versioned hash in blob witness"));
            }
        }
        Ok(Self {
            sidecars: index,
            verified: Arc::new(Mutex::new(false)),
        })
    }
}

#[async_trait]
impl BlobProvider for AnchoredBlobs<'_> {
    type Error = PipelineErrorKind;

    async fn get_and_validate_blobs(
        &mut self,
        _: &BlockInfo,
        hashes: &[B256],
    ) -> Result<Vec<Box<Blob>>, Self::Error> {
        if hashes.len() > MAX_SIDECARS {
            return Err(invalid("too many blob references in anchored L1 block"));
        }
        if hashes.is_empty() {
            return Ok(Vec::new());
        }
        if hashes.iter().any(|hash| !self.sidecars.contains_key(hash)) {
            return Err(invalid("missing anchored blob"));
        }
        {
            let mut verified = self.verified.lock();
            if !*verified {
                if !verify_sidecar_batch(self.sidecars.values().copied()) {
                    return Err(invalid("invalid EIP-4844 blob proof batch"));
                }
                *verified = true;
            }
        }
        hashes
            .iter()
            .map(|hash| {
                let sidecar = self
                    .sidecars
                    .get(hash)
                    .ok_or_else(|| invalid("missing anchored blob"))?;
                #[cfg(all(feature = "host", feature = "transition-program"))]
                crate::transition_trace::blob(*hash);
                Ok(Box::new(*sidecar.blob))
            })
            .collect()
    }
}

fn versioned_hash(commitment: &[u8; 48]) -> B256 {
    let mut hash: [u8; 32] = Sha256::digest(commitment).into();
    hash[0] = 1;
    hash.into()
}

fn scalar_bytes(value: Fr) -> [u8; 32] {
    value
        .into_bigint()
        .to_bytes_be()
        .try_into()
        .expect("Fr width")
}

fn evaluation_point(sidecar: &BlobSidecar<'_>) -> Fr {
    let mut hash = Sha256::new();
    hash.update(b"FSBLOBVERIFY_V1_");
    hash.update((FIELD_ELEMENTS as u128).to_be_bytes());
    hash.update(sidecar.blob.as_slice());
    hash.update(sidecar.commitment);
    Fr::from_be_bytes_mod_order(&hash.finalize())
}

fn verify_sidecar(sidecar: &BlobSidecar<'_>) -> bool {
    let z = evaluation_point(sidecar);
    let Some(y) = evaluate_blob(sidecar.blob, z, evaluation_roots()) else {
        return false;
    };
    revm_precompile::kzg_point_evaluation::arkworks::verify_kzg_proof(
        &sidecar.commitment,
        &scalar_bytes(z),
        &scalar_bytes(y),
        &sidecar.proof,
    )
}

fn compress_g1(point: &G1Affine) -> [u8; 48] {
    let mut bytes = [0; 48];
    point
        .serialize_compressed(bytes.as_mut_slice())
        .expect("G1 width");
    bytes
}

fn parse_g1(bytes: &[u8; 48]) -> Option<G1Affine> {
    let point = G1Affine::deserialize_compressed(bytes.as_slice()).ok()?;
    // Require the canonical encoding, including for the point at infinity.
    (compress_g1(&point) == *bytes).then_some(point)
}

/// EIP-4844 batch equation and transcript, matching c-kzg 2.1.8's
/// compute_r_powers_for_verify_kzg_proof_batch. Order is fixed by the
/// witness's versioned hashes. Verify once before any blob reaches Kona.
fn verify_sidecar_batch<'a>(mut sidecars: impl ExactSizeIterator<Item = BlobSidecar<'a>>) -> bool {
    let count = sidecars.len();
    if count < 2 {
        return sidecars
            .next()
            .is_none_or(|sidecar| verify_sidecar(&sidecar));
    }
    let roots = evaluation_roots();
    let mut transcript = Sha256::new();
    transcript.update(b"RCKZGBATCH___V1_");
    transcript.update((FIELD_ELEMENTS as u64).to_be_bytes());
    transcript.update((count as u64).to_be_bytes());
    let mut commitments = Vec::with_capacity(count);
    let mut proofs = Vec::with_capacity(count);
    let mut evaluations = Vec::with_capacity(count);
    for sidecar in sidecars {
        let (Some(commitment), Some(proof)) =
            (parse_g1(&sidecar.commitment), parse_g1(&sidecar.proof))
        else {
            return false;
        };
        let z = evaluation_point(&sidecar);
        let Some(y) = evaluate_blob(sidecar.blob, z, roots) else {
            return false;
        };
        transcript.update(sidecar.commitment);
        transcript.update(scalar_bytes(z));
        transcript.update(scalar_bytes(y));
        transcript.update(sidecar.proof);
        commitments.push(commitment);
        proofs.push(proof);
        evaluations.push((z, y));
    }

    let r = Fr::from_be_bytes_mod_order(&transcript.finalize());
    let mut power = Fr::ONE;
    let mut powers = Vec::with_capacity(count);
    let mut weighted_z = Vec::with_capacity(count);
    let mut weighted_y = Fr::ZERO;
    for (z, y) in evaluations {
        powers.push(power);
        weighted_z.push(power * z);
        weighted_y += power * y;
        power *= r;
    }

    // Pair e(Σ r^i P_i, τ G2) with
    // e(Σ r^i (C_i + z_i P_i - y_i G1), -G2).
    let proof = G1Projective::msm_unchecked(&proofs, &powers);
    let commitment = G1Projective::msm_unchecked(&commitments, &powers)
        + G1Projective::msm_unchecked(&proofs, &weighted_z)
        - G1Affine::generator().mul_bigint(weighted_y.into_bigint());
    // Reuse the admitted trusted setup and pairing routine at point (0, 0).
    revm_precompile::kzg_point_evaluation::arkworks::verify_kzg_proof(
        &compress_g1(&commitment.into_affine()),
        &[0; 32],
        &[0; 32],
        &compress_g1(&proof.into_affine()),
    )
}

fn evaluation_roots() -> &'static [Fr; FIELD_ELEMENTS] {
    &crate::blob_roots::ROOTS
}

fn evaluate_blob(blob: &Blob, z: Fr, roots: &[Fr]) -> Option<Fr> {
    // EIP-4844 evaluations are in bit-reversed order, so each adjacent pair
    // lives at (w, -w). Fold the even and odd interpolation polynomials:
    //   2 f_z(w^2) = a + b + (z / w) (a - b).
    // Recurse at z^2. Twelve unscaled folds introduce a factor of 4096,
    // removed once at the end. All divisors w are public roots of unity;
    // roots[N-k] supplies their inverses without a witness-dependent inverse.
    // Dense blobs take 2(N-1) multiplications plus twelve squares, versus
    // roughly 4N multiplications in the streaming single-fraction formula.
    let mut values = Vec::with_capacity(FIELD_ELEMENTS);
    for bytes in blob.as_slice().chunks_exact(32) {
        let limbs = core::array::from_fn(|i| {
            let start = 24 - 8 * i;
            u64::from_be_bytes(bytes[start..start + 8].try_into().expect("scalar limb"))
        });
        // Decode every field element before folding, including if z is a
        // domain point. No on-domain shortcut may bypass canonical admission.
        values.push(Fr::from_bigint(BigInt(limbs))?);
    }
    // Sparse or heavily padded blobs can make the streaming recurrence cheaper.
    // It needs four multiplies per nonzero value; folding needs at most 2N.
    // Choose conservatively by authenticated values, never an external hint.
    let nonzero = values.iter().filter(|v| **v != Fr::ZERO).count();
    if nonzero == 0 {
        return Some(Fr::ZERO);
    }
    let z_to_n = z.pow([FIELD_ELEMENTS as u64]);
    if z_to_n == Fr::ONE {
        let index = roots.iter().position(|root| *root == z)?;
        return Some(values[index.reverse_bits() >> (usize::BITS - FIELD_ELEMENTS.ilog2())]);
    }
    if nonzero <= FIELD_ELEMENTS / 2 {
        return evaluate_blob_sparse(&values, z, z_to_n, roots);
    }
    evaluate_blob_folded(&mut values, z, roots)
}

fn evaluate_blob_folded(values: &mut [Fr], z: Fr, roots: &[Fr]) -> Option<Fr> {
    let mut count = FIELD_ELEMENTS;
    let mut point = z;
    while count > 1 {
        for j in 0..count / 2 {
            let a = values[2 * j];
            let b = values[2 * j + 1];
            let difference = a - b;
            let mut folded = a + b;
            if difference != Fr::ZERO {
                // rev_logN(2j) already includes the 2^stage factor; the
                // same public root prefix serves every fold depth.
                let index = (2 * j).reverse_bits() >> (usize::BITS - FIELD_ELEMENTS.ilog2());
                let inverse_root = roots[(FIELD_ELEMENTS - index) & (FIELD_ELEMENTS - 1)];
                folded += difference * inverse_root * point;
            }
            values[j] = folded;
        }
        point.square_in_place();
        count /= 2;
    }
    Some(values[0] * INV_DOMAIN)
}

fn evaluate_blob_sparse(values: &[Fr], z: Fr, z_to_n: Fr, roots: &[Fr]) -> Option<Fr> {
    let mut numerator = Fr::ZERO;
    let mut denominator = Fr::ONE;
    for (i, value) in values.iter().copied().enumerate() {
        if value == Fr::ZERO {
            continue;
        }
        // The caller has already handled z^N == 1 after canonical decoding.
        // Skip zero values before root lookup and bit reversal; their absence
        // contributes no fraction and cannot hide an on-domain value.
        let root = roots[i.reverse_bits() >> (usize::BITS - FIELD_ELEMENTS.ilog2())];
        let difference = z - root;
        numerator = numerator * difference + (root * value) * denominator;
        denominator *= difference;
    }
    Some(
        numerator
            * (z_to_n - Fr::ONE)
            * (denominator * Fr::from(FIELD_ELEMENTS as u64)).inverse()?,
    )
}

/// Independent streaming barycentric reference retained for qualification.
#[cfg(any(test, feature = "blob-eval-probe"))]
fn evaluate_blob_fraction(blob: &Blob, z: Fr, roots: &[Fr]) -> Option<Fr> {
    let mut numerator = Fr::ZERO;
    let mut denominator = Fr::ONE;
    let mut on_domain = None;
    for (index, bytes) in blob.as_slice().chunks_exact(32).enumerate() {
        // Blob limbs are canonical big-endian scalars. Convert the four
        // limbs once and let from_bigint reject values at or above Fr::MODULUS.
        // Modular byte decoding would perform extra arithmetic for every limb.
        let limbs = core::array::from_fn(|i| {
            let start = 24 - 8 * i;
            u64::from_be_bytes(bytes[start..start + 8].try_into().expect("scalar limb"))
        });
        let value = Fr::from_bigint(BigInt(limbs))?;
        let root = roots[index.reverse_bits() >> (usize::BITS - FIELD_ELEMENTS.ilog2())];
        if z == root {
            on_domain = Some(value);
        } else if value != Fr::ZERO && on_domain.is_none() {
            // Maintain the barycentric sum as a single fraction. This avoids
            // storing and batch-inverting every denominator. Zero evaluations
            // need no term, but all blob scalars are still decoded and checked.
            let difference = z - root;
            numerator = numerator * difference + (root * value) * denominator;
            denominator *= difference;
        }
    }
    if let Some(value) = on_domain {
        return Some(value);
    }
    Some(
        numerator
            * (z.pow([FIELD_ELEMENTS as u64]) - Fr::ONE)
            * (denominator * Fr::from(FIELD_ELEMENTS as u64)).inverse()?,
    )
}

/// Diagnostic program only: BEV1 || mode:u8 || canonical z:32 || blob:131072.
/// The 43-byte output has a BEV1 marker and BP suffix, which cannot be admitted
/// as OP/OD. Reuses the execution runner without relaxing its output contract.
/// Modes compare the retained reference, production selection, and forced fold.
#[cfg(feature = "blob-eval-probe")]
pub fn evaluation_probe(input: &[u8]) -> Option<[u8; 43]> {
    if input.get(..4) == Some(b"BKV1") {
        return kzg_probe(input);
    }
    if input.len() != 4 + 1 + 32 + 131072 || &input[..4] != b"BEV1" {
        return None;
    }
    let point_bytes: &[u8; 32] = input[5..37].try_into().ok()?;
    let limbs = core::array::from_fn(|i| {
        let start = 24 - 8 * i;
        u64::from_be_bytes(
            point_bytes[start..start + 8]
                .try_into()
                .expect("scalar limb"),
        )
    });
    let point = Fr::from_bigint(BigInt(limbs))?;
    let mut blob = Box::<Blob>::default();
    blob.as_mut_slice().copy_from_slice(&input[37..]);
    let roots = evaluation_roots();
    let result = match input[4] {
        0 => evaluate_blob_fraction(&blob, point, roots),
        1 => evaluate_blob(&blob, point, roots),
        2 => {
            let mut values = Vec::with_capacity(FIELD_ELEMENTS);
            for bytes in blob.as_slice().chunks_exact(32) {
                let value = Fr::from_be_bytes_mod_order(bytes);
                if scalar_bytes(value).as_slice() != bytes {
                    return None;
                }
                values.push(value);
            }
            evaluate_blob_folded(&mut values, point, roots)
        }
        _ => None,
    }?;
    let mut output = [0; 43];
    output[..32].copy_from_slice(&scalar_bytes(result));
    output[32..36].copy_from_slice(b"BEV1");
    output[41..].copy_from_slice(b"BP");
    Some(output)
}

/// Bounded diagnostic only: BKV1 || count:u32-le ||
/// (commitment:48 || proof:48 || blob:131072)*count. The blob views borrow
/// input bytes. Verify the same canonical, sorted batch as anchored derivation.
/// Output remains BP-tagged and cannot authorize OP/OD execution or derivation.
#[cfg(feature = "blob-eval-probe")]
fn kzg_probe(input: &[u8]) -> Option<[u8; 43]> {
    const STRIDE: usize = 96 + 131072;
    let count = u32::from_le_bytes(input.get(4..8)?.try_into().ok()?) as usize;
    if count == 0 || count > MAX_SIDECARS || input.len() != 8 + count * STRIDE {
        return None;
    }
    let sidecars: Vec<_> = input[8..]
        .chunks_exact(STRIDE)
        .map(|bytes| BlobSidecar {
            commitment: bytes[..48].try_into().unwrap(),
            proof: bytes[48..96].try_into().unwrap(),
            blob: bytes[96..].try_into().unwrap(),
        })
        .collect();
    let indexed = AnchoredBlobs::new(&sidecars).ok()?;
    if !verify_sidecar_batch(indexed.sidecars.values().copied()) {
        return None;
    }
    let mut digest = Sha256::new();
    digest.update(b"STWO/BLOB/KZG/PROBE1");
    digest.update((count as u32).to_le_bytes());
    for sidecar in &sidecars {
        digest.update(sidecar.commitment);
        digest.update(sidecar.proof);
    }
    let mut output = [0; 43];
    output[..32].copy_from_slice(&digest.finalize());
    output[32..36].copy_from_slice(b"BKV1");
    output[36..40].copy_from_slice(&(count as u32).to_le_bytes());
    output[41..].copy_from_slice(b"BP");
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::{
        future::Future,
        task::{Context, Poll, Waker},
    };

    // Generated with c-kzg 2.1.8 and the Ethereum ceremony setup using the
    // evaluation vector below. The cubic sequence exercises bit reversal.
    const COMMITMENT: [u8; 48] = hex!(
        "b150de850d4a7008b1b4f810add779e9e2fba3a66619413a0ee9cadbef7e56873503cdd01651529dc0e0addb8df20fab"
    );
    const PROOF: [u8; 48] = hex!(
        "966e952d4cffa5c843d682cc60d2491c2e705280393c5ca70003d56b5eb15ed231ed23271df5ad0aa836a444ead2ca07"
    );

    fn example_blob() -> Box<Blob> {
        let mut blob = Box::<Blob>::default();
        for (i, bytes) in blob.as_mut_slice().chunks_exact_mut(32).enumerate() {
            bytes[24..].copy_from_slice(&(1 + (i as u64).pow(3)).to_be_bytes());
        }
        blob
    }

    fn ready<F: Future>(future: F) -> F::Output {
        match core::pin::pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("in-memory blob provider blocked"),
        }
    }

    #[test]
    fn admits_only_valid_sidecars_for_the_requested_versioned_hash() {
        let mut blob = example_blob();
        let sidecar = BlobSidecar {
            blob: &blob,
            commitment: COMMITMENT,
            proof: PROOF,
        };
        assert!(AnchoredBlobs::new(&[sidecar, sidecar]).is_err());
        let mut provider = AnchoredBlobs::new(&[sidecar]).unwrap();
        let block = BlockInfo::default();
        let hash = versioned_hash(&COMMITMENT);
        assert!(ready(provider.get_and_validate_blobs(&block, &[B256::ZERO])).is_err());
        let verified = ready(provider.get_and_validate_blobs(&block, &[hash])).unwrap();
        assert_eq!(verified[0].as_slice(), blob.as_slice());

        let mut invalid_proof = sidecar;
        invalid_proof.proof[47] ^= 1;
        assert!(!verify_sidecar(&invalid_proof));
        blob.as_mut_slice()[31] ^= 1;
        let changed = BlobSidecar {
            blob: &blob,
            commitment: COMMITMENT,
            proof: PROOF,
        };
        assert!(!verify_sidecar(&changed));
    }

    #[test]
    fn batch_matches_individual_c_kzg_vectors_and_rejects_each_kind_of_tamper() {
        let first = example_blob();
        let mut second = Box::<Blob>::default();
        for (i, bytes) in second.as_mut_slice().chunks_exact_mut(32).enumerate() {
            bytes[24..].copy_from_slice(&(17 + (i as u64).pow(2)).to_be_bytes());
        }
        let a = BlobSidecar {
            blob: &first,
            commitment: COMMITMENT,
            proof: PROOF,
        };
        let b = BlobSidecar {
            blob: &second,
            commitment: hex!(
                "ac55315f6eb653492046af4a94d7237b16f2adb94ecdabecb909b7535a2833189c93d7713380e34bbcabd46e9c8932c7"
            ),
            proof: hex!(
                "92ab28ca7a01eb62d4647629e7bd30412e8b0907a0b1494f1a29fae0e4284b642a46be061eb102cf9f031756f9910e9a"
            ),
        };
        assert!(verify_sidecar(&a));
        assert!(verify_sidecar(&b));
        assert!(verify_sidecar_batch([a, b].into_iter()));
        assert!(verify_sidecar_batch([b, a].into_iter()));
        assert!(!verify_sidecar_batch(
            [
                BlobSidecar {
                    proof: b.proof,
                    ..a
                },
                b
            ]
            .into_iter()
        ));
        assert!(!verify_sidecar_batch(
            [
                BlobSidecar {
                    commitment: b.commitment,
                    ..a
                },
                b
            ]
            .into_iter()
        ));

        let mut changed = example_blob();
        changed.as_mut_slice()[31] ^= 1;
        assert!(!verify_sidecar_batch(
            [
                BlobSidecar {
                    blob: &changed,
                    ..a
                },
                b
            ]
            .into_iter()
        ));
    }

    #[cfg(feature = "blob-eval-probe")]
    #[test]
    fn kzg_probe_admits_known_vector_and_rejects_invalid_and_duplicate_sidecars() {
        let blob = example_blob();
        let mut input = Vec::with_capacity(8 + 96 + 131072);
        input.extend_from_slice(b"BKV1");
        input.extend_from_slice(&1u32.to_le_bytes());
        input.extend_from_slice(&COMMITMENT);
        input.extend_from_slice(&PROOF);
        input.extend_from_slice(blob.as_slice());
        let result = evaluation_probe(&input).unwrap();
        assert_eq!(&result[32..36], b"BKV1");
        assert_eq!(&result[36..40], &1u32.to_le_bytes());
        assert_eq!(&result[41..], b"BP");
        input[8 + 48 + 7] ^= 1;
        assert!(evaluation_probe(&input).is_none());
        input[8 + 48 + 7] ^= 1;
        input[8 + 96 + 31] ^= 1;
        assert!(evaluation_probe(&input).is_none());
        input[8 + 96 + 31] ^= 1;
        input[8 + 96 + 32 * 4095..].copy_from_slice(&SCALAR_MODULUS);
        assert!(evaluation_probe(&input).is_none());
        input[8 + 96..].copy_from_slice(blob.as_slice());
        let second = input[8..].to_vec();
        input.extend_from_slice(&second);
        input[4..8].copy_from_slice(&2u32.to_le_bytes());
        assert!(evaluation_probe(&input).is_none());
        assert!(evaluation_probe(&input[..input.len() - 1]).is_none());
        input[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert!(evaluation_probe(&input).is_none());
        input[4..8].copy_from_slice(&257u32.to_le_bytes());
        assert!(evaluation_probe(&input).is_none());
    }

    #[test]
    fn domain_hit_still_checks_every_scalar_for_canonical_encoding() {
        let mut blob = example_blob();
        assert_eq!(
            evaluate_blob(&blob, Fr::ONE, evaluation_roots()),
            Some(Fr::ONE)
        );
        blob.as_mut_slice()[32..64].copy_from_slice(&SCALAR_MODULUS);
        assert_eq!(evaluate_blob(&blob, Fr::ONE, evaluation_roots()), None);
    }

    #[cfg(feature = "blob-eval-probe")]
    #[test]
    fn diagnostic_framing_is_distinct_and_does_not_bypass_scalar_admission() {
        let mut input = alloc::vec![0; 37 + 131072];
        input[..4].copy_from_slice(b"BEV1");
        input[36] = 1; // on-domain point 1, not permission to skip later scalars
        for mode in 0..=2 {
            input[4] = mode;
            let result = evaluation_probe(&input).unwrap();
            assert_eq!(&result[..32], &[0; 32]);
            assert_eq!(&result[32..36], b"BEV1");
            assert_eq!(&result[41..], b"BP");
        }
        input[4] = 3;
        assert!(evaluation_probe(&input).is_none());
        input[4] = 1;
        input[5..37].copy_from_slice(&SCALAR_MODULUS);
        assert!(evaluation_probe(&input).is_none());
        input[5..37].fill(0);
        input[36] = 1;
        input[37 + 32 * 4095..].copy_from_slice(&SCALAR_MODULUS);
        for mode in 0..=2 {
            input[4] = mode;
            assert!(evaluation_probe(&input).is_none());
        }
        assert!(evaluation_probe(&input[..input.len() - 1]).is_none());
        input[0] ^= 1;
        assert!(evaluation_probe(&input).is_none());
    }

    #[test]
    fn folded_interpolation_matches_fraction_for_dense_sparse_and_domain_points() {
        assert_eq!(INV_DOMAIN * Fr::from(FIELD_ELEMENTS as u64), Fr::ONE);
        let roots = evaluation_roots();
        let mut dense = Box::<Blob>::default();
        let mut sparse = Box::<Blob>::default();
        // Deterministic full-width canonical values. The reference follows a
        // rational barycentric recurrence, not the folding identity above.
        for (i, bytes) in dense.as_mut_slice().chunks_exact_mut(32).enumerate() {
            let value = Fr::from_be_bytes_mod_order(&Sha256::digest((i as u64).to_be_bytes()));
            bytes.copy_from_slice(&scalar_bytes(value));
            if i % 31 == 0 {
                sparse.as_mut_slice()[32 * i..32 * (i + 1)].copy_from_slice(bytes);
            }
        }
        for blob in [&dense, &sparse, &Box::<Blob>::default(), &example_blob()] {
            for point in [
                Fr::ZERO,
                Fr::from(17),
                Fr::from(1729),
                roots[0],
                roots[1],
                roots[29],
                roots[2048],
                roots[4095],
            ] {
                assert_eq!(
                    evaluate_blob(blob, point, roots),
                    evaluate_blob_fraction(blob, point, roots)
                );
                let mut values: Vec<_> = blob
                    .as_slice()
                    .chunks_exact(32)
                    .map(Fr::from_be_bytes_mod_order)
                    .collect();
                assert_eq!(
                    evaluate_blob_folded(&mut values, point, roots),
                    evaluate_blob_fraction(blob, point, roots)
                );
            }
        }
        // Domain points must select the corresponding bit-reversed input,
        // including both halves and the last adjacent pair.
        for i in [0usize, 1, 2, 3, 17, 255, 2048, 4094, 4095] {
            let index = i.reverse_bits() >> (usize::BITS - FIELD_ELEMENTS.ilog2());
            let expected = Fr::from_be_bytes_mod_order(&dense.as_slice()[32 * i..32 * (i + 1)]);
            assert_eq!(evaluate_blob(&dense, roots[index], roots), Some(expected));
        }
        for index in [0usize, 1, 2048, 4095] {
            let mut malformed = dense.clone();
            malformed.as_mut_slice()[32 * index..32 * (index + 1)].copy_from_slice(&SCALAR_MODULUS);
            assert_eq!(evaluate_blob(&malformed, roots[0], roots), None);
            assert_eq!(evaluate_blob(&malformed, Fr::from(17), roots), None);
        }
    }
}
