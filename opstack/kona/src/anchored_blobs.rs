//! EIP-4844 blob admission for hashes supplied by the anchored L1 source.
use crate::statement_sha2::{Digest, Sha256};
use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec::Vec};
use alloy_eips::eip4844::Blob;
use alloy_primitives::{B256, hex};
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AdditiveGroup, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, FftField, Field, PrimeField, batch_inversion};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use async_trait::async_trait;
use kona_derive::{BlobProvider, PipelineError, PipelineErrorKind};
use kona_protocol::BlockInfo;
use spin::Mutex;

const FIELD_ELEMENTS: usize = 4096;
const MAX_SIDECARS: usize = 256;
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
    let Some(y) = evaluate_blob(sidecar.blob, z, &evaluation_roots()) else {
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
        let Some(y) = evaluate_blob(sidecar.blob, z, &roots) else {
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

fn evaluation_roots() -> Vec<Fr> {
    let step = Fr::get_root_of_unity(FIELD_ELEMENTS as u64).expect("EIP-4844 domain");
    let mut roots = alloc::vec![Fr::ONE; FIELD_ELEMENTS];
    for i in 1..FIELD_ELEMENTS {
        roots[i] = roots[i - 1] * step;
    }
    roots
}

fn evaluate_blob(blob: &Blob, z: Fr, roots: &[Fr]) -> Option<Fr> {
    let mut numerators = Vec::with_capacity(FIELD_ELEMENTS);
    let mut denominators = Vec::with_capacity(FIELD_ELEMENTS);
    let mut on_domain = None;
    for (index, bytes) in blob.as_slice().chunks_exact(32).enumerate() {
        if bytes >= SCALAR_MODULUS.as_slice() {
            return None;
        }
        let value = Fr::from_be_bytes_mod_order(bytes);
        let root = roots[index.reverse_bits() >> (usize::BITS - FIELD_ELEMENTS.ilog2())];
        if z == root {
            on_domain = Some(value);
        }
        numerators.push(root * value);
        denominators.push(z - root);
    }
    if let Some(value) = on_domain {
        return Some(value);
    }
    batch_inversion(&mut denominators);
    let sum = numerators
        .into_iter()
        .zip(denominators)
        .map(|(n, d)| n * d)
        .sum::<Fr>();
    Some(
        sum * (z.pow([FIELD_ELEMENTS as u64]) - Fr::ONE)
            * Fr::from(FIELD_ELEMENTS as u64).inverse()?,
    )
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

    #[test]
    fn domain_hit_still_checks_every_scalar_for_canonical_encoding() {
        let mut blob = example_blob();
        assert_eq!(
            evaluate_blob(&blob, Fr::ONE, &evaluation_roots()),
            Some(Fr::ONE)
        );
        blob.as_mut_slice()[32..64].copy_from_slice(&SCALAR_MODULUS);
        assert_eq!(evaluate_blob(&blob, Fr::ONE, &evaluation_roots()), None);
    }
}
