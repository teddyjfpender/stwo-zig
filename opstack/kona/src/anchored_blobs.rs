//! EIP-4844 blob admission for hashes supplied by the anchored L1 source.
use crate::statement_sha2::{Digest, Sha256};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use alloy_eips::eip4844::Blob;
use alloy_primitives::{B256, hex};
use ark_bls12_381::Fr;
use ark_ff::{BigInteger, FftField, Field, PrimeField, batch_inversion};
use async_trait::async_trait;
use kona_derive::{BlobProvider, PipelineError, PipelineErrorKind};
use kona_protocol::BlockInfo;

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
        Ok(Self { sidecars: index })
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
        hashes
            .iter()
            .map(|hash| {
                let sidecar = self
                    .sidecars
                    .get(hash)
                    .ok_or_else(|| invalid("missing anchored blob"))?;
                if !verify_sidecar(sidecar) {
                    return Err(invalid("invalid EIP-4844 blob proof"));
                }
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

fn verify_sidecar(sidecar: &BlobSidecar<'_>) -> bool {
    let mut hash = Sha256::new();
    hash.update(b"FSBLOBVERIFY_V1_");
    hash.update((FIELD_ELEMENTS as u128).to_be_bytes());
    hash.update(sidecar.blob.as_slice());
    hash.update(sidecar.commitment);
    let z = Fr::from_be_bytes_mod_order(&hash.finalize());
    let Some(y) = evaluate_blob(sidecar.blob, z) else {
        return false;
    };
    let z: [u8; 32] = z.into_bigint().to_bytes_be().try_into().expect("Fr width");
    let y: [u8; 32] = y.into_bigint().to_bytes_be().try_into().expect("Fr width");
    revm_precompile::kzg_point_evaluation::arkworks::verify_kzg_proof(
        &sidecar.commitment,
        &z,
        &y,
        &sidecar.proof,
    )
}

fn evaluate_blob(blob: &Blob, z: Fr) -> Option<Fr> {
    let step = Fr::get_root_of_unity(FIELD_ELEMENTS as u64).expect("EIP-4844 domain");
    let mut roots = alloc::vec![Fr::ONE; FIELD_ELEMENTS];
    for i in 1..FIELD_ELEMENTS {
        roots[i] = roots[i - 1] * step;
    }
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
    fn domain_hit_still_checks_every_scalar_for_canonical_encoding() {
        let mut blob = example_blob();
        assert_eq!(evaluate_blob(&blob, Fr::ONE), Some(Fr::ONE));
        blob.as_mut_slice()[32..64].copy_from_slice(&SCALAR_MODULUS);
        assert_eq!(evaluate_blob(&blob, Fr::ONE), None);
    }
}
