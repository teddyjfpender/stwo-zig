//! One checkpoint transition through Kona's authenticated derivation pipeline.
use crate::{
    anchored_l1::{AnchorError, AnchoredL1},
    anchored_l2::AnchoredL2,
    execution::{public_output, single_block_output},
    statement_sha2::{Digest, Sha256},
    witness::{Validation, Witness},
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use alloy_eips::{BlockNumHash, eip4844::Blob};
use alloy_primitives::B256;
use async_trait::async_trait;
use kona_derive::{
    ActivationSignal, BlobProvider, ChainProvider, EthereumDataSource, Pipeline, PipelineBuilder,
    PipelineError, PipelineErrorKind, ResetError, ResetSignal, Signal, SignalReceiver,
    StatefulAttributesBuilder, StepResult,
};
use kona_genesis::{L1ChainConfig, RollupConfig};
use kona_protocol::{BatchValidationProvider, BlockInfo, L2BlockInfo};

const MAX_PIPELINE_STEPS: usize = 100_000;

/// Values supplied by the verifier, independently of the witness bytes.
#[derive(Debug, Clone, Copy)]
pub struct Transition {
    pub anchor: BlockNumHash,
    pub previous_number: u64,
    pub previous_root: B256,
    pub next_number: u64,
    pub next_root: B256,
    pub next_origin: BlockNumHash,
}

/// Public inputs for the one-block derivation and execution join. The witness
/// does not select the L1 anchor or chain configurations.
#[derive(Debug, Clone, Copy)]
pub struct TransitionStatement {
    pub chain_id: u64,
    pub l1_chain_id: u64,
    pub claim: Transition,
    pub payload_commitment: [u8; 32],
    pub block_hash: B256,
}

impl TransitionStatement {
    /// The derivation guest's output, distinct from the OP execution transport.
    pub fn public_output(&self) -> [u8; 43] {
        let mut digest = Sha256::new();
        digest.update(b"stwo/opstack/anchored-transition/v1\0");
        digest.update(self.chain_id.to_le_bytes());
        digest.update(self.l1_chain_id.to_le_bytes());
        digest.update(self.claim.anchor.number.to_le_bytes());
        digest.update(self.claim.anchor.hash);
        digest.update(self.claim.previous_number.to_le_bytes());
        digest.update(self.claim.previous_root);
        digest.update(self.claim.next_number.to_le_bytes());
        digest.update(self.claim.next_root);
        digest.update(self.claim.next_origin.number.to_le_bytes());
        digest.update(self.claim.next_origin.hash);
        digest.update(self.payload_commitment);
        digest.update(self.block_hash);
        public_output(self.chain_id, digest.finalize().into(), b"OD")
    }

    /// The execution guest's existing output for this exact payload and block.
    pub fn execution_output(&self) -> [u8; 43] {
        single_block_output(self.chain_id, self.payload_commitment, self.block_hash)
    }
}

#[derive(Debug)]
pub struct VerifiedTransition {
    pub block: L2BlockInfo,
    pub statement: TransitionStatement,
}

#[derive(Debug, thiserror::Error)]
pub enum TransitionError {
    #[error(transparent)]
    Anchor(#[from] AnchorError),
    #[error("Kona derivation: {0}")]
    Pipeline(#[from] PipelineErrorKind),
    #[error("configuration requires unsupported data availability or interop")]
    UnsupportedConfig,
    #[error("derived L1 origin differs from the transition statement")]
    Origin,
    #[error("Kona derivation exceeded its step budget")]
    StepBudget,
    #[error("Kona prepared an empty attributes queue")]
    MissingAttributes,
}

#[derive(Debug, Clone, Copy)]
struct RejectBlobs;

#[async_trait]
impl BlobProvider for RejectBlobs {
    type Error = PipelineErrorKind;

    async fn get_and_validate_blobs(
        &mut self,
        _: &BlockInfo,
        hashes: &[B256],
    ) -> Result<Vec<Box<Blob>>, Self::Error> {
        if hashes.is_empty() {
            return Ok(Vec::new());
        }
        Err(PipelineError::Provider("authenticated blob data is unsupported".into()).crit())
    }
}

/// Derive the next payload from the anchored L1 and safe L2 histories, then
/// execute it and check the claimed output root and origin. The caller owns
/// canonical L1 anchor selection and the pinned chain configurations.
pub async fn verify_calldata_transition(
    input: &[u8],
    claim: Transition,
    config: Arc<RollupConfig>,
    l1_config: Arc<L1ChainConfig>,
) -> Result<L2BlockInfo, TransitionError> {
    Ok(
        verify_calldata_transition_statement(input, claim, config, l1_config)
            .await?
            .block,
    )
}

pub async fn verify_calldata_transition_statement(
    input: &[u8],
    claim: Transition,
    config: Arc<RollupConfig>,
    l1_config: Arc<L1ChainConfig>,
) -> Result<VerifiedTransition, TransitionError> {
    verify_transition(input, claim, config, l1_config, RejectBlobs).await
}

/// Verify a transition with EIP-4844 data authenticated against the blob
/// versioned hashes in canonical L1 transactions. The caller supplies the
/// same public checkpoint and configuration authority as the calldata path.
#[cfg(feature = "blob-derivation")]
pub async fn verify_blob_transition(
    input: &[u8],
    claim: Transition,
    config: Arc<RollupConfig>,
    l1_config: Arc<L1ChainConfig>,
    sidecars: &[crate::anchored_blobs::BlobSidecar<'_>],
) -> Result<L2BlockInfo, TransitionError> {
    Ok(
        verify_blob_transition_statement(input, claim, config, l1_config, sidecars)
            .await?
            .block,
    )
}

#[cfg(feature = "blob-derivation")]
pub async fn verify_blob_transition_statement(
    input: &[u8],
    claim: Transition,
    config: Arc<RollupConfig>,
    l1_config: Arc<L1ChainConfig>,
    sidecars: &[crate::anchored_blobs::BlobSidecar<'_>],
) -> Result<VerifiedTransition, TransitionError> {
    let blobs = crate::anchored_blobs::AnchoredBlobs::new(sidecars)?;
    verify_transition(input, claim, config, l1_config, blobs).await
}

async fn verify_transition<B: BlobProvider + Send + Sync + Clone + core::fmt::Debug>(
    input: &[u8],
    claim: Transition,
    config: Arc<RollupConfig>,
    l1_config: Arc<L1ChainConfig>,
    blobs: B,
) -> Result<VerifiedTransition, TransitionError> {
    if claim.previous_number.checked_add(1) != Some(claim.next_number) {
        return Err(AnchorError::Ancestry.into());
    }
    if config.l1_chain_id != l1_config.chain_id || config.is_alt_da_enabled() {
        return Err(TransitionError::UnsupportedConfig);
    }
    let chain_id = config.l2_chain_id.into();
    let l1_chain_id = config.l1_chain_id;
    let witness = || Witness::parse_transition(input, Validation::Lazy).map_err(AnchorError::from);
    let mut l1 = AnchoredL1::new(witness()?, claim.anchor.number, claim.anchor.hash)?;
    let mut l2 = AnchoredL2::new(
        witness()?,
        claim.previous_number,
        claim.previous_root,
        config.clone(),
    )?;
    l2.bind_l1_history(l1.clone());
    let safe = l2.l2_block_info_by_number(claim.previous_number).await?;
    let next_timestamp = safe
        .block_info
        .timestamp
        .checked_add(config.block_time)
        .ok_or(AnchorError::Ancestry)?;
    if config.is_interop_active(next_timestamp) {
        return Err(TransitionError::UnsupportedConfig);
    }
    let origin = l1.block_info_by_number(safe.l1_origin.number).await?;
    if origin.hash != safe.l1_origin.hash
        || l1
            .block_info_by_number(claim.next_origin.number)
            .await?
            .hash
            != claim.next_origin.hash
    {
        return Err(TransitionError::Origin);
    }

    let l1 = l1.for_derivation(&config);
    let data = EthereumDataSource::new_from_parts(l1.clone(), blobs, &config);
    let attributes =
        StatefulAttributesBuilder::new(config.clone(), l1_config, l2.clone(), l1.clone(), None);
    let mut pipeline = PipelineBuilder::new()
        .rollup_config(config)
        .origin(origin)
        .dap_source(data)
        .l2_chain_provider(l2.clone())
        .chain_provider(l1)
        .builder(attributes)
        .build_polled();
    pipeline
        .signal(Signal::Reset(ResetSignal { l2_safe_head: safe }))
        .await?;
    for _ in 0..MAX_PIPELINE_STEPS {
        match pipeline.step(safe).await {
            StepResult::PreparedAttributes => {
                let prepared = pipeline.next().ok_or(TransitionError::MissingAttributes)?;
                let (next, payload_commitment) = l2.execute_prepared_with_commitment(
                    prepared,
                    claim.next_number,
                    claim.next_root,
                )?;
                if next.l1_origin != claim.next_origin {
                    return Err(TransitionError::Origin);
                }
                let block_hash = next.block_info.hash;
                return Ok(VerifiedTransition {
                    block: next,
                    statement: TransitionStatement {
                        chain_id,
                        l1_chain_id,
                        claim,
                        payload_commitment,
                        block_hash,
                    },
                });
            }
            StepResult::AdvancedOrigin
            | StepResult::StepFailed(PipelineErrorKind::Temporary(_))
            | StepResult::OriginAdvanceErr(PipelineErrorKind::Temporary(_)) => {}
            StepResult::StepFailed(PipelineErrorKind::Reset(ResetError::HoloceneActivation))
            | StepResult::OriginAdvanceErr(PipelineErrorKind::Reset(
                ResetError::HoloceneActivation,
            )) => {
                pipeline
                    .signal(Signal::Activation(ActivationSignal { l2_safe_head: safe }))
                    .await?;
            }
            StepResult::StepFailed(error) | StepResult::OriginAdvanceErr(error) => {
                return Err(error.into());
            }
        }
    }
    Err(TransitionError::StepBudget)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_outputs_match_the_independent_receiver_vector() {
        let statement = TransitionStatement {
            chain_id: 10,
            l1_chain_id: 1,
            claim: Transition {
                anchor: BlockNumHash {
                    number: 100,
                    hash: [0xa1; 32].into(),
                },
                previous_number: 200,
                previous_root: [0xb2; 32].into(),
                next_number: 201,
                next_root: [0xc3; 32].into(),
                next_origin: BlockNumHash {
                    number: 99,
                    hash: [0xd4; 32].into(),
                },
            },
            payload_commitment: [0xe5; 32],
            block_hash: [0xf6; 32].into(),
        };
        assert_eq!(
            statement.public_output(),
            alloy_primitives::hex!(
                "79dc71b2ef04d3b09ab72857909758cc2d94b77d82907b8568d187e7b529ba72010a000000000000004f44"
            )
        );
        assert_eq!(
            statement.execution_output(),
            alloy_primitives::hex!(
                "a1070315845855c79cb5c43f2782fa954672205424a5b42a47d1962a0ca2a9ca010a000000000000004f50"
            )
        );
    }
}
