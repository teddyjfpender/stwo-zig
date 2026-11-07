//! One checkpoint transition through Kona's authenticated calldata pipeline.
use crate::{
    anchored_l1::{AnchorError, AnchoredL1},
    anchored_l2::AnchoredL2,
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
    if claim.previous_number.checked_add(1) != Some(claim.next_number) {
        return Err(AnchorError::Ancestry.into());
    }
    if config.l1_chain_id != l1_config.chain_id || config.is_alt_da_enabled() {
        return Err(TransitionError::UnsupportedConfig);
    }
    let witness = || Witness::parse(input, Validation::Lazy).map_err(AnchorError::from);
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

    let data = EthereumDataSource::new_from_parts(l1.clone(), RejectBlobs, &config);
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
                let next = l2.execute_prepared(prepared, claim.next_number, claim.next_root)?;
                if next.l1_origin != claim.next_origin {
                    return Err(TransitionError::Origin);
                }
                return Ok(next);
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
