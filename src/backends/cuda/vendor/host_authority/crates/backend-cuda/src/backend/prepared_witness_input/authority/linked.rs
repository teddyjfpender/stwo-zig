//! Binding of one canonical gather contract to the authenticated static build.

use super::{WitnessInputGatherAuthorityError, WitnessInputGatherContract};
use crate::backend::prepared_witness_input::static_build::{
    bind_static_build, StaticBuildBindError, StaticBuildBinding,
};

pub(super) const STATIC_BUILD_DOMAIN: &[u8] = b"stwo-cuda-witness-input-gather-static-build-v1\0";
const LINKED_DOMAIN: &[u8] = b"stwo-cuda-witness-input-gather-linked-v1\0";

impl WitnessInputGatherContract {
    pub fn bind_static_build(
        &self,
        target_sm: u32,
    ) -> Result<Option<WitnessInputGatherLinkedContract>, WitnessInputGatherAuthorityError> {
        self.validate()?;
        bind_static_build(STATIC_BUILD_DOMAIN, self.identity(), target_sm)
            .map(|binding| binding.map(|binding| linked_contract(self.identity(), binding)))
            .map_err(Into::into)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessInputGatherLinkedContract {
    contract_identity: [u8; 32],
    module_build_identity: [u8; 32],
    static_build_source_identity: [u8; 32],
    static_build_identity: [u8; 32],
    target_sm: u32,
    sm_identity: [u8; 32],
    identity: [u8; 32],
}

impl WitnessInputGatherLinkedContract {
    pub fn validate(
        &self,
        contract: &WitnessInputGatherContract,
    ) -> Result<(), WitnessInputGatherAuthorityError> {
        let expected = contract
            .bind_static_build(self.target_sm)?
            .ok_or(WitnessInputGatherAuthorityError::StaticBuildUnavailable)?;
        if *self == expected {
            Ok(())
        } else {
            Err(WitnessInputGatherAuthorityError::StaticBuildMismatch)
        }
    }

    pub const fn contract_identity(&self) -> [u8; 32] {
        self.contract_identity
    }
    pub const fn module_build_identity(&self) -> [u8; 32] {
        self.module_build_identity
    }
    pub const fn static_build_source_identity(&self) -> [u8; 32] {
        self.static_build_source_identity
    }
    pub const fn static_build_identity(&self) -> [u8; 32] {
        self.static_build_identity
    }
    pub const fn target_sm(&self) -> u32 {
        self.target_sm
    }
    pub const fn sm_identity(&self) -> [u8; 32] {
        self.sm_identity
    }
    pub const fn identity(&self) -> [u8; 32] {
        self.identity
    }
}

pub(super) fn linked_contract(
    contract_identity: [u8; 32],
    binding: StaticBuildBinding,
) -> WitnessInputGatherLinkedContract {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LINKED_DOMAIN);
    hasher.update(&contract_identity);
    hasher.update(&binding.identity);
    hasher.update(&binding.module_build_identity);
    hasher.update(&binding.static_build_source_identity);
    hasher.update(&binding.target_sm.to_le_bytes());
    hasher.update(&binding.sm_identity);
    WitnessInputGatherLinkedContract {
        contract_identity,
        module_build_identity: binding.module_build_identity,
        static_build_source_identity: binding.static_build_source_identity,
        static_build_identity: binding.identity,
        target_sm: binding.target_sm,
        sm_identity: binding.sm_identity,
        identity: *hasher.finalize().as_bytes(),
    }
}

impl From<StaticBuildBindError> for WitnessInputGatherAuthorityError {
    fn from(error: StaticBuildBindError) -> Self {
        match error {
            StaticBuildBindError::UnsupportedTargetSm(sm) => Self::UnsupportedTargetSm(sm),
            StaticBuildBindError::BuildReceiptUnavailable => Self::StaticBuildUnavailable,
            StaticBuildBindError::InconsistentBuildMetadata
            | StaticBuildBindError::BuildReceiptMismatch => Self::StaticBuildMismatch,
        }
    }
}
