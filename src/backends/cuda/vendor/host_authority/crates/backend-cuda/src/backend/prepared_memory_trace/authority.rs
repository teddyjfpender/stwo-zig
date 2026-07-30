//! Address-free authority for the ordered Cairo memory Base-trace graph.
//!
//! The prepared graph is a Rust composite, not one CUDA wrapper. This contract
//! therefore seals the real wrapper sequence and each wrapper's exact ABI,
//! effect geometry, and internal launch. It never invents a synthetic kernel.

use super::{
    readable_source_words, MEMORY_ADDRESS_BASE_COLUMNS, MEMORY_BIG_BASE_COLUMNS,
    MEMORY_SMALL_BASE_COLUMNS,
};
use crate::backend::prepared_execution_tables::{
    EXECUTION_TABLE_BIG_LIMBS, EXECUTION_TABLE_SMALL_LIMBS,
};
use crate::backend::prepared_witness_input::static_build::{
    bind_static_build, StaticBuildBindError,
};

mod abi;
mod identity;

pub use abi::{
    MemoryBaseTraceAbi, MemoryBaseTraceAbiAccess, MemoryBaseTraceAbiArgument,
    MemoryBaseTraceAbiArgumentKind,
};
use identity::*;

const BLOCK_THREADS: u32 = 256;
const RC99_TABLE_WORDS: usize = 1 << 18;
const RC99_RELATIONS: usize = 8;
const ZERO_IDENTITY: [u8; 32] = [0; 32];
const BINDER_SOURCE: &[u8] = include_bytes!("../prepared_memory_trace.rs");
const AUTHORITY_SOURCE: &[u8] = include_bytes!("authority.rs");
const ABI_SOURCE: &[u8] = include_bytes!("authority/abi.rs");
const IDENTITY_SOURCE: &[u8] = include_bytes!("authority/identity.rs");
const RAW_FFI_SOURCE: &[u8] = include_bytes!("../../../../backend-cuda-kernels/src/raw.rs");
const WRAPPER_SOURCE: &[u8] =
    include_bytes!("../../../../backend-cuda-kernels/cuda/memory_witness.cu");

const WRAPPER_SOURCE_DOMAIN: &[u8] = b"stwo-cuda-memory-base-wrapper-source-v2\0";
const SOURCE_DOMAIN: &[u8] = b"stwo-cuda-memory-base-source-v2\0";
const REQUIREMENTS_DOMAIN: &[u8] = b"stwo-cuda-memory-base-requirements-v2\0";
const ABI_DOMAIN: &[u8] = b"stwo-cuda-memory-base-abi-v2\0";
const EFFECT_DOMAIN: &[u8] = b"stwo-cuda-memory-base-effect-v2\0";
const LAUNCH_DOMAIN: &[u8] = b"stwo-cuda-memory-base-launch-v2\0";
const STEP_DOMAIN: &[u8] = b"stwo-cuda-memory-base-step-v2\0";
const CONTRACT_DOMAIN: &[u8] = b"stwo-cuda-memory-base-contract-v2\0";
const STATIC_BUILD_DOMAIN: &[u8] = b"stwo-cuda-memory-base-static-build-v2\0";
const LINKED_DOMAIN: &[u8] = b"stwo-cuda-memory-base-linked-v2\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryBaseTraceValuePartRequirements {
    /// Dense `MemoryBig` ordinal. Small uses its dedicated field below.
    pub part_ordinal: u32,
    pub source_offset: usize,
    pub row_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryBaseTraceRequirements {
    pub n_addrs: usize,
    pub raw_address_words: usize,
    pub address_rows: usize,
    pub address_count_words: usize,
    pub big_source_words: usize,
    pub big_count_words: usize,
    pub big_parts: Vec<MemoryBaseTraceValuePartRequirements>,
    pub small_source_words: usize,
    pub small_count_words: usize,
    pub small_part: MemoryBaseTraceValuePartRequirements,
    pub rc99_lut_words: usize,
    pub rc99_count_words: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MemoryBaseTraceStepKind {
    Address = 1,
    BigValue = 2,
    BigRc99 = 3,
    SmallValue = 4,
    SmallRc99 = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MemoryBaseTraceEffectRole {
    AddressTable = 1,
    AddressMultiplicity = 2,
    ValueSource = 3,
    ValueMultiplicity = 4,
    BaseOutput = 5,
    Rc99Limb = 6,
    Rc99Lut = 7,
    Rc99Counts = 8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryBaseTraceEffectAccess {
    pub role: MemoryBaseTraceEffectRole,
    pub ordinal: u32,
    pub start_words: usize,
    pub len_words: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryBaseTraceKernelLaunch {
    pub grid: [u32; 3],
    pub block: [u32; 3],
    pub dynamic_shared_bytes: u32,
    pub cooperative: bool,
    pub cluster: Option<[u32; 3]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryBaseTraceStepContract {
    kind: MemoryBaseTraceStepKind,
    part_ordinal: Option<u32>,
    abi: MemoryBaseTraceAbi,
    row_count: u32,
    source_offset: u32,
    source_words: u32,
    multiplicity_words: u32,
    limb_or_pair_count: u32,
    reads: Vec<MemoryBaseTraceEffectAccess>,
    writes: Vec<MemoryBaseTraceEffectAccess>,
    atomic: Option<MemoryBaseTraceEffectAccess>,
    launch: MemoryBaseTraceKernelLaunch,
    abi_identity: [u8; 32],
    effect_identity: [u8; 32],
    launch_identity: [u8; 32],
    identity: [u8; 32],
}

impl MemoryBaseTraceStepContract {
    pub const fn kind(&self) -> MemoryBaseTraceStepKind {
        self.kind
    }
    pub const fn part_ordinal(&self) -> Option<u32> {
        self.part_ordinal
    }
    pub const fn abi(&self) -> MemoryBaseTraceAbi {
        self.abi
    }
    pub const fn row_count(&self) -> u32 {
        self.row_count
    }
    pub const fn source_offset(&self) -> u32 {
        self.source_offset
    }
    pub const fn source_words(&self) -> u32 {
        self.source_words
    }
    pub const fn multiplicity_words(&self) -> u32 {
        self.multiplicity_words
    }
    pub const fn limb_or_pair_count(&self) -> u32 {
        self.limb_or_pair_count
    }
    pub fn reads(&self) -> &[MemoryBaseTraceEffectAccess] {
        &self.reads
    }
    pub fn writes(&self) -> &[MemoryBaseTraceEffectAccess] {
        &self.writes
    }
    pub const fn atomic(&self) -> Option<MemoryBaseTraceEffectAccess> {
        self.atomic
    }
    pub const fn launch(&self) -> MemoryBaseTraceKernelLaunch {
        self.launch
    }
    pub const fn abi_identity(&self) -> [u8; 32] {
        self.abi_identity
    }
    pub const fn effect_identity(&self) -> [u8; 32] {
        self.effect_identity
    }
    pub const fn launch_identity(&self) -> [u8; 32] {
        self.launch_identity
    }
    pub const fn identity(&self) -> [u8; 32] {
        self.identity
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryBaseTraceContract {
    requirements: MemoryBaseTraceRequirements,
    steps: Vec<MemoryBaseTraceStepContract>,
    static_source_identity: [u8; 32],
    wrapper_source_identity: [u8; 32],
    source_identity: [u8; 32],
    requirements_identity: [u8; 32],
    identity: [u8; 32],
}

impl MemoryBaseTraceContract {
    pub fn compile(
        requirements: &MemoryBaseTraceRequirements,
    ) -> Result<Self, MemoryBaseTraceAuthorityError> {
        validate_requirements(requirements)?;
        let steps = compile_steps(requirements)?;
        for step in &steps {
            for symbol in [step.abi().entry_symbol(), step.abi().kernel_symbol()] {
                if !contains_bytes(WRAPPER_SOURCE, symbol.as_bytes()) {
                    return Err(MemoryBaseTraceAuthorityError::MissingStaticSymbol(symbol));
                }
            }
            if !step.abi().source_declares_entry(WRAPPER_SOURCE) {
                return Err(MemoryBaseTraceAuthorityError::InvalidStaticAbi(
                    step.abi().entry_symbol(),
                ));
            }
        }
        let static_source_identity = stwo_backend_cuda_kernels::static_cuda_source_identity();
        let wrapper_source_identity = digest(WRAPPER_SOURCE_DOMAIN, WRAPPER_SOURCE);
        let source_identity = digest_many(
            SOURCE_DOMAIN,
            &[
                &static_source_identity,
                &wrapper_source_identity,
                BINDER_SOURCE,
                AUTHORITY_SOURCE,
                ABI_SOURCE,
                IDENTITY_SOURCE,
                RAW_FFI_SOURCE,
            ],
        )?;
        if [
            static_source_identity,
            wrapper_source_identity,
            source_identity,
        ]
        .contains(&ZERO_IDENTITY)
        {
            return Err(MemoryBaseTraceAuthorityError::MissingStaticSourceIdentity);
        }
        let requirements_identity = hash_requirements(requirements)?;
        let identity = digest_many(
            CONTRACT_DOMAIN,
            &[
                &source_identity,
                &requirements_identity,
                &hash_step_order(&steps)?,
            ],
        )?;
        Ok(Self {
            requirements: requirements.clone(),
            steps,
            static_source_identity,
            wrapper_source_identity,
            source_identity,
            requirements_identity,
            identity,
        })
    }

    pub fn validate(&self) -> Result<(), MemoryBaseTraceAuthorityError> {
        (Self::compile(&self.requirements)? == *self)
            .then_some(())
            .ok_or(MemoryBaseTraceAuthorityError::InvalidCanonicalRequirements)
    }

    pub fn bind_static_build(
        &self,
        target_sm: u32,
    ) -> Result<Option<MemoryBaseTraceLinkedContract>, MemoryBaseTraceAuthorityError> {
        self.validate()?;
        bind_static_build(STATIC_BUILD_DOMAIN, self.identity, target_sm)
            .map(|binding| binding.map(|binding| linked(self.identity, binding)))
            .map_err(Into::into)
    }

    pub const fn requirements(&self) -> &MemoryBaseTraceRequirements {
        &self.requirements
    }
    pub fn steps(&self) -> &[MemoryBaseTraceStepContract] {
        &self.steps
    }
    pub const fn static_source_identity(&self) -> [u8; 32] {
        self.static_source_identity
    }
    pub const fn wrapper_source_identity(&self) -> [u8; 32] {
        self.wrapper_source_identity
    }
    pub const fn source_identity(&self) -> [u8; 32] {
        self.source_identity
    }
    pub const fn requirements_identity(&self) -> [u8; 32] {
        self.requirements_identity
    }
    pub const fn identity(&self) -> [u8; 32] {
        self.identity
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryBaseTraceLinkedContract {
    contract_identity: [u8; 32],
    module_build_identity: [u8; 32],
    static_build_source_identity: [u8; 32],
    static_build_identity: [u8; 32],
    target_sm: u32,
    sm_identity: [u8; 32],
    identity: [u8; 32],
}

impl MemoryBaseTraceLinkedContract {
    pub fn validate(
        &self,
        contract: &MemoryBaseTraceContract,
    ) -> Result<(), MemoryBaseTraceAuthorityError> {
        let expected = contract
            .bind_static_build(self.target_sm)?
            .ok_or(MemoryBaseTraceAuthorityError::StaticBuildUnavailable)?;
        (*self == expected)
            .then_some(())
            .ok_or(MemoryBaseTraceAuthorityError::StaticBuildMismatch)
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemoryBaseTraceAuthorityError {
    MissingStaticSourceIdentity,
    MissingStaticSymbol(&'static str),
    InvalidStaticAbi(&'static str),
    InvalidCanonicalRequirements,
    SizeOverflow,
    StaticBuildUnavailable,
    StaticBuildMismatch,
    UnsupportedTargetSm(u32),
}

impl From<StaticBuildBindError> for MemoryBaseTraceAuthorityError {
    fn from(error: StaticBuildBindError) -> Self {
        match error {
            StaticBuildBindError::UnsupportedTargetSm(sm) => Self::UnsupportedTargetSm(sm),
            StaticBuildBindError::BuildReceiptUnavailable => Self::StaticBuildUnavailable,
            StaticBuildBindError::InconsistentBuildMetadata
            | StaticBuildBindError::BuildReceiptMismatch => Self::StaticBuildMismatch,
        }
    }
}

fn validate_requirements(
    r: &MemoryBaseTraceRequirements,
) -> Result<(), MemoryBaseTraceAuthorityError> {
    let address_words = r
        .address_rows
        .checked_mul(16)
        .ok_or(MemoryBaseTraceAuthorityError::SizeOverflow)?;
    let address_id_words = r.n_addrs.saturating_sub(1);
    let rc99_words = r
        .rc99_lut_words
        .checked_mul(RC99_RELATIONS)
        .ok_or(MemoryBaseTraceAuthorityError::SizeOverflow)?;
    let big_end = r.big_parts.iter().try_fold(0usize, |end, part| {
        let next = part
            .source_offset
            .checked_add(part.row_count)
            .ok_or(MemoryBaseTraceAuthorityError::SizeOverflow)?;
        Ok::<_, MemoryBaseTraceAuthorityError>(end.max(next))
    })?;
    let dense_big = r
        .big_parts
        .iter()
        .enumerate()
        .all(|(index, part)| part.part_ordinal as usize == index && part.row_count != 0);
    let small_end = r
        .small_part
        .source_offset
        .checked_add(r.small_part.row_count)
        .ok_or(MemoryBaseTraceAuthorityError::SizeOverflow)?;
    if r.n_addrs < 2
        || r.raw_address_words != r.n_addrs.max(1)
        || address_id_words > r.address_count_words
        || r.address_rows == 0
        || r.address_count_words != address_words
        || r.big_parts.is_empty()
        || !dense_big
        || big_end != r.big_count_words
        || r.small_part.part_ordinal != 0
        || r.small_part.source_offset != 0
        || r.small_part.row_count == 0
        || small_end != r.small_count_words
        || r.rc99_lut_words != RC99_TABLE_WORDS
        || r.rc99_count_words != rc99_words
    {
        return Err(MemoryBaseTraceAuthorityError::InvalidCanonicalRequirements);
    }
    for value in [
        r.n_addrs,
        r.address_rows,
        r.address_count_words,
        r.big_source_words,
        r.big_count_words,
        r.small_source_words,
        r.small_count_words,
        r.rc99_lut_words,
        r.rc99_count_words,
    ] {
        u32::try_from(value).map_err(|_| MemoryBaseTraceAuthorityError::SizeOverflow)?;
    }
    Ok(())
}

fn compile_steps(
    r: &MemoryBaseTraceRequirements,
) -> Result<Vec<MemoryBaseTraceStepContract>, MemoryBaseTraceAuthorityError> {
    let mut steps = Vec::with_capacity(3 + 2 * r.big_parts.len());
    steps.push(address_step(r)?);
    for part in &r.big_parts {
        steps.push(value_step(r, part, true)?);
        steps.push(rc99_step(r, part, true)?);
    }
    steps.push(value_step(r, &r.small_part, false)?);
    steps.push(rc99_step(r, &r.small_part, false)?);
    Ok(steps)
}

fn address_step(
    r: &MemoryBaseTraceRequirements,
) -> Result<MemoryBaseTraceStepContract, MemoryBaseTraceAuthorityError> {
    build_step(
        MemoryBaseTraceStepKind::Address,
        None,
        MemoryBaseTraceAbi::AddressSlicedV2,
        r.address_rows,
        1,
        r.n_addrs - 1,
        r.address_count_words,
        0,
        vec![
            access(MemoryBaseTraceEffectRole::AddressTable, 0, 1, r.n_addrs - 1),
            access(
                MemoryBaseTraceEffectRole::AddressMultiplicity,
                0,
                0,
                r.address_count_words,
            ),
        ],
        (0..MEMORY_ADDRESS_BASE_COLUMNS)
            .map(|ordinal| {
                access(
                    MemoryBaseTraceEffectRole::BaseOutput,
                    ordinal as u32,
                    0,
                    r.address_rows,
                )
            })
            .collect(),
        None,
    )
}

fn value_step(
    r: &MemoryBaseTraceRequirements,
    part: &MemoryBaseTraceValuePartRequirements,
    big: bool,
) -> Result<MemoryBaseTraceStepContract, MemoryBaseTraceAuthorityError> {
    let (kind, limbs, source_words, outputs, part_ordinal) = if big {
        (
            MemoryBaseTraceStepKind::BigValue,
            EXECUTION_TABLE_BIG_LIMBS,
            r.big_source_words,
            MEMORY_BIG_BASE_COLUMNS,
            Some(part.part_ordinal),
        )
    } else {
        (
            MemoryBaseTraceStepKind::SmallValue,
            EXECUTION_TABLE_SMALL_LIMBS,
            r.small_source_words,
            MEMORY_SMALL_BASE_COLUMNS,
            None,
        )
    };
    let source_read_words = readable_source_words(source_words, part.source_offset, part.row_count);
    let mut reads = if source_read_words == 0 {
        Vec::new()
    } else {
        (0..limbs)
            .map(|ordinal| {
                access(
                    MemoryBaseTraceEffectRole::ValueSource,
                    ordinal as u32,
                    part.source_offset,
                    source_read_words,
                )
            })
            .collect::<Vec<_>>()
    };
    reads.push(access(
        MemoryBaseTraceEffectRole::ValueMultiplicity,
        0,
        part.source_offset,
        part.row_count,
    ));
    build_step(
        kind,
        part_ordinal,
        MemoryBaseTraceAbi::ValueSlicedV2,
        part.row_count,
        part.source_offset,
        source_read_words,
        part.row_count,
        limbs,
        reads,
        (0..outputs)
            .map(|ordinal| {
                access(
                    MemoryBaseTraceEffectRole::BaseOutput,
                    ordinal as u32,
                    0,
                    part.row_count,
                )
            })
            .collect(),
        None,
    )
}

fn rc99_step(
    r: &MemoryBaseTraceRequirements,
    part: &MemoryBaseTraceValuePartRequirements,
    big: bool,
) -> Result<MemoryBaseTraceStepContract, MemoryBaseTraceAuthorityError> {
    let (kind, pairs, part_ordinal) = if big {
        (
            MemoryBaseTraceStepKind::BigRc99,
            EXECUTION_TABLE_BIG_LIMBS / 2,
            Some(part.part_ordinal),
        )
    } else {
        (
            MemoryBaseTraceStepKind::SmallRc99,
            EXECUTION_TABLE_SMALL_LIMBS / 2,
            None,
        )
    };
    let mut reads = (0..2 * pairs)
        .map(|ordinal| {
            access(
                MemoryBaseTraceEffectRole::Rc99Limb,
                ordinal as u32,
                0,
                part.row_count,
            )
        })
        .collect::<Vec<_>>();
    reads.push(access(
        MemoryBaseTraceEffectRole::Rc99Lut,
        0,
        0,
        r.rc99_lut_words,
    ));
    let atomic_relations = pairs.min(RC99_RELATIONS);
    build_step(
        kind,
        part_ordinal,
        MemoryBaseTraceAbi::Rc99V1,
        part.row_count,
        0,
        0,
        r.rc99_count_words,
        pairs,
        reads,
        Vec::new(),
        Some(access(
            MemoryBaseTraceEffectRole::Rc99Counts,
            0,
            0,
            atomic_relations * r.rc99_lut_words,
        )),
    )
}

#[allow(clippy::too_many_arguments)]
fn build_step(
    kind: MemoryBaseTraceStepKind,
    part_ordinal: Option<u32>,
    abi: MemoryBaseTraceAbi,
    row_count: usize,
    source_offset: usize,
    source_words: usize,
    multiplicity_words: usize,
    limb_or_pair_count: usize,
    reads: Vec<MemoryBaseTraceEffectAccess>,
    writes: Vec<MemoryBaseTraceEffectAccess>,
    atomic: Option<MemoryBaseTraceEffectAccess>,
) -> Result<MemoryBaseTraceStepContract, MemoryBaseTraceAuthorityError> {
    let row_count = u32_value(row_count)?;
    let source_offset = u32_value(source_offset)?;
    let source_words = u32_value(source_words)?;
    let multiplicity_words = u32_value(multiplicity_words)?;
    let limb_or_pair_count = u32_value(limb_or_pair_count)?;
    let launch = MemoryBaseTraceKernelLaunch {
        grid: [1 + (row_count - 1) / BLOCK_THREADS, 1, 1],
        block: [BLOCK_THREADS, 1, 1],
        dynamic_shared_bytes: 0,
        cooperative: false,
        cluster: None,
    };
    let abi_identity = hash_abi(abi);
    let effect_identity = hash_effect(&reads, &writes, atomic)?;
    let launch_identity = hash_launch(abi, launch);
    let mut canonical = Vec::new();
    canonical.push(kind as u8);
    canonical.extend_from_slice(&part_ordinal.unwrap_or(u32::MAX).to_le_bytes());
    canonical.extend_from_slice(&row_count.to_le_bytes());
    canonical.extend_from_slice(&source_offset.to_le_bytes());
    canonical.extend_from_slice(&source_words.to_le_bytes());
    canonical.extend_from_slice(&multiplicity_words.to_le_bytes());
    canonical.extend_from_slice(&limb_or_pair_count.to_le_bytes());
    canonical.extend_from_slice(&abi_identity);
    canonical.extend_from_slice(&effect_identity);
    canonical.extend_from_slice(&launch_identity);
    let identity = digest(STEP_DOMAIN, &canonical);
    Ok(MemoryBaseTraceStepContract {
        kind,
        part_ordinal,
        abi,
        row_count,
        source_offset,
        source_words,
        multiplicity_words,
        limb_or_pair_count,
        reads,
        writes,
        atomic,
        launch,
        abi_identity,
        effect_identity,
        launch_identity,
        identity,
    })
}

const fn access(
    role: MemoryBaseTraceEffectRole,
    ordinal: u32,
    start_words: usize,
    len_words: usize,
) -> MemoryBaseTraceEffectAccess {
    MemoryBaseTraceEffectAccess {
        role,
        ordinal,
        start_words,
        len_words,
    }
}

fn u32_value(value: usize) -> Result<u32, MemoryBaseTraceAuthorityError> {
    u32::try_from(value).map_err(|_| MemoryBaseTraceAuthorityError::SizeOverflow)
}

fn contains_bytes(source: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && source.windows(needle.len()).any(|window| window == needle)
}

#[cfg(test)]
mod tests;
