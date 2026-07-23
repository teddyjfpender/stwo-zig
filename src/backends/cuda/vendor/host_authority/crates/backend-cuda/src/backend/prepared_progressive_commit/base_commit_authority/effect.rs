//! Complete logical, installed-memory, and alias effects for Base commit calls.

use super::encoding::{hash_role, hash_size};
use super::*;

mod validation;

use validation::validate_effect;

const POINTER_WORDS: usize = core::mem::size_of::<usize>() / core::mem::size_of::<u32>();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BaseCommitAccessKind {
    Read,
    Write,
    ReadWrite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BaseCommitAccess {
    pub kind: BaseCommitAccessKind,
    pub role: BaseCommitValueRole,
    pub first_word: usize,
    pub word_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BaseCommitDependencyRole {
    BatchSourcePointerTable { batch_index: u32 },
    BatchRetainedPointerTable { batch_index: u32 },
    InverseTwiddles,
    ForwardTwiddles,
    InPlaceScratch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BaseCommitDependencyRange {
    Whole { words: usize },
    Suffix { words: usize },
    Slice { first_word: usize, words: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BaseCommitInstalledAccess {
    pub kind: BaseCommitAccessKind,
    pub role: BaseCommitDependencyRole,
    pub range: BaseCommitDependencyRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BaseCommitAliasRequirement {
    Required,
    Optional,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BaseCommitAliasDiscipline {
    ExactLowerPrefixReadBeforeWrite,
    ElementWiseReadBeforeWrite,
    OrderedCompositeInPlace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BaseCommitAliasAuthority {
    pub source_access: u32,
    pub destination_access: u32,
    pub requirement: BaseCommitAliasRequirement,
    pub discipline: BaseCommitAliasDiscipline,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BaseCommitPointerTarget {
    Values {
        access_indices: Vec<u32>,
    },
    PointerTable {
        table: BaseCommitInstalledAccess,
        access_indices: Vec<u32>,
    },
    Installed {
        access: BaseCommitInstalledAccess,
    },
    ExecutionStream,
}

impl BaseCommitPointerTarget {
    fn access_indices(&self) -> &[u32] {
        match self {
            Self::Values { access_indices } | Self::PointerTable { access_indices, .. } => {
                access_indices
            }
            Self::Installed { .. } | Self::ExecutionStream => &[],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BaseCommitPointerBinding {
    pub argument_ordinal: u8,
    pub target: BaseCommitPointerTarget,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BaseCommitEffect {
    pub accesses: Vec<BaseCommitAccess>,
    pub aliases: Vec<BaseCommitAliasAuthority>,
    pub pointer_bindings: Vec<BaseCommitPointerBinding>,
    pub identity: [u8; 32],
}

impl BaseCommitEffect {
    pub fn validate_for_abi(&self, abi: BaseCommitAbi) -> Result<(), BaseCommitAuthorityError> {
        validate_effect(abi, self)?;
        (effect_identity(&self.accesses, &self.aliases, &self.pointer_bindings) == self.identity)
            .then_some(())
            .ok_or(BaseCommitAuthorityError::InvalidEffect)
    }
}

pub(super) fn direct_b2n_effect(
    batch_index: u32,
    segment_offset: u32,
    canonical: &[u32],
    source_log: u32,
    retained_log: u32,
) -> Result<BaseCommitEffect, BaseCommitAuthorityError> {
    let mut builder = EffectBuilder::new(BaseCommitAbi::DirectB2nV1);
    let mut reads = Vec::with_capacity(canonical.len());
    let mut writes = Vec::with_capacity(canonical.len());
    for &canonical_column in canonical {
        let source = builder.read(
            BaseCommitValueRole::SourceEvaluation { canonical_column },
            words(source_log)?,
        )?;
        let destination = builder.write(
            BaseCommitValueRole::RetainedStageTwo { canonical_column },
            words(retained_log)?,
        )?;
        builder.alias(
            source,
            destination,
            BaseCommitAliasRequirement::Optional,
            BaseCommitAliasDiscipline::ExactLowerPrefixReadBeforeWrite,
        );
        reads.push(source);
        writes.push(destination);
    }
    let table_range = pointer_table_range(segment_offset, canonical.len())?;
    builder.pointer_table(
        0,
        BaseCommitDependencyRole::BatchSourcePointerTable { batch_index },
        table_range,
        reads,
    );
    builder.pointer_table(
        1,
        BaseCommitDependencyRole::BatchRetainedPointerTable { batch_index },
        table_range,
        writes,
    );
    builder.installed(
        4,
        BaseCommitInstalledAccess {
            kind: BaseCommitAccessKind::Read,
            role: BaseCommitDependencyRole::InverseTwiddles,
            range: BaseCommitDependencyRange::Suffix {
                words: transform_twiddle_words(source_log)?,
            },
        },
    );
    builder.stream(7);
    builder.finish()
}

pub(super) fn direct_n2b_effect(
    batch_index: u32,
    segment_offset: u32,
    canonical: &[u32],
    retained_log: u32,
) -> Result<BaseCommitEffect, BaseCommitAuthorityError> {
    let mut builder = EffectBuilder::new(BaseCommitAbi::DirectN2bV1);
    let mut values = Vec::with_capacity(canonical.len() * 2);
    for &canonical_column in canonical {
        let source = builder.read(
            BaseCommitValueRole::RetainedStageTwo { canonical_column },
            words(retained_log)?,
        )?;
        let destination = builder.write(
            BaseCommitValueRole::RetainedEvaluation { canonical_column },
            words(retained_log)?,
        )?;
        builder.alias(
            source,
            destination,
            BaseCommitAliasRequirement::Required,
            BaseCommitAliasDiscipline::OrderedCompositeInPlace,
        );
        values.extend([source, destination]);
    }
    builder.pointer_table(
        0,
        BaseCommitDependencyRole::BatchRetainedPointerTable { batch_index },
        pointer_table_range(segment_offset, canonical.len())?,
        values,
    );
    builder.installed(
        3,
        BaseCommitInstalledAccess {
            kind: BaseCommitAccessKind::Read,
            role: BaseCommitDependencyRole::ForwardTwiddles,
            range: BaseCommitDependencyRange::Suffix {
                words: transform_twiddle_words(retained_log)?,
            },
        },
    );
    builder.stream(6);
    builder.finish()
}

pub(super) fn state_init_effect(
    log_size: u32,
    destination: BaseCommitValueRole,
) -> Result<BaseCommitEffect, BaseCommitAuthorityError> {
    let mut builder = EffectBuilder::new(BaseCommitAbi::StateInitV1);
    let destination = builder.write(destination, state_words(log_size)?)?;
    builder.values(1, vec![destination]);
    builder.stream(2);
    builder.finish()
}

pub(super) fn state_absorb_effect(
    batch_index: u32,
    segment_offset: u32,
    log_size: u32,
    source: BaseCommitValueRole,
    destination: BaseCommitValueRole,
    canonical: &[u32],
) -> Result<BaseCommitEffect, BaseCommitAuthorityError> {
    let mut builder = EffectBuilder::new(BaseCommitAbi::StateAbsorbV1);
    let state_read = builder.read(source, state_words(log_size)?)?;
    let mut evaluation_reads = Vec::with_capacity(canonical.len());
    for &canonical_column in canonical {
        evaluation_reads.push(builder.read(
            BaseCommitValueRole::RetainedEvaluation { canonical_column },
            words(log_size)?,
        )?);
    }
    let state_write = builder.write(destination, state_words(log_size)?)?;
    builder.alias(
        state_read,
        state_write,
        BaseCommitAliasRequirement::Required,
        BaseCommitAliasDiscipline::ElementWiseReadBeforeWrite,
    );
    builder.pointer_table(
        3,
        BaseCommitDependencyRole::BatchRetainedPointerTable { batch_index },
        pointer_table_range(segment_offset, canonical.len())?,
        evaluation_reads,
    );
    builder.values(4, vec![state_read, state_write]);
    builder.stream(5);
    builder.finish()
}

pub(super) fn state_expand_effect(
    from_log_size: u32,
    to_log_size: u32,
    source: BaseCommitValueRole,
    destination: BaseCommitValueRole,
) -> Result<BaseCommitEffect, BaseCommitAuthorityError> {
    let mut builder = EffectBuilder::new(BaseCommitAbi::StateExpandInPlaceV1);
    let source = builder.read(source, state_words(from_log_size)?)?;
    let destination = builder.write(destination, state_words(to_log_size)?)?;
    builder.alias(
        source,
        destination,
        BaseCommitAliasRequirement::Required,
        BaseCommitAliasDiscipline::OrderedCompositeInPlace,
    );
    builder.values(2, vec![source, destination]);
    builder.installed(3, scratch_access(2 * STATE_WORDS)?);
    builder.stream(4);
    builder.finish()
}

pub(super) fn state_finalize_effect(
    log_size: u32,
    source: BaseCommitValueRole,
    destination: BaseCommitValueRole,
) -> Result<BaseCommitEffect, BaseCommitAuthorityError> {
    let mut builder = EffectBuilder::new(BaseCommitAbi::StateFinalizeInPlaceV1);
    let source = builder.read(source, state_words(log_size)?)?;
    let destination = builder.write(destination, hash_words(log_size)?)?;
    builder.alias(
        source,
        destination,
        BaseCommitAliasRequirement::Required,
        BaseCommitAliasDiscipline::OrderedCompositeInPlace,
    );
    builder.values(2, vec![source, destination]);
    builder.installed(3, scratch_access(STATE_WORDS)?);
    builder.stream(4);
    builder.finish()
}

pub(super) fn merkle_in_place_effect(
    source: BaseCommitValueRole,
    destination: BaseCommitValueRole,
) -> Result<BaseCommitEffect, BaseCommitAuthorityError> {
    let mut builder = EffectBuilder::new(BaseCommitAbi::MerkleLayerInPlaceV1);
    let source = builder.read(source, hash_role_words(source)?)?;
    let destination = builder.write(destination, hash_role_words(destination)?)?;
    builder.alias(
        source,
        destination,
        BaseCommitAliasRequirement::Required,
        BaseCommitAliasDiscipline::OrderedCompositeInPlace,
    );
    builder.values(1, vec![source, destination]);
    builder.installed(2, scratch_access(2 * HASH_WORDS)?);
    builder.stream(3);
    builder.finish()
}

pub(super) fn merkle_effect(
    source: BaseCommitValueRole,
    destination: BaseCommitValueRole,
) -> Result<BaseCommitEffect, BaseCommitAuthorityError> {
    let mut builder = EffectBuilder::new(BaseCommitAbi::MerkleLayerV1);
    let source = builder.read(source, hash_role_words(source)?)?;
    let destination = builder.write(destination, hash_role_words(destination)?)?;
    builder.values(0, vec![source]);
    builder.values(2, vec![destination]);
    builder.stream(3);
    builder.finish()
}

struct EffectBuilder {
    abi: BaseCommitAbi,
    accesses: Vec<BaseCommitAccess>,
    aliases: Vec<BaseCommitAliasAuthority>,
    pointer_bindings: Vec<BaseCommitPointerBinding>,
}

impl EffectBuilder {
    fn new(abi: BaseCommitAbi) -> Self {
        Self {
            abi,
            accesses: Vec::new(),
            aliases: Vec::new(),
            pointer_bindings: Vec::new(),
        }
    }

    fn read(
        &mut self,
        role: BaseCommitValueRole,
        word_len: usize,
    ) -> Result<u32, BaseCommitAuthorityError> {
        self.access(BaseCommitAccessKind::Read, role, word_len)
    }

    fn write(
        &mut self,
        role: BaseCommitValueRole,
        word_len: usize,
    ) -> Result<u32, BaseCommitAuthorityError> {
        self.access(BaseCommitAccessKind::Write, role, word_len)
    }

    fn access(
        &mut self,
        kind: BaseCommitAccessKind,
        role: BaseCommitValueRole,
        word_len: usize,
    ) -> Result<u32, BaseCommitAuthorityError> {
        if word_len == 0 {
            return Err(BaseCommitAuthorityError::InvalidEffect);
        }
        let index = u32::try_from(self.accesses.len())
            .map_err(|_| BaseCommitAuthorityError::SizeOverflow)?;
        self.accesses.push(BaseCommitAccess {
            kind,
            role,
            first_word: 0,
            word_len,
        });
        Ok(index)
    }

    fn alias(
        &mut self,
        source_access: u32,
        destination_access: u32,
        requirement: BaseCommitAliasRequirement,
        discipline: BaseCommitAliasDiscipline,
    ) {
        self.aliases.push(BaseCommitAliasAuthority {
            source_access,
            destination_access,
            requirement,
            discipline,
        });
    }

    fn values(&mut self, argument_ordinal: u8, access_indices: Vec<u32>) {
        self.pointer_bindings.push(BaseCommitPointerBinding {
            argument_ordinal,
            target: BaseCommitPointerTarget::Values { access_indices },
        });
    }

    fn pointer_table(
        &mut self,
        argument_ordinal: u8,
        role: BaseCommitDependencyRole,
        range: BaseCommitDependencyRange,
        access_indices: Vec<u32>,
    ) {
        self.pointer_bindings.push(BaseCommitPointerBinding {
            argument_ordinal,
            target: BaseCommitPointerTarget::PointerTable {
                table: BaseCommitInstalledAccess {
                    kind: BaseCommitAccessKind::Read,
                    role,
                    range,
                },
                access_indices,
            },
        });
    }

    fn installed(&mut self, argument_ordinal: u8, access: BaseCommitInstalledAccess) {
        self.pointer_bindings.push(BaseCommitPointerBinding {
            argument_ordinal,
            target: BaseCommitPointerTarget::Installed { access },
        });
    }

    fn stream(&mut self, argument_ordinal: u8) {
        self.pointer_bindings.push(BaseCommitPointerBinding {
            argument_ordinal,
            target: BaseCommitPointerTarget::ExecutionStream,
        });
    }

    fn finish(self) -> Result<BaseCommitEffect, BaseCommitAuthorityError> {
        let identity = effect_identity(&self.accesses, &self.aliases, &self.pointer_bindings);
        let effect = BaseCommitEffect {
            accesses: self.accesses,
            aliases: self.aliases,
            pointer_bindings: self.pointer_bindings,
            identity,
        };
        effect.validate_for_abi(self.abi)?;
        Ok(effect)
    }
}

fn effect_identity(
    accesses: &[BaseCommitAccess],
    aliases: &[BaseCommitAliasAuthority],
    pointers: &[BaseCommitPointerBinding],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EFFECT_DOMAIN);
    hash_size(&mut hasher, accesses.len());
    for access in accesses {
        hasher.update(&[access_kind_tag(access.kind)]);
        hash_role(&mut hasher, access.role);
        hash_size(&mut hasher, access.first_word);
        hash_size(&mut hasher, access.word_len);
    }
    hash_size(&mut hasher, aliases.len());
    for alias in aliases {
        hasher.update(&alias.source_access.to_le_bytes());
        hasher.update(&alias.destination_access.to_le_bytes());
        hasher.update(&[
            match alias.requirement {
                BaseCommitAliasRequirement::Required => 1,
                BaseCommitAliasRequirement::Optional => 2,
            },
            match alias.discipline {
                BaseCommitAliasDiscipline::ExactLowerPrefixReadBeforeWrite => 1,
                BaseCommitAliasDiscipline::ElementWiseReadBeforeWrite => 2,
                BaseCommitAliasDiscipline::OrderedCompositeInPlace => 3,
            },
        ]);
    }
    hash_size(&mut hasher, pointers.len());
    for pointer in pointers {
        hasher.update(&[pointer.argument_ordinal]);
        match &pointer.target {
            BaseCommitPointerTarget::Values { access_indices } => {
                hasher.update(&[1]);
                hash_access_indices(&mut hasher, access_indices);
            }
            BaseCommitPointerTarget::PointerTable {
                table,
                access_indices,
            } => {
                hasher.update(&[2]);
                hash_installed_access(&mut hasher, *table);
                hash_access_indices(&mut hasher, access_indices);
            }
            BaseCommitPointerTarget::Installed { access } => {
                hasher.update(&[3]);
                hash_installed_access(&mut hasher, *access);
            }
            BaseCommitPointerTarget::ExecutionStream => {
                hasher.update(&[4]);
            }
        }
    }
    *hasher.finalize().as_bytes()
}

fn hash_installed_access(hasher: &mut blake3::Hasher, access: BaseCommitInstalledAccess) {
    hasher.update(&[access_kind_tag(access.kind)]);
    match access.role {
        BaseCommitDependencyRole::BatchSourcePointerTable { batch_index } => {
            hasher.update(&[1]);
            hasher.update(&batch_index.to_le_bytes());
        }
        BaseCommitDependencyRole::BatchRetainedPointerTable { batch_index } => {
            hasher.update(&[2]);
            hasher.update(&batch_index.to_le_bytes());
        }
        BaseCommitDependencyRole::InverseTwiddles => {
            hasher.update(&[3]);
        }
        BaseCommitDependencyRole::ForwardTwiddles => {
            hasher.update(&[4]);
        }
        BaseCommitDependencyRole::InPlaceScratch => {
            hasher.update(&[5]);
        }
    }
    match access.range {
        BaseCommitDependencyRange::Whole { words } => {
            hasher.update(&[1]);
            hash_size(hasher, words);
        }
        BaseCommitDependencyRange::Suffix { words } => {
            hasher.update(&[2]);
            hash_size(hasher, words);
        }
        BaseCommitDependencyRange::Slice { first_word, words } => {
            hasher.update(&[3]);
            hash_size(hasher, first_word);
            hash_size(hasher, words);
        }
    }
}

fn hash_access_indices(hasher: &mut blake3::Hasher, indices: &[u32]) {
    hash_size(hasher, indices.len());
    for index in indices {
        hasher.update(&index.to_le_bytes());
    }
}

const fn access_kind_tag(kind: BaseCommitAccessKind) -> u8 {
    match kind {
        BaseCommitAccessKind::Read => 1,
        BaseCommitAccessKind::Write => 2,
        BaseCommitAccessKind::ReadWrite => 3,
    }
}

fn scratch_access(words: usize) -> Result<BaseCommitInstalledAccess, BaseCommitAuthorityError> {
    if words == 0 {
        return Err(BaseCommitAuthorityError::InvalidEffect);
    }
    Ok(BaseCommitInstalledAccess {
        kind: BaseCommitAccessKind::ReadWrite,
        role: BaseCommitDependencyRole::InPlaceScratch,
        range: BaseCommitDependencyRange::Whole { words },
    })
}

fn pointer_words(columns: usize) -> Result<usize, BaseCommitAuthorityError> {
    columns
        .checked_mul(POINTER_WORDS)
        .filter(|&words| words != 0)
        .ok_or(BaseCommitAuthorityError::SizeOverflow)
}

fn pointer_table_range(
    segment_offset: u32,
    columns: usize,
) -> Result<BaseCommitDependencyRange, BaseCommitAuthorityError> {
    let first_word = usize::try_from(segment_offset)
        .ok()
        .and_then(|offset| offset.checked_mul(POINTER_WORDS))
        .ok_or(BaseCommitAuthorityError::SizeOverflow)?;
    Ok(BaseCommitDependencyRange::Slice {
        first_word,
        words: pointer_words(columns)?,
    })
}

fn transform_twiddle_words(log_size: u32) -> Result<usize, BaseCommitAuthorityError> {
    log_size
        .checked_sub(1)
        .and_then(|log_size| 1usize.checked_shl(log_size))
        .ok_or(BaseCommitAuthorityError::SizeOverflow)
}

fn words(log_size: u32) -> Result<usize, BaseCommitAuthorityError> {
    1usize
        .checked_shl(log_size)
        .ok_or(BaseCommitAuthorityError::SizeOverflow)
}

fn state_words(log_size: u32) -> Result<usize, BaseCommitAuthorityError> {
    words(log_size)?
        .checked_mul(STATE_WORDS)
        .ok_or(BaseCommitAuthorityError::SizeOverflow)
}

fn hash_words(log_size: u32) -> Result<usize, BaseCommitAuthorityError> {
    words(log_size)?
        .checked_mul(HASH_WORDS)
        .ok_or(BaseCommitAuthorityError::SizeOverflow)
}

fn hash_role_words(role: BaseCommitValueRole) -> Result<usize, BaseCommitAuthorityError> {
    match role {
        BaseCommitValueRole::HashLayer { log_size } => hash_words(log_size),
        _ => Err(BaseCommitAuthorityError::InvalidProgramOrder),
    }
}
