//! Role-bound compiler authority for the direct-retained Interaction commit.
//!
//! Interaction uses the same exact CUDA ABI, effects, invocations, and execution
//! manifest as Base. This authority therefore seals the canonical Base compiler
//! result instead of copying that compiler, while binding a distinct tree role
//! into every outer source, program, and static-link identity.

use super::prepared_decommit::TraceTreeRole;
use super::prepared_progressive_commit::{
    BaseCommitAuthorityError, BaseCommitLayout, BaseCommitLinkedAuthority, BaseCommitOperation,
    BaseCommitProgramAuthority, BaseCommitRetainedEvaluation, BaseCommitRetainedLayer,
    BaseCommitValueRole, CommitProgram, DirectRetainedB2nProgram,
};

const SOURCE_DOMAIN: &[u8] = b"stwo-cuda-interaction-commit-source-v1\0";
const PROGRAM_DOMAIN: &[u8] = b"stwo-cuda-interaction-commit-program-v1\0";
const LINKED_DOMAIN: &[u8] = b"stwo-cuda-interaction-commit-linked-v1\0";
const AUTHORITY_SOURCE: &[u8] = include_bytes!("prepared_interaction_commit_authority.rs");

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InteractionCommitProgramAuthority {
    role: TraceTreeRole,
    direct: DirectRetainedB2nProgram,
    canonical: BaseCommitProgramAuthority,
    source_identity: [u8; 32],
    identity: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InteractionCommitLinkedAuthority {
    role: TraceTreeRole,
    program_identity: [u8; 32],
    canonical: BaseCommitLinkedAuthority,
    identity: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InteractionCommitAuthorityError {
    UnsupportedRole(TraceTreeRole),
    ProgramMismatch,
    Canonical(BaseCommitAuthorityError),
}

impl core::fmt::Display for InteractionCommitAuthorityError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "invalid direct Interaction commit authority: {self:?}"
        )
    }
}

impl std::error::Error for InteractionCommitAuthorityError {}

impl From<BaseCommitAuthorityError> for InteractionCommitAuthorityError {
    fn from(error: BaseCommitAuthorityError) -> Self {
        Self::Canonical(error)
    }
}

impl InteractionCommitProgramAuthority {
    pub fn compile(
        commit: &CommitProgram,
        direct: &DirectRetainedB2nProgram,
    ) -> Result<Self, InteractionCommitAuthorityError> {
        Self::compile_for_role(TraceTreeRole::Interaction, commit, direct)
    }

    fn compile_for_role(
        role: TraceTreeRole,
        commit: &CommitProgram,
        direct: &DirectRetainedB2nProgram,
    ) -> Result<Self, InteractionCommitAuthorityError> {
        if role != TraceTreeRole::Interaction {
            return Err(InteractionCommitAuthorityError::UnsupportedRole(role));
        }
        if direct.role() != role {
            return Err(InteractionCommitAuthorityError::UnsupportedRole(
                direct.role(),
            ));
        }
        let expected_direct = DirectRetainedB2nProgram::compile(role, commit)
            .map_err(|_| InteractionCommitAuthorityError::ProgramMismatch)?;
        if expected_direct != *direct {
            return Err(InteractionCommitAuthorityError::ProgramMismatch);
        }

        let canonical_direct = DirectRetainedB2nProgram::compile(TraceTreeRole::Base, commit)
            .map_err(|_| InteractionCommitAuthorityError::ProgramMismatch)?;
        let canonical = BaseCommitProgramAuthority::compile(commit, &canonical_direct)?;
        let source_identity = source_identity(role, direct, &canonical)?;
        let identity = program_identity(role, direct, &canonical, source_identity)?;
        Ok(Self {
            role,
            direct: direct.clone(),
            canonical,
            source_identity,
            identity,
        })
    }

    pub fn validate(&self) -> Result<(), InteractionCommitAuthorityError> {
        (Self::compile_for_role(self.role, self.commit(), &self.direct)? == *self)
            .then_some(())
            .ok_or(InteractionCommitAuthorityError::ProgramMismatch)
    }

    pub fn bind_static_build(
        &self,
        target_sm: u32,
    ) -> Result<Option<InteractionCommitLinkedAuthority>, InteractionCommitAuthorityError> {
        self.validate()?;
        self.canonical
            .bind_static_build(target_sm)?
            .map(|canonical| {
                let identity = linked_identity(self.role, self.identity, canonical)?;
                Ok(InteractionCommitLinkedAuthority {
                    role: self.role,
                    program_identity: self.identity,
                    canonical,
                    identity,
                })
            })
            .transpose()
    }

    pub const fn role(&self) -> TraceTreeRole {
        self.role
    }
    pub const fn commit(&self) -> &CommitProgram {
        self.canonical.commit()
    }
    pub const fn direct(&self) -> &DirectRetainedB2nProgram {
        &self.direct
    }
    pub fn layouts(&self) -> &[BaseCommitLayout] {
        self.canonical.layouts()
    }
    pub fn operations(&self) -> &[BaseCommitOperation] {
        self.canonical.operations()
    }
    pub fn retained_evaluations(&self) -> &[BaseCommitRetainedEvaluation] {
        self.canonical.retained_evaluations()
    }
    pub fn retained_layers_bottom_up(&self) -> &[BaseCommitRetainedLayer] {
        self.canonical.retained_layers_bottom_up()
    }
    pub const fn root(&self) -> BaseCommitValueRole {
        self.canonical.root()
    }
    pub const fn source_identity(&self) -> [u8; 32] {
        self.source_identity
    }
    pub const fn identity(&self) -> [u8; 32] {
        self.identity
    }
    pub const fn canonical(&self) -> &BaseCommitProgramAuthority {
        &self.canonical
    }
}

impl InteractionCommitLinkedAuthority {
    pub fn validate(
        &self,
        program: &InteractionCommitProgramAuthority,
    ) -> Result<(), InteractionCommitAuthorityError> {
        let expected = program.bind_static_build(self.target_sm())?.ok_or(
            InteractionCommitAuthorityError::Canonical(
                BaseCommitAuthorityError::StaticBuildUnavailable,
            ),
        )?;
        (*self == expected)
            .then_some(())
            .ok_or(InteractionCommitAuthorityError::Canonical(
                BaseCommitAuthorityError::StaticBuildMismatch,
            ))
    }

    pub const fn role(&self) -> TraceTreeRole {
        self.role
    }
    pub const fn program_identity(&self) -> [u8; 32] {
        self.program_identity
    }
    pub const fn canonical(&self) -> BaseCommitLinkedAuthority {
        self.canonical
    }
    pub const fn module_build_identity(&self) -> [u8; 32] {
        self.canonical.module_build_identity()
    }
    pub const fn static_build_source_identity(&self) -> [u8; 32] {
        self.canonical.static_build_source_identity()
    }
    pub const fn static_build_identity(&self) -> [u8; 32] {
        self.canonical.static_build_identity()
    }
    pub const fn target_sm(&self) -> u32 {
        self.canonical.target_sm()
    }
    pub const fn sm_identity(&self) -> [u8; 32] {
        self.canonical.sm_identity()
    }
    pub const fn identity(&self) -> [u8; 32] {
        self.identity
    }
}

fn source_identity(
    role: TraceTreeRole,
    direct: &DirectRetainedB2nProgram,
    canonical: &BaseCommitProgramAuthority,
) -> Result<[u8; 32], InteractionCommitAuthorityError> {
    let source_len = u64::try_from(AUTHORITY_SOURCE.len())
        .map_err(|_| InteractionCommitAuthorityError::ProgramMismatch)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(SOURCE_DOMAIN);
    hash_role(&mut hasher, role)?;
    hasher.update(&canonical.source_identity());
    hasher.update(&source_len.to_le_bytes());
    hasher.update(AUTHORITY_SOURCE);
    hasher.update(&direct.commit_cache_key().to_le_bytes());
    Ok(*hasher.finalize().as_bytes())
}

fn program_identity(
    role: TraceTreeRole,
    direct: &DirectRetainedB2nProgram,
    canonical: &BaseCommitProgramAuthority,
    source_identity: [u8; 32],
) -> Result<[u8; 32], InteractionCommitAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROGRAM_DOMAIN);
    hash_role(&mut hasher, role)?;
    hasher.update(&canonical.commit().identity().cache_key.to_le_bytes());
    hasher.update(&direct.commit_cache_key().to_le_bytes());
    hasher.update(&source_identity);
    hasher.update(&canonical.identity());
    Ok(*hasher.finalize().as_bytes())
}

fn linked_identity(
    role: TraceTreeRole,
    program_identity: [u8; 32],
    canonical: BaseCommitLinkedAuthority,
) -> Result<[u8; 32], InteractionCommitAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LINKED_DOMAIN);
    hash_role(&mut hasher, role)?;
    hasher.update(&program_identity);
    hasher.update(&canonical.identity());
    Ok(*hasher.finalize().as_bytes())
}

fn hash_role(
    hasher: &mut blake3::Hasher,
    role: TraceTreeRole,
) -> Result<(), InteractionCommitAuthorityError> {
    let tag = match role {
        // Stable authority wire tag. It is intentionally independent of the
        // Rust enum representation and may never be reordered implicitly.
        TraceTreeRole::Interaction => 2,
        _ => return Err(InteractionCommitAuthorityError::UnsupportedRole(role)),
    };
    hasher.update(&[tag]);
    Ok(())
}

#[cfg(test)]
#[path = "prepared_interaction_commit_authority_tests.rs"]
mod tests;
