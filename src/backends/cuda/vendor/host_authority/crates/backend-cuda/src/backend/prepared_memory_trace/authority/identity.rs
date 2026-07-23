//! Canonical identities for the memory Base-trace contract and linked build.

use super::*;
use crate::backend::prepared_witness_input::static_build::StaticBuildBinding;

pub(super) fn hash_requirements(
    requirements: &MemoryBaseTraceRequirements,
) -> Result<[u8; 32], MemoryBaseTraceAuthorityError> {
    let mut out = Vec::new();
    for value in [
        requirements.n_addrs,
        requirements.raw_address_words,
        requirements.address_rows,
        requirements.address_count_words,
        requirements.big_source_words,
        requirements.big_count_words,
        requirements.small_source_words,
        requirements.small_count_words,
        requirements.rc99_lut_words,
        requirements.rc99_count_words,
    ] {
        push_size(&mut out, value)?;
    }
    push_size(&mut out, requirements.big_parts.len())?;
    for part in requirements
        .big_parts
        .iter()
        .chain([&requirements.small_part])
    {
        out.extend_from_slice(&part.part_ordinal.to_le_bytes());
        push_size(&mut out, part.source_offset)?;
        push_size(&mut out, part.row_count)?;
    }
    Ok(digest(REQUIREMENTS_DOMAIN, &out))
}

pub(super) fn hash_abi(abi: MemoryBaseTraceAbi) -> [u8; 32] {
    let mut out = vec![abi as u8];
    for argument in abi.arguments() {
        out.push(argument.ordinal);
        out.push(argument.kind as u8);
        out.push(argument.access as u8);
        out.extend_from_slice(argument.name.as_bytes());
        out.push(0);
    }
    digest(ABI_DOMAIN, &out)
}

pub(super) fn hash_effect(
    reads: &[MemoryBaseTraceEffectAccess],
    writes: &[MemoryBaseTraceEffectAccess],
    atomic: Option<MemoryBaseTraceEffectAccess>,
) -> Result<[u8; 32], MemoryBaseTraceAuthorityError> {
    let mut out = Vec::new();
    for (tag, values) in [(1u8, reads), (2, writes)] {
        push_size(&mut out, values.len())?;
        for value in values {
            out.push(tag);
            encode_access(&mut out, *value)?;
        }
    }
    out.push(u8::from(atomic.is_some()));
    if let Some(value) = atomic {
        encode_access(&mut out, value)?;
    }
    Ok(digest(EFFECT_DOMAIN, &out))
}

pub(super) fn hash_launch(
    abi: MemoryBaseTraceAbi,
    launch: MemoryBaseTraceKernelLaunch,
) -> [u8; 32] {
    let mut out = vec![abi as u8];
    out.extend_from_slice(abi.kernel_symbol().as_bytes());
    out.push(0);
    for value in launch.grid.into_iter().chain(launch.block) {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(&launch.dynamic_shared_bytes.to_le_bytes());
    out.push(u8::from(launch.cooperative));
    digest(LAUNCH_DOMAIN, &out)
}

pub(super) fn hash_step_order(
    steps: &[MemoryBaseTraceStepContract],
) -> Result<[u8; 32], MemoryBaseTraceAuthorityError> {
    let mut out = Vec::new();
    push_size(&mut out, steps.len())?;
    for step in steps {
        out.extend_from_slice(&step.identity);
    }
    Ok(digest(CONTRACT_DOMAIN, &out))
}

pub(super) fn linked(
    contract_identity: [u8; 32],
    binding: StaticBuildBinding,
) -> MemoryBaseTraceLinkedContract {
    let identity = digest_many(
        LINKED_DOMAIN,
        &[
            &contract_identity,
            &binding.module_build_identity,
            &binding.static_build_source_identity,
            &binding.sm_identity,
            &binding.identity,
        ],
    )
    .expect("fixed-size linked identity cannot overflow");
    MemoryBaseTraceLinkedContract {
        contract_identity,
        module_build_identity: binding.module_build_identity,
        static_build_source_identity: binding.static_build_source_identity,
        static_build_identity: binding.identity,
        target_sm: binding.target_sm,
        sm_identity: binding.sm_identity,
        identity,
    }
}

fn encode_access(
    out: &mut Vec<u8>,
    value: MemoryBaseTraceEffectAccess,
) -> Result<(), MemoryBaseTraceAuthorityError> {
    out.push(value.role as u8);
    out.extend_from_slice(&value.ordinal.to_le_bytes());
    push_size(out, value.start_words)?;
    push_size(out, value.len_words)
}

fn push_size(out: &mut Vec<u8>, value: usize) -> Result<(), MemoryBaseTraceAuthorityError> {
    out.extend_from_slice(
        &u64::try_from(value)
            .map_err(|_| MemoryBaseTraceAuthorityError::SizeOverflow)?
            .to_le_bytes(),
    );
    Ok(())
}

pub(super) fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

pub(super) fn digest_many(
    domain: &[u8],
    chunks: &[&[u8]],
) -> Result<[u8; 32], MemoryBaseTraceAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(
        &u64::try_from(chunks.len())
            .map_err(|_| MemoryBaseTraceAuthorityError::SizeOverflow)?
            .to_le_bytes(),
    );
    for chunk in chunks {
        hasher.update(
            &u64::try_from(chunk.len())
                .map_err(|_| MemoryBaseTraceAuthorityError::SizeOverflow)?
                .to_le_bytes(),
        );
        hasher.update(chunk);
    }
    Ok(*hasher.finalize().as_bytes())
}
