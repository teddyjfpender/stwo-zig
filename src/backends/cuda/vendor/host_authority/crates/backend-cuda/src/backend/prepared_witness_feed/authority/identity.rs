//! Canonical content, effect, launch and contract identities.

use super::*;

pub(super) fn requirements_identity(
    requirements: &WitnessFeedWorkspaceRequirements,
) -> Result<[u8; 32], WitnessFeedAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REQUIREMENTS_DOMAIN);
    for value in [
        requirements.row_count,
        requirements.sub_words_per_row,
        requirements.source_words,
        requirements.descriptor_words,
        requirements.descriptor_count,
        requirements.lut_pointer_words,
        requirements.multiplicity_pointer_words,
    ] {
        hash_size(&mut hasher, value)?;
    }
    hash_sizes(&mut hasher, &requirements.lut_words)?;
    hash_sizes(&mut hasher, &requirements.multiplicity_words)?;
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn content_identity(
    descriptor_identity: [u8; 32],
    descriptor_kinds: &[WitnessFeedDescriptorKind],
    lut_identity: [u8; 32],
) -> Result<[u8; 32], WitnessFeedAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONTENT_DOMAIN);
    hash_size(&mut hasher, WITNESS_FEED_DESCRIPTOR_FIELD_ORDER.len())?;
    for field in WITNESS_FEED_DESCRIPTOR_FIELD_ORDER {
        hasher.update(&[field as u8]);
    }
    hasher.update(&descriptor_identity);
    hash_size(&mut hasher, descriptor_kinds.len())?;
    for kind in descriptor_kinds {
        hasher.update(&[*kind as u8]);
    }
    hasher.update(&lut_identity);
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn combined_lut_identity(
    lut_identities: &[[u8; 32]],
) -> Result<[u8; 32], WitnessFeedAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LUT_DOMAIN);
    hash_size(&mut hasher, lut_identities.len())?;
    for identity in lut_identities {
        hasher.update(identity);
    }
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn lut_identity(
    ordinal: usize,
    words: &[u32],
) -> Result<[u8; 32], WitnessFeedAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LUT_DOMAIN);
    hash_size(&mut hasher, ordinal)?;
    hash_words(&mut hasher, words)?;
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn abi_identity(abi: WitnessFeedAbi) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ABI_DOMAIN);
    hasher.update(&[abi as u8]);
    hash_bytes(&mut hasher, abi.entry_symbol().as_bytes());
    for argument in abi.arguments() {
        hasher.update(&[argument.ordinal, argument.kind as u8, argument.access as u8]);
        hash_bytes(&mut hasher, argument.name.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn effect_identity(
    effect: WitnessFeedEffectAbi,
    geometry: &WitnessFeedEffectGeometry,
) -> Result<[u8; 32], WitnessFeedAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EFFECT_DOMAIN);
    hasher.update(&[effect as u8]);
    hasher.update(&geometry.row_domain.row_count.to_le_bytes());
    hasher.update(&geometry.row_domain.sub_words_per_row.to_le_bytes());
    hash_size(&mut hasher, geometry.row_domain.source_words)?;
    hash_size(&mut hasher, geometry.source.read_start_words)?;
    hash_size(&mut hasher, geometry.source.read_len_words)?;
    hash_size(&mut hasher, geometry.descriptor_words)?;
    hash_size(&mut hasher, geometry.lut_reads.len())?;
    for read in &geometry.lut_reads {
        hasher.update(&read.lut_ordinal.to_le_bytes());
        hash_size(&mut hasher, read.read_start_words)?;
        hash_size(&mut hasher, read.read_len_words)?;
        hasher.update(&read.content_identity);
    }
    hash_size(&mut hasher, geometry.destinations.len())?;
    for destination in &geometry.destinations {
        hasher.update(&destination.destination_ordinal.to_le_bytes());
        hash_size(&mut hasher, destination.atomic_start_words)?;
        hash_size(&mut hasher, destination.atomic_len_words)?;
        hash_size(&mut hasher, destination.may_write_ranges.len())?;
        for range in &destination.may_write_ranges {
            hash_size(&mut hasher, range.start_words)?;
            hash_size(&mut hasher, range.len_words)?;
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn launch_identity(launch: WitnessFeedKernelLaunch) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LAUNCH_DOMAIN);
    hash_bytes(&mut hasher, launch.symbol().as_bytes());
    for value in launch.grid.into_iter().chain(launch.block) {
        hasher.update(&value.to_le_bytes());
    }
    hasher.update(&launch.static_shared_bytes.to_le_bytes());
    hasher.update(&launch.dynamic_shared_bytes.to_le_bytes());
    hasher.update(&[u8::from(launch.cooperative)]);
    hash_cluster(&mut hasher, launch.cluster);
    *hasher.finalize().as_bytes()
}

pub(super) fn source_identity(
    static_source: [u8; 32],
    wrapper_source: [u8; 32],
    sources: &[&[u8]],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SOURCE_DOMAIN);
    hasher.update(&static_source);
    hasher.update(&wrapper_source);
    for source in sources {
        hash_bytes(&mut hasher, source);
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn contract_identity(identities: [[u8; 32]; 6]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONTRACT_DOMAIN);
    for identity in identities {
        hasher.update(&identity);
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hash_bytes(&mut hasher, bytes);
    *hasher.finalize().as_bytes()
}

pub(super) fn digest_words(
    domain: &[u8],
    words: &[u32],
) -> Result<[u8; 32], WitnessFeedAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hash_words(&mut hasher, words)?;
    Ok(*hasher.finalize().as_bytes())
}

fn hash_cluster(hasher: &mut blake3::Hasher, cluster: Option<[u32; 3]>) {
    hasher.update(&[u8::from(cluster.is_some())]);
    for value in cluster.unwrap_or([0; 3]) {
        hasher.update(&value.to_le_bytes());
    }
}

fn hash_sizes(
    hasher: &mut blake3::Hasher,
    values: &[usize],
) -> Result<(), WitnessFeedAuthorityError> {
    hash_size(hasher, values.len())?;
    for &value in values {
        hash_size(hasher, value)?;
    }
    Ok(())
}

fn hash_size(hasher: &mut blake3::Hasher, value: usize) -> Result<(), WitnessFeedAuthorityError> {
    hasher.update(
        &u64::try_from(value)
            .map_err(|_| WitnessFeedAuthorityError::SizeOverflow)?
            .to_le_bytes(),
    );
    Ok(())
}

fn hash_words(hasher: &mut blake3::Hasher, words: &[u32]) -> Result<(), WitnessFeedAuthorityError> {
    hash_size(hasher, words.len())?;
    for word in words {
        hasher.update(&word.to_le_bytes());
    }
    Ok(())
}

fn hash_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}
