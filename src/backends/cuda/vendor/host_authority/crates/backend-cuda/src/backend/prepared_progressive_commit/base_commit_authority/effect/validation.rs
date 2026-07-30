//! Fail-closed reconciliation of logical effects with the physical wrapper ABI.

use super::*;

pub(super) fn validate_effect(
    abi: BaseCommitAbi,
    effect: &BaseCommitEffect,
) -> Result<(), BaseCommitAuthorityError> {
    let expected_ordinals = abi
        .arguments()
        .iter()
        .filter(|argument| argument.kind.is_pointer_bearing())
        .map(|argument| argument.ordinal)
        .collect::<Vec<_>>();
    let actual_ordinals = effect
        .pointer_bindings
        .iter()
        .map(|binding| binding.argument_ordinal)
        .collect::<Vec<_>>();
    if actual_ordinals != expected_ordinals
        || effect.accesses.is_empty()
        || effect.accesses.iter().any(|access| {
            access.first_word != 0
                || access.word_len == 0
                || access.kind == BaseCommitAccessKind::ReadWrite
        })
    {
        return Err(BaseCommitAuthorityError::InvalidEffect);
    }

    let mut references = vec![0u8; effect.accesses.len()];
    for binding in &effect.pointer_bindings {
        let argument = abi
            .arguments()
            .get(usize::from(binding.argument_ordinal))
            .filter(|argument| argument.ordinal == binding.argument_ordinal)
            .ok_or(BaseCommitAuthorityError::InvalidEffect)?;
        if !target_matches(abi, argument, &binding.target, &effect.accesses) {
            return Err(BaseCommitAuthorityError::InvalidEffect);
        }
        for &index in binding.target.access_indices() {
            let reference = references
                .get_mut(
                    usize::try_from(index).map_err(|_| BaseCommitAuthorityError::SizeOverflow)?,
                )
                .ok_or(BaseCommitAuthorityError::InvalidEffect)?;
            *reference = reference
                .checked_add(1)
                .ok_or(BaseCommitAuthorityError::SizeOverflow)?;
        }
    }
    if references.iter().any(|&count| count != 1) {
        return Err(BaseCommitAuthorityError::InvalidEffect);
    }

    let expected_aliases = expected_aliases(abi, effect)?;
    if effect.aliases != expected_aliases
        || !effect.aliases.iter().all(|alias| {
            alias_roles_match(alias, &effect.accesses)
                && effect
                    .accesses
                    .get(alias.source_access as usize)
                    .is_some_and(|access| access.kind == BaseCommitAccessKind::Read)
                && effect
                    .accesses
                    .get(alias.destination_access as usize)
                    .is_some_and(|access| access.kind == BaseCommitAccessKind::Write)
        })
    {
        return Err(BaseCommitAuthorityError::InvalidEffect);
    }
    Ok(())
}

fn target_matches(
    abi: BaseCommitAbi,
    argument: &BaseCommitAbiArgument,
    target: &BaseCommitPointerTarget,
    accesses: &[BaseCommitAccess],
) -> bool {
    match (argument.access, target) {
        (
            BaseCommitAbiAccess::ReadSourceEvaluations,
            BaseCommitPointerTarget::PointerTable {
                table,
                access_indices,
            },
        ) => {
            argument.kind == BaseCommitAbiArgumentKind::DeviceConstPointerTableU32
                && source_table_matches(table, access_indices.len())
                && accesses_match(access_indices, accesses, |access| {
                    access.kind == BaseCommitAccessKind::Read
                        && matches!(access.role, BaseCommitValueRole::SourceEvaluation { .. })
                })
        }
        (
            BaseCommitAbiAccess::WriteRetainedStageTwo,
            BaseCommitPointerTarget::PointerTable {
                table,
                access_indices,
            },
        ) => {
            argument.kind == BaseCommitAbiArgumentKind::DeviceMutPointerTableConstU32
                && retained_table_matches(table, access_indices.len())
                && accesses_match(access_indices, accesses, |access| {
                    access.kind == BaseCommitAccessKind::Write
                        && matches!(access.role, BaseCommitValueRole::RetainedStageTwo { .. })
                })
        }
        (
            BaseCommitAbiAccess::ReadWriteRetainedEvaluation,
            BaseCommitPointerTarget::PointerTable {
                table,
                access_indices,
            },
        ) => {
            argument.kind == BaseCommitAbiArgumentKind::DeviceMutPointerTableU32
                && access_indices.len() % 2 == 0
                && retained_table_matches(table, access_indices.len() / 2)
                && n2b_pairs_match(access_indices, accesses)
        }
        (
            BaseCommitAbiAccess::ReadRetainedEvaluations,
            BaseCommitPointerTarget::PointerTable {
                table,
                access_indices,
            },
        ) => {
            argument.kind == BaseCommitAbiArgumentKind::DeviceMutPointerTableU32
                && retained_table_matches(table, access_indices.len())
                && accesses_match(access_indices, accesses, |access| {
                    access.kind == BaseCommitAccessKind::Read
                        && matches!(access.role, BaseCommitValueRole::RetainedEvaluation { .. })
                })
        }
        (
            BaseCommitAbiAccess::WriteInitialState,
            BaseCommitPointerTarget::Values { access_indices },
        ) => {
            argument.kind == BaseCommitAbiArgumentKind::DeviceMutProgressiveBlake2sState
                && single_access_matches(access_indices, accesses, |access| {
                    access.kind == BaseCommitAccessKind::Write
                        && matches!(access.role, BaseCommitValueRole::State { .. })
                })
        }
        (
            BaseCommitAbiAccess::ReadWriteState,
            BaseCommitPointerTarget::Values { access_indices },
        ) => {
            argument.kind == BaseCommitAbiArgumentKind::DeviceMutProgressiveBlake2sState
                && state_pair_matches(abi, access_indices, accesses)
        }
        (BaseCommitAbiAccess::WriteHashes, BaseCommitPointerTarget::Values { access_indices }) => {
            argument.kind == BaseCommitAbiArgumentKind::DeviceMutBlake2sHash
                && hash_write_matches(abi, access_indices, accesses)
        }
        (
            BaseCommitAbiAccess::ReadPreviousHashes,
            BaseCommitPointerTarget::Values { access_indices },
        ) => {
            argument.kind == BaseCommitAbiArgumentKind::DeviceConstBlake2sHash
                && single_access_matches(access_indices, accesses, |access| {
                    access.kind == BaseCommitAccessKind::Read
                        && matches!(access.role, BaseCommitValueRole::HashLayer { .. })
                })
        }
        (BaseCommitAbiAccess::ReadTwiddles, BaseCommitPointerTarget::Installed { access }) => {
            matches!(
                (abi, argument.kind, access.kind, access.role, access.range),
                (
                    BaseCommitAbi::DirectB2nV1,
                    BaseCommitAbiArgumentKind::DeviceConstPointerU32,
                    BaseCommitAccessKind::Read,
                    BaseCommitDependencyRole::InverseTwiddles,
                    BaseCommitDependencyRange::Suffix { words: 1.. }
                ) | (
                    BaseCommitAbi::DirectN2bV1,
                    BaseCommitAbiArgumentKind::DeviceMutPointerU32,
                    BaseCommitAccessKind::Read,
                    BaseCommitDependencyRole::ForwardTwiddles,
                    BaseCommitDependencyRange::Suffix { words: 1.. }
                )
            )
        }
        (BaseCommitAbiAccess::ScratchPair, BaseCommitPointerTarget::Installed { access }) => {
            argument.kind == BaseCommitAbiArgumentKind::DeviceMutProgressiveBlake2sState
                && matches!(
                    access,
                    BaseCommitInstalledAccess {
                        kind: BaseCommitAccessKind::ReadWrite,
                        role: BaseCommitDependencyRole::InPlaceScratch,
                        range: BaseCommitDependencyRange::Whole { words: 1.. },
                    }
                )
        }
        (BaseCommitAbiAccess::OrderedExecutionStream, BaseCommitPointerTarget::ExecutionStream) => {
            argument.kind == BaseCommitAbiArgumentKind::CudaStream
        }
        _ => false,
    }
}

fn source_table_matches(table: &BaseCommitInstalledAccess, pointers: usize) -> bool {
    let Some(expected_words) = pointers.checked_mul(POINTER_WORDS) else {
        return false;
    };
    matches!(
        table,
        BaseCommitInstalledAccess {
            kind: BaseCommitAccessKind::Read,
            role: BaseCommitDependencyRole::BatchSourcePointerTable { .. },
            range: BaseCommitDependencyRange::Slice { first_word, words },
        } if *words == expected_words
            && *first_word % POINTER_WORDS == 0
            && pointers != 0
    )
}

fn retained_table_matches(table: &BaseCommitInstalledAccess, pointers: usize) -> bool {
    let Some(expected_words) = pointers.checked_mul(POINTER_WORDS) else {
        return false;
    };
    matches!(
        table,
        BaseCommitInstalledAccess {
            kind: BaseCommitAccessKind::Read,
            role: BaseCommitDependencyRole::BatchRetainedPointerTable { .. },
            range: BaseCommitDependencyRange::Slice { first_word, words },
        } if *words == expected_words
            && *first_word % POINTER_WORDS == 0
            && pointers != 0
    )
}

fn accesses_match(
    indices: &[u32],
    accesses: &[BaseCommitAccess],
    predicate: impl Fn(&BaseCommitAccess) -> bool,
) -> bool {
    !indices.is_empty()
        && indices
            .iter()
            .all(|&index| accesses.get(index as usize).is_some_and(&predicate))
}

fn single_access_matches(
    indices: &[u32],
    accesses: &[BaseCommitAccess],
    predicate: impl Fn(&BaseCommitAccess) -> bool,
) -> bool {
    indices.len() == 1 && accesses.get(indices[0] as usize).is_some_and(predicate)
}

fn n2b_pairs_match(indices: &[u32], accesses: &[BaseCommitAccess]) -> bool {
    !indices.is_empty()
        && indices.chunks_exact(2).all(|pair| {
            let Some(source) = accesses.get(pair[0] as usize) else {
                return false;
            };
            let Some(destination) = accesses.get(pair[1] as usize) else {
                return false;
            };
            matches!(
                (source.kind, source.role, destination.kind, destination.role),
                (
                    BaseCommitAccessKind::Read,
                    BaseCommitValueRole::RetainedStageTwo {
                        canonical_column: source_column
                    },
                    BaseCommitAccessKind::Write,
                    BaseCommitValueRole::RetainedEvaluation {
                        canonical_column: destination_column
                    }
                ) if source_column == destination_column && source.word_len == destination.word_len
            )
        })
}

fn state_pair_matches(abi: BaseCommitAbi, indices: &[u32], accesses: &[BaseCommitAccess]) -> bool {
    let Some((source, destination)) = access_pair(indices, accesses) else {
        return false;
    };
    match (abi, source.role, destination.role) {
        (
            BaseCommitAbi::StateExpandInPlaceV1 | BaseCommitAbi::StateAbsorbV1,
            BaseCommitValueRole::State { .. },
            BaseCommitValueRole::State { .. },
        ) => {
            source.kind == BaseCommitAccessKind::Read
                && destination.kind == BaseCommitAccessKind::Write
        }
        (
            BaseCommitAbi::StateFinalizeInPlaceV1,
            BaseCommitValueRole::State {
                log_size: source_log,
                ..
            },
            BaseCommitValueRole::HashLayer {
                log_size: destination_log,
            },
        ) => {
            source.kind == BaseCommitAccessKind::Read
                && destination.kind == BaseCommitAccessKind::Write
                && source_log == destination_log
        }
        _ => false,
    }
}

fn hash_write_matches(abi: BaseCommitAbi, indices: &[u32], accesses: &[BaseCommitAccess]) -> bool {
    if abi == BaseCommitAbi::MerkleLayerV1 {
        return single_access_matches(indices, accesses, |access| {
            access.kind == BaseCommitAccessKind::Write
                && matches!(access.role, BaseCommitValueRole::HashLayer { .. })
        });
    }
    let Some((source, destination)) = access_pair(indices, accesses) else {
        return false;
    };
    matches!(
        (source.kind, source.role, destination.kind, destination.role),
        (
            BaseCommitAccessKind::Read,
            BaseCommitValueRole::HashLayer {
                log_size: source_log
            },
            BaseCommitAccessKind::Write,
            BaseCommitValueRole::HashLayer {
                log_size: destination_log
            }
        ) if source_log == destination_log + 1
    )
}

fn access_pair<'a>(
    indices: &[u32],
    accesses: &'a [BaseCommitAccess],
) -> Option<(&'a BaseCommitAccess, &'a BaseCommitAccess)> {
    (indices.len() == 2)
        .then(|| {
            Some((
                accesses.get(indices[0] as usize)?,
                accesses.get(indices[1] as usize)?,
            ))
        })
        .flatten()
}

fn expected_aliases(
    abi: BaseCommitAbi,
    effect: &BaseCommitEffect,
) -> Result<Vec<BaseCommitAliasAuthority>, BaseCommitAuthorityError> {
    let aliases = match abi {
        BaseCommitAbi::DirectB2nV1 => {
            let sources = binding_indices(effect, 0)?;
            let destinations = binding_indices(effect, 1)?;
            if sources.len() != destinations.len() {
                return Err(BaseCommitAuthorityError::InvalidEffect);
            }
            sources
                .iter()
                .zip(destinations)
                .map(
                    |(&source_access, &destination_access)| BaseCommitAliasAuthority {
                        source_access,
                        destination_access,
                        requirement: BaseCommitAliasRequirement::Optional,
                        discipline: BaseCommitAliasDiscipline::ExactLowerPrefixReadBeforeWrite,
                    },
                )
                .collect()
        }
        BaseCommitAbi::DirectN2bV1 => binding_indices(effect, 0)?
            .chunks_exact(2)
            .map(|pair| ordered_alias(pair[0], pair[1]))
            .collect(),
        BaseCommitAbi::StateExpandInPlaceV1 | BaseCommitAbi::StateFinalizeInPlaceV1 => {
            let pair = binding_indices(effect, 2)?;
            vec![ordered_alias_pair(pair)?]
        }
        BaseCommitAbi::StateAbsorbV1 => {
            let pair = binding_indices(effect, 4)?;
            let [source_access, destination_access] = pair else {
                return Err(BaseCommitAuthorityError::InvalidEffect);
            };
            vec![BaseCommitAliasAuthority {
                source_access: *source_access,
                destination_access: *destination_access,
                requirement: BaseCommitAliasRequirement::Required,
                discipline: BaseCommitAliasDiscipline::ElementWiseReadBeforeWrite,
            }]
        }
        BaseCommitAbi::MerkleLayerInPlaceV1 => {
            let pair = binding_indices(effect, 1)?;
            vec![ordered_alias_pair(pair)?]
        }
        BaseCommitAbi::StateInitV1 | BaseCommitAbi::MerkleLayerV1 => Vec::new(),
    };
    Ok(aliases)
}

fn binding_indices(
    effect: &BaseCommitEffect,
    ordinal: u8,
) -> Result<&[u32], BaseCommitAuthorityError> {
    effect
        .pointer_bindings
        .iter()
        .find(|binding| binding.argument_ordinal == ordinal)
        .map(|binding| binding.target.access_indices())
        .filter(|indices| !indices.is_empty())
        .ok_or(BaseCommitAuthorityError::InvalidEffect)
}

fn ordered_alias(source_access: u32, destination_access: u32) -> BaseCommitAliasAuthority {
    BaseCommitAliasAuthority {
        source_access,
        destination_access,
        requirement: BaseCommitAliasRequirement::Required,
        discipline: BaseCommitAliasDiscipline::OrderedCompositeInPlace,
    }
}

fn ordered_alias_pair(pair: &[u32]) -> Result<BaseCommitAliasAuthority, BaseCommitAuthorityError> {
    let [source_access, destination_access] = pair else {
        return Err(BaseCommitAuthorityError::InvalidEffect);
    };
    Ok(ordered_alias(*source_access, *destination_access))
}

fn alias_roles_match(alias: &BaseCommitAliasAuthority, accesses: &[BaseCommitAccess]) -> bool {
    let Some(source) = accesses.get(alias.source_access as usize) else {
        return false;
    };
    let Some(destination) = accesses.get(alias.destination_access as usize) else {
        return false;
    };
    match (alias.discipline, source.role, destination.role) {
        (
            BaseCommitAliasDiscipline::ExactLowerPrefixReadBeforeWrite,
            BaseCommitValueRole::SourceEvaluation {
                canonical_column: source_column,
            },
            BaseCommitValueRole::RetainedStageTwo {
                canonical_column: destination_column,
            },
        ) => {
            source_column == destination_column
                && source.word_len.checked_mul(2) == Some(destination.word_len)
        }
        (
            BaseCommitAliasDiscipline::ElementWiseReadBeforeWrite,
            BaseCommitValueRole::State {
                log_size: source_log,
                ..
            },
            BaseCommitValueRole::State {
                log_size: destination_log,
                ..
            },
        ) => source_log == destination_log && source.word_len == destination.word_len,
        (
            BaseCommitAliasDiscipline::OrderedCompositeInPlace,
            BaseCommitValueRole::RetainedStageTwo {
                canonical_column: source_column,
            },
            BaseCommitValueRole::RetainedEvaluation {
                canonical_column: destination_column,
            },
        ) => source_column == destination_column && source.word_len == destination.word_len,
        (
            BaseCommitAliasDiscipline::OrderedCompositeInPlace,
            BaseCommitValueRole::State {
                log_size: source_log,
                ..
            },
            BaseCommitValueRole::State {
                log_size: destination_log,
                ..
            },
        ) => source_log <= destination_log && source.word_len <= destination.word_len,
        (
            BaseCommitAliasDiscipline::OrderedCompositeInPlace,
            BaseCommitValueRole::State {
                log_size: source_log,
                ..
            },
            BaseCommitValueRole::HashLayer {
                log_size: destination_log,
            },
        ) => source_log == destination_log && destination.word_len <= source.word_len,
        (
            BaseCommitAliasDiscipline::OrderedCompositeInPlace,
            BaseCommitValueRole::HashLayer {
                log_size: source_log,
            },
            BaseCommitValueRole::HashLayer {
                log_size: destination_log,
            },
        ) => {
            source_log == destination_log + 1
                && source.word_len == destination.word_len.saturating_mul(2)
        }
        _ => false,
    }
}
