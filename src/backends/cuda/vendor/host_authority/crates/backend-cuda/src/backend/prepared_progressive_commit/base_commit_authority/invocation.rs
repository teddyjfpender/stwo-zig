//! Typed address-free arguments for each unfused Base commit wrapper call.

use super::*;

const INVOCATION_DOMAIN: &[u8] = b"stwo-cuda-base-commit-invocation-v2\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BaseCommitInvocationValue {
    PointerEffect {
        binding_index: u32,
        installed_range: Option<BaseCommitDependencyRange>,
    },
    U32(u32),
    Unsigned(u32),
    InstalledWordLength {
        dependency: BaseCommitDependencyRole,
    },
    ExecutionStream,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BaseCommitInvocationArgument {
    pub ordinal: u8,
    pub name: &'static str,
    pub kind: BaseCommitAbiArgumentKind,
    pub value: BaseCommitInvocationValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BaseCommitInvocation {
    pub arguments: Vec<BaseCommitInvocationArgument>,
    pub identity: [u8; 32],
}

impl BaseCommitInvocation {
    pub fn validate(
        &self,
        abi: BaseCommitAbi,
        operation: &BaseCommitOperationKind,
        effect: &BaseCommitEffect,
    ) -> Result<(), BaseCommitAuthorityError> {
        (compile_invocation(abi, operation, effect)? == *self)
            .then_some(())
            .ok_or(BaseCommitAuthorityError::InvalidInvocation)
    }
}

pub(super) fn compile_invocation(
    abi: BaseCommitAbi,
    operation: &BaseCommitOperationKind,
    effect: &BaseCommitEffect,
) -> Result<BaseCommitInvocation, BaseCommitAuthorityError> {
    effect.validate_for_abi(abi)?;
    let arguments = abi
        .arguments()
        .iter()
        .map(|argument| {
            let value = if argument.kind.is_pointer_bearing() {
                let (binding_index, binding) = effect
                    .pointer_bindings
                    .iter()
                    .position(|binding| binding.argument_ordinal == argument.ordinal)
                    .and_then(|index| {
                        u32::try_from(index)
                            .ok()
                            .map(|binding_index| (binding_index, &effect.pointer_bindings[index]))
                    })
                    .ok_or(BaseCommitAuthorityError::InvalidInvocation)?;
                if argument.kind == BaseCommitAbiArgumentKind::CudaStream {
                    BaseCommitInvocationValue::ExecutionStream
                } else {
                    BaseCommitInvocationValue::PointerEffect {
                        binding_index,
                        installed_range: target_installed_range(&binding.target),
                    }
                }
            } else {
                scalar_value(abi, argument.ordinal, operation)?
            };
            Ok(BaseCommitInvocationArgument {
                ordinal: argument.ordinal,
                name: argument.name,
                kind: argument.kind,
                value,
            })
        })
        .collect::<Result<Vec<_>, BaseCommitAuthorityError>>()?;
    validate_argument_types(abi, effect, &arguments)?;
    let identity = invocation_identity(abi, &arguments);
    Ok(BaseCommitInvocation {
        arguments,
        identity,
    })
}

fn scalar_value(
    abi: BaseCommitAbi,
    ordinal: u8,
    operation: &BaseCommitOperationKind,
) -> Result<BaseCommitInvocationValue, BaseCommitAuthorityError> {
    let value = match (abi, operation, ordinal) {
        (
            BaseCommitAbi::DirectB2nV1,
            BaseCommitOperationKind::DirectB2n {
                source_log_size, ..
            },
            2,
        ) => BaseCommitInvocationValue::U32(*source_log_size),
        (
            BaseCommitAbi::DirectB2nV1,
            BaseCommitOperationKind::DirectB2n {
                canonical_columns, ..
            },
            3,
        ) => BaseCommitInvocationValue::U32(u32_len(canonical_columns)?),
        (BaseCommitAbi::DirectB2nV1, BaseCommitOperationKind::DirectB2n { .. }, 5) => {
            BaseCommitInvocationValue::InstalledWordLength {
                dependency: BaseCommitDependencyRole::InverseTwiddles,
            }
        }
        (
            BaseCommitAbi::DirectB2nV1,
            BaseCommitOperationKind::DirectB2n {
                source_log_size, ..
            },
            6,
        ) => BaseCommitInvocationValue::U32(transform_words(*source_log_size)?),
        (
            BaseCommitAbi::DirectN2bV1,
            BaseCommitOperationKind::DirectN2b {
                retained_log_size, ..
            },
            1,
        ) => BaseCommitInvocationValue::Unsigned(*retained_log_size),
        (
            BaseCommitAbi::DirectN2bV1,
            BaseCommitOperationKind::DirectN2b {
                canonical_columns, ..
            },
            2,
        ) => BaseCommitInvocationValue::Unsigned(u32_len(canonical_columns)?),
        (BaseCommitAbi::DirectN2bV1, BaseCommitOperationKind::DirectN2b { .. }, 4) => {
            BaseCommitInvocationValue::InstalledWordLength {
                dependency: BaseCommitDependencyRole::ForwardTwiddles,
            }
        }
        (
            BaseCommitAbi::DirectN2bV1,
            BaseCommitOperationKind::DirectN2b {
                retained_log_size, ..
            },
            5,
        ) => BaseCommitInvocationValue::Unsigned(transform_words(*retained_log_size)?),
        (BaseCommitAbi::StateInitV1, BaseCommitOperationKind::StateInit { log_size }, 0) => {
            BaseCommitInvocationValue::U32(rows(*log_size)?)
        }
        (
            BaseCommitAbi::StateExpandInPlaceV1,
            BaseCommitOperationKind::StateExpandInPlace { from_log_size, .. },
            0,
        ) => BaseCommitInvocationValue::U32(*from_log_size),
        (
            BaseCommitAbi::StateExpandInPlaceV1,
            BaseCommitOperationKind::StateExpandInPlace { to_log_size, .. },
            1,
        ) => BaseCommitInvocationValue::U32(*to_log_size),
        (
            BaseCommitAbi::StateAbsorbV1,
            BaseCommitOperationKind::StateAbsorb { log_size, .. },
            0,
        ) => BaseCommitInvocationValue::U32(rows(*log_size)?),
        (
            BaseCommitAbi::StateAbsorbV1,
            BaseCommitOperationKind::StateAbsorb {
                canonical_columns, ..
            },
            1,
        ) => BaseCommitInvocationValue::U32(u32_len(canonical_columns)?),
        (
            BaseCommitAbi::StateAbsorbV1,
            BaseCommitOperationKind::StateAbsorb {
                absorbed_columns_before,
                ..
            },
            2,
        ) => BaseCommitInvocationValue::U32(*absorbed_columns_before),
        (
            BaseCommitAbi::StateFinalizeInPlaceV1,
            BaseCommitOperationKind::StateFinalizeInPlace { log_size, .. },
            0,
        ) => BaseCommitInvocationValue::U32(rows(*log_size)?),
        (
            BaseCommitAbi::StateFinalizeInPlaceV1,
            BaseCommitOperationKind::StateFinalizeInPlace {
                absorbed_columns, ..
            },
            1,
        ) => BaseCommitInvocationValue::U32(*absorbed_columns),
        (
            BaseCommitAbi::MerkleLayerInPlaceV1,
            BaseCommitOperationKind::MerkleLayerInPlace { output_hashes, .. },
            0,
        )
        | (
            BaseCommitAbi::MerkleLayerV1,
            BaseCommitOperationKind::MerkleLayer { output_hashes, .. },
            1,
        ) => BaseCommitInvocationValue::U32(*output_hashes),
        _ => return Err(BaseCommitAuthorityError::InvalidInvocation),
    };
    Ok(value)
}

fn validate_argument_types(
    abi: BaseCommitAbi,
    effect: &BaseCommitEffect,
    arguments: &[BaseCommitInvocationArgument],
) -> Result<(), BaseCommitAuthorityError> {
    if arguments.len() != abi.arguments().len() {
        return Err(BaseCommitAuthorityError::InvalidInvocation);
    }
    for (argument, expected) in arguments.iter().zip(abi.arguments()) {
        if argument.ordinal != expected.ordinal
            || argument.name != expected.name
            || argument.kind != expected.kind
        {
            return Err(BaseCommitAuthorityError::InvalidInvocation);
        }
        let valid = match argument.value {
            BaseCommitInvocationValue::PointerEffect {
                binding_index,
                installed_range: expected_range,
            } => {
                expected.kind.is_pointer_bearing()
                    && expected.kind != BaseCommitAbiArgumentKind::CudaStream
                    && effect
                        .pointer_bindings
                        .get(binding_index as usize)
                        .is_some_and(|binding| {
                            binding.argument_ordinal == argument.ordinal
                                && target_installed_range(&binding.target) == expected_range
                        })
            }
            BaseCommitInvocationValue::U32(_) => expected.kind == BaseCommitAbiArgumentKind::U32,
            BaseCommitInvocationValue::Unsigned(_) => {
                expected.kind == BaseCommitAbiArgumentKind::Unsigned
            }
            BaseCommitInvocationValue::InstalledWordLength { dependency } => {
                matches!(
                    expected.kind,
                    BaseCommitAbiArgumentKind::U32 | BaseCommitAbiArgumentKind::Unsigned
                ) && effect.pointer_bindings.iter().any(|binding| {
                    matches!(
                        &binding.target,
                        BaseCommitPointerTarget::Installed { access }
                            if access.role == dependency
                    )
                })
            }
            BaseCommitInvocationValue::ExecutionStream => {
                expected.kind == BaseCommitAbiArgumentKind::CudaStream
            }
        };
        if !valid {
            return Err(BaseCommitAuthorityError::InvalidInvocation);
        }
    }
    Ok(())
}

fn invocation_identity(abi: BaseCommitAbi, arguments: &[BaseCommitInvocationArgument]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(INVOCATION_DOMAIN);
    hasher.update(&[abi.tag()]);
    hasher.update(&(arguments.len() as u64).to_le_bytes());
    for argument in arguments {
        hasher.update(&[argument.ordinal, argument.kind as u8]);
        hasher.update(&(argument.name.len() as u64).to_le_bytes());
        hasher.update(argument.name.as_bytes());
        match argument.value {
            BaseCommitInvocationValue::PointerEffect {
                binding_index,
                installed_range,
            } => {
                hasher.update(&[1]);
                hasher.update(&binding_index.to_le_bytes());
                hash_installed_range(&mut hasher, installed_range);
            }
            BaseCommitInvocationValue::U32(value) => {
                hasher.update(&[2]);
                hasher.update(&value.to_le_bytes());
            }
            BaseCommitInvocationValue::Unsigned(value) => {
                hasher.update(&[3]);
                hasher.update(&value.to_le_bytes());
            }
            BaseCommitInvocationValue::InstalledWordLength { dependency } => {
                hasher.update(&[4]);
                hash_dependency(&mut hasher, dependency);
            }
            BaseCommitInvocationValue::ExecutionStream => {
                hasher.update(&[5]);
            }
        }
    }
    *hasher.finalize().as_bytes()
}

fn target_installed_range(target: &BaseCommitPointerTarget) -> Option<BaseCommitDependencyRange> {
    match target {
        BaseCommitPointerTarget::PointerTable { table, .. } => Some(table.range),
        BaseCommitPointerTarget::Installed { access } => Some(access.range),
        BaseCommitPointerTarget::Values { .. } | BaseCommitPointerTarget::ExecutionStream => None,
    }
}

fn hash_installed_range(hasher: &mut blake3::Hasher, range: Option<BaseCommitDependencyRange>) {
    match range {
        None => {
            hasher.update(&[0]);
        }
        Some(BaseCommitDependencyRange::Whole { words }) => {
            hasher.update(&[1]);
            hasher.update(&(words as u64).to_le_bytes());
        }
        Some(BaseCommitDependencyRange::Suffix { words }) => {
            hasher.update(&[2]);
            hasher.update(&(words as u64).to_le_bytes());
        }
        Some(BaseCommitDependencyRange::Slice { first_word, words }) => {
            hasher.update(&[3]);
            hasher.update(&(first_word as u64).to_le_bytes());
            hasher.update(&(words as u64).to_le_bytes());
        }
    }
}

fn hash_dependency(hasher: &mut blake3::Hasher, dependency: BaseCommitDependencyRole) {
    match dependency {
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
}

fn rows(log_size: u32) -> Result<u32, BaseCommitAuthorityError> {
    1u32.checked_shl(log_size)
        .ok_or(BaseCommitAuthorityError::SizeOverflow)
}

fn transform_words(log_size: u32) -> Result<u32, BaseCommitAuthorityError> {
    log_size
        .checked_sub(1)
        .and_then(|log_size| 1u32.checked_shl(log_size))
        .ok_or(BaseCommitAuthorityError::SizeOverflow)
}

fn u32_len(values: &[u32]) -> Result<u32, BaseCommitAuthorityError> {
    u32::try_from(values.len()).map_err(|_| BaseCommitAuthorityError::SizeOverflow)
}
