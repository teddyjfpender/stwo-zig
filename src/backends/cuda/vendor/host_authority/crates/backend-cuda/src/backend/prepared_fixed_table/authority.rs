//! Address-free authority for one fixed-table materialization launch.
//!
//! The contract seals the real wrapper ABI, source/descriptor topology and
//! launch. [`super::PreparedFixedTableGraph`] remains the sole owner of device
//! pointer tables, descriptor uploads and their lifetime.

use super::{
    fixed_table_workspace_requirements, FixedTableMaterializationConfig,
    FixedTableWorkspaceRequirements,
};
use crate::backend::prepared_witness_input::static_build::{
    bind_static_build, StaticBuildBindError, StaticBuildBinding,
};

const ZERO_IDENTITY: [u8; 32] = [0; 32];
const BLOCK_THREADS: u32 = 256;
const BINDER_SOURCE: &[u8] = include_bytes!("../prepared_fixed_table.rs");
const AUTHORITY_SOURCE: &[u8] = include_bytes!("authority.rs");
const RAW_FFI_SOURCE: &[u8] = include_bytes!("../../../../backend-cuda-kernels/src/raw.rs");
const WRAPPER_SOURCE: &[u8] =
    include_bytes!("../../../../backend-cuda-kernels/cuda/fixed_table_materializer.cu");

const SOURCE_DOMAIN: &[u8] = b"stwo-cuda-fixed-table-source-v1\0";
const WRAPPER_DOMAIN: &[u8] = b"stwo-cuda-fixed-table-wrapper-v1\0";
const CONFIG_DOMAIN: &[u8] = b"stwo-cuda-fixed-table-config-v1\0";
const ABI_DOMAIN: &[u8] = b"stwo-cuda-fixed-table-abi-v1\0";
const EFFECT_DOMAIN: &[u8] = b"stwo-cuda-fixed-table-effect-v1\0";
const LAUNCH_DOMAIN: &[u8] = b"stwo-cuda-fixed-table-launch-v1\0";
const CONTRACT_DOMAIN: &[u8] = b"stwo-cuda-fixed-table-contract-v1\0";
const STATIC_BUILD_DOMAIN: &[u8] = b"stwo-cuda-fixed-table-static-build-v1\0";
const LINKED_DOMAIN: &[u8] = b"stwo-cuda-fixed-table-linked-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FixedTableMaterializerAbiArgumentKind {
    OptionalDeviceConstPointerTableU32 = 1,
    DeviceConstPointerTableU32 = 2,
    DeviceConstPointerU32 = 3,
    DeviceMutPointerTableU32 = 4,
    U32 = 5,
    CudaStream = 6,
}

impl FixedTableMaterializerAbiArgumentKind {
    const fn c_type(self) -> &'static str {
        match self {
            Self::OptionalDeviceConstPointerTableU32 | Self::DeviceConstPointerTableU32 => {
                "constuint32_t*const*"
            }
            Self::DeviceConstPointerU32 => "constuint32_t*",
            Self::DeviceMutPointerTableU32 => "uint32_t*const*",
            Self::U32 => "uint32_t",
            Self::CudaStream => "void*",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FixedTableMaterializerAbiAccess {
    ReadSourceColumnsWhenPresent = 1,
    ReadMultiplicityColumns = 2,
    ReadTraceMapping = 3,
    WriteTraceOutputs = 4,
    TraceOutputCount = 5,
    ReadLookupDescriptors = 6,
    WriteLookupOutputs = 7,
    LookupOutputCount = 8,
    RowCount = 9,
    OrderedExecutionStream = 10,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedTableMaterializerAbiArgument {
    pub ordinal: u8,
    pub name: &'static str,
    pub kind: FixedTableMaterializerAbiArgumentKind,
    pub access: FixedTableMaterializerAbiAccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FixedTableMaterializerAbi {
    MaterializeV1 = 1,
}

impl FixedTableMaterializerAbi {
    pub const fn entry_symbol(self) -> &'static str {
        "stwo_fixed_table_materialize_on"
    }

    pub const fn kernel_symbol(self) -> &'static str {
        "fixed_table_materialize_kernel"
    }

    pub const fn arguments(self) -> &'static [FixedTableMaterializerAbiArgument] {
        &ARGUMENTS
    }

    pub(super) fn source_declares_entry(self, source: &[u8]) -> bool {
        let Ok(source) = core::str::from_utf8(source) else {
            return false;
        };
        let Some(source) = source_without_comments_or_literals(source) else {
            return false;
        };
        let canonical_source = strip_ascii_whitespace(&source);
        if canonical_source.match_indices(self.entry_symbol()).count() != 1 {
            return false;
        }
        let mut expected = format!("extern\"C\"int{}(", self.entry_symbol());
        for (index, argument) in self.arguments().iter().enumerate() {
            if index != 0 {
                expected.push(',');
            }
            expected.push_str(argument.kind.c_type());
            expected.push_str(argument.name);
        }
        expected.push_str("){");
        canonical_source.find(&expected).is_some_and(|start| {
            canonical_source[..start]
                .chars()
                .next_back()
                .is_none_or(|character| !is_identifier_byte(character as u8))
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedTableMaterializerKernelLaunch {
    pub grid: [u32; 3],
    pub block: [u32; 3],
    pub dynamic_shared_bytes: u32,
    pub cooperative: bool,
    pub cluster: Option<[u32; 3]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedTableMaterializerContract {
    config: FixedTableMaterializationConfig,
    requirements: FixedTableWorkspaceRequirements,
    abi: FixedTableMaterializerAbi,
    launch: FixedTableMaterializerKernelLaunch,
    static_source_identity: [u8; 32],
    wrapper_source_identity: [u8; 32],
    source_identity: [u8; 32],
    config_identity: [u8; 32],
    abi_identity: [u8; 32],
    effect_identity: [u8; 32],
    launch_identity: [u8; 32],
    identity: [u8; 32],
}

impl FixedTableMaterializerContract {
    pub fn compile(
        config: &FixedTableMaterializationConfig,
    ) -> Result<Self, FixedTableMaterializerAuthorityError> {
        let requirements = fixed_table_workspace_requirements(config)
            .map_err(|_| FixedTableMaterializerAuthorityError::InvalidCanonicalConfig)?;
        let rows = u32_value(config.row_count)?;
        let outputs = requirements
            .trace_output_count
            .checked_add(requirements.lookup_output_count)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(FixedTableMaterializerAuthorityError::SizeOverflow)?;
        let abi = FixedTableMaterializerAbi::MaterializeV1;
        for symbol in [abi.entry_symbol(), abi.kernel_symbol()] {
            if !contains_bytes(WRAPPER_SOURCE, symbol.as_bytes()) {
                return Err(FixedTableMaterializerAuthorityError::MissingStaticSymbol(
                    symbol,
                ));
            }
        }
        if !abi.source_declares_entry(WRAPPER_SOURCE) {
            return Err(FixedTableMaterializerAuthorityError::InvalidStaticAbi(
                abi.entry_symbol(),
            ));
        }
        let launch = FixedTableMaterializerKernelLaunch {
            grid: [1 + (rows - 1) / BLOCK_THREADS, outputs, 1],
            block: [BLOCK_THREADS, 1, 1],
            dynamic_shared_bytes: 0,
            cooperative: false,
            cluster: None,
        };
        let static_source_identity = stwo_backend_cuda_kernels::static_cuda_source_identity();
        let wrapper_source_identity = digest(WRAPPER_DOMAIN, WRAPPER_SOURCE)?;
        let source_identity = digest_many(
            SOURCE_DOMAIN,
            &[
                &static_source_identity,
                &wrapper_source_identity,
                BINDER_SOURCE,
                AUTHORITY_SOURCE,
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
            return Err(FixedTableMaterializerAuthorityError::MissingStaticSourceIdentity);
        }
        let config_identity = hash_config(config)?;
        let abi_identity = hash_abi(abi)?;
        let effect_identity = digest_many(
            EFFECT_DOMAIN,
            &[&config_identity, &requirements_bytes(&requirements)?],
        )?;
        let launch_identity = hash_launch(launch)?;
        let identity = digest_many(
            CONTRACT_DOMAIN,
            &[
                &source_identity,
                &config_identity,
                &abi_identity,
                &effect_identity,
                &launch_identity,
            ],
        )?;
        Ok(Self {
            config: config.clone(),
            requirements,
            abi,
            launch,
            static_source_identity,
            wrapper_source_identity,
            source_identity,
            config_identity,
            abi_identity,
            effect_identity,
            launch_identity,
            identity,
        })
    }

    pub fn validate(&self) -> Result<(), FixedTableMaterializerAuthorityError> {
        (Self::compile(&self.config)? == *self)
            .then_some(())
            .ok_or(FixedTableMaterializerAuthorityError::InvalidCanonicalConfig)
    }

    pub fn bind_static_build(
        &self,
        target_sm: u32,
    ) -> Result<Option<FixedTableMaterializerLinkedContract>, FixedTableMaterializerAuthorityError>
    {
        self.validate()?;
        bind_static_build(STATIC_BUILD_DOMAIN, self.identity, target_sm)
            .map(|binding| binding.map(|binding| linked(self.identity, binding)))
            .map_err(Into::into)
    }

    pub const fn config(&self) -> &FixedTableMaterializationConfig {
        &self.config
    }
    pub const fn requirements(&self) -> &FixedTableWorkspaceRequirements {
        &self.requirements
    }
    pub const fn abi(&self) -> FixedTableMaterializerAbi {
        self.abi
    }
    pub const fn launch(&self) -> FixedTableMaterializerKernelLaunch {
        self.launch
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
    pub const fn config_identity(&self) -> [u8; 32] {
        self.config_identity
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedTableMaterializerLinkedContract {
    contract_identity: [u8; 32],
    module_build_identity: [u8; 32],
    static_build_source_identity: [u8; 32],
    static_build_identity: [u8; 32],
    target_sm: u32,
    sm_identity: [u8; 32],
    identity: [u8; 32],
}

impl FixedTableMaterializerLinkedContract {
    pub fn validate(
        &self,
        contract: &FixedTableMaterializerContract,
    ) -> Result<(), FixedTableMaterializerAuthorityError> {
        let expected = contract
            .bind_static_build(self.target_sm)?
            .ok_or(FixedTableMaterializerAuthorityError::StaticBuildUnavailable)?;
        (*self == expected)
            .then_some(())
            .ok_or(FixedTableMaterializerAuthorityError::StaticBuildMismatch)
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
pub enum FixedTableMaterializerAuthorityError {
    InvalidCanonicalConfig,
    MissingStaticSourceIdentity,
    MissingStaticSymbol(&'static str),
    InvalidStaticAbi(&'static str),
    SizeOverflow,
    StaticBuildUnavailable,
    StaticBuildMismatch,
    UnsupportedTargetSm(u32),
}

impl From<StaticBuildBindError> for FixedTableMaterializerAuthorityError {
    fn from(error: StaticBuildBindError) -> Self {
        match error {
            StaticBuildBindError::UnsupportedTargetSm(sm) => Self::UnsupportedTargetSm(sm),
            StaticBuildBindError::BuildReceiptUnavailable => Self::StaticBuildUnavailable,
            StaticBuildBindError::InconsistentBuildMetadata
            | StaticBuildBindError::BuildReceiptMismatch => Self::StaticBuildMismatch,
        }
    }
}

const ARGUMENTS: [FixedTableMaterializerAbiArgument; 10] = [
    argument(
        0,
        "source_columns_dev",
        FixedTableMaterializerAbiArgumentKind::OptionalDeviceConstPointerTableU32,
        FixedTableMaterializerAbiAccess::ReadSourceColumnsWhenPresent,
    ),
    argument(
        1,
        "multiplicity_columns_dev",
        FixedTableMaterializerAbiArgumentKind::DeviceConstPointerTableU32,
        FixedTableMaterializerAbiAccess::ReadMultiplicityColumns,
    ),
    argument(
        2,
        "trace_multiplicity_columns_dev",
        FixedTableMaterializerAbiArgumentKind::DeviceConstPointerU32,
        FixedTableMaterializerAbiAccess::ReadTraceMapping,
    ),
    argument(
        3,
        "trace_outputs_dev",
        FixedTableMaterializerAbiArgumentKind::DeviceMutPointerTableU32,
        FixedTableMaterializerAbiAccess::WriteTraceOutputs,
    ),
    argument(
        4,
        "n_trace_outputs",
        FixedTableMaterializerAbiArgumentKind::U32,
        FixedTableMaterializerAbiAccess::TraceOutputCount,
    ),
    argument(
        5,
        "lookup_descriptors_dev",
        FixedTableMaterializerAbiArgumentKind::DeviceConstPointerU32,
        FixedTableMaterializerAbiAccess::ReadLookupDescriptors,
    ),
    argument(
        6,
        "lookup_outputs_dev",
        FixedTableMaterializerAbiArgumentKind::DeviceMutPointerTableU32,
        FixedTableMaterializerAbiAccess::WriteLookupOutputs,
    ),
    argument(
        7,
        "n_lookup_outputs",
        FixedTableMaterializerAbiArgumentKind::U32,
        FixedTableMaterializerAbiAccess::LookupOutputCount,
    ),
    argument(
        8,
        "row_count",
        FixedTableMaterializerAbiArgumentKind::U32,
        FixedTableMaterializerAbiAccess::RowCount,
    ),
    argument(
        9,
        "stream",
        FixedTableMaterializerAbiArgumentKind::CudaStream,
        FixedTableMaterializerAbiAccess::OrderedExecutionStream,
    ),
];

const fn argument(
    ordinal: u8,
    name: &'static str,
    kind: FixedTableMaterializerAbiArgumentKind,
    access: FixedTableMaterializerAbiAccess,
) -> FixedTableMaterializerAbiArgument {
    FixedTableMaterializerAbiArgument {
        ordinal,
        name,
        kind,
        access,
    }
}

fn linked(
    contract_identity: [u8; 32],
    binding: StaticBuildBinding,
) -> FixedTableMaterializerLinkedContract {
    let identity = digest_many_infallible(
        LINKED_DOMAIN,
        &[
            &contract_identity,
            &binding.module_build_identity,
            &binding.static_build_source_identity,
            &binding.identity,
            &binding.target_sm.to_le_bytes(),
            &binding.sm_identity,
        ],
    );
    FixedTableMaterializerLinkedContract {
        contract_identity,
        module_build_identity: binding.module_build_identity,
        static_build_source_identity: binding.static_build_source_identity,
        static_build_identity: binding.identity,
        target_sm: binding.target_sm,
        sm_identity: binding.sm_identity,
        identity,
    }
}

fn hash_config(
    config: &FixedTableMaterializationConfig,
) -> Result<[u8; 32], FixedTableMaterializerAuthorityError> {
    let mut bytes = Vec::new();
    push_size(&mut bytes, config.row_count)?;
    push_size(&mut bytes, config.source_column_count)?;
    push_size(&mut bytes, config.multiplicity_column_count)?;
    push_size(&mut bytes, config.trace_multiplicity_columns.len())?;
    for value in &config.trace_multiplicity_columns {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    push_size(&mut bytes, config.lookup_sources.len())?;
    for source in &config.lookup_sources {
        for word in source.descriptor() {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
    }
    digest(CONFIG_DOMAIN, &bytes)
}

fn requirements_bytes(
    requirements: &FixedTableWorkspaceRequirements,
) -> Result<Vec<u8>, FixedTableMaterializerAuthorityError> {
    let mut bytes = Vec::new();
    for value in [
        requirements.row_count,
        requirements.source_column_count,
        requirements.multiplicity_column_count,
        requirements.trace_output_count,
        requirements.lookup_output_count,
        requirements.source_pointer_words,
        requirements.multiplicity_pointer_words,
        requirements.trace_mapping_words,
        requirements.trace_pointer_words,
        requirements.lookup_descriptor_words,
        requirements.lookup_pointer_words,
    ] {
        push_size(&mut bytes, value)?;
    }
    for value in requirements.trace_multiplicity_columns() {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    for value in requirements.lookup_descriptors() {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    Ok(bytes)
}

fn hash_abi(
    abi: FixedTableMaterializerAbi,
) -> Result<[u8; 32], FixedTableMaterializerAuthorityError> {
    let mut bytes = vec![abi as u8];
    push_size(&mut bytes, abi.arguments().len())?;
    for argument in abi.arguments() {
        bytes.extend_from_slice(&[argument.ordinal, argument.kind as u8, argument.access as u8]);
        push_size(&mut bytes, argument.name.len())?;
        bytes.extend_from_slice(argument.name.as_bytes());
    }
    digest(ABI_DOMAIN, &bytes)
}

fn hash_launch(
    launch: FixedTableMaterializerKernelLaunch,
) -> Result<[u8; 32], FixedTableMaterializerAuthorityError> {
    let mut bytes = Vec::new();
    for value in launch.grid.into_iter().chain(launch.block) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(&launch.dynamic_shared_bytes.to_le_bytes());
    bytes.push(u8::from(launch.cooperative));
    bytes.push(u8::from(launch.cluster.is_some()));
    if let Some(cluster) = launch.cluster {
        for value in cluster {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
    }
    digest(LAUNCH_DOMAIN, &bytes)
}

fn u32_value(value: usize) -> Result<u32, FixedTableMaterializerAuthorityError> {
    u32::try_from(value).map_err(|_| FixedTableMaterializerAuthorityError::SizeOverflow)
}

fn push_size(out: &mut Vec<u8>, value: usize) -> Result<(), FixedTableMaterializerAuthorityError> {
    out.extend_from_slice(
        &u64::try_from(value)
            .map_err(|_| FixedTableMaterializerAuthorityError::SizeOverflow)?
            .to_le_bytes(),
    );
    Ok(())
}

fn digest(domain: &[u8], bytes: &[u8]) -> Result<[u8; 32], FixedTableMaterializerAuthorityError> {
    digest_many(domain, &[bytes])
}

fn digest_many(
    domain: &[u8],
    fields: &[&[u8]],
) -> Result<[u8; 32], FixedTableMaterializerAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(
        &u64::try_from(fields.len())
            .map_err(|_| FixedTableMaterializerAuthorityError::SizeOverflow)?
            .to_le_bytes(),
    );
    for field in fields {
        hasher.update(
            &u64::try_from(field.len())
                .map_err(|_| FixedTableMaterializerAuthorityError::SizeOverflow)?
                .to_le_bytes(),
        );
        hasher.update(field);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn digest_many_infallible(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(fields.len() as u64).to_le_bytes());
    for field in fields {
        hasher.update(&(field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    *hasher.finalize().as_bytes()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|candidate| candidate == needle)
}

fn strip_ascii_whitespace(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect()
}

/// Remove every source region that cannot declare a real C++ function.
///
/// Raw strings fail closed: the checked wrapper does not use them, and
/// accepting an unparsed delimiter would reopen the declaration-decoy gap.
fn source_without_comments_or_literals(value: &str) -> Option<String> {
    let source = value.as_bytes();
    let mut output = Vec::with_capacity(source.len());
    let mut index = 0;
    while index < source.len() {
        if raw_string_starts_at(source, index) {
            return None;
        }
        match (source[index], source.get(index + 1).copied()) {
            (b'/', Some(b'/')) => {
                output.extend_from_slice(b"  ");
                index += 2;
                while index < source.len() && source[index] != b'\n' {
                    output.push(b' ');
                    index += 1;
                }
            }
            (b'/', Some(b'*')) => {
                output.extend_from_slice(b"  ");
                index += 2;
                let mut closed = false;
                while index < source.len() {
                    if source[index] == b'*' && source.get(index + 1) == Some(&b'/') {
                        output.extend_from_slice(b"  ");
                        index += 2;
                        closed = true;
                        break;
                    }
                    output.push(if source[index] == b'\n' { b'\n' } else { b' ' });
                    index += 1;
                }
                if !closed {
                    return None;
                }
            }
            (b'"', _) => {
                let end = quoted_literal_end(source, index, b'"')?;
                let linkage = &source[index..end] == b"\"C\"" && previous_token_is_extern(&output);
                if linkage {
                    output.extend_from_slice(&source[index..end]);
                } else {
                    output.extend(core::iter::repeat(b' ').take(end - index));
                }
                index = end;
            }
            (b'\'', _) => {
                let end = quoted_literal_end(source, index, b'\'')?;
                output.extend(core::iter::repeat(b' ').take(end - index));
                index = end;
            }
            (byte, _) => {
                output.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(output).ok()
}

fn quoted_literal_end(source: &[u8], start: usize, quote: u8) -> Option<usize> {
    let mut index = start + 1;
    while index < source.len() {
        match source[index] {
            b'\\' => index = index.checked_add(2)?,
            byte if byte == quote => return Some(index + 1),
            b'\n' | b'\r' => return None,
            _ => index += 1,
        }
    }
    None
}

fn previous_token_is_extern(output: &[u8]) -> bool {
    let end = output
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(0, |index| index + 1);
    let Some(start) = end.checked_sub(b"extern".len()) else {
        return false;
    };
    &output[start..end] == b"extern"
        && start
            .checked_sub(1)
            .and_then(|index| output.get(index))
            .is_none_or(|byte| !is_identifier_byte(*byte))
}

fn raw_string_starts_at(source: &[u8], index: usize) -> bool {
    const PREFIXES: &[&[u8]] = &[b"R\"", b"u8R\"", b"uR\"", b"UR\"", b"LR\""];
    PREFIXES
        .iter()
        .any(|prefix| source[index..].starts_with(prefix))
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}
