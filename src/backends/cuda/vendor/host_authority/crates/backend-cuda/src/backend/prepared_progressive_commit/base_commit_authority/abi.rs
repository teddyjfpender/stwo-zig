//! Exact ordinary-CUDA wrapper ABI schemas used by the unfused Base commit.

use super::{BaseCommitAbi, B2N_SOURCE, BLAKE_SOURCE, IN_PLACE_SOURCE, N2B_SOURCE};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BaseCommitAbiArgumentKind {
    DeviceConstPointerTableU32 = 1,
    DeviceMutPointerTableConstU32 = 2,
    DeviceMutPointerTableU32 = 3,
    DeviceConstPointerU32 = 4,
    DeviceMutPointerU32 = 5,
    DeviceMutProgressiveBlake2sState = 6,
    DeviceConstBlake2sHash = 7,
    DeviceMutBlake2sHash = 8,
    U32 = 9,
    Unsigned = 10,
    CudaStream = 11,
}

impl BaseCommitAbiArgumentKind {
    const fn c_type(self) -> &'static str {
        match self {
            Self::DeviceConstPointerTableU32 => "constuint32_t*const*",
            Self::DeviceMutPointerTableConstU32 => "uint32_t*const*",
            Self::DeviceMutPointerTableU32 => "uint32_t**",
            Self::DeviceConstPointerU32 => "constuint32_t*",
            Self::DeviceMutPointerU32 => "uint32_t*",
            Self::DeviceMutProgressiveBlake2sState => "ProgressiveBlake2sState*",
            Self::DeviceConstBlake2sHash => "constBlake2sHash*",
            Self::DeviceMutBlake2sHash => "Blake2sHash*",
            Self::U32 => "uint32_t",
            Self::Unsigned => "unsigned",
            Self::CudaStream => "void*",
        }
    }

    pub(super) const fn is_pointer_bearing(self) -> bool {
        !matches!(self, Self::U32 | Self::Unsigned)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BaseCommitAbiAccess {
    ReadSourceEvaluations = 1,
    WriteRetainedStageTwo = 2,
    ReadWriteRetainedEvaluation = 3,
    TransformLogSize = 4,
    ColumnCount = 5,
    ReadTwiddles = 6,
    TwiddleWords = 7,
    EvaluationDomainSize = 8,
    OrderedExecutionStream = 9,
    RowCount = 10,
    WriteInitialState = 11,
    FromLogSize = 12,
    ToLogSize = 13,
    ReadWriteState = 14,
    ScratchPair = 15,
    AbsorbedColumnCount = 16,
    ReadRetainedEvaluations = 17,
    WriteHashes = 18,
    OutputHashCount = 19,
    ReadPreviousHashes = 20,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BaseCommitAbiArgument {
    pub ordinal: u8,
    pub name: &'static str,
    pub kind: BaseCommitAbiArgumentKind,
    pub access: BaseCommitAbiAccess,
}

impl BaseCommitAbi {
    pub const fn arguments(self) -> &'static [BaseCommitAbiArgument] {
        match self {
            Self::DirectB2nV1 => &DIRECT_B2N_ARGUMENTS,
            Self::DirectN2bV1 => &DIRECT_N2B_ARGUMENTS,
            Self::StateInitV1 => &STATE_INIT_ARGUMENTS,
            Self::StateExpandInPlaceV1 => &STATE_EXPAND_ARGUMENTS,
            Self::StateAbsorbV1 => &STATE_ABSORB_ARGUMENTS,
            Self::StateFinalizeInPlaceV1 => &STATE_FINALIZE_ARGUMENTS,
            Self::MerkleLayerInPlaceV1 => &MERKLE_IN_PLACE_ARGUMENTS,
            Self::MerkleLayerV1 => &MERKLE_ARGUMENTS,
        }
    }

    pub(super) const fn wrapper_source(self) -> &'static [u8] {
        match self {
            Self::DirectB2nV1 => B2N_SOURCE,
            Self::DirectN2bV1 => N2B_SOURCE,
            Self::StateInitV1 | Self::StateAbsorbV1 | Self::MerkleLayerV1 => BLAKE_SOURCE,
            Self::StateExpandInPlaceV1
            | Self::StateFinalizeInPlaceV1
            | Self::MerkleLayerInPlaceV1 => IN_PLACE_SOURCE,
        }
    }

    pub(super) fn source_declares_entry(self, source: &[u8]) -> bool {
        let Ok(source) = core::str::from_utf8(source) else {
            return false;
        };
        let Some(source) = source_without_comments_or_literals(source) else {
            return false;
        };
        let Some(source) = source_without_preprocessor_regions(&source) else {
            return false;
        };
        let canonical = strip_ascii_whitespace(&source);
        if canonical.match_indices(self.wrapper_symbol()).count() != 1 {
            return false;
        }
        let mut expected = format!("extern\"C\"int{}(", self.wrapper_symbol());
        for (index, argument) in self.arguments().iter().enumerate() {
            if index != 0 {
                expected.push(',');
            }
            expected.push_str(argument.kind.c_type());
            expected.push_str(argument.name);
        }
        expected.push_str("){");
        canonical.find(&expected).is_some_and(|start| {
            canonical[..start]
                .bytes()
                .next_back()
                .is_none_or(|byte| !is_identifier_byte(byte))
        })
    }
}

const DIRECT_B2N_ARGUMENTS: [BaseCommitAbiArgument; 8] = [
    argument(
        0,
        "inputs",
        BaseCommitAbiArgumentKind::DeviceConstPointerTableU32,
        BaseCommitAbiAccess::ReadSourceEvaluations,
    ),
    argument(
        1,
        "retained_outputs",
        BaseCommitAbiArgumentKind::DeviceMutPointerTableConstU32,
        BaseCommitAbiAccess::WriteRetainedStageTwo,
    ),
    argument(
        2,
        "log_n",
        BaseCommitAbiArgumentKind::U32,
        BaseCommitAbiAccess::TransformLogSize,
    ),
    argument(
        3,
        "num_poly",
        BaseCommitAbiArgumentKind::U32,
        BaseCommitAbiAccess::ColumnCount,
    ),
    argument(
        4,
        "g_twiddles",
        BaseCommitAbiArgumentKind::DeviceConstPointerU32,
        BaseCommitAbiAccess::ReadTwiddles,
    ),
    argument(
        5,
        "twiddles_size",
        BaseCommitAbiArgumentKind::U32,
        BaseCommitAbiAccess::TwiddleWords,
    ),
    argument(
        6,
        "eval_domain_size",
        BaseCommitAbiArgumentKind::U32,
        BaseCommitAbiAccess::EvaluationDomainSize,
    ),
    argument(
        7,
        "stream_raw",
        BaseCommitAbiArgumentKind::CudaStream,
        BaseCommitAbiAccess::OrderedExecutionStream,
    ),
];

const DIRECT_N2B_ARGUMENTS: [BaseCommitAbiArgument; 7] = [
    argument(
        0,
        "device_values",
        BaseCommitAbiArgumentKind::DeviceMutPointerTableU32,
        BaseCommitAbiAccess::ReadWriteRetainedEvaluation,
    ),
    argument(
        1,
        "log_n",
        BaseCommitAbiArgumentKind::Unsigned,
        BaseCommitAbiAccess::TransformLogSize,
    ),
    argument(
        2,
        "num_poly",
        BaseCommitAbiArgumentKind::Unsigned,
        BaseCommitAbiAccess::ColumnCount,
    ),
    argument(
        3,
        "g_twiddles",
        BaseCommitAbiArgumentKind::DeviceMutPointerU32,
        BaseCommitAbiAccess::ReadTwiddles,
    ),
    argument(
        4,
        "twiddles_size",
        BaseCommitAbiArgumentKind::Unsigned,
        BaseCommitAbiAccess::TwiddleWords,
    ),
    argument(
        5,
        "eval_domain_size",
        BaseCommitAbiArgumentKind::Unsigned,
        BaseCommitAbiAccess::EvaluationDomainSize,
    ),
    argument(
        6,
        "stream",
        BaseCommitAbiArgumentKind::CudaStream,
        BaseCommitAbiAccess::OrderedExecutionStream,
    ),
];

const STATE_INIT_ARGUMENTS: [BaseCommitAbiArgument; 3] = [
    argument(
        0,
        "size",
        BaseCommitAbiArgumentKind::U32,
        BaseCommitAbiAccess::RowCount,
    ),
    argument(
        1,
        "states",
        BaseCommitAbiArgumentKind::DeviceMutProgressiveBlake2sState,
        BaseCommitAbiAccess::WriteInitialState,
    ),
    argument(
        2,
        "stream",
        BaseCommitAbiArgumentKind::CudaStream,
        BaseCommitAbiAccess::OrderedExecutionStream,
    ),
];

const STATE_EXPAND_ARGUMENTS: [BaseCommitAbiArgument; 5] = [
    argument(
        0,
        "from_log_size",
        BaseCommitAbiArgumentKind::U32,
        BaseCommitAbiAccess::FromLogSize,
    ),
    argument(
        1,
        "to_log_size",
        BaseCommitAbiArgumentKind::U32,
        BaseCommitAbiAccess::ToLogSize,
    ),
    argument(
        2,
        "states",
        BaseCommitAbiArgumentKind::DeviceMutProgressiveBlake2sState,
        BaseCommitAbiAccess::ReadWriteState,
    ),
    argument(
        3,
        "scratch_pair",
        BaseCommitAbiArgumentKind::DeviceMutProgressiveBlake2sState,
        BaseCommitAbiAccess::ScratchPair,
    ),
    argument(
        4,
        "stream",
        BaseCommitAbiArgumentKind::CudaStream,
        BaseCommitAbiAccess::OrderedExecutionStream,
    ),
];

const STATE_ABSORB_ARGUMENTS: [BaseCommitAbiArgument; 6] = [
    argument(
        0,
        "size",
        BaseCommitAbiArgumentKind::U32,
        BaseCommitAbiAccess::RowCount,
    ),
    argument(
        1,
        "number_of_columns",
        BaseCommitAbiArgumentKind::U32,
        BaseCommitAbiAccess::ColumnCount,
    ),
    argument(
        2,
        "absorbed_columns_before",
        BaseCommitAbiArgumentKind::U32,
        BaseCommitAbiAccess::AbsorbedColumnCount,
    ),
    argument(
        3,
        "columns",
        BaseCommitAbiArgumentKind::DeviceMutPointerTableU32,
        BaseCommitAbiAccess::ReadRetainedEvaluations,
    ),
    argument(
        4,
        "states",
        BaseCommitAbiArgumentKind::DeviceMutProgressiveBlake2sState,
        BaseCommitAbiAccess::ReadWriteState,
    ),
    argument(
        5,
        "stream",
        BaseCommitAbiArgumentKind::CudaStream,
        BaseCommitAbiAccess::OrderedExecutionStream,
    ),
];

const STATE_FINALIZE_ARGUMENTS: [BaseCommitAbiArgument; 5] = [
    argument(
        0,
        "size",
        BaseCommitAbiArgumentKind::U32,
        BaseCommitAbiAccess::RowCount,
    ),
    argument(
        1,
        "absorbed_columns",
        BaseCommitAbiArgumentKind::U32,
        BaseCommitAbiAccess::AbsorbedColumnCount,
    ),
    argument(
        2,
        "states_and_hashes",
        BaseCommitAbiArgumentKind::DeviceMutProgressiveBlake2sState,
        BaseCommitAbiAccess::ReadWriteState,
    ),
    argument(
        3,
        "scratch_pair",
        BaseCommitAbiArgumentKind::DeviceMutProgressiveBlake2sState,
        BaseCommitAbiAccess::ScratchPair,
    ),
    argument(
        4,
        "stream",
        BaseCommitAbiArgumentKind::CudaStream,
        BaseCommitAbiAccess::OrderedExecutionStream,
    ),
];

const MERKLE_IN_PLACE_ARGUMENTS: [BaseCommitAbiArgument; 4] = [
    argument(
        0,
        "output_size",
        BaseCommitAbiArgumentKind::U32,
        BaseCommitAbiAccess::OutputHashCount,
    ),
    argument(
        1,
        "hashes",
        BaseCommitAbiArgumentKind::DeviceMutBlake2sHash,
        BaseCommitAbiAccess::WriteHashes,
    ),
    argument(
        2,
        "scratch_pair",
        BaseCommitAbiArgumentKind::DeviceMutProgressiveBlake2sState,
        BaseCommitAbiAccess::ScratchPair,
    ),
    argument(
        3,
        "stream",
        BaseCommitAbiArgumentKind::CudaStream,
        BaseCommitAbiAccess::OrderedExecutionStream,
    ),
];

const MERKLE_ARGUMENTS: [BaseCommitAbiArgument; 4] = [
    argument(
        0,
        "previous_layer",
        BaseCommitAbiArgumentKind::DeviceConstBlake2sHash,
        BaseCommitAbiAccess::ReadPreviousHashes,
    ),
    argument(
        1,
        "output_size",
        BaseCommitAbiArgumentKind::U32,
        BaseCommitAbiAccess::OutputHashCount,
    ),
    argument(
        2,
        "result",
        BaseCommitAbiArgumentKind::DeviceMutBlake2sHash,
        BaseCommitAbiAccess::WriteHashes,
    ),
    argument(
        3,
        "stream",
        BaseCommitAbiArgumentKind::CudaStream,
        BaseCommitAbiAccess::OrderedExecutionStream,
    ),
];

const fn argument(
    ordinal: u8,
    name: &'static str,
    kind: BaseCommitAbiArgumentKind,
    access: BaseCommitAbiAccess,
) -> BaseCommitAbiArgument {
    BaseCommitAbiArgument {
        ordinal,
        name,
        kind,
        access,
    }
}

fn strip_ascii_whitespace(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect()
}

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

/// Remove directives and every conditional region instead of attempting to
/// emulate the build's preprocessor configuration. A checked entry must be an
/// unconditional definition in ordinary C++ tokens.
fn source_without_preprocessor_regions(value: &str) -> Option<String> {
    let mut output = String::with_capacity(value.len());
    let mut conditional_depth = 0usize;
    let mut continuation = false;
    for line in value.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let directive = !continuation && trimmed.starts_with('#');
        if directive {
            let body = trimmed.strip_prefix('#')?.trim_start();
            let end = body
                .bytes()
                .position(|byte| !(byte.is_ascii_alphanumeric() || byte == b'_'))
                .unwrap_or(body.len());
            match &body[..end] {
                "if" | "ifdef" | "ifndef" => {
                    conditional_depth = conditional_depth.checked_add(1)?;
                }
                "elif" | "else" if conditional_depth == 0 => return None,
                "elif" | "else" => {}
                "endif" => {
                    conditional_depth = conditional_depth.checked_sub(1)?;
                }
                _ => {}
            }
        }
        if directive || continuation || conditional_depth != 0 {
            output.extend(line.chars().map(|character| {
                if matches!(character, '\n' | '\r') {
                    character
                } else {
                    ' '
                }
            }));
        } else {
            output.push_str(line);
        }
        continuation = (directive || continuation) && directive_continues(line);
    }
    if conditional_depth == 0 && !continuation {
        Some(output)
    } else {
        None
    }
}

fn directive_continues(line: &str) -> bool {
    line.trim_end_matches(['\n', '\r'])
        .trim_end_matches(|character: char| character.is_ascii_whitespace())
        .ends_with('\\')
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
