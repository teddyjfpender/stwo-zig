//! Native wrapper ABI descriptors for the memory Base-trace graph.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MemoryBaseTraceAbi {
    AddressV1 = 1,
    ValueV1 = 2,
    Rc99V1 = 3,
    AddressSlicedV2 = 4,
    ValueSlicedV2 = 5,
}

impl MemoryBaseTraceAbi {
    pub const fn entry_symbol(self) -> &'static str {
        match self {
            Self::AddressV1 => "memory_address_base_trace_on",
            Self::ValueV1 => "memory_value_base_trace_on",
            Self::Rc99V1 => "memory_rc99_count_on",
            Self::AddressSlicedV2 => "memory_address_base_trace_sliced_on",
            Self::ValueSlicedV2 => "memory_value_base_trace_sliced_on",
        }
    }

    pub const fn kernel_symbol(self) -> &'static str {
        match self {
            Self::AddressV1 => "memory_address_base_trace_kernel",
            Self::ValueV1 => "memory_value_base_trace_kernel",
            Self::Rc99V1 => "rc99_count_on_kernel",
            Self::AddressSlicedV2 => "memory_address_base_trace_sliced_kernel",
            Self::ValueSlicedV2 => "memory_value_base_trace_sliced_kernel",
        }
    }

    pub const fn arguments(self) -> &'static [MemoryBaseTraceAbiArgument] {
        match self {
            Self::AddressV1 => &ADDRESS_V1_ARGUMENTS,
            Self::ValueV1 => &VALUE_V1_ARGUMENTS,
            Self::Rc99V1 => &RC99_ARGUMENTS,
            Self::AddressSlicedV2 => &ADDRESS_SLICED_V2_ARGUMENTS,
            Self::ValueSlicedV2 => &VALUE_SLICED_V2_ARGUMENTS,
        }
    }

    pub(super) fn source_declares_entry(self, source: &[u8]) -> bool {
        let Ok(source) = core::str::from_utf8(source) else {
            return false;
        };
        let canonical_source = strip_ascii_whitespace(source);
        let mut expected = format!("extern\"C\"int{}(", self.entry_symbol());
        for (index, argument) in self.arguments().iter().enumerate() {
            if index != 0 {
                expected.push(',');
            }
            expected.push_str(argument.kind.c_type());
            expected.push_str(argument.name);
        }
        expected.push(')');
        canonical_source.contains(&expected)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MemoryBaseTraceAbiArgumentKind {
    DeviceConstPointerU32 = 1,
    /// A host table of device pointers. Sliced-v2 value entries are all null
    /// exactly when `source_slice_words == 0`; no source is then dereferenced.
    HostConstPointerTableU32 = 2,
    HostMutPointerTableU32 = 3,
    DeviceMutPointerU32 = 4,
    U32 = 5,
    CudaStream = 6,
}

impl MemoryBaseTraceAbiArgumentKind {
    const fn c_type(self) -> &'static str {
        match self {
            Self::DeviceConstPointerU32 => "constuint32_t*",
            Self::HostConstPointerTableU32 => "constuint32_t*const*",
            Self::HostMutPointerTableU32 => "uint32_t*const*",
            Self::DeviceMutPointerU32 => "uint32_t*",
            Self::U32 => "uint32_t",
            Self::CudaStream => "cudaStream_t",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MemoryBaseTraceAbiAccess {
    ReadAddressTable = 1,
    ReadMultiplicity = 2,
    ReadValueSources = 3,
    ReadRc99Limbs = 4,
    ReadRc99Lut = 5,
    WriteOutputs = 6,
    AtomicRc99Counts = 7,
    AddressCount = 8,
    SourceColumnWords = 9,
    SourceOffset = 10,
    MultiplicityWords = 11,
    RowCount = 12,
    LimbCount = 13,
    PairCount = 14,
    Rc99TableWords = 15,
    OrderedExecutionStream = 16,
    AddressIdWords = 17,
    SourceSliceWords = 18,
    MultiplicitySliceWords = 19,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryBaseTraceAbiArgument {
    pub ordinal: u8,
    pub name: &'static str,
    pub kind: MemoryBaseTraceAbiArgumentKind,
    pub access: MemoryBaseTraceAbiAccess,
}

const ADDRESS_V1_ARGUMENTS: [MemoryBaseTraceAbiArgument; 7] = [
    arg(
        0,
        "raw_addr_to_id",
        MemoryBaseTraceAbiArgumentKind::DeviceConstPointerU32,
        MemoryBaseTraceAbiAccess::ReadAddressTable,
    ),
    arg(
        1,
        "n_addrs",
        MemoryBaseTraceAbiArgumentKind::U32,
        MemoryBaseTraceAbiAccess::AddressCount,
    ),
    arg(
        2,
        "multiplicities",
        MemoryBaseTraceAbiArgumentKind::DeviceConstPointerU32,
        MemoryBaseTraceAbiAccess::ReadMultiplicity,
    ),
    arg(
        3,
        "count_words",
        MemoryBaseTraceAbiArgumentKind::U32,
        MemoryBaseTraceAbiAccess::MultiplicityWords,
    ),
    arg(
        4,
        "column_length",
        MemoryBaseTraceAbiArgumentKind::U32,
        MemoryBaseTraceAbiAccess::RowCount,
    ),
    arg(
        5,
        "outputs_host",
        MemoryBaseTraceAbiArgumentKind::HostMutPointerTableU32,
        MemoryBaseTraceAbiAccess::WriteOutputs,
    ),
    arg(
        6,
        "stream",
        MemoryBaseTraceAbiArgumentKind::CudaStream,
        MemoryBaseTraceAbiAccess::OrderedExecutionStream,
    ),
];

const VALUE_V1_ARGUMENTS: [MemoryBaseTraceAbiArgument; 9] = [
    arg(
        0,
        "sources_host",
        MemoryBaseTraceAbiArgumentKind::HostConstPointerTableU32,
        MemoryBaseTraceAbiAccess::ReadValueSources,
    ),
    arg(
        1,
        "n_limbs",
        MemoryBaseTraceAbiArgumentKind::U32,
        MemoryBaseTraceAbiAccess::LimbCount,
    ),
    arg(
        2,
        "source_words",
        MemoryBaseTraceAbiArgumentKind::U32,
        MemoryBaseTraceAbiAccess::SourceColumnWords,
    ),
    arg(
        3,
        "source_offset",
        MemoryBaseTraceAbiArgumentKind::U32,
        MemoryBaseTraceAbiAccess::SourceOffset,
    ),
    arg(
        4,
        "multiplicities",
        MemoryBaseTraceAbiArgumentKind::DeviceConstPointerU32,
        MemoryBaseTraceAbiAccess::ReadMultiplicity,
    ),
    arg(
        5,
        "count_words",
        MemoryBaseTraceAbiArgumentKind::U32,
        MemoryBaseTraceAbiAccess::MultiplicityWords,
    ),
    arg(
        6,
        "column_length",
        MemoryBaseTraceAbiArgumentKind::U32,
        MemoryBaseTraceAbiAccess::RowCount,
    ),
    arg(
        7,
        "outputs_host",
        MemoryBaseTraceAbiArgumentKind::HostMutPointerTableU32,
        MemoryBaseTraceAbiAccess::WriteOutputs,
    ),
    arg(
        8,
        "stream",
        MemoryBaseTraceAbiArgumentKind::CudaStream,
        MemoryBaseTraceAbiAccess::OrderedExecutionStream,
    ),
];

const ADDRESS_SLICED_V2_ARGUMENTS: [MemoryBaseTraceAbiArgument; 7] = [
    arg(
        0,
        "address_ids",
        MemoryBaseTraceAbiArgumentKind::DeviceConstPointerU32,
        MemoryBaseTraceAbiAccess::ReadAddressTable,
    ),
    arg(
        1,
        "address_id_words",
        MemoryBaseTraceAbiArgumentKind::U32,
        MemoryBaseTraceAbiAccess::AddressIdWords,
    ),
    arg(
        2,
        "multiplicities",
        MemoryBaseTraceAbiArgumentKind::DeviceConstPointerU32,
        MemoryBaseTraceAbiAccess::ReadMultiplicity,
    ),
    arg(
        3,
        "multiplicity_words",
        MemoryBaseTraceAbiArgumentKind::U32,
        MemoryBaseTraceAbiAccess::MultiplicitySliceWords,
    ),
    arg(
        4,
        "column_length",
        MemoryBaseTraceAbiArgumentKind::U32,
        MemoryBaseTraceAbiAccess::RowCount,
    ),
    arg(
        5,
        "outputs_host",
        MemoryBaseTraceAbiArgumentKind::HostMutPointerTableU32,
        MemoryBaseTraceAbiAccess::WriteOutputs,
    ),
    arg(
        6,
        "stream",
        MemoryBaseTraceAbiArgumentKind::CudaStream,
        MemoryBaseTraceAbiAccess::OrderedExecutionStream,
    ),
];

const VALUE_SLICED_V2_ARGUMENTS: [MemoryBaseTraceAbiArgument; 8] = [
    arg(
        0,
        "sources_host",
        MemoryBaseTraceAbiArgumentKind::HostConstPointerTableU32,
        MemoryBaseTraceAbiAccess::ReadValueSources,
    ),
    arg(
        1,
        "n_limbs",
        MemoryBaseTraceAbiArgumentKind::U32,
        MemoryBaseTraceAbiAccess::LimbCount,
    ),
    arg(
        2,
        "source_slice_words",
        MemoryBaseTraceAbiArgumentKind::U32,
        MemoryBaseTraceAbiAccess::SourceSliceWords,
    ),
    arg(
        3,
        "multiplicities",
        MemoryBaseTraceAbiArgumentKind::DeviceConstPointerU32,
        MemoryBaseTraceAbiAccess::ReadMultiplicity,
    ),
    arg(
        4,
        "multiplicity_slice_words",
        MemoryBaseTraceAbiArgumentKind::U32,
        MemoryBaseTraceAbiAccess::MultiplicitySliceWords,
    ),
    arg(
        5,
        "column_length",
        MemoryBaseTraceAbiArgumentKind::U32,
        MemoryBaseTraceAbiAccess::RowCount,
    ),
    arg(
        6,
        "outputs_host",
        MemoryBaseTraceAbiArgumentKind::HostMutPointerTableU32,
        MemoryBaseTraceAbiAccess::WriteOutputs,
    ),
    arg(
        7,
        "stream",
        MemoryBaseTraceAbiArgumentKind::CudaStream,
        MemoryBaseTraceAbiAccess::OrderedExecutionStream,
    ),
];

const RC99_ARGUMENTS: [MemoryBaseTraceAbiArgument; 7] = [
    arg(
        0,
        "limb_cols_host",
        MemoryBaseTraceAbiArgumentKind::HostConstPointerTableU32,
        MemoryBaseTraceAbiAccess::ReadRc99Limbs,
    ),
    arg(
        1,
        "n_pairs",
        MemoryBaseTraceAbiArgumentKind::U32,
        MemoryBaseTraceAbiAccess::PairCount,
    ),
    arg(
        2,
        "column_length",
        MemoryBaseTraceAbiArgumentKind::U32,
        MemoryBaseTraceAbiAccess::RowCount,
    ),
    arg(
        3,
        "input_to_row_lut",
        MemoryBaseTraceAbiArgumentKind::DeviceConstPointerU32,
        MemoryBaseTraceAbiAccess::ReadRc99Lut,
    ),
    arg(
        4,
        "rc_table_size",
        MemoryBaseTraceAbiArgumentKind::U32,
        MemoryBaseTraceAbiAccess::Rc99TableWords,
    ),
    arg(
        5,
        "counts",
        MemoryBaseTraceAbiArgumentKind::DeviceMutPointerU32,
        MemoryBaseTraceAbiAccess::AtomicRc99Counts,
    ),
    arg(
        6,
        "stream",
        MemoryBaseTraceAbiArgumentKind::CudaStream,
        MemoryBaseTraceAbiAccess::OrderedExecutionStream,
    ),
];

const fn arg(
    ordinal: u8,
    name: &'static str,
    kind: MemoryBaseTraceAbiArgumentKind,
    access: MemoryBaseTraceAbiAccess,
) -> MemoryBaseTraceAbiArgument {
    MemoryBaseTraceAbiArgument {
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
