use super::*;

pub(super) fn b2n_interval_arguments(
    input_ordinal: u8,
    output_ordinal: u8,
    log_size: u32,
    column_base: u32,
    columns: u32,
    min_stage: u32,
    max_stage: u32,
    rescale: Option<u32>,
) -> Result<Vec<BaseCommitKernelArgument>, BaseCommitAuthorityError> {
    let pointer_offset = pointer_table_byte_offset(column_base);
    let mut arguments = vec![
        buffer_argument("input", wrapper_buffer(input_ordinal, pointer_offset)),
        buffer_argument("output", wrapper_buffer(output_ordinal, pointer_offset)),
        u32_argument("log_n", log_size),
        u32_argument("num_poly", columns),
        u32_argument("min_stage", min_stage),
        u32_argument("max_stage", max_stage),
        buffer_argument(
            "g_twiddles",
            dependency_suffix(BaseCommitDependencyRole::InverseTwiddles, 0),
        ),
    ];
    if let Some(value) = rescale {
        arguments.push(m31_argument("rescale_factor", value));
    }
    Ok(arguments)
}

pub(super) fn b2n_stage_arguments(
    log_size: u32,
    column_base: u32,
    stage: u32,
) -> Result<Vec<BaseCommitKernelArgument>, BaseCommitAuthorityError> {
    let pointer_offset = pointer_table_byte_offset(column_base);
    let input_ordinal = if stage == 1 { 0 } else { 1 };
    Ok(vec![
        buffer_argument("input", wrapper_buffer(input_ordinal, pointer_offset)),
        buffer_argument("output", wrapper_buffer(1, pointer_offset)),
        u32_argument("log_n", log_size),
        u32_argument("stage", stage),
        buffer_argument(
            "layer_twiddles",
            dependency_suffix(
                BaseCommitDependencyRole::InverseTwiddles,
                word_byte_offset(b2n_twiddle_word_offset(log_size, stage)?),
            ),
        ),
        m31_argument("rescale_factor", rescale_factor(log_size)?),
    ])
}

pub(super) fn n2b_interval_arguments(
    log_size: u32,
    column_base: u32,
    columns: u32,
    min_stage: u32,
    max_stage: Option<u32>,
) -> Result<Vec<BaseCommitKernelArgument>, BaseCommitAuthorityError> {
    let pointer_offset = pointer_table_byte_offset(column_base);
    let mut arguments = vec![
        buffer_argument("input", wrapper_buffer(0, pointer_offset)),
        buffer_argument("output", wrapper_buffer(0, pointer_offset)),
        u32_argument("log_n", log_size),
        u32_argument("num_poly", columns),
        u32_argument("min_stage", min_stage),
    ];
    if let Some(max_stage) = max_stage {
        arguments.push(u32_argument("max_stage", max_stage));
    }
    arguments.push(buffer_argument(
        "g_twiddles",
        dependency_suffix(BaseCommitDependencyRole::ForwardTwiddles, 0),
    ));
    Ok(arguments)
}

pub(super) fn n2b_stage_arguments(
    log_size: u32,
    column_base: u32,
    stage: u32,
) -> Result<Vec<BaseCommitKernelArgument>, BaseCommitAuthorityError> {
    let pointer_offset = pointer_table_byte_offset(column_base);
    Ok(vec![
        buffer_argument("input", wrapper_buffer(0, pointer_offset)),
        buffer_argument("output", wrapper_buffer(0, pointer_offset)),
        u32_argument("log_n", log_size),
        u32_argument("stage", stage),
        buffer_argument(
            "layer_twiddles",
            dependency_suffix(
                BaseCommitDependencyRole::ForwardTwiddles,
                word_byte_offset(n2b_twiddle_word_offset(log_size, stage)?),
            ),
        ),
    ])
}

pub(super) fn expand_arguments(
    source_pair_first: u32,
    destination_pair_first: u32,
    pair_count: u32,
    expansion: u32,
    sources: BaseCommitExecutionBuffer,
    destinations: BaseCommitExecutionBuffer,
) -> Vec<BaseCommitKernelArgument> {
    vec![
        u32_argument("source_pair_first", source_pair_first),
        u32_argument("destination_pair_first", destination_pair_first),
        u32_argument("pair_count", pair_count),
        u32_argument("expansion", expansion),
        buffer_argument("sources", sources),
        buffer_argument("destinations", destinations),
    ]
}

pub(super) fn finalize_arguments(
    size: u32,
    absorbed_columns: u32,
    states: BaseCommitExecutionBuffer,
    result: BaseCommitExecutionBuffer,
) -> Vec<BaseCommitKernelArgument> {
    vec![
        u32_argument("size", size),
        u32_argument("absorbed_columns", absorbed_columns),
        buffer_argument("states", states),
        buffer_argument("result", result),
    ]
}

pub(super) fn merkle_arguments(
    size: u32,
    previous_layer: BaseCommitExecutionBuffer,
    result: BaseCommitExecutionBuffer,
) -> Vec<BaseCommitKernelArgument> {
    vec![
        u32_argument("size", size),
        u32_argument("number_of_columns", 0),
        null_argument("data"),
        buffer_argument("prev_layer", previous_layer),
        buffer_argument("result", result),
    ]
}

pub(super) fn b2n_twiddle_word_offset(
    log_size: u32,
    stage: u32,
) -> Result<u32, BaseCommitAuthorityError> {
    if stage <= 2 {
        return Ok(0);
    }
    pow2(log_size - 1)?
        .checked_sub(pow2(log_size - stage + 1)?)
        .ok_or(BaseCommitAuthorityError::InvalidExecutionManifest)
}

pub(super) fn n2b_twiddle_word_offset(
    log_size: u32,
    stage: u32,
) -> Result<u32, BaseCommitAuthorityError> {
    if stage == log_size {
        return Ok(0);
    }
    pow2(log_size - 1)?
        .checked_sub(pow2(stage)?)
        .ok_or(BaseCommitAuthorityError::InvalidExecutionManifest)
}

pub(super) fn rescale_factor(log_size: u32) -> Result<u32, BaseCommitAuthorityError> {
    1u32.checked_shl(31 - log_size)
        .ok_or(BaseCommitAuthorityError::InvalidExecutionManifest)
}

fn pointer_table_byte_offset(columns: u32) -> u64 {
    u64::from(columns) * core::mem::size_of::<usize>() as u64
}

pub(super) fn state_byte_offset(rows: u32) -> u64 {
    u64::from(rows) * PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES as u64
}

pub(super) fn hash_byte_offset(hashes: u32) -> u64 {
    u64::from(hashes) * core::mem::size_of::<Blake2sHash>() as u64
}

fn word_byte_offset(words: u32) -> u64 {
    u64::from(words) * core::mem::size_of::<u32>() as u64
}

pub(super) const fn wrapper_buffer(ordinal: u8, byte_offset: u64) -> BaseCommitExecutionBuffer {
    BaseCommitExecutionBuffer::WrapperArgument {
        ordinal,
        byte_offset,
    }
}

const fn dependency_suffix(
    role: BaseCommitDependencyRole,
    byte_offset: u64,
) -> BaseCommitExecutionBuffer {
    BaseCommitExecutionBuffer::DependencySuffix { role, byte_offset }
}

pub(super) const fn buffer_argument(
    name: &'static str,
    buffer: BaseCommitExecutionBuffer,
) -> BaseCommitKernelArgument {
    BaseCommitKernelArgument {
        name,
        value: BaseCommitKernelArgumentValue::Buffer(buffer),
    }
}

pub(super) const fn u32_argument(name: &'static str, value: u32) -> BaseCommitKernelArgument {
    BaseCommitKernelArgument {
        name,
        value: BaseCommitKernelArgumentValue::U32(value),
    }
}

const fn m31_argument(name: &'static str, value: u32) -> BaseCommitKernelArgument {
    BaseCommitKernelArgument {
        name,
        value: BaseCommitKernelArgumentValue::M31(value),
    }
}

const fn null_argument(name: &'static str) -> BaseCommitKernelArgument {
    BaseCommitKernelArgument {
        name,
        value: BaseCommitKernelArgumentValue::Null,
    }
}

pub(super) const fn device_copy(
    source: BaseCommitExecutionBuffer,
    destination: BaseCommitExecutionBuffer,
    bytes: u64,
) -> BaseCommitExecutionStep {
    BaseCommitExecutionStep::DeviceCopyD2D {
        source,
        destination,
        bytes,
    }
}

pub(super) fn kernel(
    symbol: &'static str,
    grid_x: u32,
    block_x: u32,
    arguments: Vec<BaseCommitKernelArgument>,
) -> BaseCommitExecutionStep {
    kernel_3d(symbol, [grid_x, 1, 1], [block_x, 1, 1], arguments)
}

pub(super) fn kernel_3d(
    symbol: &'static str,
    grid: [u32; 3],
    block: [u32; 3],
    arguments: Vec<BaseCommitKernelArgument>,
) -> BaseCommitExecutionStep {
    BaseCommitExecutionStep::KernelLaunch(BaseCommitKernelLaunch {
        symbol,
        grid,
        block,
        cluster: None,
        dynamic_shared_bytes: 0,
        cooperative: false,
        arguments,
    })
}
