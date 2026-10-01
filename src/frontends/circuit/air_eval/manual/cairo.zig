//! Hand-written Cairo-AIR evaluators: ports of
//! `crates/cairo_verifier/src/components/{memory_address_to_id,memory_id_to_big,verify_bitwise_xor_12}.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). Each function is the Rust
//! `CircuitEval::evaluate` body, in its call order. The upstream constants
//! they depend on come from the projection header, not from the Cairo
//! frontend.

const std = @import("std");
const component_utils = @import("../../common/component_utils.zig");
const component_table = @import("../component_table.zig");
const xor_12 = @import("verify_bitwise_xor_12.zig");
const tree = @import("eval_tree.zig");

const Shape = component_table.Shape;
const constantM31 = tree.constantM31;
const modulus: u64 = 0x7fff_ffff;

/// Relation ids hard-coded in the upstream hand-written evaluators (the
/// `VerifyBitwiseXor_12` id is shared with the circuit AIR, `xor_12.relation_id`).
const memory_address_to_id_relation_id: u32 = 1444891767;
const memory_id_to_big_relation_id: u32 = 1662111297;

/// The projection-header constants these evaluators read.
pub const Constants = struct {
    large_memory_value_id_base: u32,
    max_sequence_log_size: u32,
    memory_address_to_id_split: u32,
};

pub fn memoryAddressToIdShape(constants: Constants) Shape {
    const split: usize = constants.memory_address_to_id_split;
    return .{
        .trace_columns = 2 * split,
        .interaction_columns = 4 * ((split + 1) / 2),
        .relation_uses_per_row = &.{},
        .log_size = .dynamic,
    };
}

pub const memory_id_to_big_shape: Shape = .{
    .trace_columns = 29,
    .interaction_columns = 32,
    .relation_uses_per_row = &.{
        .{ .relation_id = "RangeCheck_9_9", .uses = 2 },
        .{ .relation_id = "RangeCheck_9_9_B", .uses = 2 },
        .{ .relation_id = "RangeCheck_9_9_C", .uses = 2 },
        .{ .relation_id = "RangeCheck_9_9_D", .uses = 2 },
        .{ .relation_id = "RangeCheck_9_9_E", .uses = 2 },
        .{ .relation_id = "RangeCheck_9_9_F", .uses = 2 },
        .{ .relation_id = "RangeCheck_9_9_G", .uses = 1 },
        .{ .relation_id = "RangeCheck_9_9_H", .uses = 1 },
    },
    .log_size = .dynamic,
};

pub const verify_bitwise_xor_12_shape: Shape = .{
    .trace_columns = xor_12.trace_columns,
    .interaction_columns = xor_12.interaction_columns,
    .relation_uses_per_row = &.{},
    .log_size = .{ .fixed = xor_12.log_size },
};

/// `memory_address_to_id::Component::evaluate`: the addresses
/// `seq + 1 + k * n_instances` of the `split` interleaved lanes.
pub fn evaluateMemoryAddressToId(interp: anytype, constants: Constants) !void {
    const ctx = interp.ctx;
    const input = interp.data.traceColumns();
    if (input.len != memoryAddressToIdShape(constants).trace_columns) return error.TraceColumnCountMismatch;
    // Addresses are offset by 1: address 0 is reserved.
    const seq = try component_utils.seqOfComponentSize(@TypeOf(ctx.*), ctx, interp.data, interp.acc.preprocessed_columns);
    var address = try ctx.add(seq, try constantM31(ctx, 1));
    for (0..constants.memory_address_to_id_split) |i| {
        if (i != 0) address = try ctx.add(address, interp.data.nInstances());
        const id = input[2 * i];
        const multiplicity = input[2 * i + 1];
        const relation = try constantM31(ctx, memory_address_to_id_relation_id);
        const numerator = try ctx.sub(ctx.zero(), multiplicity);
        try interp.acc.addToRelation(ctx, numerator, &.{ relation, address, id });
    }
}

/// `memory_id_to_big::Component { index }::evaluate`: yields the big values of
/// ids `LARGE_MEMORY_VALUE_ID_BASE + index * 2^MAX_SEQUENCE_LOG_SIZE + seq`.
pub fn evaluateMemoryIdToBig(interp: anytype, constants: Constants, index: u32) !void {
    const ctx = interp.ctx;
    const max_rows: u64 = @as(u64, 1) << @intCast(constants.max_sequence_log_size);
    // Upstream asserts the ids of this component stay within M31.
    if (constants.large_memory_value_id_base + (@as(u64, index) + 1) * max_rows - 1 >= modulus)
        return error.MemoryIdOutOfRange;
    const input = interp.data.traceColumns();
    if (input.len != memory_id_to_big_shape.trace_columns) return error.TraceColumnCountMismatch;
    const multiplicity = input[0];
    const values = input[1..];

    const seq = try component_utils.seqOfComponentSize(@TypeOf(ctx.*), ctx, interp.data, interp.acc.preprocessed_columns);
    var range_check_inputs: [29]@TypeOf(ctx.*).Var = undefined;
    @memcpy(range_check_inputs[0..28], values);
    range_check_inputs[28] = try constantM31(ctx, 1);
    _ = try interp.callByName("range_check_mem_value_n_28", &range_check_inputs);

    const offset: u32 = @intCast(constants.large_memory_value_id_base + @as(u64, index) * max_rows);
    var tuple: [30]@TypeOf(ctx.*).Var = undefined;
    tuple[0] = try constantM31(ctx, memory_id_to_big_relation_id);
    tuple[1] = try ctx.add(seq, try constantM31(ctx, offset));
    @memcpy(tuple[2..], values);
    const numerator = try ctx.sub(ctx.zero(), multiplicity);
    try interp.acc.addToRelation(ctx, numerator, &tuple);

    // The component size must not exceed 2^MAX_SEQUENCE_LOG_SIZE rows, or its
    // ids would overlap the next component's. Like the Rust range, empty when
    // the verified trace is too small for that (e.g. canonical_small leaves,
    // whose size bits stop below MAX_SEQUENCE_LOG_SIZE + 1).
    const first_checked_bit = constants.max_sequence_log_size + 1;
    for (@min(first_checked_bit, interp.data.maxComponentSizeBits())..interp.data.maxComponentSizeBits()) |bit_pos| {
        const bit = try interp.data.getNInstancesBit(ctx, bit_pos);
        try ctx.eq(bit, ctx.zero());
    }
}

/// `verify_bitwise_xor_12::Component::evaluate` (Cairo AIR): 16 lookups of
/// the 10-bit table expanded by the top two bits, then the 2^20-row check.
pub fn evaluateVerifyBitwiseXor12(interp: anytype) !void {
    const ctx = interp.ctx;
    const a_low = try interp.acc.getPreprocessedColumn(xor_12.a_column);
    const b_low = try interp.acc.getPreprocessedColumn(xor_12.b_column);
    const c_low = try interp.acc.getPreprocessedColumn(xor_12.c_column);
    const multiplicities = interp.data.traceColumns();
    const relation = try constantM31(ctx, xor_12.relation_id);
    try xor_12.addLookups(interp, relation, a_low, b_low, c_low, multiplicities);
    const size_bit = try interp.data.getNInstancesBit(ctx, xor_12.log_size);
    try ctx.eq(size_bit, ctx.one());
}
