//! Concrete AOT witness binding for the exact resident Blake arena.

const witness =
    @import("../../../../backends/cuda/runtime/traces/blake_exact.zig");
const facades = @import("facades.zig");
const geometry_mod = @import("geometry.zig");
const slots = @import("slots.zig");
const views_mod = @import("views.zig");

pub const abi_schema = @import(
    "../../../../backends/cuda/abi/schema.zig",
).KernelSchema.native_blake_exact_trace_v2;
pub const cache_key = witness.cache_key;
pub const kernel_name = witness.kernel_name;
pub const program_identity = witness.program_identity;

/// Generates both committed trace trees and the immutable relation-source
/// mirror from canonical exact-arena slots. The descriptor identity is fixed
/// by the authenticated AOT manifest; no caller callback or identity is used.
pub fn generate(
    transaction: anytype,
    invocation: facades.Invocation,
) !void {
    const shape = try validate(invocation);
    const main_xor = shape.main[3].offset_words;
    const xor_words = shape.main_words - main_xor;
    try transaction.zeroResidentSlice(
        u32,
        .trace_generation,
        slots.main_evaluations,
        main_xor,
        xor_words,
    );
    try witness.generate(transaction.proofSession(), .{
        .preprocessed = try transaction.slot(slots.preprocessed_evaluations),
        .main = try transaction.slot(slots.main_evaluations),
    }, statement(invocation.geometry));
}

pub fn validate(
    invocation: facades.Invocation,
) !witness.Layout {
    if (invocation.preprocessed_slot !=
        slots.preprocessed_evaluations or
        invocation.main_slot != slots.main_evaluations or
        invocation.interaction_slot != slots.interaction_evaluations or
        invocation.composition_slot != slots.composition_evaluations)
    {
        return error.InvalidKernelDescriptor;
    }
    try invocation.views.validate(invocation.geometry);
    const shape = try witness.Layout.init(statement(invocation.geometry));
    try validatePreprocessed(
        &shape.preprocessed,
        &invocation.views.preprocessed,
    );
    try validateGroups(&shape.main, &invocation.views.main);
    if (shape.preprocessed_words !=
        invocation.geometry.treeWords(.preprocessed) or
        shape.main_words != invocation.geometry.main_words)
    {
        return error.InvalidKernelDescriptor;
    }
    return shape;
}

fn statement(
    geometry: geometry_mod.Geometry,
) witness.Statement {
    return .{
        .log_n_rows = geometry.statement.log_n_rows,
        .n_rounds = geometry.statement.n_rounds,
    };
}

fn validatePreprocessed(
    expected: []const witness.Group,
    actual: []const views_mod.XorGroupView,
) !void {
    if (expected.len != actual.len) return error.InvalidKernelDescriptor;
    for (expected, actual) |left, right| {
        if (@as(usize, left.first_column) != right.column_offset or
            @as(usize, left.column_count) != right.column_count or
            left.log_rows != right.log_rows or
            left.offset_words != right.arena_offset_words or
            left.rowCount() != right.column_stride_words)
        {
            return error.InvalidKernelDescriptor;
        }
    }
}

fn validateGroups(
    expected: []const witness.Group,
    actual: []const views_mod.GroupView,
) !void {
    if (expected.len != actual.len) return error.InvalidKernelDescriptor;
    for (expected, actual) |left, right| {
        if (@as(usize, left.first_column) != right.column_offset or
            @as(usize, left.column_count) != right.column_count or
            left.log_rows != right.log_rows or
            left.offset_words != right.arena_offset_words or
            left.rowCount() != right.column_stride_words)
        {
            return error.InvalidKernelDescriptor;
        }
    }
}
