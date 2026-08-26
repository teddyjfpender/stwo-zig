//! Verifier-owned fixed profile derivation for a base RISC-V recursive leaf.
//!
//! Geometry is reconstructed from an independently admitted statement and the
//! successful native verifier capture. Stable program and table-layout IDs are
//! derived from protocol authorities, never supplied by proof bytes.

const std = @import("std");
const stwo_core = @import("stwo_core");
const statement_mod = @import("../air/statement.zig");
const statement_validation = @import("../prover/statement_validation.zig");
const prover_types = @import("../prover/types.zig");
const component_order = @import("../air/component_order.zig");
const relation = @import("../air/lang/relation.zig");
const static_registry = @import("../air/lang/static_profile_registry.zig");
const transcript_claims = @import("../air/transcript/claims.zig");
const witness_layout = @import("../witness_layout.zig");
const channel = @import("poseidon2_channel.zig");
const engine = @import("engine.zig");
const fixed_profile = @import("fixed_profile.zig");
const fixed_wire = @import("fixed_wire.zig");
const protocol = @import("protocol.zig");

const ProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(engine.Hasher);
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const AIR_PROGRAM_ID_VERSION: u16 = 1;
pub const TABLE_LAYOUT_ID_VERSION: u16 = 1;
pub const AIR_PROGRAM_ID_DOMAIN: u32 = 0x4c41_4952; // "LAIR"
pub const TABLE_LAYOUT_ID_DOMAIN: u32 = 0x4c54_424c; // "LTBL"

pub const Error = prover_types.ProverError || fixed_profile.Error ||
    fixed_wire.Error || error{
    CaptureShapeMismatch,
    InvalidProfileCount,
};

/// Identity of the currently admitted typed VM leaf program surface.
///
/// This binds the frozen recursive PCS, all seventeen typed opcode semantic
/// programs and their physical/lookup geometry, canonical component/table
/// order, the full universal relation order, and the Sail-authoritative
/// witness layout. Infrastructure semantic-manifest completion remains a
/// release item; changing that authority must bump this version and preimage.
pub fn airProgramId() channel.Digest {
    var hash = Sha256.init(.{});
    hash.update("stwo-zig/riscv/recursion/base-leaf-air-program/v1\x00");
    hashInt(&hash, u16, AIR_PROGRAM_ID_VERSION);
    for (protocol.PROTOCOL_ID_WORDS) |word| hashInt(&hash, u32, word);
    const relation_digest = relation.registryOrderDigest();
    const layout_digest = witness_layout.digest();
    hash.update(&relation_digest);
    hash.update(&layout_digest);
    hashInt(&hash, u16, component_order.TRANSCRIPT_COMPONENT_COUNT);
    for (component_order.OPCODE_FAMILIES) |family| {
        hashInt(&hash, u8, @intFromEnum(family));
    }
    for (component_order.LOOKUP_TABLES) |table| {
        hashInt(&hash, u8, @intFromEnum(table));
    }
    for (static_registry.DESCRIPTORS) |descriptor| {
        hashInt(&hash, u8, @intFromEnum(descriptor.family));
        hashInt(&hash, u32, descriptor.physical_main_columns);
        hashInt(&hash, u32, descriptor.authored_constraint_roots);
        hashInt(&hash, u32, descriptor.authored_lookup_events);
        hashInt(&hash, u8, descriptor.audited_lookup_batch_size);
        hash.update(&descriptor.semantic_program_digest);
    }
    const digest = hash.finalResult();
    return channel.hashBytes(&digest, AIR_PROGRAM_ID_DOMAIN);
}

/// Identity of the exact ordered shard/table geometry admitted by a statement.
pub fn tableLayoutId(statement: *const statement_mod.RiscVStatement) channel.Digest {
    var hash = Sha256.init(.{});
    hash.update("stwo-zig/riscv/recursion/base-leaf-table-layout/v1\x00");
    hashInt(&hash, u16, TABLE_LAYOUT_ID_VERSION);
    hashInt(&hash, u32, statement.n_components);
    hashInt(&hash, u32, statement.n_infra);
    hashInt(&hash, u32, @intCast(statement.nPreprocessedColumns()));
    hashInt(&hash, u32, @intCast(statement.nMainColumns()));
    hashInt(&hash, u32, @intCast(statement.nInteractionColumns()));
    for (statement.component_descs[0..statement.n_components]) |descriptor| {
        hashInt(&hash, u8, @intFromEnum(descriptor.family));
        hashInt(&hash, u32, descriptor.log_size);
        hashInt(&hash, u32, descriptor.n_rows);
        hashInt(&hash, u32, descriptor.n_columns);
    }
    for (statement.infra_descs[0..statement.n_infra]) |descriptor| {
        hashInt(&hash, u32, @intFromEnum(descriptor.kind));
        hashInt(&hash, u32, descriptor.log_size);
        hashInt(&hash, u32, descriptor.n_rows);
        hashInt(&hash, u32, descriptor.n_columns);
    }
    const digest = hash.finalResult();
    return channel.hashBytes(&digest, TABLE_LAYOUT_ID_DOMAIN);
}

/// Derives and validates the exact fixed shape selected by a generated wire
/// type. The native verifier has already authenticated `capture`; this routine
/// additionally proves its geometry agrees with the statement and with every
/// comptime wire dimension before returning an identity-bearing shape.
pub fn deriveShape(
    comptime dimensions: fixed_wire.Dimensions,
    statement: *const statement_mod.RiscVStatement,
    capture: *const ProofCapture,
) Error!fixed_profile.ProofShapeV1 {
    try statement_validation.validate(statement.*, .proof);
    if (capture.commitments.len != fixed_profile.TREE_COUNT or
        capture.column_log_sizes.len != fixed_profile.TREE_COUNT or
        capture.trace_paths.len != fixed_profile.TREE_COUNT or
        capture.queries.raw.len != protocol.FRI_QUERY_COUNT or
        capture.sampled_values.len != dimensions.sampled_value_count or
        capture.queried_values.len != dimensions.queried_value_count or
        capture.fri.layers.len != dimensions.fri_layer_count)
    {
        return error.CaptureShapeMismatch;
    }

    const composition_columns = stwo_core.verifier_types.compositionColumnCount(
        stwo_core.verifier_types.COMPOSITION_LOG_SPLIT,
        stwo_core.fields.qm31.SECURE_EXTENSION_DEGREE,
    ) orelse return error.CaptureShapeMismatch;
    const tree_column_counts_usize = [fixed_profile.TREE_COUNT]usize{
        statement.nPreprocessedColumns(),
        statement.nMainColumns(),
        statement.nInteractionColumns(),
        composition_columns,
    };
    var tree_column_counts: [fixed_profile.TREE_COUNT]u32 = undefined;
    var table_count: u32 = 0;
    for (tree_column_counts_usize, 0..) |count, index| {
        tree_column_counts[index] = std.math.cast(u32, count) orelse
            return error.InvalidProfileCount;
        table_count = std.math.add(u32, table_count, tree_column_counts[index]) catch
            return error.InvalidProfileCount;
    }

    var tree_heights: [fixed_profile.TREE_COUNT]u32 = undefined;
    for (capture.trace_paths, capture.column_log_sizes, tree_column_counts, 0..) |
        paths,
        logs,
        expected_column_count,
        index,
    | {
        if (logs.len != @as(usize, expected_column_count) or logs.len == 0)
            return error.CaptureShapeMismatch;
        var maximum_log: u32 = 0;
        for (logs) |log_size| maximum_log = @max(maximum_log, log_size);
        if (maximum_log != paths.path_depth)
            return error.CaptureShapeMismatch;
        tree_heights[index] = paths.path_depth;
    }
    const composition_height = tree_heights[fixed_profile.TREE_COUNT - 1];
    const column_log_degree = std.math.sub(
        u32,
        composition_height,
        protocol.PCS_CONFIG.fri_config.log_blowup_factor,
    ) catch return error.CaptureShapeMismatch;
    const fri = try fixed_profile.FriSchedule.init(
        column_log_degree,
        protocol.PCS_CONFIG.fri_config,
    );

    const shape = fixed_profile.ProofShapeV1{
        .air_program_id = airProgramId(),
        .preprocessing_id = capture.commitments[0],
        .table_layout_id = tableLayoutId(statement),
        .table_count = table_count,
        .claimed_sum_count = transcript_claims.COMPONENT_COUNT,
        .sampled_value_count = std.math.cast(
            u32,
            capture.sampled_values.len,
        ) orelse return error.InvalidProfileCount,
        .preprocessed_column_count = tree_column_counts[0],
        .tree_column_counts = tree_column_counts,
        .tree_heights = tree_heights,
        .column_log_degree = column_log_degree,
        .proof_wire_bytes = fixed_wire.serializedByteCount(dimensions),
        .fri = fri,
    };
    try shape.validate();
    try fixed_wire.validateDimensionsAgainstShape(dimensions, shape);

    for (capture.fri.layers, shape.fri.active()) |layer, round| {
        if (layer.fold_step != round.fold_step or
            layer.fold_width != round.fold_width or
            layer.path_depth != round.authentication_path_depth)
        {
            return error.CaptureShapeMismatch;
        }
    }
    return shape;
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

test "recursion leaf profile: AIR identity is stable nonzero and authority-bound" {
    const first = airProgramId();
    try std.testing.expectEqual(first, airProgramId());
    try std.testing.expect(!std.meta.eql(first, [_]u32{0} ** channel.RATE));
    try std.testing.expect(!std.meta.eql(first, protocol.PROTOCOL_ID_WORDS));
}
