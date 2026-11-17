//! Canonical resident-plan identity and trace/quotient geometry projections.
const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const compact = @import("stwo_cairo_frontend").compact_verifier_interchange;
const telemetry = @import("stwo_cuda_backend").runtime.telemetry;
const quotient_topology = @import("quotient/topology.zig");
const types = @import("resident_plan_types.zig");
const SlotKind = types.SlotKind;
const Slot = types.Slot;
const Summary = types.Summary;
const QuotientGeometry = types.QuotientGeometry;
const Error = types.Error;

pub fn treeIsMixed(
    program: proof_ir.ProofProgram,
    tree: proof_ir.CommitmentTree,
) bool {
    const columns = program.trace_columns[tree.first_column .. tree.first_column + tree.column_count];
    if (columns.len < 2) return false;
    const first_log = columns[0].log_rows;
    for (columns[1..]) |column| {
        if (column.log_rows != first_log) return true;
    }
    return false;
}

pub fn slotIdentity(
    program: proof_ir.ProofProgram,
    plan_hash: u64,
    kind: SlotKind,
    ordinal: u32,
    slot_words: usize,
    alignment: usize,
    live_from: telemetry.Stage,
    live_through: telemetry.Stage,
    first_phase: u1,
    last_phase: u1,
    storage: proof_ir.StorageClass,
    immutable: bool,
) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig-cairo-cuda-resident-slot-v3");
    hash.update(&program.semantic_digest);
    hashInt(&hash, u64, plan_hash);
    hashInt(&hash, u8, @intFromEnum(kind));
    hashInt(&hash, u32, ordinal);
    hashInt(&hash, u64, slot_words);
    hashInt(&hash, u64, alignment);
    hashInt(&hash, u8, @intFromEnum(live_from));
    hashInt(&hash, u8, @intFromEnum(live_through));
    hashInt(&hash, u8, first_phase);
    hashInt(&hash, u8, last_phase);
    hashInt(&hash, u8, @intFromEnum(storage));
    hashInt(&hash, u8, @intFromBool(immutable));
    var result: proof_ir.Digest = undefined;
    hash.final(&result);
    return result;
}

pub fn planIdentity(
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
    composition_plan_hash: u64,
    ingress_identity: proof_ir.Digest,
    quotient_identity: proof_ir.Digest,
    slots: []const Slot,
    summary: Summary,
) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig-cairo-cuda-resident-plan-v2");
    hash.update(&program.program_digest);
    hash.update(&(protocol.encode() catch unreachable));
    hashInt(&hash, u64, composition_plan_hash);
    hash.update(&ingress_identity);
    hash.update(&quotient_identity);
    for (slots) |slot| hash.update(&slot.identity);
    hashInt(&hash, u64, summary.logical_words);
    hashInt(&hash, u64, summary.request_arena_words);
    hashInt(&hash, u64, summary.persistent_words);
    var result: proof_ir.Digest = undefined;
    hash.final(&result);
    return result;
}

pub fn quotientGeometry(
    topology: quotient_topology.Topology,
) Error!QuotientGeometry {
    return .{
        .term_count = topology.prepared_terms.len,
        .group_count = topology.group_log_sizes.len,
        .source_count = topology.sources.len,
        .partial_word_count = std.math.cast(
            usize,
            topology.partial_offsets[topology.partial_offsets.len - 1],
        ) orelse return Error.GeometryOverflow,
        .maximum_partial_rows = topology.maximum_partial_rows,
        .identity = topology.identity,
    };
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: anytype,
) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

// An explicit diagnostic transaction retains these snapshots until its
// terminal reads, then aborts without publishing a proof or timing receipt.
// Normal proving keeps the bounded trace-commit lifetime.
pub fn relationSourceLifetime() telemetry.Stage {
    return if (std.posix.getenv("STWO_CAIRO_CUDA_SOURCE_DIAGNOSTIC") != null)
        .proof_assembly
    else
        .trace_commit;
}
