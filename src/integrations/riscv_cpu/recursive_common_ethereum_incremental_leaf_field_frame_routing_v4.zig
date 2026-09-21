//! Same-word source comparisons for the shared native schema4 frame plan.
//! The caller owns the admitted frame geometry; all scalar values remain
//! transcript witnesses compared to real statement or canonical claim sources.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const plan_mod = @import("recursive_common_ethereum_incremental_leaf_field_frame_plan_v4.zig");
const frames = @import("ethereum_incremental_field_transcript_v4.zig");
const routing = frontend.recursion.ethereum_publication_routing_v1;
const Air = frontend.recursion.air.ethereum_publication_control_v1;
const M31 = core.fields.m31.M31;
pub const Row = Air.Relation.Row;

fn selected(descriptor: plan_mod.Descriptor, word: plan_mod.Word) bool {
    if (descriptor.kind == .native_statement_words or word != .existing_source) return false;
    const source = word.existing_source;
    if (source.endpoint == .raw_publication) return false;
    return source.projection != .canonical_m31_limb or source.projection.canonical_m31_limb == 0;
}

pub fn rowCount(plan: *const plan_mod.OwnedPlan) usize {
    var count: usize = 0;
    for (plan.descriptors(), 0..) |descriptor, frame_index| {
        if (descriptor.kind == .native_statement_words) continue;
        const words = plan.wordsFor(frame_index) catch unreachable;
        for (words) |word| count += @intFromBool(selected(descriptor, word));
    }
    return count;
}

pub fn claimUses(plan: *const plan_mod.OwnedPlan, claim_index: u32) u32 {
    var count: u32 = 0;
    for (plan.descriptors(), 0..) |descriptor, frame_index| {
        if (descriptor.kind == .native_statement_words) continue;
        const words = plan.wordsFor(frame_index) catch unreachable;
        for (words) |word| if (selected(descriptor, word)) {
            const endpoint = word.existing_source.endpoint;
            if (endpoint == .claim_word and endpoint.claim_word == claim_index) count += 1;
        };
    }
    return count;
}

pub fn statementUses(plan: *const plan_mod.OwnedPlan, scope: u32, index: u32) u32 {
    var count: u32 = 0;
    for (plan.descriptors(), 0..) |descriptor, frame_index| {
        if (descriptor.kind == .native_statement_words) continue;
        const words = plan.wordsFor(frame_index) catch unreachable;
        for (words) |word| if (selected(descriptor, word)) {
            const endpoint = word.existing_source.endpoint;
            if (endpoint == .statement_word and endpoint.statement_word.scope == scope and endpoint.statement_word.index == index) count += 1;
        };
    }
    return count;
}

pub fn write(plan: *const plan_mod.OwnedPlan, execution: *const frontend.recursion.recording_poseidon_channel_v4.ExecutionV4, destination: []Row) !void {
    if (destination.len != rowCount(plan)) return error.InvalidEthereumFieldSourceRows;
    var at: usize = 0;
    for (plan.descriptors(), 0..) |descriptor, frame_index| {
        if (descriptor.kind == .native_statement_words) continue;
        const words = try plan.wordsFor(frame_index);
        const payload = try frames.recordedOperationPayload(execution, descriptor.operation_index);
        if (payload.len != words.len) return error.InvalidEthereumFieldSourceRows;
        for (words, 0..) |word, index| {
            if (!selected(descriptor, word)) continue;
            const source = word.existing_source;
            const joined = source.projection == .canonical_m31_limb;
            const low = payload[index];
            const high = if (joined) blk: {
                if (index + 1 >= words.len or words[index + 1] != .existing_source) return error.InvalidEthereumFieldSourceRows;
                var expected = source;
                expected.projection = .{ .canonical_m31_limb = 1 };
                if (!std.meta.eql(expected, words[index + 1].existing_source)) return error.InvalidEthereumFieldSourceRows;
                break :blk payload[index + 1];
            } else M31.zero();
            const value_u64 = @as(u64, low.toU32()) + @as(u64, high.toU32()) * 65536;
            if (value_u64 >= core.fields.m31.Modulus) return error.InvalidEthereumFieldSourceRows;
            var pp = [_]u32{0} ** Air.PREPROCESSED_COLUMN_COUNT;
            pp[9] = 1;
            switch (source.endpoint) {
                .statement_word => |endpoint| {
                    pp[10] = 1;
                    pp[11] = endpoint.scope;
                    pp[12] = endpoint.index;
                },
                .claim_word => |claim_index| {
                    pp[32] = 1;
                    pp[11] = frontend.recursion.air.vm_public_claim_input.VM_PUBLIC_LOGUP_SCOPE;
                    pp[12] = claim_index;
                },
                .raw_publication => unreachable,
            }
            if (source.geometry_expected) |expected| {
                if (value_u64 != expected) return error.InvalidEthereumFieldSourceRows;
                pp[30] = 1;
                pp[31] = expected;
            }
            const source_index = routing.fieldFrameSourceIndex(try std.math.add(u32, descriptor.payload_word_first, @intCast(index))) orelse return error.InvalidEthereumFieldSourceRows;
            destination[at] = try Air.rawWordRow(M31.fromCanonical(@intCast(value_u64)), low, high, joined, source_index, pp);
            at += 1;
        }
    }
    std.debug.assert(at == destination.len);
}
