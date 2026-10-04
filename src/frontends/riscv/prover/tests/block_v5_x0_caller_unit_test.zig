//! Scalar source qualification only. The standalone arithmetic profile has
//! not yet selected these versioned layouts; no STARK/segment is invoked.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const envelope = @import("../../air/guest_precompile/x0_caller_envelope_v1.zig");
const keccak = @import("../../air/guest_precompile/keccakf_caller.zig");
const zero_keccak = @import("../../air/guest_precompile/keccakf_caller_local_zero_v1.zig");
const signer = @import("../../air/guest_precompile/secp256k1_recovery_caller.zig");
const zero_signer = @import("../../air/guest_precompile/secp256k1_caller_local_zero_v1.zig");
const Sink = struct {
    failed: bool = false,
    count: usize = 0,
    pub fn add(self: *@This(), value: anytype, degree: u8) void {
        if (degree > 4) self.failed = true;
        self.failed = self.failed or !value.isZero();
        self.count += 1;
    }
};

test "block-v5 x0 caller authentic Keccak and signer events preserve RW retirement and signed table census" {
    const keccak_relations = @import("../../air/guest_precompile/keccakf_relations.zig").Relations.dummy();
    const signer_relations = @import("../../air/guest_precompile/secp256k1_relations.zig").Relations.dummy();
    const width = @import("../../air/guest_precompile/keccakf_witness.zig").state_cell_count;
    var input: [width]M = @splat(M.zero());
    var output: [width]M = @splat(M.zero());
    input[71] = M.one();
    output[1599] = M.one();
    for ([_]u32{ 0, 1, 31 }) |register| {
        var main: [zero_keccak.Layout.main_columns]M = @splat(M.zero());
        main[keccak.Layout.enabler] = M.one();
        main[keccak.Layout.execution_clock] = M.fromCanonical(5);
        main[keccak.Layout.pc] = M.fromCanonical(16);
        main[keccak.Layout.pointer_register] = M.fromCanonical(register);
        main[keccak.Layout.span_end_limbs] = M.fromCanonical(@intCast(keccak.word_count - 1));
        try envelope.fillHintsAndNormalize(.keccak, &main, M.one());
        var sink = Sink{};
        try zero_keccak.evaluateDirect(M, &main, M.one(), &sink);
        try std.testing.expect(!sink.failed);
        try std.testing.expectEqual(zero_keccak.direct_constraint_count, sink.count);
        const original = keccak.coreEvents(M, main[0..keccak.Layout.main_columns], &input, &output, &keccak_relations);
        const updated = try zero_keccak.coreEvents(M, &main, &input, &output, &keccak_relations);
        var table_difference = Q.zero();
        for (original, updated, 0..) |before, after, i| {
            try std.testing.expect(before.d1.eql(after.d1));
            try std.testing.expect(before.d2.eql(after.d2) and before.n2.eql(after.n2));
            if (register == 0 and i >= 3 and i < 6) {
                try std.testing.expect(after.n1.isZero());
                if (i == 5) table_difference = after.n1.sub(before.n1);
            } else try std.testing.expect(before.n1.eql(after.n1));
        }
        try std.testing.expect(table_difference.eql(if (register == 0) Q.one() else Q.zero()));
        var caller: [zero_signer.Layout.main_columns]M = @splat(M.zero());
        caller[signer.Layout.is_active] = M.one();
        caller[signer.Layout.execution_clock] = M.fromCanonical(7);
        caller[signer.Layout.pc] = M.fromCanonical(24);
        caller[signer.Layout.pointer_register] = M.fromCanonical(register);
        caller[signer.Layout.span_end_limbs] = M.fromCanonical(@intCast(signer.memory_word_count - 1));
        caller[signer.Layout.status_bytes] = M.one();
        try envelope.fillHintsAndNormalize(.signer, &caller, M.one());
        sink = .{};
        try zero_signer.evaluateDirect(M, &caller, &sink);
        try std.testing.expect(!sink.failed);
        try std.testing.expectEqual(zero_signer.constraint_count, sink.count);
        const old_events = signer.rowEvents(M, caller[0..signer.Layout.main_columns], &signer_relations);
        const new_events = try zero_signer.rowEvents(M, &caller, &signer_relations);
        for (old_events, new_events, 0..) |before, after, i| {
            try std.testing.expect(before.d1.eql(after.d1));
            try std.testing.expect(before.d2.eql(after.d2) and before.n2.eql(after.n2));
            if (register == 0 and i >= 3 and i < 6) try std.testing.expect(after.n1.isZero()) else try std.testing.expect(before.n1.eql(after.n1));
        }
        const paired = try zero_signer.rowPairs(M, &caller, &signer_relations);
        for (paired, 0..) |pair, i| {
            try std.testing.expect(pair.n1.eql(new_events[2 * i].n1));
            try std.testing.expect(pair.n2.eql(new_events[2 * i + 1].n1));
        }
    }
}

test "block-v5 x0 caller quotient numerators are algebraic at nonboolean points" {
    const relations = @import("../../air/guest_precompile/keccakf_relations.zig").Relations.dummy();
    var caller: [zero_keccak.Layout.main_columns]Q = undefined;
    for (&caller, 0..) |*value, i| value.* = Q.fromU32Unchecked(@intCast(3 + i), 2, 5, 7);
    const width = @import("../../air/guest_precompile/keccakf_witness.zig").state_cell_count;
    var state: [width]Q = undefined;
    for (&state, 0..) |*value, i| value.* = Q.fromU32Unchecked(@intCast(11 + i), 1, 3, 5);
    const original = keccak.coreEvents(Q, caller[0..keccak.Layout.main_columns], &state, &state, &relations);
    const updated = try zero_keccak.coreEvents(Q, &caller, &state, &state, &relations);
    const keep = caller[zero_keccak.Layout.hints];
    try std.testing.expect(!keep.isZero() and !keep.eql(Q.one()));
    for (original, updated, 0..) |before, after, i| {
        try std.testing.expect(before.d1.eql(after.d1));
        try std.testing.expect(after.n1.eql(if (i >= 3 and i < 6) before.n1.mul(keep) else before.n1));
    }
}

test "block-v5 x0 caller SHA typed recipe binds local equations and exact original effect roster" {
    const a = std.testing.allocator;
    const original = @import("../../air/guest_precompile/sha256_memory_caller.zig");
    const source = @import("../../air/guest_precompile/sha256_caller_local_zero_v1.zig");
    const lang = @import("../../air/lang/mod.zig");
    const support = @import("../../recursion/air/test_support.zig");
    const compression = @import("../../air/guest_precompile/sha256_compression.zig");
    var block: [64]u8 = undefined;
    for (&block, 0..) |*byte, i| byte.* = @truncate(7 + 31 * i);
    const state: compression.State = .{ 0, 1, 2, 3, 4, 5, 6, 7 };
    const record = @import("../../air/guest_precompile/sha256_memory_record.zig").Record{
        .execution_clock = 17,
        .pc = 1024,
        .state_register = 0,
        .block_register = 9,
        .state_ptr = 0,
        .block_ptr = 4096,
        .pointer_previous_clocks = .{ 1, 2 },
        .memory_previous_clocks = @splat(3),
        .state = state,
        .block = block,
        .output = compression.compress(state, block),
    };
    var old_definition = try original.build(a);
    defer old_definition.deinit();
    var candidate = try source.buildCandidate(a);
    defer candidate.deinit();
    const identity = try candidate.identity();
    std.debug.print("SHA_CALLER_LOCAL_ZERO constraints={d} events={d} digest={s}\n", .{ candidate.arena.constraintsView().len, candidate.arena.effectsView().len, std.fmt.bytesToHex(identity, .lower) });
    try std.testing.expect(!std.meta.eql(identity, original.SEMANTIC_DIGEST));
    const old_row = try original.row(record);
    const current = try source.row(record);
    const old_values = try support.evaluateArena(a, &old_definition.arena, &old_row);
    defer a.free(old_values);
    const values = try support.evaluateArena(a, &candidate.arena, &current);
    defer a.free(values);
    for (candidate.arena.constraintsView()) |constraint| try std.testing.expect(values[lang.types.idIndex(constraint.root)].isZero());
    var memory_count: usize = 0;
    var absent_pointer_effects: usize = 0;
    var old_range: M = M.zero();
    var new_range: M = M.zero();
    for (old_definition.arena.effectsView(), candidate.arena.effectsView(), 0..) |before, after, i| {
        try std.testing.expectEqualDeep(before.binding, after.binding);
        const old_ids = old_definition.arena.effectValues(@enumFromInt(i)).?;
        const ids = candidate.arena.effectValues(@enumFromInt(i)).?;
        try std.testing.expectEqual(old_ids.len, ids.len);
        const first_weight = old_values[lang.types.idIndex(before.liveness.?)];
        const last_weight = values[lang.types.idIndex(after.liveness.?)];
        if (before.binding.?.schema == lang.relation.id(.memory_access)) {
            memory_count += 1;
            if (values[lang.types.idIndex(ids[0])].isZero() and values[lang.types.idIndex(ids[1])].isZero()) {
                try std.testing.expect(last_weight.isZero());
                absent_pointer_effects += 1;
                continue;
            }
        }
        if (before.binding.?.schema == lang.relation.id(.range_check_20)) {
            old_range = old_range.add(first_weight);
            new_range = new_range.add(last_weight);
        }
        if (last_weight.isZero()) continue;
        for (old_ids, ids) |first, last| try std.testing.expect(old_values[lang.types.idIndex(first)].eql(values[lang.types.idIndex(last)]));
        try std.testing.expect(first_weight.eql(last_weight));
    }
    try std.testing.expectEqual(@as(usize, 52), memory_count);
    try std.testing.expectEqual(@as(usize, 2), absent_pointer_effects);
    try std.testing.expect(old_range.sub(new_range).eql(M.one()));
    // A coherent nonzero x0 pointer satisfies the old scalar caller equations;
    // only the new local source-zero assertions reject it, without custody.
    var nonzero = record;
    nonzero.state_register = 3;
    nonzero.state_ptr = 4;
    nonzero.pointer_previous_clocks[0] = 0;
    var forged_old = try original.row(nonzero);
    forged_old[original.Layout.registers] = M.zero();
    forged_old[original.Layout.scaled_register] = M.zero();
    forged_old[original.Layout.register_difference_inverse] = try M.zero().sub(M.fromCanonical(nonzero.block_register)).inv();
    const old_forgery = try support.evaluateArena(a, &old_definition.arena, &forged_old);
    defer a.free(old_forgery);
    for (old_definition.arena.constraintsView()) |constraint| try std.testing.expect(old_forgery[lang.types.idIndex(constraint.root)].isZero());
    var forged: source.Row = @splat(M.zero());
    @memcpy(forged[0..original.PHYSICAL_MAIN_COLUMN_COUNT], forged_old[0..original.PHYSICAL_MAIN_COLUMN_COUNT]);
    forged[source.PHYSICAL_MAIN_COLUMN_COUNT] = M.one();
    forged[original.PHYSICAL_MAIN_COLUMN_COUNT + 2] = current[original.PHYSICAL_MAIN_COLUMN_COUNT + 2];
    forged[original.PHYSICAL_MAIN_COLUMN_COUNT + 3] = current[original.PHYSICAL_MAIN_COLUMN_COUNT + 3];
    const forged_values = try support.evaluateArena(a, &candidate.arena, &forged);
    defer a.free(forged_values);
    var rejected = false;
    for (candidate.arena.constraintsView()) |constraint| rejected = rejected or !forged_values[lang.types.idIndex(constraint.root)].isZero();
    try std.testing.expect(rejected);
    // A different reviewed literal cannot admit the newly authored graph.
    const Wrong = source.ForDigest(@splat(1));
    var wrong = try source.buildCandidate(a);
    defer wrong.deinit();
    const definition = Wrong.Definition{ .arena = wrong.arena, .events = wrong.events };
    try std.testing.expectError(error.InvalidShaCallerLocalZeroIdentity, definition.validate());
}
