//! Actual standalone STARK plus independent source receiver; not R7 admission.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Authority = @import("authority.zig");
const K = @import("physical_key.zig");
const P = @import("physical.zig");
const M = K.M;
const Q = K.Q;
const O = K.O;
const F = struct {
    terms0: [2]Authority.Term = .{ .{ .weight = .{ 1, 2 }, .scalar = 3 }, .{ .weight = .{ 1, 2 }, .scalar = 4 } },
    terms2: [1]Authority.Term = .{.{ .weight = .{ 8, 9 }, .scalar = 4 }},
    values: [14]Q = @splat(Q.zero()),
    uses: [14]u32 = @splat(0),
    bindings: [7]K.Binding = undefined,
    fn init() F {
        var f = F{};
        f.values[1] = Q.fromM31Array(.{ M.fromCanonical(2), M.fromCanonical(3), M.fromCanonical(5), M.fromCanonical(7) });
        f.values[2] = Q.fromM31Array(.{ M.fromCanonical(11), M.fromCanonical(13), M.fromCanonical(17), M.fromCanonical(19) });
        f.values[3] = Q.fromBase(M.fromCanonical(3));
        f.values[4] = Q.fromBase(M.fromCanonical(5));
        f.computeOutputs();
        for ([_]usize{ 8, 9, 12, 13 }) |id| f.uses[id] = 1;
        for (&f.bindings, [_]u32{ 0, 1, 2, 3, 4, 12, 13 }) |*binding, id| binding.* = .{ .id = id, .value = f.values[id] };
        return f;
    }
    // Native expected output computation is independent of dot row filling,
    // fixed masks, LogUp fractions and MAIN columns.
    fn computeOutputs(f: *F) void {
        const weight = O{ .c0 = f.values[1], .c1 = f.values[2] };
        const first = weight.mulM31(M.fromCanonical(8));
        const last = weight.mulM31(M.fromCanonical(40));
        f.values[8] = first.c0;
        f.values[9] = first.c1;
        f.values[12] = last.c0;
        f.values[13] = last.c1;
    }
    fn calls(f: *const F) [3]Authority.Call {
        return .{ .{ .terms = &f.terms0, .outputs = .{ 8, 9 } }, .{ .terms = &.{}, .outputs = .{ 10, 11 } }, .{ .terms = &f.terms2, .outputs = .{ 12, 13 } } };
    }
};
fn physicalReject(a: std.mem.Allocator, key: *const K.Key, values: []const Q, mutation: P.Mutation) !void {
    if (P.prove(a, key, values, mutation)) |proof| {
        defer a.free(proof);
        if (P.verify(a, key, proof)) |_| return error.NativeDotPhysicalMutationAccepted else |err| {
            if (err == error.OutOfMemory) return err;
            std.debug.print("OP_DOT_MUTATION mode={s} receiver={s}\n", .{ @tagName(mutation), @errorName(err) });
        }
    } else |err| {
        if (err == error.OutOfMemory) return err;
        std.debug.print("OP_DOT_MUTATION mode={s} prover={s}\n", .{ @tagName(mutation), @errorName(err) });
    }
}
test "OP native dot physical standalone mixed height closes pinned external Var debt" {
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 2 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    {
        const f = F.init();
        var producer = try K.Key.init(a, &f.calls(), &f.uses, &f.bindings, 6);
        var producer_live = true;
        defer if (producer_live) producer.deinit();
        const proof = try P.prove(a, &producer, &f.values, .none);
        defer a.free(proof);
        const identity = producer.identity;
        producer.deinit();
        producer_live = false;
        // Fresh independent source/caller values, not retained producer MAIN.
        const independent = F.init();
        var receiver = try K.Key.init(a, &independent.calls(), &independent.uses, &independent.bindings, 6);
        defer receiver.deinit();
        try std.testing.expectEqualSlices(u8, &identity, &receiver.identity);
        try P.verify(a, &receiver, proof);
        {
            const Component = @import("component.zig");
            const c = Component.Component{ .key = &receiver, .elements = Component.Elements.init(O.one(), O.one()), .claim = O.zero(), .mode = .dot };
            const point = Core.circle.GENERATOR;
            var masks = try c.maskPoints(a, .{ .x = O.fromBase(point.x), .y = O.fromBase(point.y) }, receiver.auxiliary_log);
            defer masks.deinitDeep(a);
            var main_samples: usize = 0;
            var inter_samples: usize = 0;
            for (masks.items[1]) |ports| main_samples += ports.len;
            for (masks.items[2]) |ports| inter_samples += ports.len;
            try std.testing.expectEqual(@as(usize, 25), main_samples);
            try std.testing.expectEqual(@as(usize, 32), inter_samples);
            try std.testing.expectEqual(receiver.dot_log + 1, c.maxConstraintLogDegreeBound());
        }

        try std.testing.expect(std.meta.isError(P.verify(a, &receiver, proof[0 .. proof.len - 1])));
        const changed = try a.dupe(u8, proof);
        defer a.free(changed);
        changed[8] ^= 1;
        try std.testing.expectError(error.NativeDotPhysicalAuthority, P.verify(a, &receiver, changed));
        @memcpy(changed, proof);
        std.mem.writeInt(u32, changed[P.CLAIM_OFFSET..][0..4], Core.fields.m31.Modulus, .little);
        try std.testing.expectError(error.NativeDotNoncanonicalClaim, P.verify(a, &receiver, changed));
        var calls = independent.calls();
        std.mem.swap(Authority.Call, &calls[0], &calls[1]);
        var reordered = try K.Key.init(a, &calls, &independent.uses, &independent.bindings, 6);
        defer reordered.deinit();
        try std.testing.expectError(error.NativeDotPhysicalAuthority, P.verify(a, &reordered, proof));
        try std.testing.expectError(error.NativeDotExternalCoverage, K.Key.init(a, &independent.calls(), &independent.uses, independent.bindings[0..6], 6));
        var duplicate = independent.bindings;
        duplicate[1] = duplicate[0];
        try std.testing.expectError(error.NativeDotExternalOrder, K.Key.init(a, &independent.calls(), &independent.uses, &duplicate, 6));
        // Locally consistent wrong inputs/sums produce a physical fragment,
        // but the external Var authority still refers to the original values.
        var wrong = F.init();
        wrong.values[1] = wrong.values[1].add(Q.one());
        wrong.computeOutputs();
        const wrong_fragment = try P.prove(a, &receiver, &wrong.values, .none);
        defer a.free(wrong_fragment);
        try std.testing.expect(!(try P.checkStarkFragmentForTest(a, &receiver, wrong_fragment)).external_var_debt_closed);
        try std.testing.expectError(error.NativeDotExternalVarDebt, P.verify(a, &receiver, wrong_fragment));
        // A nonbase scalar public slot cannot be hidden by projection onto its
        // first coordinate, even though the local recurrence remains valid.
        var hidden = independent.bindings;
        hidden[3].value = hidden[3].value.add(Q.fromM31Array(.{ M.zero(), M.one(), M.zero(), M.zero() }));
        var high_key = try K.Key.init(a, &independent.calls(), &independent.uses, &hidden, 6);
        defer high_key.deinit();
        try std.testing.expectEqualSlices(u8, &receiver.identity, &high_key.identity);
        try std.testing.expect(!std.mem.eql(u8, &receiver.statement, &high_key.statement));
        try std.testing.expectError(error.NativeDotPhysicalStatement, P.verify(a, &high_key, proof));
        const hidden_fragment = try P.prove(a, &high_key, &independent.values, .none);
        defer a.free(hidden_fragment);
        try std.testing.expect(!(try P.checkStarkFragmentForTest(a, &high_key, hidden_fragment)).external_var_debt_closed);
        try std.testing.expectError(error.NativeDotExternalVarDebt, P.verify(a, &high_key, hidden_fragment));
        for ([_]P.Mutation{ .accumulator, .empty_result, .prefix, .auxiliary }) |mutation| try physicalReject(a, &receiver, &independent.values, mutation);
        std.debug.print("OP_DOT_PHYSICAL bytes={} dot_log={} auxiliary_log={} first_last_resets=true empty_dot=true pinned_external_Var=true native_debt_closed=true fresh_source=true production_admission=false peak={}\n", .{ proof.len, receiver.dot_log, receiver.auxiliary_log, budget.snapshot().peak_live_bytes });
    }
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
}
