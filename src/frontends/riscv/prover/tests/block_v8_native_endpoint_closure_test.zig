//! Pure algebra/coverage tests, not original or recursive proof qualification.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const C = @import("../block_v8_native_endpoint_closure_v1.zig");
const L = @import("../block_v8_native_endpoint_layout_v1.zig");
const V7 = @import("../block_v7_native_relation_layout_v1.zig");
const Full = @import("../block_v6_relation_layout_v1.zig");
const BoundedV7 = @import("../block_v7_degree_bounded_relation_layout_v1.zig");
const FrozenV7 = @import("block_v7_degree_bounded_layout_reference.zig");
const Shape = @import("../../air/statement.zig").Blake3ExecutionStatement;
const Opcode = @import("../../runner/trace.zig");
const Source = @import("../block_v5_native_projection_fused_source_v1.zig");
const Claim = @import("../block_v5_native_projection_fused_proof_v1.zig").Claim;
const Universal = @import("../../recursion/air/universal_challenges.zig").UniversalRelations;
fn q(value: u32) Q {
    return Q.fromBase(M.fromCanonical(value));
}
fn shapeFor(family: Opcode.OpcodeFamily) Shape {
    var shape = std.mem.zeroes(Shape);
    shape.initializeDescriptorStorage();
    shape.n_components = 1;
    shape.component_descs[0] = .{ .family = family, .log_size = 1, .n_rows = 1, .n_columns = @intCast(Opcode.nColumnsForFamily(family)) };
    shape.n_infra = 1;
    shape.infra_descs[0] = .{ .kind = .clock_update, .log_size = 1, .n_rows = 1, .n_columns = @import("../../air/clock_update_interaction.zig").N_MAIN_COLUMNS };
    shape.total_steps = 1;
    shape.public_data.clock = 1;
    shape.public_data.program_root = .{ .bytes = @splat(1) };
    shape.public_data.completion = @import("../../air/public_data.zig").Completion.canonicalSelfLoop(0);
    shape.public_data.io_entries.input_words = &.{};
    shape.public_data.io_entries.output_words = &.{};
    return shape;
}
fn scope() C.Scope {
    return .{ .native_index = 7, .native_identity = @splat(3), .execution_profile = .rv32im_zkvm_ethereum_sha_v1, .endpoint_count = 1, .policy = .{ .source_ordinal = 7, .max_local_clock = 3 } };
}
test "endpoint native roster restores RAM gap projections with a distinct exact identity" {
    const a = std.testing.allocator;
    for (0..Opcode.N_FAMILIES) |ordinal| {
        var shape = shapeFor(@enumFromInt(ordinal));
        var original = try Full.Layout.init(a, &shape, 0, 1);
        defer original.deinit();
        var endpoint = try L.Layout.init(a, &shape, 0);
        defer endpoint.deinit();
        var actual_event = try V7.Layout.init(a, &shape, 0, 1);
        defer actual_event.deinit();
        // The old verifier pins unsplit physical pair order; preserve that
        // validator instead of teaching it to accept a different protocol.
        try Full.requireCoverage(a, &shape, 0, 1, original.slots);
        var frozen = try FrozenV7.Layout.init(a, &shape, 0, 1);
        defer frozen.deinit();
        var legacy = try BoundedV7.Layout.init(a, &shape, 0, 1);
        defer legacy.deinit();
        try std.testing.expectEqualDeep(frozen.slots, legacy.slots);
        try std.testing.expectEqualDeep(frozen.digest, legacy.digest);
        try std.testing.expectEqual(frozen.split_pairs, legacy.split_pairs);
        try std.testing.expectEqual(frozen.slots.len + 1, endpoint.slots.len);
        var filtered: std.ArrayList(Source.Slot) = .empty;
        defer filtered.deinit(a);
        var ram_clocks: usize = 0;
        for (endpoint.slots) |slot| {
            try std.testing.expect(slot.degree <= L.MAX_DEGREE);
            if (slot.kind == .lookup and slot.kind.lookup.source == .clock and slot.kind.lookup.partition == .clock_memory_access) {
                ram_clocks += 1;
                try std.testing.expectEqual(@as(u8, 4), slot.degree);
            } else try filtered.append(a, slot);
        }
        try std.testing.expectEqual(@as(usize, 1), ram_clocks);
        try std.testing.expectEqualDeep(frozen.slots, filtered.items);
        try std.testing.expectEqual(frozen.split_pairs, endpoint.split_pairs);
        // Check every refinement independently: unchanged slots are exact;
        // split requests preserve both original typed ordinals and their
        // rational sum at arbitrary secure OODS values, including nonlinear
        // register/RAM selector weights.
        const main = try a.alloc(Q, @as(usize, shape.component_descs[0].n_columns) + @import("../../air/clock_update_interaction.zig").N_MAIN_COLUMNS);
        defer a.free(main);
        const relations = Universal.dummy();
        var next: usize = 0;
        for (original.slots) |slot| {
            if (slot.degree <= L.MAX_DEGREE) {
                try std.testing.expectEqualDeep(slot, endpoint.slots[next]);
                next += 1;
                continue;
            }
            const first = endpoint.slots[next];
            const second = endpoint.slots[next + 1];
            for ([_]Source.Slot{ first, second }, slot.kind.lookup.entries) |single, ordinal_| {
                var expected = slot;
                expected.kind.lookup.entries = .{ ordinal_, 0 };
                expected.kind.lookup.entry_count = 1;
                expected.kind.lookup.degree = single.kind.lookup.degree;
                expected.degree = single.degree;
                try std.testing.expectEqualDeep(expected, single);
            }
            for (0..3) |sample| {
                for (main, 0..) |*value, index| value.* = Q.fromU32Unchecked(@intCast(3 + 5 * index + sample), @intCast(7 + 3 * index + sample), @intCast(11 + index), @intCast(13 + 2 * index));
                const old_pair = try Source.fromCommittedMain(slot, main[slot.main_offset..][0..slot.width], &relations);
                const left = try Source.fromCommittedMain(first, main[first.main_offset..][0..first.width], &relations);
                const right = try Source.fromCommittedMain(second, main[second.main_offset..][0..second.width], &relations);
                const old_value = try old_pair.numerator().div(old_pair.denominator());
                const new_value = (try left.numerator().div(left.denominator())).add(try right.numerator().div(right.denominator()));
                try std.testing.expect(old_value.eql(new_value));
            }
            next += 2;
        }
        try std.testing.expectEqual(endpoint.slots.len, next);
        try std.testing.expect(!std.meta.eql(original.digest, endpoint.digest));
        try std.testing.expect(!std.meta.eql(actual_event.digest, endpoint.digest));
        try L.requireCoverage(a, &shape, 0, endpoint.slots);
        try std.testing.expectError(error.InvalidEndpointNativeCoverage, L.requireCoverage(a, &shape, 0, actual_event.slots));
        const changed = try a.dupe(Source.Slot, endpoint.slots);
        defer a.free(changed);
        std.mem.swap(Source.Slot, &changed[0], &changed[changed.len - 1]);
        try std.testing.expectError(error.InvalidEndpointNativeCoverage, L.requireCoverage(a, &shape, 0, changed));
        try std.testing.expectError(error.UnsupportedEndpointCallerInterleaving, L.Layout.init(a, &shape, 1));
    }
}
test "endpoint native claims retain ordinary and RAM clock projections separately" {
    const a = std.testing.allocator;
    var shape = shapeFor(.load_store);
    var layout = try L.Layout.init(a, &shape, 0);
    defer layout.deinit();
    const claims = try a.alloc(Claim, layout.slots.len);
    defer a.free(claims);
    for (claims, 0..) |*claim, index| claim.* = .{ .sum = q(@intCast(index + 1)), .row_count = 1 };
    const parts = try C.extract(a, &shape, 0, layout.slots, claims);
    try std.testing.expect(!parts.ordinary_ram_sum.isZero());
    try std.testing.expect(!parts.ram_clock_sum.isZero());
    var expected = Q.zero();
    for (layout.slots, claims) |slot, claim| {
        if (slot.kind == .lookup and slot.kind.lookup.partition == .clock_memory_access) expected = expected.add(claim.sum);
    }
    try std.testing.expect(parts.ram_clock_sum.eql(expected));
    try std.testing.expectError(error.InvalidEndpointNativeClaims, C.extract(a, &shape, 0, layout.slots, claims[1..]));
    claims[0].row_count = 3;
    try std.testing.expectError(error.InvalidEndpointNativeClaims, C.extract(a, &shape, 0, layout.slots, claims));
}
test "endpoint local closure requires clock bridges and rejects compensated source swapping" {
    var a = C.Partitions{ .ordinary_ram_sum = q(11), .ram_clock_sum = q(17) };
    const supplied_a = q(28).neg();
    try C.closeLocal(a, supplied_a, Q.zero(), Q.zero());
    const omitted_clock = C.Partitions{ .ordinary_ram_sum = a.ordinary_ram_sum };
    try std.testing.expectError(error.UnclosedEndpointLocalRam, C.closeLocal(omitted_clock, supplied_a, Q.zero(), Q.zero()));
    const b = C.Partitions{ .ordinary_ram_sum = q(19), .ram_clock_sum = q(23) };
    const supplied_b = q(42).neg();
    const swapped_a = a.ordinary_ram_sum.add(a.ram_clock_sum).add(supplied_b);
    const swapped_b = b.ordinary_ram_sum.add(b.ram_clock_sum).add(supplied_a);
    try std.testing.expect(swapped_a.add(swapped_b).isZero());
    try std.testing.expectError(error.UnclosedEndpointLocalRam, C.closeLocal(a, supplied_b, Q.zero(), Q.zero()));
    try std.testing.expectError(error.UnclosedEndpointLocalRam, C.closeLocal(b, supplied_a, Q.zero(), Q.zero()));
    try std.testing.expectError(error.UnclosedEndpointNativeRegisters, C.closeLocal(a, supplied_a, q(1), q(1).neg()));
    a.ordinary_ram_sum.c0.a.v = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidEndpointNativeClaims, C.closeLocal(a, supplied_a, Q.zero(), Q.zero()));
}
test "native endpoint admission binds source policy and leaves all provider planes open" {
    var shape = shapeFor(.load_store);
    const admitted = scope();
    try admitted.admit(&shape, 0);
    var changed = admitted;
    changed.policy.source_ordinal += 1;
    try std.testing.expectError(error.InvalidEndpointNativeScope, changed.admit(&shape, 0));
    changed = admitted;
    changed.policy.max_local_clock += 1;
    try std.testing.expectError(error.InvalidEndpointNativeScope, changed.admit(&shape, 0));
    changed = admitted;
    changed.endpoint_count = 2;
    try std.testing.expectError(error.InvalidEndpointNativeCensus, changed.admit(&shape, 0));
    try std.testing.expectError(error.UnsupportedEndpointCallerInterleaving, admitted.admit(&shape, 1));
    const prefix = Universal.dummy();
    const shared = try @import("../../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&prefix);
    const Public = @import("../../air/public_logup_arithmetic.zig");
    var parts = C.Partitions{};
    parts.state_sum = (try Public.registersStateSumFor(Q, &shape.public_data, &shared.native)).neg();
    parts.register_sum = (try Public.registerMemoryAccessSumFor(Q, &shape.public_data, &shared.native)).neg();
    parts.ordinary_ram_sum = q(28);
    var endpoint_claims = C.EndpointClaims{ .scope = admitted, .sums = @splat(Q.zero()) };
    endpoint_claims.sums[0] = q(28).neg();
    for (endpoint_claims.sums[1..], 1..) |*sum, index| sum.* = q(@intCast(index));
    const open = try C.closeNative(&shape, 0, admitted, parts, endpoint_claims, &prefix);
    try std.testing.expect(open.global_transition_sum.eql(q(1)));
    try std.testing.expect(open.range16_sum.eql(q(35)));
    try std.testing.expect(open.byte_pair_sum.eql(q(19)));
    endpoint_claims.scope.native_identity[0] ^= 1;
    try std.testing.expectError(error.UntrustedEndpointSource, C.closeNative(&shape, 0, admitted, parts, endpoint_claims, &prefix));
}
