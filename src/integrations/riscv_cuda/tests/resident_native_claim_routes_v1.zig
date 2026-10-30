const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Routes = @import("../resident_native_claim_routes_v1.zig");
const Fixture = @import("../resident_native_plan_test_v1.zig");
const Fused = @import("../../../frontends/riscv/prover/block_v5_native_projection_fused_proof_v2.zig");
const Memory = @import("../../../frontends/riscv/prover/block_v5_opcode_memory_sidecar_proof_v1.zig");
const Statement = @import("../../../frontends/riscv/recursion/air/block_v7_native_statement_v1.zig");
fn qAt(words: []const u32) Q {
    var limbs: [4]M = undefined;
    for (&limbs, words[0..4]) |*m, word| m.* = M.fromCanonical(word);
    return Q.fromM31Array(limbs);
}
test "native claim routes preserve original word field integer transcript frames" {
    const a = std.testing.allocator;
    inline for (.{ 4, 5 }) |N| {
        for ([_]bool{ false, true }) |q2| {
            const program = try Fixture.fixture(N, a, q2);
            defer program.deinit();
            const profile = program.view().profile;
            const plan = try Routes.Plan.init(a, profile);
            defer plan.deinit();
            const source = try a.alloc(u32, plan.source_words);
            defer a.free(source);
            for (source, 0..) |*v, i| v.* = @intCast(19 + i * 31);
            const claims = try a.alloc(Fused.Claim, profile.projections.len);
            defer a.free(claims);
            for (claims, profile.projections, 0..) |*c, slot, i| c.* = .{ .sum = qAt(source[i * 4 ..]), .row_count = slot.n_rows };
            const memory = try a.alloc(Memory.Claim, profile.slots.len);
            defer a.free(memory);
            for (memory, 0..) |*c, i| {
                const words = source[claims.len * 4 + i * 40 ..][0..40];
                @memset(words[8..12], 0);
                words[8] = 1;
                c.* = .{ .transition_sum = qAt(words[0..4]), .universal_sum = qAt(words[4..8]), .active_count = 1, .range_claims = undefined };
                for (&c.range_claims, 0..) |*q, j| q.* = qAt(words[12 + 4 * j ..]);
            }
            var reconstructed = try plan.statement.clone(a);
            defer reconstructed.deinit();
            for (plan.routes) |route| switch (route.kind) {
                .word => reconstructed.words[route.destination] = source[route.source],
                .count => {
                    reconstructed.words[route.destination] = source[route.source];
                    reconstructed.words[route.destination + 1] = 0;
                },
                .field => {
                    const index = route.destination / 4;
                    var limbs = reconstructed.felts[index].toM31Array();
                    limbs[route.destination % 4] = M.fromCanonical(source[route.source]);
                    reconstructed.felts[index] = Q.fromM31Array(limbs);
                },
            };
            var original = try Statement.init(a, profile, claims, memory);
            defer original.deinit();
            try std.testing.expectEqualSlices(u32, original.words, reconstructed.words);
            try std.testing.expectEqualDeep(original.felts, reconstructed.felts);
            var x = profile.epoch.sharedChannel();
            var y = x;
            try original.replay(&x, original.claims);
            try reconstructed.replay(&y, reconstructed.claims);
            try std.testing.expectEqualDeep(x.digestBytes(), y.digestBytes());
            try std.testing.expectEqual(profile.projections.len * 4 + profile.slots.len * 37, plan.routes.len);
        }
    }
}

test "native claim packing controller typechecks resident operations" {
    std.mem.doNotOptimizeAway(&@import("../resident_native_claim_pack_v1.zig").Bound.execute);
}
