//! Metadata routing census after genuine original proofs, without parent rows.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Fixture = @import("frontends/riscv/prover/block_v7_execution_caller_test_v1.zig");
const Metadata = @import("frontends/riscv/recursion/block_v7_mixed_metadata_v1.zig");
const Cold = @import("frontends/riscv/recursion/block_v7_native_fixed_roster_v1.zig");
const Capsule = @import("frontends/riscv/recursion/block_v7_native_compiler_capsule_v1.zig").Capsule;
const Fixed = @import("frontends/riscv/recursion/blake3_parent_fixed_key_v1.zig");
const Protocol = @import("frontends/riscv/recursion/blake3_execution_parent_protocol.zig");
const Program = @import("integrations/riscv_cuda/resident_parent_program_v1.zig");
const Registry = @import("integrations/riscv_cuda/resident_parent_wire_registry_v1.zig");
const Consumer = struct {
    pub const Result = *Metadata.Owned;
    pub fn consume(f: Fixture.Fixture) !Result {
        return Metadata.Owned.init(f.allocator, f.trusted, f.input);
    }
};
test "genuine original native fixed roster resident registry census" {
    const a = std.testing.allocator;
    const metadata = try Fixture.runFixture(true, true, Consumer);
    defer metadata.deinit();
    const child = metadata.input().natives[0];
    const capsule = try Capsule.derive(a, child.profile, .{});
    defer capsule.deinit();
    var cold = try Cold.Owned.deriveFromCapsule(a, capsule, child.claims, 2, .{});
    defer cold.deinit();
    const key = try Fixed.ForBackend(Cpu).derive(a, cold.fixed, cold.context, .diagnostic_q8_pow0);
    const admission = try Protocol.Admission.init(key, try key.identity());
    const program = try Program.Owned.derive(a, admission, .{});
    defer program.deinit();
    const hash = try @import("integrations/riscv_cuda/resident_parent_hash_plan_v1.zig").Owned.deriveFixed(a, cold.fixed, .{ .max_frames = 1 << 20 });
    defer hash.deinit();
    std.debug.print("RESIDENT_FIXED_HASH calls={d} input_endpoints={d} output_endpoints={d}\n", .{ hash.view().calls.len, hash.view().source_endpoints.len, hash.view().output_endpoints.len });
    var registry = try Registry.Plan.init(a, program, cold.fixed, .{});
    defer registry.deinit();
    var missing: usize = 0;
    var multiple: usize = 0;
    var conditional: usize = 0;
    for (registry.consumers) |c| {
        if (registry.expressions[c.weight].op == @intFromEnum(Registry.Op.constant) and registry.expressions[c.weight].value == 0) continue;
        const e = registry.endpoint(c.endpoint) orelse {
            missing += 1;
            continue;
        };
        if (e.count != 1) multiple += 1;
        for (registry.candidates[e.first..][0..e.count]) |candidate| if (registry.expressions[candidate.weight].op != @intFromEnum(Registry.Op.constant)) {
            conditional += 1;
            break;
        };
    }
    std.debug.print("RESIDENT_REGISTRY expressions={d} candidates={d} endpoints={d} consumers={d} unresolved={d} missing={d} multiple={d} conditional={d} main_words={d}\n", .{ registry.expressions.len, registry.candidates.len, registry.endpoints.len, registry.consumers.len, registry.unresolved.len, missing, multiple, conditional, registry.main_words });
    var unresolved: [23][3]usize = @splat(@splat(0));
    for (registry.unresolved) |u| unresolved[u.cohort][u.reason] += 1;
    for (unresolved, 0..) |reasons, cohort| for (reasons, 0..) |n, reason| if (n != 0) {
        std.debug.print("RESIDENT_REGISTRY_UNRESOLVED cohort={d} reason={d} count={d}\n", .{ cohort, reason, n });
    };

    try std.testing.expect(registry.consumers.len != 0);
    try std.testing.expect(registry.candidates.len != 0);
}
