const std = @import("std");
const core = @import("stwo_core");
const Native = @import("../block_v7_native_proof_v1.zig");
const E = @import("../block_v7_execution_epoch_v1.zig");
const Support = @import("../block_v7_execution_test_support.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
fn run(comptime access: bool) !void {
    const code = if (access) [_]u32{
        0x00700313, // x6=7
        0x00900393, // x7=9
        0x02730433, // mul x8,x6,x7
        0x001002b7, // x5=data base
        0x10028293, // x5+=256
        0x0082a023, // store product
        0x0002a483, // load x9
        0x0000006f,
    } else [_]u32{ 0x00700313, 0x00900393, 0x02730433, 0x0000006f };
    const elf = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 512, .rv32im_zkvm_v1);
    const a = std.testing.allocator;
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config();
    var session = try @import("../../runner/mod.zig").BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var executed = try session.startSegment(code.len - 1);
    defer executed.deinit();
    try std.testing.expectEqual(@as(u32, 63), executed.exit_cpu.regs[8]);
    if (access) try std.testing.expectEqual(@as(u32, 63), executed.exit_cpu.regs[9]);
    var counters = try @import("../../air/lookups/tables/mod.zig").counter.Set.init(a);
    defer counters.deinit(a);
    var segment = try Support.Segment.init(a, &executed, config, @splat(7), 0, .rv32im_zkvm_v1, 0, &counters);
    defer segment.deinit();
    var layout = try @import("../block_v7_native_relation_layout_v1.zig").Layout.init(a, segment.pin.shape, 0, 1);
    defer layout.deinit();
    try std.testing.expectEqual(@as(u32, 3), @import("../block_v5_native_projection_fused_proof_v2.zig").compositionSplit(layout.slots));
    const entries = [_]E.Entry{try segment.pin.entry(a)};
    var counts: E.Counts = @splat(0);
    counts[0] = 1;
    const epoch = try E.Epoch.init(@splat(9), config, counts, &entries, entries.len);
    var proof = try Native.For(Cpu).proveWithOptions(a, &segment.first, segment.owner, segment.source.inputs, segment.pin, epoch, &entries, .{ .native_main_cache_bytes = 0 });
    defer proof.deinit(a);
    if (access) {
        const drawn = try epoch.draw(a);
        var components = try @import("../block_v7_native_components_v1.zig").Owner.init(a, segment.pin, proof.claims, proof.memory_claims, &drawn);
        defer components.deinit();
        try std.testing.expect(components.access.len != 0);
        for (components.access) |*component| {
            const prover = component.asProverComponent();
            const verifier = component.asVerifierComponent();
            try std.testing.expectEqual(component.inner.maxConstraintLogDegreeBound() + 1, prover.maxConstraintLogDegreeBound());
            try std.testing.expectEqual(prover.maxConstraintLogDegreeBound(), verifier.maxConstraintLogDegreeBound());
            try std.testing.expectEqual(@as(u8, 1), prover.composition_geometry_override_v1.?.max_constraint_log_degree_bound_delta);
            // The established q2 route retains its original handle geometry.
            var original = component.*;
            original.composition_split = original.inner.compositionLogSplit();
            original = try original.init();
            try std.testing.expect(original.asProverComponent().composition_geometry_override_v1 == null);
            try std.testing.expect(original.asVerifierComponent().composition_geometry_override_v1 == null);
            try std.testing.expectEqual(original.inner.maxConstraintLogDegreeBound(), original.asProverComponent().maxConstraintLogDegreeBound());
        }
    }
    try Support.roundTrip(a, &proof.stark);
    _ = try Native.For(Cpu).verify(a, &proof, segment.pin, epoch, &entries);
}
test "native MUL degree5 projections q3 genuine proof without access" {
    try run(false);
}
test "native MUL degree5 projections q3 genuine proof with access" {
    try run(true);
}
