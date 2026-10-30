const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Fixture = @import("../prover/block_v7_execution_caller_test_v1.zig");
const Metadata = @import("block_v7_mixed_metadata_v1.zig");
const Capture = @import("../prover/block_v7_caller_joint_capture_v1.zig");
const Capsule = @import("block_v7_caller_joint_compiler_capsule_v1.zig").Capsule;
const Cold = @import("block_v7_caller_joint_fixed_roster_v1.zig");
const Live = @import("block_v7_caller_joint_preparation_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Protocol = @import("block_v7_caller_joint_parent_protocol_v1.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Output = struct {
    metadata: *Metadata.Owned,
    bytes: []u8,
    key: Protocol.Key,
    wires: []Cold.Wire,
    fn deinit(self: *Output) void {
        self.metadata.allocator.free(self.bytes);
        self.metadata.allocator.free(self.wires);
        self.metadata.deinit();
    }
};
const Consumer = struct {
    pub const Result = Output;
    pub fn consume(f: Fixture.Fixture) !Output {
        const a = f.allocator;
        const metadata = try Metadata.Owned.init(a, f.trusted, f.input);
        errdefer metadata.deinit();
        const profile = metadata.callers[0];
        var capture = try Capture.ForBackend(Cpu).verify(a, f.input.callers[0].proof, &profile.admitted);
        defer capture.deinit();
        var clock = try std.time.Timer.start();
        const capsule = try Capsule.derive(a, profile.input(), .{ .transcript_capacity = 2 });
        var capsule_owned = true;
        defer if (capsule_owned) capsule.deinit();
        const compile_ns = clock.lap();
        try capsule.requireProfile(a, profile);
        try std.testing.expectError(error.CallerTranscriptCapacityMismatch, Cold.Owned.deriveFromCapsule(a, capsule, 3, .{}));
        var wrong_profile = profile.*;
        wrong_profile.admitted.epoch.digest[0] ^= 1;
        try std.testing.expectError(error.CallerCompilerProfileMismatch, capsule.requireProfile(a, &wrong_profile));
        var cold = try Cold.Owned.deriveFromCapsule(a, capsule, 2, .{});
        defer cold.deinit();
        const fixed_ns = clock.lap();
        var baseline_cold = try Cold.Owned.derive(a, profile.input(), 2, .{});
        defer baseline_cold.deinit();
        const baseline_cold_ns = clock.lap();
        try std.testing.expectEqualDeep(cold.context, baseline_cold.context);
        try std.testing.expectEqualDeep(cold.wires, baseline_cold.wires);
        inline for (0..Storage.Airs.len) |i| try std.testing.expectEqualDeep(cold.fixed[i], baseline_cold.fixed[i]);
        clock.reset();
        var baseline = try Live.prepare(a, &profile.admitted, &capture, 2, .{});
        defer baseline.deinit();
        const baseline_ns = clock.lap();
        var candidate = try Live.prepareFromCapsule(a, capsule, &capture, 2, .{});
        defer candidate.deinit();
        const candidate_ns = clock.lap();
        try cold.validateLive(&baseline);
        try cold.validateLive(&candidate);
        try @import("block_v7_caller_joint_public_v1.zig").requireSameFrame(candidate.values, baseline.values);
        inline for (0..Storage.Airs.len) |i| {
            try std.testing.expectEqual(baseline.recursive.rows.main[i].len, candidate.recursive.rows.main[i].len);
            for (baseline.recursive.rows.main[i], candidate.recursive.rows.main[i]) |left, right| {
                try std.testing.expectEqual(left.log_size, right.log_size);
                try std.testing.expectEqualDeep(left.values, right.values);
            }
        }
        // A modified sampled value cannot be substituted into retained code.
        const old = capture.original.proof.sampled_values[0];
        capture.original.proof.sampled_values[0] = old.add(core.fields.qm31.QM31.one());
        if (capsule.prepareComposition(a, &capture)) |value| {
            var bad = value;
            bad.deinit();
            return error.AcceptedChangedCapsuleCapture;
        } else |_| {}
        capture.original.proof.sampled_values[0] = old;
        const composition_nodes = capsule.compiler().composition.circuit.nodes.len;
        // Production drops bounded compiler capsules after row collection and
        // before the independently keyed parent commitments/proof are created.
        capsule.deinit();
        capsule_owned = false;
        const base = try Parent.ForBackend(Cpu).deriveKeyFromFixed(a, cold.fixed, cold.context, .diagnostic_q8_pow0);
        const expected = [_]Protocol.Bus.Expected{.{ .profile = profile.seal, .epoch = profile.admitted.epoch.digest, .roots = profile.admitted.source.roots ++ .{profile.admitted.source.access_root} }};
        const key = try Protocol.Key.fromGeometry(base, cold.wires, &expected);
        const admission = try Protocol.Admission.init(key, try key.identity(), cold.wires, .{ .children = &.{candidate.values} }, &expected);
        const Plan = @import("blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Protocol);
        const plan = try Plan.init(a, &candidate.recursive.rows, admission);
        defer plan.deinit();
        var proof = try plan.prove(a, &candidate.recursive.rows);
        defer proof.deinit();
        const bytes = try Parent.codec.encode(a, &proof, &admission);
        errdefer a.free(bytes);
        const wires = try a.dupe(Cold.Wire, cold.wires);
        std.debug.print("V7_CALLER_CAPSULE compile_ns={d} fixed_from_capsule_ns={d} baseline_cold_ns={d} baseline_live_ns={d} capsule_live_ns={d} composition_nodes={d} exact_fixed_and_main=true shared_epoch=false diagnostic_unranked=true\n", .{ compile_ns, fixed_ns, baseline_cold_ns, baseline_ns, candidate_ns, composition_nodes });
        return .{ .metadata = metadata, .bytes = bytes, .key = key, .wires = wires };
    }
};
test "v7 caller capsule reuses trusted graph with exact rows and detached parent proof" {
    const a = std.testing.allocator;
    var output = try Fixture.runFixture(true, true, Consumer);
    defer output.deinit();
    var verified = try @import("block_v7_caller_joint_receiver_v1.zig").verify(a, output.bytes, output.metadata.callers[0], output.key, output.wires);
    defer verified.deinit();
    try std.testing.expect(verified.open.internal_residual.isZero());
    std.debug.print("V7_CALLER_CAPSULE parent_verified=true proof_bytes={d} compiler_destroyed=true original_proofs_destroyed=true producer_rows_destroyed=true canonical_security=false\n", .{output.bytes.len});
}
