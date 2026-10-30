//! Original proof/capture -> two independently equivalent recursive witnesses.
//! All source producers and original proof bytes are destroyed before comparison.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const engine = @import("stwo_prover_engine");
const Q = core.fields.qm31.QM31;
const Native = @import("../block_v7_native_proof_v1.zig");
const Source = @import("../block_v7_native_source_v1.zig");
const E = @import("../block_v7_execution_epoch_v1.zig");
const Profile = @import("../../recursion/block_v7_native_fixed_profile_v1.zig");
const Capsule = @import("../../recursion/block_v7_native_compiler_capsule_v1.zig").Capsule;
const Cold = @import("../../recursion/block_v7_native_fixed_roster_v1.zig");
const Prepare = @import("../../recursion/block_v7_native_preparation_v1.zig");
const Public = @import("../../recursion/block_v7_native_public_v1.zig");
const Storage = @import("../../recursion/air/blake3_parent_row_storage.zig");
const Protocol = @import("../../recursion/block_v7_native_parent_protocol_v1.zig");
const Parent = @import("../../recursion/blake3_execution_parent_proof.zig");
const Receive = @import("../../recursion/block_v7_native_receiver_v1.zig");
const parent_profile = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0;
fn equalRows(left: *const Prepare.Prepared, right: *const Prepare.Prepared) !void {
    try std.testing.expectEqualDeep(left.wires, right.wires);
    try std.testing.expectEqualDeep(left.recursive.context, right.recursive.context);
    try Public.requireSameFrame(left.values, right.values);
    inline for (0..Storage.Airs.len) |i| {
        try std.testing.expectEqualDeep(left.recursive.rows.fixed[i], right.recursive.rows.fixed[i]);
        try std.testing.expectEqual(left.recursive.rows.main[i].len, right.recursive.rows.main[i].len);
        for (left.recursive.rows.main[i], right.recursive.rows.main[i]) |x, y| {
            try std.testing.expectEqualDeep(x.log_size, y.log_size);
            try std.testing.expectEqualDeep(x.values, y.values);
        }
    }
}
fn prove(a: std.mem.Allocator, ready: *Prepare.Prepared, key: Protocol.Key, expected: []const Protocol.Bus.Expected) ![]u8 {
    const admission = try Protocol.Admission.init(key, try key.identity(), ready.wires, .{ .children = &.{ready.values} }, expected);
    const Plan = @import("../../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Protocol);
    const plan = try Plan.init(a, &ready.recursive.rows, admission);
    defer plan.deinit();
    var proof = try plan.prove(a, &ready.recursive.rows);
    defer proof.deinit();
    return Parent.codec.encode(a, &proof, &admission);
}
fn run(comptime access: bool, comptime mul: bool, mode: Source.LayoutMode, comptime parent: bool) !void {
    const code = if (access) [_]u32{ 0x00700313, 0x00900393, if (mul) 0x02730433 else 0x00730433, 0x001002b7, 0x10028293, 0x0082a023, 0x0002a483, 0x0000006f } else [_]u32{ 0x00700313, 0x00900393, 0x00730433, 0x0000006f };
    const elf = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 512, .rv32im_zkvm_v1);
    const a = std.testing.allocator;
    var phase = try std.time.Timer.start();
    var session = try @import("../../runner/mod.zig").BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    var session_live = true;
    defer if (session_live) session.deinit();
    var executed = try session.startSegment(code.len - 1);
    var executed_live = true;
    defer if (executed_live) executed.deinit();
    var counters = try @import("../../air/lookups/tables/mod.zig").counter.Set.init(a);
    var counters_live = true;
    defer if (counters_live) counters.deinit(a);
    var segment = try @import("../block_v7_execution_test_support.zig").Segment.init(a, &executed, parent_profile.config(), @splat(7), 0, .rv32im_zkvm_v1, 0, &counters);
    var segment_live = true;
    defer if (segment_live) segment.deinit();
    segment.pin.layout_mode = mode;
    const entries = [_]E.Entry{try segment.pin.entry(a)};
    var counts: E.Counts = @splat(0);
    counts[0] = 1;
    const epoch = try E.Epoch.init(@splat(9), parent_profile.config(), counts, &entries, 1);
    std.debug.print("V7_NATIVE_COMPILER_GATE phase=original_profile access={} mul={}\n", .{ access, mul });
    const profile = try Profile.Owned.derive(a, segment.pin, epoch, &entries, .{});
    defer profile.deinit();
    std.debug.print("V7_NATIVE_COMPILER_GATE phase=original_prove access={} mul={}\n", .{ access, mul });
    var original = try Native.For(Cpu).prove(a, &segment.first, segment.owner, segment.source.inputs, segment.pin, epoch, &entries);
    var original_live = true;
    defer if (original_live) original.deinit(a);
    std.debug.print("V7_NATIVE_COMPILER_GATE phase=original_capture access={} mul={}\n", .{ access, mul });
    var capture = try Native.For(Cpu).verifyAndCapture(a, &original, segment.pin, epoch, &entries);
    defer capture.deinit();
    std.debug.print("V7_NATIVE_COMPILER_GATE phase=destroy_sources access={} mul={}\n", .{ access, mul });
    original.deinit(a);
    original_live = false;
    segment.deinit();
    segment_live = false;
    counters.deinit(a);
    counters_live = false;
    executed.deinit();
    executed_live = false;
    session.deinit();
    session_live = false;
    const claims = Public.Claims{ .projection = capture.claims, .access = capture.memory_claims };
    phase.reset();
    std.debug.print("V7_NATIVE_COMPILER_GATE phase=capsule_derive access={} mul={}\n", .{ access, mul });
    const selected_copy = try Profile.Owned.derive(a, profile.pin, profile.epoch, profile.roster, profile.limits);
    const capsule = Capsule.derive(a, selected_copy, .{}) catch |err| {
        selected_copy.deinit();
        return err;
    };
    selected_copy.deinit();
    var capsule_live = true;
    defer if (capsule_live) capsule.deinit();
    std.debug.print("V7_NATIVE_COMPILER_GATE phase=capsule_ready access={} mul={}\n", .{ access, mul });
    const compile_ns = phase.lap();
    try capsule.requireProfile(profile);
    // Bounds and failure cleanup remain under the original enclosing request.
    std.debug.print("V7_NATIVE_COMPILER_GATE phase=allocation_negative access={} mul={}\n", .{ access, mul });
    const small = try engine.host_budget_allocator.SharedHostBudget.create(a, 4096);
    defer small.destroy();
    try std.testing.expectError(error.OutOfMemory, Capsule.derive(small.allocator(), profile, .{}));
    try std.testing.expectEqual(@as(usize, 0), small.snapshot().live_bytes);
    std.debug.print("V7_NATIVE_COMPILER_GATE phase=profile_negatives access={} mul={}\n", .{ access, mul });
    const saved = profile.shape.mask_log;
    profile.shape.mask_log += 1;
    try std.testing.expectError(error.NativeCompilerProfileMismatch, capsule.requireProfile(profile));
    profile.shape.mask_log = saved;
    const old_mode = profile.pin.layout_mode;
    profile.pin.layout_mode = if (old_mode == .canonical_v1) .degree_bounded_q2_v1 else .canonical_v1;
    try std.testing.expectError(error.NativeCompilerProfileMismatch, capsule.requireProfile(profile));
    profile.pin.layout_mode = old_mode;
    const old_root = profile.pin.roots[1];
    profile.pin.roots[1][0] ^= 1;
    try std.testing.expectError(error.NativeCompilerProfileMismatch, capsule.requireProfile(profile));
    profile.pin.roots[1] = old_root;
    const old_config = profile.shape.config;
    profile.shape.config.pow_bits += 1;
    try std.testing.expectError(error.NativeCompilerProfileMismatch, capsule.requireProfile(profile));
    profile.shape.config = old_config;
    phase.reset();
    std.debug.print("V7_NATIVE_COMPILER_GATE phase=cold_uncached access={} mul={}\n", .{ access, mul });
    var cold = try Cold.Owned.derive(a, profile, claims, 2, .{});
    defer cold.deinit();
    const uncached_cold_ns = phase.lap();
    std.debug.print("V7_NATIVE_COMPILER_GATE phase=cold_cached access={} mul={}\n", .{ access, mul });
    var cached = try Cold.Owned.deriveFromCapsule(a, capsule, claims, 2, .{});
    defer cached.deinit();
    const cached_cold_ns = phase.lap();
    try std.testing.expectEqualDeep(cold.context, cached.context);
    try std.testing.expectEqualDeep(cold.wires, cached.wires);
    inline for (0..Storage.Airs.len) |i| try std.testing.expectEqualDeep(cold.fixed[i], cached.fixed[i]);
    // Same exact original transcript and OODS input vector; the fresh capture
    // supplies values, never geometry. Mutated claims fail original equations.
    if (mul) {
        var legacy_plan = try Prepare.plan(a, profile, &capture, 2);
        defer legacy_plan.deinit();
        var cached_plan = try Prepare.planFromCapsule(a, capsule, &capture, 2, false);
        defer cached_plan.deinit();
        try std.testing.expectEqualDeep(legacy_plan.transcript.?.plan.id, cached_plan.transcript.?.plan.id);
        try std.testing.expectEqualDeep(legacy_plan.transcript.?.operations, cached_plan.transcript.?.operations);
        try std.testing.expectEqualDeep(legacy_plan.state.?.composition.inputs, cached_plan.state.?.composition.inputs);
        try std.testing.expectEqualDeep(legacy_plan.state.?.composition.values, cached_plan.state.?.composition.values);
        try std.testing.expectEqualDeep(legacy_plan.state.?.deep.inputs.inputs, cached_plan.state.?.deep.inputs.inputs);
        const old = capture.claims[0].sum;
        capture.claims[0].sum = old.add(Q.one());
        if (capsule.prepareComposition(a, &capture)) |ok| {
            var bad = ok;
            bad.deinit();
            return error.AcceptedChangedNativeClaim;
        } else |_| {}
        capture.claims[0].sum = old;
        const last = capture.proof.sampled_values.len - 1;
        const sample = capture.proof.sampled_values[last];
        capture.proof.sampled_values[last] = sample.add(Q.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, capsule.prepareComposition(a, &capture));
        capture.proof.sampled_values[last] = sample;
        const channel = capture.final_channel;
        capture.final_channel.mixU32s(&.{0x42414443});
        try std.testing.expectError(error.InvalidNativeTranscript, Prepare.planFromCapsule(a, capsule, &capture, 2, false));
        capture.final_channel = channel;
    }
    phase.reset();
    var legacy = try Prepare.prepare(a, profile, &capture, 2, .{});
    var legacy_live = true;
    defer if (legacy_live) legacy.deinit();
    const uncached_live_ns = phase.lap();
    var reused = try Prepare.prepareFromCapsule(a, capsule, &capture, 2, .{});
    var reused_live = true;
    defer if (reused_live) reused.deinit();
    const cached_live_ns = phase.lap();
    // Destruction before namespace mutation and proving proves no graph/plan
    // storage escapes the capsule's immutable borrow lifetime.
    capsule.deinit();
    capsule_live = false;
    try cold.validateLive(&legacy);
    try cached.validateLive(&reused);
    try equalRows(&legacy, &reused);
    if (parent) {
        const base = try Parent.ForBackend(Cpu).deriveKeyFromFixed(a, cold.fixed, cold.context, parent_profile);
        const expected = [_]Protocol.Bus.Expected{Cold.expected(profile)};
        const key = try Protocol.Key.fromGeometry(base, cold.wires, &expected);
        const bytes = try prove(a, &legacy, key, &expected);
        defer a.free(bytes);
        const reused_bytes = try prove(a, &reused, key, &expected);
        defer a.free(reused_bytes);
        try std.testing.expectEqualSlices(u8, bytes, reused_bytes);
        legacy.deinit();
        legacy_live = false;
        reused.deinit();
        reused_live = false;
        var verified = try Receive.verify(a, reused_bytes, profile, claims, key, cached.wires);
        defer verified.deinit();
        try std.testing.expectEqualDeep(capture.open, verified.open);
        var wrong = key;
        wrong.preprocessed_root[0] ^= 1;
        if (Receive.verify(a, reused_bytes, profile, claims, wrong, cached.wires)) |ok| {
            var bad = ok;
            bad.deinit();
            return error.AcceptedWrongNativeKey;
        } else |_| {}
        const old = capture.claims[0].sum;
        capture.claims[0].sum = old.add(Q.one());
        if (Receive.verify(a, reused_bytes, profile, claims, key, cached.wires)) |ok| {
            var bad = ok;
            bad.deinit();
            return error.AcceptedChangedNativeClaim;
        } else |_| {}
        capture.claims[0].sum = old;
    }
    std.debug.print("V7_NATIVE_COMPILER access={} mul={} mode={s} parent={} compile_ns={d} cold_uncached_ns={d} cold_cached_ns={d} live_uncached_ns={d} live_cached_ns={d} exact_rows=true producer_destroyed=true timings=diagnostic\n", .{ access, mul, @tagName(mode), parent, compile_ns, uncached_cold_ns, cached_cold_ns, uncached_live_ns, cached_live_ns });
}
test "native compiler capsule exact no-access rows and detached parent proof" {
    try run(false, false, .canonical_v1, true);
}
test "native compiler capsule exact q3 access rows and detached parent proof" {
    try run(true, true, .canonical_v1, true);
}
test "native compiler capsule exact degree-bounded access rows and detached parent proof" {
    try run(true, true, .degree_bounded_q2_v1, true);
}
