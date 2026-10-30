//! Genuine active caller -> exact independently compiled verifier -> parent.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const F = @import("../../recursion/block_v7_caller_family_v1.zig").Active;
const Epoch = @import("../block_v7_execution_epoch_v1.zig");
pub fn qualify(a: std.mem.Allocator, pin: F.Source.Pin, epoch: Epoch.Epoch, entries: []const Epoch.Entry, proof: *const F.Proof.Proof, name: []const u8) !void {
    const input = F.FixedProfile.Input{ .pin = pin, .epoch = epoch, .entries = entries, .arithmetic = proof.arithmetic, .claims = proof.relations };
    const capsule = try F.Capsule.Capsule.derive(a, input, .{ .max_bytes = 3 << 30, .transcript_capacity = 4 });
    defer capsule.deinit();
    const admitted = capsule.admitted();
    var capture = try F.Capture.ForBackend(Cpu).verify(a, proof, admitted);
    defer capture.deinit();
    var equations = try capsule.prepareComposition(a, &capture);
    defer equations.deinit();
    try equations.circuit.evaluateInto(equations.inputs, equations.values);
    // Check every omitted operand has an explicit zero output in linear time;
    // only replay boundary mutations per family, avoiding thousands of full
    // DAG evaluations in the development loop.
    const input_nodes = try a.alloc(u32, equations.inputs.len);
    defer a.free(input_nodes);
    const is_zero = try a.alloc(bool, equations.circuit.nodes.len);
    defer a.free(is_zero);
    @memset(is_zero, false);
    for (equations.circuit.outputs) |node| is_zero[node] = true;
    var input_at: usize = 0;
    for (equations.circuit.nodes, 0..) |node, i| if (node.op == .input) {
        input_nodes[input_at] = @intCast(i);
        input_at += 1;
    };
    try std.testing.expectEqual(input_nodes.len, input_at);
    var public_count: usize = 0;
    for (equations.sources) |source| if (source == .public_input) {
        public_count = @max(public_count, @as(usize, source.public_input) + 1);
    };
    const public_sources = try a.alloc(usize, public_count);
    defer a.free(public_sources);
    @memset(public_sources, std.math.maxInt(usize));
    for (equations.sources, 0..) |source, i| if (source == .public_input) {
        public_sources[source.public_input] = i;
    };
    var offset: u32 = 0;
    var rejected: usize = 0;
    var zero_fields: usize = 0;
    for (proof.arithmetic.componentClaims(), admitted.arithmetic.selected) |claim, included| {
        const count: u32 = @intCast(claim.detailed.len + @intFromBool(claim.has_batch_frame));
        if (!included) for (offset..offset + count) |public_index| {
            if (public_index >= public_sources.len or public_sources[public_index] == std.math.maxInt(usize)) return error.MissingOmittedCallerPublicClaim;
            const i = public_sources[public_index];
            try std.testing.expect(is_zero[input_nodes[i]]);
            zero_fields += 1;
            if (public_index == offset or public_index == offset + count - 1) {
                const saved = equations.inputs[i];
                equations.inputs[i] = saved.add(core.fields.qm31.QM31.one());
                try std.testing.expectError(error.UnsatisfiedCircuit, equations.circuit.evaluateInto(equations.inputs, equations.values));
                equations.inputs[i] = saved;
                rejected += 1;
            }
        };
        offset += count;
    }
    try equations.circuit.evaluateInto(equations.inputs, equations.values);
    if (std.process.hasEnvVarConstant("STWO_V7_ACTIVE_CALLER_COMPOSITION_ONLY")) {
        std.debug.print("V7_ACTIVE_CALLER_COMPOSITION kind={s} composition_nodes={d} rejected_omitted_fields={d} explicit_zero_fields={d} exact_original_evaluation=true parent_proof=false\n", .{ name, equations.circuit.nodes.len, rejected, zero_fields });
        return;
    }
    var live_clock = try std.time.Timer.start();
    var live = try F.Preparation.prepareFromCapsule(a, capsule, &capture, 4, .{ .max_bytes = 4 << 30 });
    const capsule_live_ns = live_clock.read();
    var live_owned = true;
    defer if (live_owned) live.deinit();
    var fixed = try F.FixedRoster.Owned.deriveFromCapsule(a, capsule, 4, .{ .max_bytes = 4 << 30 });
    defer fixed.deinit();
    try fixed.validateLive(&live);
    if (std.process.hasEnvVarConstant("STWO_V7_CALLER_CAPSULE_COMPARE")) {
        var timer = try std.time.Timer.start();
        var baseline = try F.Preparation.prepare(a, admitted, &capture, 4, .{ .max_bytes = 4 << 30 });
        defer baseline.deinit();
        const baseline_ns = timer.lap();
        try fixed.validateLive(&baseline);
        try F.Public.requireSameFrame(live.values, baseline.values);
        const Storage = @import("../../recursion/air/blake3_parent_row_storage.zig");
        inline for (0..Storage.Airs.len) |i| {
            try std.testing.expectEqualDeep(live.recursive.rows.fixed[i], baseline.recursive.rows.fixed[i]);
            try std.testing.expectEqual(live.recursive.rows.main[i].len, baseline.recursive.rows.main[i].len);
            for (live.recursive.rows.main[i], baseline.recursive.rows.main[i]) |left, right| {
                try std.testing.expectEqual(left.log_size, right.log_size);
                try std.testing.expectEqualDeep(left.values, right.values);
            }
        }
        const saved = capture.original.proof.sampled_values[0];
        capture.original.proof.sampled_values[0] = saved.add(core.fields.qm31.QM31.one());
        if (F.Preparation.prepareFromCapsule(a, capsule, &capture, 4, .{})) |value| {
            var bad = value;
            bad.deinit();
            return error.AcceptedActiveCallerChangedCapsuleCapture;
        } else |err| if (err == error.OutOfMemory) return err;
        capture.original.proof.sampled_values[0] = saved;
        std.debug.print("V7_ACTIVE_CALLER_CAPSULE kind={s} baseline_live_ns={d} capsule_live_ns={d} exact_all_fixed_main=true changed_capture_rejected=true diagnostic_unranked=true\n", .{ name, baseline_ns, capsule_live_ns });
    }

    const Parent = @import("../../recursion/blake3_execution_parent_proof.zig");
    const Protocol = F.ParentProtocol;
    const profile = try F.FixedProfile.Owned.derive(a, input, .{});
    defer profile.deinit();
    const base = try Parent.ForBackend(Cpu).deriveKeyFromFixed(a, fixed.fixed, fixed.context, .diagnostic_q8_pow0);
    const roster = [_]Protocol.Bus.Expected{.{ .profile = admitted.template_id, .epoch = epoch.digest, .roots = pin.roots ++ .{pin.access_root} }};
    const key = try Protocol.Key.fromGeometry(base, fixed.wires, &roster);
    const admission = try Protocol.Admission.init(key, try key.identity(), live.wires, .{ .children = &.{live.values} }, &roster);
    const Producer = @import("../../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Protocol);
    const producer = try Producer.init(a, &live.recursive.rows, admission);
    var producer_owned = true;
    defer if (producer_owned) producer.deinit();
    var parent = try producer.prove(a, &live.recursive.rows);
    const bytes = Parent.codec.encode(a, &parent, &admission) catch |err| {
        parent.deinit();
        return err;
    };
    defer a.free(bytes);
    parent.deinit();
    producer.deinit();
    producer_owned = false;
    live.deinit();
    live_owned = false;
    var verified = try F.Receiver.verify(a, bytes, profile, key, fixed.wires);
    defer verified.deinit();
    try std.testing.expectEqualDeep(capture.original.receipt, verified.open);
    var wrong = key;
    wrong.preprocessed_root[0] ^= 1;
    if (F.Receiver.verify(a, bytes, profile, wrong, fixed.wires)) |bad| {
        var value = bad;
        value.deinit();
        return error.AcceptedActiveCallerWrongParentKey;
    } else |err| if (err == error.OutOfMemory) return err;
    std.debug.print("V7_ACTIVE_CALLER_PARENT kind={s} composition_nodes={d} rejected_omitted_fields={d} explicit_zero_fields={d} proof_bytes={d} cold_live_equal=true detached_verified=true complete_execution=false\n", .{ name, equations.circuit.nodes.len, rejected, zero_fields, bytes.len });
}
