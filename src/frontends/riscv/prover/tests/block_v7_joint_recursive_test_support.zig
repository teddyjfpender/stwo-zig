//! Genuine original-capture differential gate; no synthetic successful capture.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Profile = @import("../../recursion/block_v7_memory_joint_fixed_profile_v1.zig");
const Native = @import("../../recursion/block_v7_memory_joint_fixed_v1.zig");
const Cold = @import("../../recursion/block_v7_memory_joint_fixed_transcript_v1.zig");
const Live = @import("../../recursion/air/block_v7_memory_joint_transcript_v1.zig");
const Inputs = @import("../../recursion/air/block_v7_memory_joint_inputs_v1.zig");
const Joint = @import("../block_v7_memory_joint_proof_v1.zig");
const E = @import("../block_v7_execution_epoch_v1.zig");
pub fn qualify(a: std.mem.Allocator, input: Profile.Input, capture: *const Joint.VerifiedCapture, comptime recursive_parent: bool) !void {
    const native = try Native.Owned.derive(a, input, .{});
    defer native.deinit();
    var deep_inputs = try @import("../../recursion/pcs_arithmetic_capture.zig").Owned.init(a, native.profile.deepProfile(), &capture.proof);
    defer deep_inputs.deinit();
    var deep_eval = try native.deep_graph.evaluate(a, deep_inputs.inputs);
    defer deep_eval.deinit();
    var fri_inputs = try @import("../../recursion/fri_arithmetic_capture.zig").Owned.init(a, native.profile.friProfile(), &capture.proof);
    defer fri_inputs.deinit();
    var fri_eval = try native.fri_graph.evaluate(a, fri_inputs.inputs);
    defer fri_eval.deinit();
    const inputs = try Inputs.composition(a, native.profile, &native.composition, &capture.proof);
    defer a.free(inputs);
    const values = try a.alloc(Q, native.composition.circuit.nodes.len);
    defer a.free(values);
    try native.composition.circuit.evaluateInto(inputs, values);
    // Wrong physical sum and a public halt clock must each fail the actual
    // original equation circuit even when all arithmetic is recomputed.
    var mutated = false;
    for (native.composition.sources, 0..) |source, i| {
        if (source == .public_input and source.public_input == 0) {
            inputs[i] = inputs[i].add(Q.one());
            try std.testing.expectError(error.UnsatisfiedCircuit, native.composition.circuit.evaluateInto(inputs, values));
            inputs[i] = inputs[i].sub(Q.one());
            mutated = true;
            break;
        }
    }
    try std.testing.expect(mutated);
    var cold = try Cold.derive(a, native.profile, 2, .{});
    defer cold.deinit();
    var live = try Live.planReplay(a, native.profile, capture, 2);
    defer live.deinit();
    try std.testing.expectEqualDeep(cold.id, live.plan.id);
    // Changing the witnessed first root/epoch and physical claim operands
    // changes admission identity, but may not specialize the fixed graph.
    const claims = try a.dupe(@import("../block_v7_memory_joint_air_v1.zig").RamClaim, input.claims.ram);
    defer a.free(claims);
    claims[0].sums[0] = claims[0].sums[0].add(Q.one());
    var changed = input;
    changed.claims.ram = claims;
    changed.roots[1][0] ^= 1;
    const entries = try a.dupe(E.Entry, input.roster);
    defer a.free(entries);
    const new_pin = try @import("../block_v7_memory_joint_protocol_v1.zig").entry(input.policy, &native.profile.layout, changed.roots);
    for (entries) |*entry| if (entry.family == .memory_joint) {
        entry.* = new_pin;
    };
    changed.roster = entries;
    changed.epoch = try E.Epoch.init(input.epoch.statement, input.epoch.config, input.epoch.counts, entries, entries.len);
    const changed_profile = try Profile.Owned.derive(a, changed, .{});
    defer changed_profile.deinit();
    try std.testing.expect(!std.meta.eql(native.profile.seal, changed_profile.seal));
    var changed_cold = try Cold.derive(a, changed_profile, 2, .{});
    defer changed_cold.deinit();
    try std.testing.expectEqualDeep(cold.id, changed_cold.id);
    if (recursive_parent) try qualifyParent(a, input, native.profile, capture);
    std.debug.print("V7_JOINT_RECURSIVE_SEAM original_capture=true composition=true deep=true fri=true transcript_cold_live=true changed_root_claim_key_invariant=true outer_parent=false\n", .{});
}

fn qualifyParent(a: std.mem.Allocator, input: Profile.Input, profile: *const Profile.Owned, capture: *const Joint.VerifiedCapture) !void {
    const ColdRoster = @import("../../recursion/block_v7_memory_joint_fixed_roster_v1.zig");
    const Prepare = @import("../../recursion/block_v7_memory_joint_preparation_v1.zig");
    const Parent = @import("../../recursion/blake3_execution_parent_proof.zig");
    const Protocol = @import("../../recursion/block_v7_memory_joint_parent_protocol_v1.zig");
    const Receive = @import("../../recursion/block_v7_memory_joint_receiver_v1.zig");
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const parent_profile = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0;
    var cold = ColdRoster.Owned.derive(a, input, 2, .{}) catch |err| {
        std.debug.print("JOINT_PARENT phase=cold_roster error={s}\n", .{@errorName(err)});
        return err;
    };
    std.debug.print("JOINT_PARENT phase=cold_roster done=true\n", .{});
    defer cold.deinit();
    const expected_base = try Parent.ForBackend(Cpu).deriveKeyFromFixed(a, cold.fixed, cold.context, parent_profile);
    const roster = [_]Protocol.Bus.Expected{.{ .profile = profile.seal, .epoch = input.epoch.digest, .roots = input.roots }};
    const key = try Protocol.Key.fromGeometry(expected_base, cold.wires, &roster);
    var ready = Prepare.prepare(a, profile, capture, 2, .{}) catch |err| {
        std.debug.print("JOINT_PARENT phase=live_prepare error={s}\n", .{@errorName(err)});
        return err;
    };
    std.debug.print("JOINT_PARENT phase=live_prepare done=true\n", .{});
    var ready_live = true;
    defer if (ready_live) ready.deinit();
    try ready.recursive.rows.partitionHashRows();
    try cold.namespace.validateLive(&ready.recursive.rows);
    try std.testing.expectEqualDeep(cold.context, ready.recursive.context);
    try std.testing.expectEqualDeep(cold.wires, ready.wires);
    inline for (0..@import("../../recursion/air/blake3_parent_row_storage.zig").Airs.len) |i| try std.testing.expectEqualDeep(cold.fixed[i], ready.recursive.rows.fixed[i]);
    const live_base = try Parent.ForBackend(Cpu).deriveKeyWithProfile(a, &ready.recursive, parent_profile);
    try std.testing.expectEqualDeep(expected_base, live_base);
    const admission = try Protocol.Admission.init(key, try key.identity(), ready.wires, .{ .children = &.{ready.values} }, &roster);
    const Plan = @import("../../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Protocol);
    const plan = try Plan.init(a, &ready.recursive.rows, admission);
    var plan_live = true;
    defer if (plan_live) plan.deinit();
    var proof = try plan.prove(a, &ready.recursive.rows);
    var proof_live = true;
    defer if (proof_live) proof.deinit();
    const bytes = try Parent.codec.encode(a, &proof, &admission);
    defer a.free(bytes);
    proof.deinit();
    proof_live = false;
    plan.deinit();
    plan_live = false;
    ready.deinit();
    ready_live = false;
    var verified = try Receive.verify(a, bytes, profile, key, cold.wires);
    defer verified.deinit();
    try std.testing.expect(verified.open.transition.eql(capture.open.transition));
    try std.testing.expectEqual(capture.open.event_count, verified.open.event_count);
    // Well-formed compensated physical claims keep both layout and aggregate
    // transition unchanged; the final proof must still bind every operand.
    const forged_claims = try a.dupe(@import("../block_v7_memory_joint_air_v1.zig").RamClaim, input.claims.ram);
    defer a.free(forged_claims);
    forged_claims[0].sums[0] = forged_claims[0].sums[0].add(Q.one());
    forged_claims[1].sums[0] = forged_claims[1].sums[0].sub(Q.one());
    var forged_input = input;
    forged_input.claims.ram = forged_claims;
    const forged_profile = try Profile.Owned.derive(a, forged_input, .{});
    defer forged_profile.deinit();
    try std.testing.expectEqualDeep(profile.seal, forged_profile.seal);
    try std.testing.expectError(error.InvalidProviderBatchPublicClosure, Receive.verify(a, bytes, forged_profile, key, cold.wires));
    // Exact public-frame reconstruction rejects a changed root-coordinate map.
    const Public = @import("../../recursion/block_v7_memory_joint_public_v1.zig");
    var canonical = try Public.reconstruct(a, profile);
    defer canonical.deinit();
    var changed = try canonical.clone(a);
    defer changed.deinit();
    changed.statement.roots_offset[0] += 1;
    try std.testing.expectError(error.UntrustedJointPublicFrame, Public.requireSameFrame(changed, canonical));
    // The separately selected key itself cannot be changed to match a proof.
    var bad_key = key;
    bad_key.preprocessed_root[0] ^= 1;
    if (Receive.verify(a, bytes, profile, bad_key, cold.wires)) |ok| {
        var bad = ok;
        bad.deinit();
        return error.AcceptedChangedJointParentKey;
    } else |_| {}
    std.debug.print("V7_JOINT_PARENT cold_live_key=true cold_live_rows=true detached_verify=true open_memory_only=true proof_bytes={d} producer_rows=0\n", .{bytes.len});
}
