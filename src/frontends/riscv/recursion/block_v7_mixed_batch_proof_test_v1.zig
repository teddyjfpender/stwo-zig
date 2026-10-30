//! A complete genuine six-original v7 root used as one OPEN reduction child.
//! This qualifies nesting and final global closure, not multi-window or >64.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Fixture = @import("../prover/tests/block_v7_complete_root_test.zig");
const Capture = @import("block_v7_mixed_batch_capture_v1.zig");
const Receive = @import("block_v7_mixed_batch_receiver_v1.zig");
const Prepare = @import("block_v7_mixed_batch_prepare_v1.zig");
const Cold = @import("block_v7_mixed_batch_fixed_join_v1.zig");
const Protocol = @import("block_v7_mixed_batch_protocol_v1.zig");
const Bus = @import("block_v7_mixed_batch_public_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
test "v7 nested complete root retains all open frames and closes only final root" {
    const a = std.testing.allocator;
    const output = try Fixture.produceComplete();
    defer output.deinit();
    var pool: @import("stwo_prover_engine").work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try @import("stwo_prover_engine").work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const pins = [_]Receive.DirectPin{.{ .key = output.key, .wires = output.wires }};
    const counts = [_]u32{@intCast(output.input().entries.len)};
    var metadata = try Receive.Metadata.init(a, output.input(), &counts, &pins, .{});
    var metadata_owned = true;
    defer if (metadata_owned) metadata.deinit();
    var capture = try Capture.verifyAndCapture(a, output.bytes, metadata.policies[0], .{});
    var capture_owned = true;
    defer if (capture_owned) capture.deinit();
    // The original proof bytes disappear before reduction row generation.
    a.free(output.bytes);
    output.bytes = &.{};
    std.debug.print("V7_NESTED_ROOT stage=original-root-captured original_children={d}\n", .{counts[0]});
    var prepared = try Prepare.prepare(a, &.{&capture}, metadata.expected, .{});
    var prepared_owned = true;
    defer if (prepared_owned) prepared.deinit();
    var cold = try Cold.Owned.derive(a, metadata.policies, metadata.expected, 2, .{});
    var cold_owned = true;
    defer if (cold_owned) cold.deinit();
    try cold.validateLive(&prepared);
    const key = try cold.deriveKey(Cpu, a);
    const key_id = try key.identity();
    const wires = try a.dupe(Bus.Wire, cold.wires);
    defer a.free(wires);
    std.debug.print("V7_NESTED_ROOT stage=independent-fixed-parity matched=true wires={d}\n", .{wires.len});
    const bytes = produce: {
        const admission = try Protocol.Admission.init(key, key_id, cold.wires, prepared.values(), cold.expected);
        const Plan = @import("blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Protocol);
        const plan = try Plan.init(a, &prepared.recursive.rows, admission);
        defer plan.deinit();
        var proof = try plan.prove(a, &prepared.recursive.rows);
        defer proof.deinit();
        break :produce try Parent.codec.encode(a, &proof, &admission);
    };
    defer a.free(bytes);
    prepared.deinit();
    prepared_owned = false;
    cold.deinit();
    cold_owned = false;
    capture.deinit();
    capture_owned = false;
    metadata.deinit();
    metadata_owned = false;
    // Fresh reconstruction uses only independently selected profiles, keys and
    // schedules. All original/child proofs, captures and wide rows are gone.
    var verified = try Receive.verify(a, bytes, output.trusted, output.input(), &counts, &pins, key, wires, .{});
    defer verified.deinit();
    try std.testing.expectEqualDeep(output.original.statement, verified.summary.statement);
    try std.testing.expectEqualDeep(output.original.output, verified.summary.output);
    var fresh = try Receive.Metadata.init(a, output.input(), &counts, &pins, .{});
    defer fresh.deinit();
    const admission = try Protocol.Admission.init(key, key_id, wires, fresh.values(), fresh.expected);
    var hostile = try Parent.codec.decode(a, bytes, &admission);
    hostile.proof.?.commitment_scheme_proof.sampled_values.items[3][0][0] = hostile.proof.?.commitment_scheme_proof.sampled_values.items[3][0][0].add(core.fields.qm31.QM31.one());
    try hostile.validate(&admission);
    if (Parent.verify(&hostile, &admission)) |accepted| {
        var unexpected = accepted;
        unexpected.deinit();
        return error.AcceptedChangedV7ReductionOods;
    } else |err| try std.testing.expectEqual(error.OodsNotMatching, err);
    const source = @constCast(fresh.sources[0]);
    source.range.first += 1;
    try std.testing.expectError(error.UntrustedMixedBatchRoster, admission.validate());
    source.range.first -= 1;
    var wrong_key = key_id;
    wrong_key[0] ^= 1;
    try std.testing.expectError(error.UntrustedProviderBatchKey, Protocol.Admission.init(key, wrong_key, wires, fresh.values(), fresh.expected));
    std.debug.print("V7_NESTED_ROOT verified=true batches=1 original_children={d} proof_bytes={d} independently_keyed=true global_closed=true original_proofs=0 captures=0 rows=0 multi_batch_qualified=false\n", .{ counts[0], bytes.len });
}
