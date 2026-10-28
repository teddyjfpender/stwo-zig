//! Direct-native batches -> one actual upper STARK. No global closure claim.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const bench = @import("block_v6_native_batch_proof_test.zig");
const parent = @import("../../recursion/blake3_execution_parent_proof.zig");
const frames = @import("../../recursion/block_v5_open_child_frames_v2.zig");
const bus = @import("../../recursion/block_v5_open_parent_public_bus_v2.zig");
const preparation = @import("../../recursion/block_v5_open_parent_preparation_v2.zig");
const protocol = @import("../../recursion/block_v5_reusable_open_parent_protocol_v2.zig");
const receiver = @import("../../recursion/block_v5_open_parent_receiver_v2.zig");
const Span = @import("../../recursion/block_v5_pc_clock_span_v1.zig").Span;

pub fn qualify(backing: std.mem.Allocator, selected: parent.protocol.Profile, left: *const bench.Retained, right: *const bench.Retained, expected_span: Span) !void {
    const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const budget = try Budget.create(backing, 32 * 1024 * 1024 * 1024);
    defer budget.destroy();
    const a = budget.allocator();
    const children = [_]frames.Child{ left.child, right.child };
    const captures = [_]*const @import("../../recursion/blake3_native_parent_verifier.zig").Verified{ &left.capture, &right.capture };
    const expected = [_]receiver.Expected{ .{ .native_batch_v6 = left.expected }, .{ .native_batch_v6 = right.expected } };
    const outer = receiver.OuterPins{ .job_id = expected_span.job_id, .source_image_digest = expected_span.source_image_digest, .sealed_digest = expected_span.sealed_digest, .segment_count = expected_span.segment_count, .first_cycle = expected_span.first_cycle, .last_cycle = expected_span.last_cycle, .initial_pc = expected_span.initial_pc, .final_pc = expected_span.final_pc };
    var timer = try std.time.Timer.start();
    var prepared = try preparation.prepare(a, .exact_outer, &children, &captures, 2);
    defer prepared.deinit();
    const prepare_ns = timer.lap();
    const geometry = try parent.ForBackend(Cpu).deriveKeyWithProfile(a, &prepared.recursive, selected);
    const key = try protocol.Key.fromGeometry(geometry, prepared.wires);
    const key_id = try key.identity();
    const authority = try protocol.Admission.init(key, key_id, prepared.wires, prepared.values);
    const Plan = @import("../../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Cpu, protocol);
    const plan = try Plan.init(a, &prepared.recursive.rows, authority);
    defer plan.deinit();
    const setup_ns = timer.lap();
    var proof = try plan.prove(a, &prepared.recursive.rows);
    defer proof.deinit();
    const prove_ns = timer.lap();
    const bytes = try parent.codec.encode(a, &proof, &authority);
    defer a.free(bytes);
    // Independently reconstitute every batch public input from the original
    // native policies/receipts, not from the producer's normalized child list.
    var fresh = try receiver.verify(a, bytes, key, key_id, prepared.wires, .exact_outer, &expected, outer);
    defer fresh.deinit();
    try std.testing.expectEqualDeep(expected_span, fresh.span);
    try std.testing.expect(fresh.native_open_sum.eql(left.child.native_open_sum.add(right.child.native_open_sum)));
    const verify_ns = timer.lap();
    var wrong_outer = outer;
    wrong_outer.final_pc ^= 4;
    try std.testing.expectError(error.UntrustedV5ExactOuterStatement, receiver.verify(a, bytes, key, key_id, prepared.wires, .exact_outer, &expected, wrong_outer));
    try std.testing.expectError(error.IncompleteV5ExactOuterSpan, receiver.verify(a, bytes, key, key_id, prepared.wires, .exact_outer, expected[0..1], outer));
    var changed = left.expected;
    changed.expected_id[0] ^= 1;
    const wrong_expected = [_]receiver.Expected{ .{ .native_batch_v6 = changed }, expected[1] };
    try std.testing.expectError(error.UntrustedNativeBatchKey, receiver.verify(a, bytes, key, key_id, prepared.wires, .exact_outer, &wrong_expected, outer));
    // Preserve the aggregate residual while changing two physical native
    // claims. The complete batch transcript/supply must still reject this.
    const receipts = try a.dupe(@import("../../recursion/block_v6_native_batch_receiver_v1.zig").Receipt, left.expected.exported);
    defer a.free(receipts);
    receipts[0].open_sum = receipts[0].open_sum.add(core.fields.qm31.QM31.one());
    receipts[1].open_sum = receipts[1].open_sum.sub(core.fields.qm31.QM31.one());
    changed = left.expected;
    changed.exported = receipts;
    const cancelling_claims = [_]receiver.Expected{ .{ .native_batch_v6 = changed }, expected[1] };
    try std.testing.expectError(error.InvalidReusableOpenParentPublicClosure, receiver.verify(a, bytes, key, key_id, prepared.wires, .exact_outer, &cancelling_claims, outer));
    // Normalized frame identities include the per-physical-claim domain.
    var wrong_frame = left.child;
    wrong_frame.claim_frame[0] ^= 1;
    try std.testing.expectError(error.TamperedV5OpenChildFrames, wrong_frame.validate());
    const costs = bench.work(&prepared.recursive.rows);
    std.debug.print("BLOCK_V6_BATCH_UPPER verified=true profile={s} segments={d} child_batches=2 prepare_ns={d} setup_ns={d} prove_ns={d} encode_verify_ns={d} recursive_ns={d} g_rows={d} air_cells={d} proof_bytes={d} charged_peak_bytes={d} globals_open=true\n", .{ @tagName(selected), expected_span.segment_count, prepare_ns, setup_ns, prove_ns, verify_ns, prepare_ns + setup_ns + prove_ns + verify_ns, costs.g_rows, costs.cells, bytes.len, budget.snapshot().peak_live_bytes });
}
