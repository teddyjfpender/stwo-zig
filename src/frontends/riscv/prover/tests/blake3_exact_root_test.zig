//! Canonical 4+2 dyadic members become one exact-count recursive proof.
const std = @import("std");
const runner = @import("../../runner/mod.zig");
const Segment = @import("../../runner/result.zig").SegmentResult;
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const parent = @import("../../recursion/blake3_execution_parent_proof.zig");
const exact = parent.exact_root;
const forest = @import("../../recursion/blake3_exact_forest_protocol.zig");
const spans = @import("../../recursion/span_statement_blake3.zig");
const statement_mod = @import("../blake3_segment_statement.zig");
const helpers = @import("blake3_segment_tree_test.zig");

test "exact-count V2 six-leaf one-root canonical proof" {
    const backing = try @import("../blake3_parent_profile_test_support.zig").benchmarkAllocator();
    const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const budget = try Budget.create(backing, 48 * 1024 * 1024 * 1024);
    defer budget.destroy();
    const a = budget.allocator();
    const config = parent.protocol.CSP_CONFIG;
    const instructions = [_]u32{
        0x00500093, 0x00708093, 0x00100137, 0x00100193,
        0x00000013, 0x00000013, 0x00312223, 0x00312423,
        0x0000006f,
    };
    const elf = @import("../../runner/guest_precompile/test_elf.zig").buildProgram(
        instructions.len,
        &instructions,
        0,
        .rv32im_zkvm_v1,
    );
    var session = try runner.BaseExecutionSession.init(
        a,
        &elf,
        .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local },
    );
    defer session.deinit();
    var segments: [6]Segment = undefined;
    var count: usize = 0;
    defer for (segments[0..count]) |*item| item.deinit();
    for (&segments, 0..) |*item, i| {
        item.* = if (i == 0) try session.startSegment(1) else try session.resumeSegment(segments[i - 1].continuation.?, if (i == 5) 100 else 1);
        count += 1;
    }
    const job = blk: {
        var first = try helpers.ownerForProfile(true, a, &segments[0]);
        defer first.deinit();
        var last = try helpers.ownerForProfile(true, a, &segments[5]);
        defer last.deinit();
        break :blk try statement_mod.initJob(
            a,
            config,
            &segments[0],
            &segments[5],
            &first.native.statement.public_data,
            &last.native.statement.public_data,
        );
    };
    var statements: [6]spans.SpanStatement = undefined;
    for (&statements, &segments) |*statement, *segment| {
        statement.* = try statement_mod.leaf(a, job, segment);
    }
    var pair01 = try helpers.provePair(Cpu, true, a, config, .{
        &segments[0], &segments[1],
    }, .{ statements[0], statements[1] });
    defer pair01.deinit();
    var pair23 = try helpers.provePair(Cpu, true, a, config, .{
        &segments[2], &segments[3],
    }, .{ statements[2], statements[3] });
    defer pair23.deinit();
    var pair45 = try helpers.provePair(Cpu, true, a, config, .{
        &segments[4], &segments[5],
    }, .{ statements[4], statements[5] });
    defer pair45.deinit();
    var four_fold = try parent.tree.preparePair(a, &pair01, &pair23, 2);
    defer four_fold.deinit();
    var four = try helpers.proveFold(Cpu, true, a, &four_fold);
    defer four.deinit();

    const entries = [_]forest.Entry{
        .{ .statement = four.statement, .expected_key_id = four.admission.expected_id },
        .{ .statement = pair45.statement, .expected_key_id = pair45.admission.expected_id },
    };
    const pin = try forest.digest(job, &entries);
    const members = [_]*const parent.tree.Node{ &four, &pair45 };
    var folded = try exact.prepareBounded(a, job, &members, pin, 2, 32 * 1024 * 1024 * 1024);
    defer folded.deinit();
    try std.testing.expectEqualDeep(try exact.expectedRoot(job), folded.fold.statement);
    const Api = parent.ForBackend(Cpu);
    const key = try Api.deriveKeyWithProfile(a, &folded.fold.prepared, .csp_q70_pow26);
    const admitted = try parent.protocol.Admission.init(key, try key.identity());
    const worker = try parent.pipeline.ForBackend(Cpu).Worker.init(
        a,
        &folded.fold.prepared.rows,
        admitted,
        .{ .worker_count = 2, .host_byte_limit = 32 * 1024 * 1024 * 1024, .retained_scratch_limit = 64 * 1024 * 1024 },
    );
    defer worker.deinit();
    var proof = try worker.proveAdmittedConsuming(&folded.fold.prepared.rows, admitted);
    defer proof.deinit();
    const bytes = try parent.codec.encode(a, &proof, &admitted);
    defer a.free(bytes);
    var verified = try exact.verifyBytes(a, bytes, admitted, job, pin);
    defer verified.deinit();
    try std.testing.expectEqual(@as(u32, 6), verified.statement.body.executed.segment_count);
    var wrong_pin = pin;
    wrong_pin[0] ^= 1;
    try std.testing.expectError(error.UntrustedExactForestRoster, exact.verifyBytes(a, bytes, admitted, job, wrong_pin));
    std.debug.print("EXACT_ROOT verified=true segments=6 children=2 proof_bytes={d} peak_bytes={d}\n", .{ bytes.len, budget.snapshot().peak_live_bytes });
}
