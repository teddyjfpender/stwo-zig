//! Four actual segments, two intermediate aggregates and one aggregate root.
const std = @import("std");
const runner = @import("../runner/mod.zig");
const segment = @import("blake3_segment_execution.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const execution = @import("blake3_execution_proof.zig").ForBackend(Cpu);
const pipeline = @import("blake3_segment_parent.zig").ForBackend(Cpu);
const parent = @import("../recursion/blake3_execution_parent_proof.zig");
const tree = parent.tree;
const spans = @import("../recursion/span_statement_blake3.zig");
const segment_statement = @import("blake3_segment_statement.zig");
const config = parent.protocol.PCS_CONFIG;
const Segment = @import("../runner/result.zig").SegmentResult;
test "BLAKE3 adjacent segments form a four-leaf tree" {
    try checkForBackend(Cpu, false);
}
/// The canonical path proves four real leaves and two aggregate levels. It uses
/// one proving worker at a time; overlap remains a separate qualification.
pub fn checkForBackend(comptime Backend: type, comptime canonical: bool) !void {
    const backing = if (canonical) try @import("blake3_parent_profile_test_support.zig").benchmarkAllocator() else std.testing.allocator;
    const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const budget: ?*Budget = if (canonical) try Budget.create(backing, 48 * 1024 * 1024 * 1024) else null;
    defer if (budget) |owned| owned.destroy();
    const a = if (budget) |owned| owned.allocator() else backing;
    const pcs_config = if (canonical) parent.protocol.CSP_CONFIG else config;
    const instructions = [_]u32{ 0x00500093, 0x00708093, 0x00100137, 0x00100193, 0x00312223, 0x00312423, 0x0000006f };
    const elf = @import("../runner/guest_precompile/test_elf.zig").buildProgram(instructions.len, &instructions, 0, .rv32im_zkvm_v1);
    var session = try runner.BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var segments: [4]Segment = undefined;
    var count: usize = 0;
    defer for (segments[0..count]) |*item| item.deinit();
    for (&segments, 0..) |*item, i| {
        item.* = if (i == 0) try session.startSegment(1) else try session.resumeSegment(segments[i - 1].continuation.?, if (i == 3) 100 else 1);
        count += 1;
    }
    var boundaries: [4]segment_statement.Boundary = undefined;
    for (&segments, 0..) |*item, i| {
        boundaries[i] = try segment_statement.boundary(a, item);
        if (i != 0) try std.testing.expectEqualDeep(boundaries[i - 1].exit, boundaries[i].entry);
    }
    // Only endpoint owners are needed to derive admitted job I/O and program.
    // Release them before materializing proof witnesses for each pair.
    const job = blk: {
        var first = try ownerForProfile(canonical, a, &segments[0]);
        defer first.deinit();
        var last = try ownerForProfile(canonical, a, &segments[3]);
        defer last.deinit();
        break :blk try segment_statement.initJob(a, pcs_config, &segments[0], &segments[3], &first.native.statement.public_data, &last.native.statement.public_data);
    };
    var statements: [4]spans.SpanStatement = undefined;
    for (&statements, &segments) |*statement, *item| {
        statement.* = try segment_statement.leaf(a, job, item);
    }
    var left = try provePair(Backend, canonical, a, pcs_config, .{ &segments[0], &segments[1] }, .{ statements[0], statements[1] });
    defer left.deinit();
    var right = try provePair(Backend, canonical, a, pcs_config, .{ &segments[2], &segments[3] }, .{ statements[2], statements[3] });
    defer right.deinit();
    try std.testing.expect(left.admission.key.context.aggregation != null);
    try std.testing.expect(right.admission.key.context.aggregation != null);
    try std.testing.expectError(error.AliasedAggregateChildren, tree.preparePair(a, &left, &left, 2));
    try std.testing.expectError(error.SlotsNotAdjacent, tree.preparePair(a, &right, &left, 2));
    var folded = try tree.preparePair(a, &left, &right, 2);
    defer folded.deinit();
    try std.testing.expectEqual(@as(u8, 2), folded.statement.slots.height);
    try std.testing.expectEqualSlices(u8, &left.admission.expected_id, &folded.prepared.context.child_key_id);
    try std.testing.expectEqualSlices(u8, &right.admission.expected_id, &folded.prepared.context.aggregation.?.right_child_key_id);
    var root = if (canonical) try proveFold(Backend, canonical, a, &folded) else try @import("blake3_tree_pipeline_test_support.zig").check(a, &left, &right, &folded);
    defer root.deinit();
    _ = try root.root();
    try std.testing.expectEqualDeep(job, root.statement.job);
    try std.testing.expectEqual(@as(u64, 6), root.statement.body.executed.cycle_count);
    try std.testing.expectEqual(@as(u32, 4), root.statement.body.executed.segment_count);
    // Nodes remain valid after another level consumes their verifier witnesses.
    try left.validate();
    try right.validate();
    if (budget) |owned| std.debug.print("CANONICAL_TREE_BUDGET peak_bytes={d} limit_bytes={d}\n", .{ owned.snapshot().peak_live_bytes, owned.snapshot().limit });
    std.debug.print("BLAKE3_TREE_PARAMETERS leaf_queries={d} leaf_pow_bits={d} parent_queries={d} parent_pow_bits={d} canonical={any}\n", .{ pcs_config.fri_config.n_queries, pcs_config.pow_bits, root.admission.key.config.fri_config.n_queries, root.admission.key.config.pow_bits, canonical });
    std.debug.print("BLAKE3_TREE verified=true leaves=4 aggregate_levels=2 cycles=6 retained_root_rows={d}\n", .{try folded.prepared.rows.retainedBytes()});
}
fn provePair(comptime Backend: type, comptime canonical: bool, a: std.mem.Allocator, pcs_config: @import("stwo_core").pcs.PcsConfig, segments: [2]*const Segment, statements: [2]spans.SpanStatement) !tree.Node {
    var left = try ownerForProfile(canonical, a, segments[0]);
    var left_alive = true;
    defer if (left_alive) left.deinit();
    var right = try ownerForProfile(canonical, a, segments[1]);
    var right_alive = true;
    defer if (right_alive) right.deinit();
    const lv = if (canonical) try execution.PreparedVerifier.initCompact(a, &left.native.statement, try left.admission(), pcs_config, left.native.compact_ranges.?.plan) else try execution.PreparedVerifier.init(a, &left.native.statement, try left.admission(), pcs_config);
    defer lv.deinit();
    const rv = if (canonical) try execution.PreparedVerifier.initCompact(a, &right.native.statement, try right.admission(), pcs_config, right.native.compact_ranges.?.plan) else try execution.PreparedVerifier.init(a, &right.native.statement, try right.admission(), pcs_config);
    defer rv.deinit();
    var wrong = rv.id;
    wrong[0] ^= 1;
    try std.testing.expectError(error.UntrustedExecutionKey, pipeline.preparePair(a, .{ &left, &right }, .{ lv, rv }, .{ lv.id, wrong }, statements, 2));
    try std.testing.expect(!left.native.interaction_ready and !right.native.interaction_ready);
    try std.testing.expectError(error.AliasedAggregateChildren, pipeline.preparePair(a, .{ &left, &left }, .{ lv, lv }, .{ lv.id, lv.id }, statements, 2));
    right.native.interaction_ready = true;
    try std.testing.expectError(error.InvalidExecutionPhase, pipeline.preparePair(a, .{ &left, &right }, .{ lv, rv }, .{ lv.id, rv.id }, statements, 2));
    right.native.interaction_ready = false;
    try std.testing.expect(!left.native.interaction_ready);
    right.hashes.plan_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedCommitmentPlan, pipeline.preparePair(a, .{ &left, &right }, .{ lv, rv }, .{ lv.id, rv.id }, statements, 2));
    right.hashes.plan_id[0] ^= 1;
    try std.testing.expect(!left.native.interaction_ready and !right.native.interaction_ready);
    // Exercise ownership transfer on admission failure using fresh witnesses;
    // the checked allocator detects either retained buffers or a double free.
    {
        var failed_left = try ownerForProfile(canonical, a, segments[0]);
        var failed_left_alive = true;
        defer if (failed_left_alive) failed_left.deinit();
        var failed_right = try ownerForProfile(canonical, a, segments[1]);
        failed_left_alive = false;
        if (pipeline.preparePairOwnedWithPool(a, .{ &failed_left, &failed_right }, .{ lv, rv }, .{ lv.id, wrong }, statements, 2, null)) |unexpected| {
            var result = unexpected;
            result.deinit();
            return error.ExpectedAdmissionRejection;
        } else |err| try std.testing.expectEqual(error.UntrustedExecutionKey, err);
    }
    {
        var aliased = try ownerForProfile(canonical, a, segments[0]);
        if (pipeline.preparePairOwnedWithPool(a, .{ &aliased, &aliased }, .{ lv, lv }, .{ lv.id, lv.id }, statements, 2, null)) |unexpected| {
            var result = unexpected;
            result.deinit();
            return error.ExpectedAdmissionRejection;
        } else |err| try std.testing.expectEqual(error.AliasedAggregateChildren, err);
    }
    left_alive = false;
    right_alive = false;
    var folded = try pipeline.preparePairOwnedWithPool(a, .{ &left, &right }, .{ lv, rv }, .{ lv.id, rv.id }, statements, 2, null);
    defer folded.deinit();
    return proveFold(Backend, canonical, a, &folded);
}
fn proveFold(comptime Backend: type, comptime canonical: bool, a: std.mem.Allocator, folded: *const parent.aggregation.Fold) !tree.Node {
    const Api = parent.ForBackend(Backend);
    const key = if (canonical) try Api.deriveKeyWithProfile(a, &folded.prepared, .csp_q70_pow26) else try Api.deriveKey(a, &folded.prepared);
    const expected = try key.identity();
    const admission = try parent.protocol.Admission.init(key, expected);
    var proof = if (canonical) blk: {
        const Worker = parent.pipeline.ForBackend(Backend).Worker;
        const worker = try Worker.init(a, &folded.prepared.rows, admission, .{ .worker_count = try @import("blake3_parent_profile_test_support.zig").benchmarkWorkerCount(a), .host_byte_limit = 32 * 1024 * 1024 * 1024, .retained_scratch_limit = 64 * 1024 * 1024 });
        defer worker.deinit();
        break :blk try worker.proveAdmitted(&folded.prepared.rows, admission);
    } else blk: {
        const plan = try Api.Plan.init(a, &folded.prepared.rows, admission);
        defer plan.deinit();
        break :blk try plan.prove(a, &folded.prepared.rows);
    };
    defer proof.deinit();
    const bytes = try parent.codec.encode(a, &proof, &admission);
    defer a.free(bytes);
    proof.deinit();
    var wrong = expected;
    wrong[0] ^= 1;
    var rejected = try parent.codec.decode(a, bytes, &admission);
    defer rejected.deinit();
    try std.testing.expectError(error.UntrustedBlake3ParentKey, tree.Node.verifyOwned(&rejected, admission, wrong, folded.statement));
    try std.testing.expect(rejected.proof == null);
    var decoded = try parent.codec.decode(a, bytes, &admission);
    defer decoded.deinit();
    const result = try tree.Node.verifyOwned(&decoded, admission, expected, folded.statement);
    try std.testing.expect(decoded.proof == null);
    std.debug.print("BLAKE3_TREE_NODE verified=true height={d} artifact_bytes={d} queries={d} pow_bits={d}\n", .{ folded.statement.slots.height, bytes.len, key.config.fri_config.n_queries, key.config.pow_bits });
    return result;
}

fn ownerForProfile(comptime canonical: bool, a: std.mem.Allocator, item: *const Segment) !segment.Owner {
    return if (canonical) segment.Owner.initCompact(a, item) else segment.Owner.init(a, item);
}

test "BLAKE3 segment Span construction binds runner coordinates and boundaries" {
    const a = std.testing.allocator;
    const instructions = [_]u32{ 0x00500093, 0x00708093, 0x0000006f };
    const elf = @import("../runner/guest_precompile/test_elf.zig").buildProgram(instructions.len, &instructions, 0, .rv32im_zkvm_v1);
    var session = try runner.BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var first = try session.startSegment(1);
    defer first.deinit();
    var last = try session.resumeSegment(first.continuation.?, 10);
    defer last.deinit();
    const initial = try segment_statement.boundary(a, &first);
    const final = try segment_statement.boundary(a, &last);
    try std.testing.expectEqualDeep(initial.exit, final.entry);
    const zero = spans.Digest{ .bytes = @splat(0) };
    // This constructor does not admit program/I/O identities. Their binding is
    // exercised by the real aggregate proof fixtures above and in Ethereum.
    const Public = @import("blake3_segment_public.zig").Owned;
    var first_io = try Public.init(a, &first);
    defer first_io.deinit();
    var last_io = try Public.init(a, &last);
    defer last_io.deinit();
    first_io.data.program_root = zero;
    last_io.data.program_root = zero;
    const job = try segment_statement.initJob(a, config, &first, &last, &first_io.data, &last_io.data);
    try std.testing.expectEqual(@as(u64, 2), job.complete.total_cycles);
    try std.testing.expectEqual(@as(u32, 2), job.segment_count);
    last_io.data.final_regs[1] ^= 1;
    try std.testing.expectError(error.InvalidBlake3SegmentPublicData, segment_statement.initJob(a, config, &first, &last, &first_io.data, &last_io.data));
    last_io.data.final_regs[1] ^= 1;
    last_io.data.program_root.?.bytes[0] ^= 1;
    try std.testing.expectError(error.SegmentProgramMismatch, segment_statement.initJob(a, config, &first, &last, &first_io.data, &last_io.data));
    last_io.data.program_root = zero;
    try std.testing.checkAllAllocationFailures(a, checkSegmentStatementAllocations, .{ &first, &last, &first_io.data, &last_io.data });
    const left = try segment_statement.leaf(a, job, &first);
    const right = try segment_statement.leaf(a, job, &last);
    try std.testing.expectEqual(@as(u64, 1), right.body.executed.first_cycle);
    try std.testing.expectEqual(@as(u32, 1), right.body.executed.first_segment);
    try std.testing.expectEqualDeep(final.exit, right.body.executed.exit);
    _ = try spans.RootStatement.init(try spans.SpanStatement.fold(left, right));
    const wrong_job = try spans.JobContext.init(job.complete, 3);
    try std.testing.expectError(error.InvalidBlake3Segment, segment_statement.leaf(a, wrong_job, &last));
    first.global_first_cycle = 0;
    try std.testing.expectError(error.InvalidBlake3Segment, segment_statement.leaf(a, job, &first));
    first.global_first_cycle = 1;
}

fn checkSegmentStatementAllocations(
    a: std.mem.Allocator,
    first: *const Segment,
    last: *const Segment,
    first_data: *const @import("../air/public_data.zig").Blake3PublicData,
    last_data: *const @import("../air/public_data.zig").Blake3PublicData,
) !void {
    const job = try segment_statement.initJob(a, config, first, last, first_data, last_data);
    const left = try segment_statement.leaf(a, job, first);
    const right = try segment_statement.leaf(a, job, last);
    _ = try spans.RootStatement.init(try spans.SpanStatement.fold(left, right));
}
