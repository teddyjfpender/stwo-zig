//! Replays the native verifier transcript of a retained Ethereum batch proof
//! and checks that the lane-generic composition evaluation reproduces the
//! composition OODS value carried by the proof, natively and over a trace lane.
//! Paths come from RV64_POINT_PROBE_CONFIG / RV64_POINT_PROBE_DIR; the test is
//! skipped when the retained probe is not present on this machine.
const std = @import("std");
const A = @import("../rv64_authenticated_execution.zig");
const Key = @import("../rv64_execution_verifier_key.zig");
const Point = @import("../rv64_point_evaluation.zig");
const Layout = @import("../rv64_point_layout.zig");
const Request = @import("../rv64_ethereum_request.zig");
const Receipt = @import("../rv64_ethereum_batch_receipt.zig");
const Trace = @import("rv64_trace_lane.zig");
const wire = @import("stwo_proof_wire");
const core = A.core;
const Q = A.Q;
const a = std.testing.allocator;
const default_config = "/private/tmp/stwo-rv64-lean-proof-probe/config-2b-run7.json";
const default_directory = "/private/tmp/stwo-rv64-lean-proof-probe/run7";

fn skipIfMissing(err: anyerror) anyerror {
    return switch (err) {
        error.FileNotFound, error.NotDir, error.AccessDenied => error.SkipZigTest,
        else => err,
    };
}

test "retained Ethereum batch: flat lane evaluation reproduces the composition OODS value" {
    const config_path = std.posix.getenv("RV64_POINT_PROBE_CONFIG") orelse default_config;
    const directory_path = std.posix.getenv("RV64_POINT_PROBE_DIR") orelse default_directory;
    const raw = std.fs.cwd().readFileAlloc(a, config_path, 16384) catch |err| return skipIfMissing(err);
    defer a.free(raw);
    const parsed = try std.json.parseFromSlice(Request.Config, a, raw, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    var request = Request.Request.init(a, parsed.value) catch |err| return skipIfMissing(err);
    defer request.deinit();
    var directory = std.fs.cwd().openDir(directory_path, .{}) catch |err| return skipIfMissing(err);
    defer directory.close();
    const metadata = directory.readFileAlloc(a, "batch-000000.json", 128 * 1024) catch |err| return skipIfMissing(err);
    defer a.free(metadata);
    const receipt = try std.json.parseFromSlice(Receipt.Receipt, a, metadata, .{});
    defer receipt.deinit();
    const public = try receipt.value.bound(&request.authority);
    const bytes = try directory.readFileAlloc(a, "batch-000000.proof", 128 * 1024 * 1024);
    defer a.free(bytes);
    try Request.pin(bytes, &receipt.value.proof_sha256);
    var proof = try wire.decodeProofBytesBinary(a, bytes);
    defer proof.deinit(a);
    var prepared = try A.Prepared.initWithAuthority(a, public, &request.policy, &request.authority);
    defer prepared.deinit();
    var key = try Key.ReceiverKey.fromPrepared(a, &prepared, public, &request.authority);
    defer key.deinit();
    var session: Key.Session = undefined;
    try key.openSession(a, public, receipt.value.claims, &proof, &session);
    defer session.deinit(a);
    const roster = try Point.Roster.init(&key, &session.components);
    // The native verifier draws composition randomness and the OODS seed; a
    // successful full verification hands both back through the capture.
    var capture: core.verifier.ProofCapture(A.P.Hasher) = undefined;
    try core.verifier.verifyBorrowedExWithProofCapture(A.P.Hasher, A.P.MerkleChannel, a, session.components.verifiers(), &session.channel, &session.verifier, &proof, false, &capture);
    defer capture.deinit(a);
    const oods_point = core.circle.secureFieldPointFromRandomSeed(capture.oods_seed);
    const expected = proof.extractCompositionOodsEvalWithSplit(oods_point, roster.global_log + roster.composition_log_split, roster.composition_log_split) orelse return error.InvalidProbeProofShape;
    const flat_challenges = try Layout.flattenChallenges(a, roster.layouts.challenges, session.challenges);
    defer a.free(flat_challenges);
    const flat_claims = try Layout.flattenClaims(a, roster.layouts.claims, receipt.value.claims);
    defer a.free(flat_claims);
    const flat_publics = try Layout.flattenPublics(a, roster.layouts.publics, public);
    defer a.free(flat_publics);
    const masks = &proof.commitment_scheme_proof.sampled_values;
    for (0..roster.count()) |ordinal| {
        var accumulator = core.air.accumulation.PointEvaluationAccumulator.init(capture.composition_randomness);
        try session.components.verifiers()[ordinal].evaluateConstraintQuotientsAtPoint(oods_point, masks, &accumulator, roster.global_log);
        const flat = try Point.evalComponentAtPointFor(Q, &roster, ordinal, oods_point, Point.NativeMasks{ .values = masks }, capture.composition_randomness, flat_challenges, flat_claims, flat_publics);
        if (!accumulator.finalize().eql(flat)) {
            std.debug.print("probe component ordinal {d} diverges between vtable and flat evaluation\n", .{ordinal});
            return error.ProbeComponentMismatch;
        }
    }
    const native = try Point.evalCompositionAtPointFor(Q, &roster, oods_point, Point.NativeMasks{ .values = masks }, capture.composition_randomness, flat_challenges, flat_claims, flat_publics);
    if (!native.eql(expected)) {
        std.debug.print("probe composition mismatch: flat {any} expected {any}\n", .{ native, expected });
        return error.ProbeCompositionMismatch;
    }
    const lane_challenges = try Trace.liftSlice(a, flat_challenges);
    defer a.free(lane_challenges);
    const lane_claims = try Trace.liftSlice(a, flat_claims);
    defer a.free(lane_claims);
    const lane_publics = try Trace.liftSlice(a, flat_publics);
    defer a.free(lane_publics);
    Trace.ops = .{};
    const over_lane = try Point.evalCompositionAtPointFor(Trace.TraceLane, &roster, Trace.liftPoint(oods_point), Trace.LaneMasks{ .values = masks }, Trace.TraceLane.fromQm31(capture.composition_randomness), lane_challenges, lane_claims, lane_publics);
    try std.testing.expect(over_lane.value.eql(expected));
    try std.testing.expectEqual(roster.count(), Trace.ops.inv);
    var shape = try Point.describeShape(a, &roster);
    defer shape.deinit();
    try std.testing.expectEqualSlices(u32, key.fixed_logs, shape.tree_column_log_sizes[0]);
    try std.testing.expectEqualSlices(u32, key.main_logs, shape.tree_column_log_sizes[1]);
    try std.testing.expectEqualSlices(u32, key.interaction_logs, shape.tree_column_log_sizes[2]);
    for (shape.mask_offsets, 0..) |tree, t| for (tree, 0..) |column, c| try std.testing.expectEqual(masks.items[t][c].len, column.len);
    std.debug.print("RV64 point evaluation probe: {d} components, {d} challenges, {d} claims, {d} publics, global log {d}, lane ops mul={d} add={d} sub={d} square={d} inv={d}\n", .{ roster.count(), flat_challenges.len, flat_claims.len, flat_publics.len, roster.global_log, Trace.ops.mul, Trace.ops.add, Trace.ops.sub, Trace.ops.square, Trace.ops.inv });
}
