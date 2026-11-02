//! PCS-only ownership qualification: no CPU/AIR execution claim.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("../rv64_main_arena.zig");
const B = @import("stwo_cpu_backend").configured(.{ .wide_preparation = true, .source_trace_arena = true });
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
const Channel = core.channel.blake2s.Blake2sChannel;
const Scheme = engine.pcs.CommitmentSchemeProver(B, H, MC);
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(H, MC);
const M = core.fields.m31.M31;
const Point = core.circle.CirclePointQM31;
const Points = core.pcs.TreeVec([][]Point);
const specs = [_]A.Spec{ .{ .role = .ram_poseidon, .log_size = 5, .width = 2 }, .{ .role = .rom, .log_size = 4, .width = 1 }, .{ .role = .cpu, .log_size = 6, .width = 3 }, .{ .role = .bytes, .log_size = 8, .width = 1 }, .{ .role = .secp_add_product, .log_size = 5, .width = 2 }, .{ .role = .ram_policy, .log_size = 4, .width = 1 } };
fn config() !core.pcs.PcsConfig {
    return .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 10) };
}
fn points(a: std.mem.Allocator, count: usize) !Points {
    const trees = try a.alloc([][]Point, 1);
    errdefer a.free(trees);
    const columns = try a.alloc([]Point, count);
    errdefer a.free(columns);
    var filled: usize = 0;
    errdefer for (columns[0..filled]) |column| a.free(column);
    for (columns) |*column| {
        column.* = try a.dupe(Point, &.{core.circle.SECURE_FIELD_CIRCLE_GEN.mul(17)});
        filled += 1;
    }
    trees[0] = columns;
    return .{ .items = trees };
}
const Result = struct { encoded: []u8, root: [32]u8, opening_digest: [32]u8, transcript: [32]u8 };
fn initializedArena(a: std.mem.Allocator, total: usize) !A.Arena {
    var shapes = specs;
    shapes[2].width = total - 7;
    var arena = try A.Arena.init(a, &shapes);
    errdefer arena.deinit();
    for (shapes) |spec| {
        const matrix = try arena.matrix(spec.role);
        const n = @as(usize, 1) << @intCast(matrix.log_size);
        for (matrix.values, 0..) |*v, i| v.* = M.fromCanonical(@intCast(173 * (@as(usize, @intFromEnum(spec.role)) + 1) + 37 * (i / n) + (i % n) * (i % n) + i % n));
        try arena.markInitialized(spec.role);
    }
    return arena;
}
fn prove(a: std.mem.Allocator, owned: bool, total: usize) !Result {
    var arena = try initializedArena(a, total);
    defer arena.deinit();
    const input = try arena.canonicalColumns(a);
    defer a.free(input);
    const expected_ptrs = try a.alloc([*]const M, input.len);
    defer a.free(expected_ptrs);
    for (expected_ptrs, input) |*p, column| p.* = column.values.ptr;
    var scheme = try Scheme.init(a, try config());
    var owns = true;
    defer if (owns) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(4);
    var channel = Channel{};
    (try config()).mixInto(&channel);
    if (owned) {
        const transfer = try arena.takeForCommit(a);
        try scheme.commitOwnedWithRecorderAndBacking(a, transfer.columns, transfer.backing, null, &channel);
    } else try scheme.commitBorrowedStreaming(a, input, 8, &channel);
    const tree = scheme.trees.items[0];
    const coefficients = tree.coefficients orelse return error.MissingArenaCoefficients;
    if (owned) for (coefficients, expected_ptrs) |poly, ptr| {
        try std.testing.expect(poly.coefficients().ptr == ptr);
    };
    const n_leaves = @as(usize, 1) << @intCast(tree.commitment.maxLogSize());
    const queries = [_]usize{ 0, 1, 5, 17, n_leaves - 1 };
    var opening = try tree.decommit(a, &queries);
    defer opening.deinit(a);
    const logs = try tree.columnLogSizes(a);
    defer a.free(logs);
    var merkle = try core.vcs_lifted.verifier.MerkleVerifierLifted(H).init(a, tree.root(), logs);
    defer merkle.deinit(a);
    try merkle.verify(a, &queries, opening.queried_values, opening.decommitment.decommitment);
    const Hash = std.crypto.hash.sha2.Sha256;
    var hash = Hash.init(.{});
    for (opening.queried_values) |values| hash.update(std.mem.sliceAsBytes(values));
    hash.update(std.mem.sliceAsBytes(opening.decommitment.decommitment.hash_witness));
    var opening_digest: [32]u8 = undefined;
    hash.final(&opening_digest);
    const root = tree.root();
    const transcript = channel.digestBytes();
    const sample = try points(a, total);
    owns = false;
    var extended = try scheme.proveValues(a, sample, &channel);
    defer extended.deinit(a);
    return .{ .encoded = try @import("stwo_proof_wire").encodeProofBytesBinary(a, .{ .commitment_scheme_proof = extended.proof }), .root = root, .opening_digest = opening_digest, .transcript = transcript };
}
fn verify(a: std.mem.Allocator, encoded: []const u8, total: usize) !void {
    var shapes = specs;
    shapes[2].width = total - 7;
    var arena = try A.Arena.init(a, &shapes);
    defer arena.deinit();
    const logs = try a.alloc(u32, total);
    defer a.free(logs);
    var at: usize = 0;
    for (arena.spans) |entry| if (entry) |value| {
        @memset(logs[at..][0..value.width], value.log_size);
        at += value.width;
    };
    var proof = try @import("stwo_proof_wire").decodeProofBytesBinary(a, encoded);
    var owns = true;
    defer if (owns) proof.deinit(a);
    var verifier = try Verifier.init(a, try config());
    defer verifier.deinit(a);
    var channel = Channel{};
    (try config()).mixInto(&channel);
    try verifier.commit(a, proof.commitment_scheme_proof.commitments.items[0], logs, &channel);
    const sample = try points(a, total);
    owns = false;
    try verifier.verifyValues(a, sample, proof.commitment_scheme_proof, &channel);
}
test "single ragged main allocation adopts native coefficients with exact PCS roots openings and proof bytes" {
    const a = std.testing.allocator;
    for ([_]usize{ 10, 64, 65, 127, 128 }) |total| {
        const reference = try prove(a, false, total);
        defer a.free(reference.encoded);
        const adopted = try prove(a, true, total);
        defer a.free(adopted.encoded);
        try std.testing.expectEqualDeep(reference.root, adopted.root);
        try std.testing.expectEqualDeep(reference.transcript, adopted.transcript);
        try std.testing.expectEqualDeep(reference.opening_digest, adopted.opening_digest);
        try std.testing.expectEqualSlices(u8, reference.encoded, adopted.encoded);
        try verify(a, adopted.encoded, total);
    }
}
fn allocationRun(a: std.mem.Allocator) !void {
    var arena = try initializedArena(a, 10);
    defer arena.deinit();
    var scheme = try Scheme.init(a, try config());
    defer scheme.deinit(a);
    scheme.setCompactPolynomialStorage(4);
    var channel = Channel{};
    (try config()).mixInto(&channel);
    const transfer = try arena.takeForCommit(a);
    try scheme.commitOwnedWithRecorderAndBacking(a, transfer.columns, transfer.backing, null, &channel);
}
test "single main allocation and PCS commit retain original backing custody on every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationRun, .{});
}

fn fullProofAllocationRun(a: std.mem.Allocator) !void {
    const result = try prove(a, true, 10);
    defer a.free(result.encoded);
}
test "owned main full PCS proof consumes FRI layers if query allocation fails after inner commit" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, fullProofAllocationRun, .{});
}
