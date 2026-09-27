//! Nonproving geometry/source/equation/ownership fixtures. No successful capture
//! or key is fabricated; actual cryptographic routes are retained by the root.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const A = @import("../recursion/block_v5_memory_source_page_forest_algebra_v1.zig");
const P = @import("../recursion/block_v5_memory_source_page_forest_plan_v1.zig");
const N = @import("../recursion/block_v5_memory_source_page_forest_normalizer_v1.zig");
const Sink = struct {
    count: usize = 0,
    pub fn zero(self: *@This(), value: Q) !void {
        self.count += 1;
        if (!value.isZero()) return error.UnclosedSourcePageFixture;
    }
};
fn validClaims() Semantic.Claims {
    var out = Semantic.Claims.zero();
    out.fold.roots = Q.one();
    out.source.initial = Q.fromU32Unchecked(7, 11, 13, 17);
    out.source.endpoint = Q.fromU32Unchecked(19, 23, 29, 31);
    return out;
}
test "source PAGE forest: exact five seventeen and sixty five physical leaves use no power of two rounding" {
    for ([_]usize{ 1, 5, 17, 65 }, [_]usize{ 1, 2, 6, 22 }) |pages, nodes| {
        var geometry = try P.derive(std.testing.allocator, pages, .{});
        defer geometry.deinit();
        try std.testing.expectEqual(pages, geometry.leaves);
        try std.testing.expectEqual(nodes, geometry.nodes.len);
        const root = geometry.nodes[geometry.root.?];
        try std.testing.expectEqual(@as(u32, 0), root.range.first);
        try std.testing.expectEqual(pages, root.range.count);
        for (geometry.nodes, 0..) |node, index| {
            try std.testing.expect(node.child_count >= (if (pages == 1) @as(u32, 1) else @as(u32, 2)) and node.child_count <= 4);
            for (node.children[0..node.child_count]) |ref| if (ref == .node) try std.testing.expect(ref.node < index);
        }
    }
}
test "source PAGE forest: zero physical roster is typed absence and caps reject before allocation" {
    var empty = try P.derive(std.testing.allocator, 0, .{});
    defer empty.deinit();
    try std.testing.expectEqual(@as(?u32, null), empty.root);
    try std.testing.expectEqual(@as(usize, 0), empty.nodes.len);
    try std.testing.expectError(error.PageForestResourceLimit, P.derive(std.testing.failing_allocator, 5, .{ .max_nodes = 1 }));
    try std.testing.expectError(error.PageForestResourceLimit, P.derive(std.testing.failing_allocator, 17, .{ .max_metadata_bytes = 1 }));
}
fn geometryAllocations(a: std.mem.Allocator) !void {
    var geometry = try P.derive(a, 17, .{});
    defer geometry.deinit();
    try std.testing.expectEqual(@as(usize, 6), geometry.nodes.len);
}
test "source PAGE forest: every exact topology allocation failure releases ownership" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, geometryAllocations, .{});
}
test "source PAGE forest: genuine empty source aggregate closes original Fold counts but exports initial endpoint open" {
    const admitted = try @import("block_v5_memory_source_page_raw_recursive_parity_test_v1.zig").emptyAdmission();
    const values = A.flatten(validClaims());
    var sink = Sink{};
    try A.close(Q, &admitted, values, &sink);
    try std.testing.expectEqual(@as(usize, 16), sink.count);
    const decoded = A.decode(Q, values);
    try std.testing.expect(!decoded.source.initial.isZero());
    try std.testing.expect(!decoded.source.endpoint.isZero());
}
test "source PAGE forest: source indexed sign hash count and all unused raw buses reject" {
    const admitted = try @import("block_v5_memory_source_page_raw_recursive_parity_test_v1.zig").emptyAdmission();
    inline for (.{ "bytes", "input", "route", "roots", "ordering", "sha_chain" }) |field| {
        var claims = validClaims();
        @field(claims.source, field) = Q.one();
        var sink = Sink{};
        try std.testing.expectError(error.UnclosedSourcePageFixture, A.close(Q, &admitted, A.flatten(claims), &sink));
    }
    inline for (.{ "indexed", "insertion", "before", "after", "route", "hash", "input", "rw", "touches", "roots" }) |field| {
        var claims = validClaims();
        @field(claims.fold, field) = @field(claims.fold, field).add(Q.one());
        var sink = Sink{};
        try std.testing.expectError(error.UnclosedSourcePageFixture, A.close(Q, &admitted, A.flatten(claims), &sink));
    }
    var claims = validClaims();
    claims.indexed = Q.one();
    claims.fold.indexed = Q.one();
    var sink = Sink{};
    try std.testing.expectError(error.UnclosedSourcePageFixture, A.close(Q, &admitted, A.flatten(claims), &sink));
    claims.fold.indexed = Q.one().neg();
    sink = .{};
    try A.close(Q, &admitted, A.flatten(claims), &sink);
}
const Frame = struct {
    words: []const u32,
    claims: []const Q,
    pub fn mix(self: *const @This(), channel: anytype) !void {
        channel.mixU32s(&.{ 0x50475446, 1 });
        channel.mixU32s(self.words);
        channel.mixFelts(self.claims);
    }
};
fn normalizeAllocations(a: std.mem.Allocator) !void {
    const words = [_]u32{ 7, 11, 13 };
    const claims = A.flatten(validClaims());
    const frame = Frame{ .words = &words, .claims = &claims };
    var normal = try N.Normalized.initWithWords(a, &frame, &claims, 0, &words, .{});
    defer normal.deinit();
    try normal.requireWithWords(a, &frame, &claims, 0, &words, .{});
    try std.testing.expectEqual(@as(?u32, 2), normal.word_first);
    try std.testing.expectEqual(@as(u32, 5), normal.claim_first);
}
test "source PAGE forest: exact invocation normalization survives all allocation failures" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, normalizeAllocations, .{});
}
test "source PAGE forest: equal valued foreign slice is not a claim authority and original words mutations reject" {
    var words = [_]u32{ 7, 11, 13 };
    var claims = A.flatten(validClaims());
    const foreign = claims;
    const frame = Frame{ .words = &words, .claims = &claims };
    try std.testing.expectError(error.UntrustedPageForestClaimLayout, N.Normalized.init(std.testing.allocator, &frame, &foreign, 0, .{}));
    var normal = try N.Normalized.initWithWords(std.testing.allocator, &frame, &claims, 0, &words, .{});
    defer normal.deinit();
    words[1] += 1;
    try std.testing.expectError(error.MutatedPageForestSource, normal.requireWithWords(std.testing.allocator, &frame, &claims, 0, &words, .{}));
    words[1] -= 1;
    claims[0] = Q.one();
    try std.testing.expectError(error.MutatedPageForestSource, normal.requireWithWords(std.testing.allocator, &frame, &claims, 0, &words, .{}));
}
test "source PAGE forest: noncanonical proposed field is rejected without violating a constructor contract" {
    var claims = A.flatten(validClaims());
    claims[0].c0.a.v = core.fields.m31.Modulus;
    try std.testing.expectError(error.NoncanonicalPageForestClaims, A.canonical(claims));
}

test "source PAGE forest: original twenty two claim merge records all operands and a mutated export rejects" {
    const R = @import("../recursion/air/composition_graph_recorder.zig");
    const a = std.testing.allocator;
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var children: [2][A.CLAIM_COUNT]Q = .{ A.flatten(validClaims()), A.flatten(validClaims()) };
    children[1][0] = Q.fromU32Unchecked(3, 5, 7, 11);
    var proposal: [A.CLAIM_COUNT]Q = undefined;
    for (&proposal, children[0], children[1]) |*value, x, y| value.* = x.add(y);
    var inputs: [3 * A.CLAIM_COUNT]Q = undefined;
    var symbols: [3][A.CLAIM_COUNT]R.Scalar = undefined;
    for (&symbols, 0..) |*group, g| for (group, 0..) |*symbol, i| {
        symbol.* = (try builder.input()).value;
        inputs[g * A.CLAIM_COUNT + i] = if (g < 2) children[g][i] else proposal[i];
    };
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    const SymbolicSink = struct {
        builder: *R.Builder,
        pub fn zero(self: *@This(), value: R.Scalar) !void {
            try self.builder.constrainZero(value);
        }
    };
    var sink = SymbolicSink{ .builder = &builder };
    try A.merge(R.Scalar, symbols[0..2], symbols[2], &sink);
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    const values = try a.alloc(Q, circuit.nodes.len);
    defer a.free(values);
    try circuit.evaluateInto(&inputs, values);
    inputs[2 * A.CLAIM_COUNT + 3] = inputs[2 * A.CLAIM_COUNT + 3].add(Q.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(&inputs, values));
}
test "source PAGE forest: closed node schedule is independently empty and old external grammar stays strict" {
    const Bus = @import("../recursion/block_v5_memory_source_page_forest_bus_v1.zig");
    const digest = try Bus.scheduleDigest(&.{});
    try std.testing.expect(!std.mem.allEqual(u8, &digest, 0));
    try std.testing.expectError(error.InvalidScopedPublicSchedule, @import("../recursion/block_v5_heterogeneous_scoped_public_bus_v1.zig").scheduleDigest(&.{}));
}

test "source PAGE forest: resealed duplicated omitted or reordered selectors reject independent physical topology" {
    const a = std.testing.allocator;
    var geometry = try P.derive(a, 5, .{});
    defer geometry.deinit();
    const expected = geometry.digest;
    try geometry.require(a, expected, .{});
    geometry.nodes[0].children[1] = geometry.nodes[0].children[0];
    try std.testing.expectError(error.UntrustedPageForestTopology, geometry.require(a, expected, .{}));
    geometry.digest = @splat(19); // A resealed proposal cannot replace the independent expected recipe.
    try std.testing.expectError(error.UntrustedPageForestTopology, geometry.require(a, expected, .{}));
}
test "source PAGE forest: every small roster attains minimum merges and each actual physical leaf occurs exactly once" {
    const a = std.testing.allocator;
    for (2..130) |count| {
        var geometry = try P.derive(a, count, .{});
        defer geometry.deinit();
        try std.testing.expectEqual(try std.math.divCeil(usize, count - 1, 3), geometry.nodes.len);
        const uses = try a.alloc(u32, count);
        defer a.free(uses);
        @memset(uses, 0);
        for (geometry.nodes) |node| {
            try std.testing.expect(node.child_count >= 2 and node.child_count <= 4);
            for (node.children[0..node.child_count]) |ref| if (ref == .leaf) {
                uses[ref.leaf] += 1;
            };
        }
        for (uses) |use| try std.testing.expectEqual(@as(u32, 1), use);
    }
}

test "source PAGE forest: cached compiled source recipe equals uncached identity" {
    const protocol = @import("../recursion/block_v5_memory_source_page_forest_protocol_v1.zig");
    const expected = protocol.testing.uncachedSourceAuthority();
    for (0..32) |_| try std.testing.expectEqual(expected, protocol.sourceAuthority());
}

test "source PAGE forest: semantic claim offset rejects underflow and preserves full u32 bounds" {
    const algebra = @import("../recursion/block_v5_memory_source_page_forest_algebra_v1.zig");
    try std.testing.expectError(error.UntrustedPageForestClaimLayout, algebra.semanticClaimOffset(21));
    try std.testing.expectEqual(@as(u32, 0), try algebra.semanticClaimOffset(22));
    try std.testing.expectEqual(@as(u32, 79), try algebra.semanticClaimOffset(101));
    try std.testing.expectEqual(std.math.maxInt(u32) - 22, try algebra.semanticClaimOffset(std.math.maxInt(u32)));
}
