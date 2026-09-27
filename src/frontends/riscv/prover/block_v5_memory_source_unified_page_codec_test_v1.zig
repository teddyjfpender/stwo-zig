//! Structural parser fixtures only. No fixture framing is accepted as proof.
const std = @import("std");
const postcard = @import("interop_postcard");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Protocol = @import("block_v5_memory_source_unified_page_protocol_v1.zig");
const Page = @import("block_v5_memory_source_unified_page_proof_v1.zig");
const Codec = @import("block_v5_memory_source_unified_page_codec_v1.zig");
const Preflight = postcard.proof_preflight;
fn shape() Preflight.ShapeFor(Protocol.PROOF_COMMITMENTS) {
    return .{
        .config = .{ .pow_bits = 10, .log_blowup_factor = 1, .n_queries = 3, .log_last_layer_degree_bound = 0, .fold_step = 1, .lifting_log_size = null },
        .tree_columns = .{ 15, 1728, 8, 5, 174, 256, 128, 16, 24, 16 },
        .sample_width_limits = .{ 1, 1, 1, 1, 1, 1, 1, 1, 2, 1 },
        .max_column_log_size = 1,
        .hash_size = 32,
        .max_wire_bytes = 1 << 20,
    };
}
fn varint(a: std.mem.Allocator, bytes: *std.ArrayList(u8), value: u64) !void {
    var rest = value;
    while (rest >= 128) {
        try bytes.append(a, @intCast((rest & 127) | 128));
        rest >>= 7;
    }
    try bytes.append(a, @intCast(rest));
}
fn config(a: std.mem.Allocator, bytes: *std.ArrayList(u8)) !void {
    const c = shape().config;
    for ([_]u64{ c.pow_bits, c.log_blowup_factor, c.n_queries, c.log_last_layer_degree_bound, c.fold_step }) |value| try varint(a, bytes, value);
    try bytes.append(a, 0);
}
fn framing(a: std.mem.Allocator) ![]u8 {
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(a);
    const s = shape();
    try config(a, &bytes);
    try varint(a, &bytes, Protocol.PROOF_COMMITMENTS);
    try bytes.appendNTimes(a, 0, Protocol.PROOF_COMMITMENTS * s.hash_size);
    try varint(a, &bytes, Protocol.PROOF_COMMITMENTS);
    for (s.tree_columns) |columns| {
        try varint(a, &bytes, columns);
        for (0..columns) |_| {
            try varint(a, &bytes, 1);
            try bytes.appendNTimes(a, 0, 4); // canonical zero QM31
        }
    }
    try varint(a, &bytes, Protocol.PROOF_COMMITMENTS);
    for (0..Protocol.PROOF_COMMITMENTS) |_| try varint(a, &bytes, 0);
    try varint(a, &bytes, Protocol.PROOF_COMMITMENTS);
    for (s.tree_columns) |columns| {
        try varint(a, &bytes, columns);
        for (0..columns) |_| try varint(a, &bytes, 0);
    }
    for (0..3) |_| try varint(a, &bytes, 0); // PoW/FRI witness/Merkle
    try bytes.appendNTimes(a, 0, s.hash_size);
    try varint(a, &bytes, 0); // inner layers
    try varint(a, &bytes, 1); // last coefficient
    try bytes.appendNTimes(a, 0, 4);
    return bytes.toOwnedSlice(a);
}
test "source unified PAGE codec: ten-tree structural parser exact counts truncation and caps" {
    const a = std.testing.allocator;
    const raw = try framing(a);
    defer a.free(raw);
    try Preflight.validateFor(Protocol.PROOF_COMMITMENTS, raw, shape());
    var wrong = shape();
    wrong.tree_columns[8] += 1;
    try std.testing.expectError(error.InvalidProofShape, Preflight.validateFor(Protocol.PROOF_COMMITMENTS, raw, wrong));
    wrong = shape();
    wrong.config.n_queries += 1;
    try std.testing.expectError(error.InvalidProofConfig, Preflight.validateFor(Protocol.PROOF_COMMITMENTS, raw, wrong));
    wrong = shape();
    wrong.max_wire_bytes = raw.len - 1;
    try std.testing.expectError(error.ProofResourceLimitExceeded, Preflight.validateFor(Protocol.PROOF_COMMITMENTS, raw, wrong));
    try std.testing.expectError(error.EndOfStream, Preflight.validateFor(Protocol.PROOF_COMMITMENTS, raw[0 .. raw.len - 1], shape()));
    // validateFor has no allocator argument and never decodes vectors.
    const deny = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try Preflight.validateFor(Protocol.PROOF_COMMITMENTS, raw, shape());
    try std.testing.expectEqual(@as(usize, 0), deny.alloc_index);
}
test "source unified PAGE codec: ten-tree overlong counts and nested sample bombs reject before allocation" {
    const a = std.testing.allocator;
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    try config(a, &bytes);
    const after_config = bytes.items.len;
    try varint(a, &bytes, 9);
    try std.testing.expectError(error.InvalidProofShape, Preflight.validateFor(Protocol.PROOF_COMMITMENTS, bytes.items, shape()));
    bytes.shrinkRetainingCapacity(after_config);
    try bytes.appendSlice(a, &.{ 0x8a, 0 }); // noncanonical ten
    try std.testing.expectError(error.NonCanonicalVarint, Preflight.validateFor(Protocol.PROOF_COMMITMENTS, bytes.items, shape()));
    bytes.shrinkRetainingCapacity(after_config);
    try varint(a, &bytes, Protocol.PROOF_COMMITMENTS);
    try bytes.appendNTimes(a, 0, Protocol.PROOF_COMMITMENTS * 32);
    try varint(a, &bytes, Protocol.PROOF_COMMITMENTS);
    try varint(a, &bytes, shape().tree_columns[0]);
    try varint(a, &bytes, std.math.maxInt(u64));
    try std.testing.expectError(error.ProofResourceLimitExceeded, Preflight.validateFor(Protocol.PROOF_COMMITMENTS, bytes.items, shape()));
}
test "source unified PAGE codec: bad domain version kind and ABI reject under deny-all allocator" {
    const a = std.testing.allocator;
    var deny = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    // Deliberately inaccessible context/pin: every case must fail before
    // touching independent metadata or trying any reconstruction allocation.
    const context: Page.Context = undefined;
    inline for (.{ Semantic.Kind.raw, Semantic.Kind.fold }) |kind| {
        const C = Codec.ForKind(kind);
        const pin: Page.ForKind(kind).Pin = undefined;
        var raw: [Codec.MAGIC.len + 8 + 32]u8 = @splat(0);
        try std.testing.expectError(error.UntrustedSourcePageArtifact, C.decode(deny.allocator(), &raw, &context, pin, &.{}, .{}, .{}));
        @memcpy(raw[0..Codec.MAGIC.len], Codec.MAGIC);
        std.mem.writeInt(u32, raw[Codec.MAGIC.len..][0..4], Protocol.VERSION + 1, .little);
        try std.testing.expectError(error.UntrustedSourcePageArtifact, C.decode(deny.allocator(), &raw, &context, pin, &.{}, .{}, .{}));
        std.mem.writeInt(u32, raw[Codec.MAGIC.len..][0..4], Protocol.VERSION, .little);
        std.mem.writeInt(u32, raw[Codec.MAGIC.len + 4 ..][0..4], @intFromEnum(kind) ^ 1, .little);
        try std.testing.expectError(error.UntrustedSourcePageArtifact, C.decode(deny.allocator(), &raw, &context, pin, &.{}, .{}, .{}));
        std.mem.writeInt(u32, raw[Codec.MAGIC.len + 4 ..][0..4], @intFromEnum(kind), .little);
        try std.testing.expectError(error.UntrustedSourcePageArtifact, C.decode(deny.allocator(), &raw, &context, pin, &.{}, .{}, .{}));
        try std.testing.expectError(error.InvalidSourcePageArtifactLimits, C.decode(deny.allocator(), &raw, &context, pin, &.{}, .{}, .{ .max_proof_bytes = 0 }));
    }
    try std.testing.expectEqual(@as(usize, 0), deny.alloc_index);
}

test "source PAGE publisher codec: proposal decode preserves cheap framing and limits under deny-all allocator" {
    var deny = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    inline for (.{ Semantic.Kind.raw, Semantic.Kind.fold }) |kind| {
        const C = Codec.ForKind(kind);
        const context: Page.Context = undefined;
        const pin: Page.ForKind(kind).Pin = undefined;
        const raw: [Codec.MAGIC.len]u8 = @splat(0);
        try std.testing.expectError(error.UntrustedSourcePageArtifact, C.decodeProposal(deny.allocator(), &raw, &context, pin, &.{}, .{}, .{}));
        try std.testing.expectError(error.InvalidSourcePageArtifactLimits, C.decodeProposal(deny.allocator(), &raw, &context, pin, &.{}, .{}, .{ .max_proof_bytes = 0 }));
        try std.testing.expectError(error.SourcePageArtifactResourceLimit, C.decodeProposal(deny.allocator(), &raw, &context, pin, &.{}, .{ .max_receiver_heap_bytes = 0 }, .{}));
    }
    try std.testing.expectEqual(@as(usize, 0), deny.alloc_index);
}
