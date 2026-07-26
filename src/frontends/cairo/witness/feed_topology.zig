//! Authenticated source-derived routing for official Cairo witness feeds.

const std = @import("std");
const claim_registry = @import("../air/official_claim_registry.zig");

pub const schema = "stwo-zig-cairo-witness-feed-topology-v1";
pub const version: u32 = 1;
pub const expected_source_tree = "2b06286971d87c6d3e834de622d3777f1ff9f41f";
pub const expected_sha256 = "2721d22a1c2aa7b069bebd08d0e73d346c579f5c93e276c30c4d56b985b1e00c";
pub const expected_component_count: usize = 64;
pub const max_document_bytes: usize = 1024 * 1024;
pub const max_feeds_per_component: usize = 4096;

pub const Source = struct {
    revision: []const u8,
    tree: []const u8,
    commit_timestamp: i64,
};

pub const Generator = struct {
    path: []const u8,
    sha256: []const u8,
    rewriter_closure_sha256: []const u8,
};

pub const Feed = struct {
    field: []const u8,
    instance: u32,
    target: []const u8,
    relation: u32,
    word_base: u32,
    words_per_instance: u32,
};

pub const Component = struct {
    producer: []const u8,
    sub_words_per_row: u32,
    feeds: []const Feed,
};

pub const Document = struct {
    components: []const Component,
    generator: Generator,
    schema: []const u8,
    source: Source,
    version: u32,
};

pub const Loaded = struct {
    parsed: std.json.Parsed(Document),
    sha256: [32]u8,

    pub fn deinit(self: *Loaded) void {
        self.parsed.deinit();
        self.* = undefined;
    }

    pub fn find(self: Loaded, producer: []const u8) ?Component {
        for (self.parsed.value.components) |component| {
            if (std.mem.eql(u8, component.producer, producer)) return component;
        }
        return null;
    }
};

pub fn readOfficial(allocator: std.mem.Allocator, path: []const u8) !Loaded {
    const encoded = try std.fs.cwd().readFileAlloc(allocator, path, max_document_bytes);
    defer allocator.free(encoded);

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &digest, .{});
    if (!std.mem.eql(u8, &digest, &(try parseDigest(expected_sha256))))
        return error.TopologyDigestMismatch;

    const parsed = try std.json.parseFromSlice(Document, allocator, encoded, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    errdefer parsed.deinit();
    try validate(parsed.value);
    return .{ .parsed = parsed, .sha256 = digest };
}

fn validate(document: Document) !void {
    if (!std.mem.eql(u8, document.schema, schema) or document.version != version)
        return error.UnsupportedTopology;
    if (!std.mem.eql(u8, document.source.revision, claim_registry.source_revision.stwo_cairo) or
        !std.mem.eql(u8, document.source.tree, expected_source_tree))
        return error.TopologySourceMismatch;
    _ = try parseDigest(document.generator.sha256);
    _ = try parseDigest(document.generator.rewriter_closure_sha256);
    if (!std.mem.eql(
        u8,
        document.generator.path,
        "scripts/generate_cairo_witness_topology.py",
    )) return error.TopologyGeneratorMismatch;
    if (document.components.len != expected_component_count)
        return error.TopologyComponentCountMismatch;

    for (document.components, 0..) |component, component_index| {
        try validateName(component.producer);
        if (component.feeds.len > max_feeds_per_component)
            return error.TopologyFeedCountTooLarge;
        if (component_index != 0 and
            std.mem.order(u8, document.components[component_index - 1].producer, component.producer) != .lt)
            return error.NonCanonicalTopologyOrder;
        for (component.feeds, 0..) |feed, feed_index| {
            try validateName(feed.field);
            try validateName(feed.target);
            if (feed.words_per_instance == 0 or
                feed.word_base > component.sub_words_per_row or
                feed.words_per_instance > component.sub_words_per_row - feed.word_base)
                return error.InvalidFeedGeometry;
            for (component.feeds[0..feed_index]) |prior| {
                if (prior.instance == feed.instance and
                    std.mem.eql(u8, prior.field, feed.field))
                    return error.DuplicateFeed;
            }
        }
    }
}

fn validateName(value: []const u8) !void {
    if (value.len == 0) return error.InvalidTopologyName;
    for (value, 0..) |byte, index| switch (byte) {
        'a'...'z' => {},
        '0'...'9', '_' => if (index == 0) return error.InvalidTopologyName,
        else => return error.InvalidTopologyName,
    };
}

fn parseDigest(value: []const u8) ![32]u8 {
    if (value.len != 64) return error.InvalidTopologyDigest;
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, value) catch return error.InvalidTopologyDigest;
    return digest;
}

test "official Cairo feed topology authenticates every generated component" {
    var loaded = try readOfficial(
        std.testing.allocator,
        "vectors/cairo/official/witness_feed_topology_v1.json",
    );
    defer loaded.deinit();

    try std.testing.expectEqual(expected_component_count, loaded.parsed.value.components.len);
    var feed_count: usize = 0;
    for (loaded.parsed.value.components) |component| feed_count += component.feeds.len;
    try std.testing.expectEqual(@as(usize, 1780), feed_count);

    const ec_op = loaded.find("ec_op_builtin") orelse return error.MissingComponent;
    try std.testing.expectEqual(@as(u32, 31_516), ec_op.sub_words_per_row);
    try std.testing.expectEqual(@as(usize, 268), ec_op.feeds.len);
    const fixed = loaded.find("range_check_9_9") orelse return error.MissingComponent;
    try std.testing.expectEqual(@as(u32, 0), fixed.sub_words_per_row);
    try std.testing.expectEqual(@as(usize, 0), fixed.feeds.len);
}
