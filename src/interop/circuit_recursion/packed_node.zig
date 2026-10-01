//! The recursive tree's root output files besides the proof.
//!
//! Ports, at https://github.com/starkware-libs/proving commit
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230:
//!
//! - `PackedNode` (`crates/leaf_proof_format`), written to
//!   `--packed_output_path` with `serde_json::to_string` (compact, no trailing
//!   newline). It is externally tagged: `{"Plain":{"output_preimage":[...]}}`
//!   for a leaf's revealed preimage (decimal felt strings, passed through
//!   verbatim) and `{"Composite":{"circuit_hash":[8 numbers],"subtasks":[...]}}`
//!   for a verifier node.
//! - The root output digest, written to `--program_output` with
//!   `sonic_rs::to_string(&[u32; 8])`: `[w0,w1,...,w7]`.
//!
//! Reading follows serde: a variant is an object with exactly one key, a
//! `circuit_hash` must hold exactly eight `u32`s, and unknown fields inside a
//! variant are ignored. Nesting is bounded by `max_depth` so hostile input
//! cannot exhaust the stack; a real tree over N leaves is `ceil(log2 N) + 2`
//! nodes deep.

const std = @import("std");
const json_text = @import("json_text.zig");

pub const n_digest_words: usize = 8;
/// Deepest accepted node nesting (a tree over 2^62 leaves).
pub const max_depth: usize = 64;

pub const PackedNode = union(enum) {
    /// A leaf's hashed-output preimage: program hash, then the task output.
    plain: []const []const u8,
    composite: Composite,

    pub const Composite = struct {
        circuit_hash: [n_digest_words]u32,
        subtasks: []const PackedNode,
    };
};

pub const ReadError = json_text.ReadError || error{
    /// Nesting deeper than `max_depth`.
    TooDeep,
};

/// A parsed tree whose nodes and strings are owned by `arena`.
pub const OwnedPackedNode = struct {
    arena: std.heap.ArenaAllocator,
    node: PackedNode,

    pub fn deinit(self: *OwnedPackedNode) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub fn parsePackedNode(gpa: std.mem.Allocator, text: []const u8) ReadError!OwnedPackedNode {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const allocator = arena.allocator();
    const parsed = try json_text.parse(allocator, text);
    return .{ .arena = arena, .node = try readNode(allocator, parsed.value, 0) };
}

fn readNode(allocator: std.mem.Allocator, value: std.json.Value, depth: usize) ReadError!PackedNode {
    if (depth == max_depth) return error.TooDeep;
    const tagged = try json_text.object(value);
    if (tagged.count() != 1) return error.InvalidValue;
    const tag = tagged.keys()[0];
    const body = try json_text.object(tagged.values()[0]);
    if (std.mem.eql(u8, tag, "Plain")) {
        const items = try json_text.array(try json_text.field(body, "output_preimage"));
        const preimage = try allocator.alloc([]const u8, items.len);
        for (items, preimage) |item, *slot| slot.* = try json_text.string(item);
        return .{ .plain = preimage };
    }
    if (std.mem.eql(u8, tag, "Composite")) {
        const words = try json_text.array(try json_text.field(body, "circuit_hash"));
        if (words.len != n_digest_words) return error.InvalidValue;
        var circuit_hash: [n_digest_words]u32 = undefined;
        for (words, &circuit_hash) |word, *slot| slot.* = try json_text.unsigned(u32, word);
        const items = try json_text.array(try json_text.field(body, "subtasks"));
        const subtasks = try allocator.alloc(PackedNode, items.len);
        for (items, subtasks) |item, *slot| slot.* = try readNode(allocator, item, depth + 1);
        return .{ .composite = .{ .circuit_hash = circuit_hash, .subtasks = subtasks } };
    }
    return error.InvalidValue;
}

/// `serde_json::to_string(&PackedNode)`.
pub fn writePackedNode(out: *std.Io.Writer, node: PackedNode) std.Io.Writer.Error!void {
    var writer = json_text.Writer.init(out, false);
    try writeNode(&writer, node);
}

fn writeNode(writer: *json_text.Writer, node: PackedNode) std.Io.Writer.Error!void {
    try writer.beginObject();
    switch (node) {
        .plain => |preimage| {
            try writer.key("Plain");
            try writer.beginObject();
            try writer.key("output_preimage");
            try writer.beginArray();
            for (preimage) |felt| try writer.stringValue(felt);
            try writer.endArray();
            try writer.endObject();
        },
        .composite => |composite| {
            try writer.key("Composite");
            try writer.beginObject();
            try writer.key("circuit_hash");
            try writer.beginArray();
            for (composite.circuit_hash) |word| try writer.unsignedValue(word);
            try writer.endArray();
            try writer.key("subtasks");
            try writer.beginArray();
            for (composite.subtasks) |child| try writeNode(writer, child);
            try writer.endArray();
            try writer.endObject();
        },
    }
    try writer.endObject();
}

/// `sonic_rs::to_string(&output_digest)`.
pub fn writeRootOutputs(out: *std.Io.Writer, words: [n_digest_words]u32) std.Io.Writer.Error!void {
    var writer = json_text.Writer.init(out, false);
    try writer.beginArray();
    for (words) |word| try writer.unsignedValue(word);
    try writer.endArray();
}

pub fn parseRootOutputs(gpa: std.mem.Allocator, text: []const u8) json_text.ReadError![n_digest_words]u32 {
    var parsed = try json_text.parse(gpa, text);
    defer parsed.deinit();
    const items = try json_text.array(parsed.value);
    if (items.len != n_digest_words) return error.InvalidValue;
    var words: [n_digest_words]u32 = undefined;
    for (items, &words) |item, *word| word.* = try json_text.unsigned(u32, item);
    return words;
}

test "packed node: the upstream round-trip example" {
    const allocator = std.testing.allocator;
    const leaf: PackedNode = .{ .composite = .{
        .circuit_hash = .{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .subtasks = &.{.{ .plain = &.{"11"} }},
    } };
    const tree: PackedNode = .{ .composite = .{ .circuit_hash = @splat(9), .subtasks = &.{ leaf, leaf } } };
    var storage: [512]u8 = undefined;
    var out = std.Io.Writer.fixed(&storage);
    try writePackedNode(&out, tree);
    const leaf_text = "{\"Composite\":{\"circuit_hash\":[1,2,3,4,5,6,7,8],\"subtasks\":[{\"Plain\":{\"output_preimage\":[\"11\"]}}]}}";
    try std.testing.expectEqualStrings(
        "{\"Composite\":{\"circuit_hash\":[9,9,9,9,9,9,9,9],\"subtasks\":[" ++ leaf_text ++ "," ++ leaf_text ++ "]}}",
        out.buffered(),
    );

    var parsed = try parsePackedNode(allocator, out.buffered());
    defer parsed.deinit();
    var again_storage: [512]u8 = undefined;
    var again = std.Io.Writer.fixed(&again_storage);
    try writePackedNode(&again, parsed.node);
    try std.testing.expectEqualStrings(out.buffered(), again.buffered());
}

test "packed node: malformed trees are rejected" {
    const allocator = std.testing.allocator;
    const cases = [_][]const u8{
        "{\"Composite\":{\"circuit_hash\":[1,2,3],\"subtasks\":[]}}",
        "{\"Plain\":{\"output_preimage\":[]},\"Composite\":{}}",
        "{\"Leaf\":{}}",
        "{\"Plain\":{\"output_preimage\":[11]}}",
    };
    for (cases) |text| try std.testing.expectError(error.InvalidValue, parsePackedNode(allocator, text));

    var deep: std.ArrayList(u8) = .empty;
    defer deep.deinit(allocator);
    for (0..max_depth + 1) |_| try deep.appendSlice(allocator, "{\"Composite\":{\"circuit_hash\":[0,0,0,0,0,0,0,0],\"subtasks\":[");
    try deep.appendSlice(allocator, "{\"Plain\":{\"output_preimage\":[]}}");
    for (0..max_depth + 1) |_| try deep.appendSlice(allocator, "]}}");
    try std.testing.expectError(error.TooDeep, parsePackedNode(allocator, deep.items));
}

test "packed node: root outputs are a compact word array" {
    const words = [n_digest_words]u32{ 897652633, 1, 2, 3, 4, 5, 6, 4294967295 };
    var storage: [128]u8 = undefined;
    var out = std.Io.Writer.fixed(&storage);
    try writeRootOutputs(&out, words);
    try std.testing.expectEqualStrings("[897652633,1,2,3,4,5,6,4294967295]", out.buffered());
    try std.testing.expectEqual(words, try parseRootOutputs(std.testing.allocator, out.buffered()));
}
