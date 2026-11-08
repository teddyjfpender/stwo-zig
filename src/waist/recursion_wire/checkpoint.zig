//! A lossless transport for a nonterminal recursive fold. Unlike a root
//! proof, the circuit proof here can be consumed by another multiverifier.
const std = @import("std");
const json_text = @import("json_text.zig");
const leaf_json = @import("leaf_proof_json.zig");
const packed_node = @import("packed_node.zig");

pub const Node = struct {
    proof: []const u8,
    preprocessed_root: [8]u32,
    output_digest: [8]u32,
    packed_output: packed_node.PackedNode,
};

pub const Owned = struct {
    arena: std.heap.ArenaAllocator,
    node: Node,

    pub fn deinit(self: *Owned) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub fn parse(gpa: std.mem.Allocator, text: []const u8) packed_node.ReadError!Owned {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();
    const parsed = try json_text.parse(a, text);
    const root = try json_text.object(parsed.value);
    if (!std.mem.eql(u8, try json_text.string(try json_text.field(root, "schema")), "stwo.fold-checkpoint.v1"))
        return error.InvalidValue;
    const preprocessed = try words(try json_text.field(root, "preprocessed_root"));
    const digest = try words(try json_text.field(root, "output_digest"));
    const proof = try leaf_json.decodeBase64(a, try json_text.string(try json_text.field(root, "proof")));
    const packed_value = try packed_node.parseValue(a, try json_text.field(root, "packed_output"), 0);
    if (packed_value != .composite) return error.InvalidValue;
    return .{ .arena = arena, .node = .{
        .proof = proof,
        .preprocessed_root = preprocessed,
        .output_digest = digest,
        .packed_output = packed_value,
    } };
}

fn words(value: std.json.Value) json_text.ReadError![8]u32 {
    const items = try json_text.array(value);
    if (items.len != 8) return error.InvalidValue;
    var result: [8]u32 = undefined;
    for (items, &result) |item, *word| word.* = try json_text.unsigned(u32, item);
    return result;
}

pub fn write(out: *std.Io.Writer, node: Node) std.Io.Writer.Error!void {
    var writer = json_text.Writer.init(out, false);
    try writer.beginObject();
    try writer.key("schema");
    try writer.stringValue("stwo.fold-checkpoint.v1");
    try writer.key("preprocessed_root");
    try writer.beginArray();
    for (node.preprocessed_root) |word| try writer.unsignedValue(word);
    try writer.endArray();
    try writer.key("output_digest");
    try writer.beginArray();
    for (node.output_digest) |word| try writer.unsignedValue(word);
    try writer.endArray();
    try writer.key("proof");
    try writer.beginVerbatimString();
    try std.base64.standard.Encoder.encodeWriter(writer.out, node.proof);
    try writer.endVerbatimString();
    try writer.key("packed_output");
    try packed_node.writeValue(&writer, node.packed_output);
    try writer.endObject();
}

test "checkpoint preserves proof, digest and packed subtree" {
    const allocator = std.testing.allocator;
    const original: Node = .{
        .proof = "binary\x00proof",
        .preprocessed_root = .{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .output_digest = .{ 8, 7, 6, 5, 4, 3, 2, 1 },
        .packed_output = .{ .composite = .{ .circuit_hash = @splat(9), .subtasks = &.{.{ .plain = &.{"123"} }} } },
    };
    var storage: [512]u8 = undefined;
    var output = std.Io.Writer.fixed(&storage);
    try write(&output, original);
    var parsed = try parse(allocator, output.buffered());
    defer parsed.deinit();
    try std.testing.expectEqualSlices(u8, original.proof, parsed.node.proof);
    try std.testing.expectEqual(original.preprocessed_root, parsed.node.preprocessed_root);
    try std.testing.expectEqual(original.output_digest, parsed.node.output_digest);
    var again: [512]u8 = undefined;
    var second = std.Io.Writer.fixed(&again);
    try write(&second, parsed.node);
    try std.testing.expectEqualStrings(output.buffered(), second.buffered());
}
