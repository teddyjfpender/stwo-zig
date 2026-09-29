//! The leaf prover's JSON output and the recursive tree's leaf inputs.
//!
//! Ports, at https://github.com/starkware-libs/proving commit
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230:
//!
//! - `DigestHex` and `SerializedLeafProof` (`crates/leaf_proof_format`): a
//!   digest is eight little-endian `u32` words written `"{:#010x}"`; the proof
//!   is standard, padded base64 of its `CircuitSerialize` bytes. The leaf
//!   prover writes `serde_json::to_string_pretty` with no trailing newline.
//! - `LeafInput` and the leaves manifest
//!   (`crates/stwo_run_and_prove_recursive_tree/src/leaf_io.rs`): a
//!   `SerializedLeafProof` flattened together with `output_preimage` (decimal
//!   felt strings), and `{"leaves": ["<path>", ...]}`.
//!
//! Reading follows serde: `DigestHex` accepts an optional `0x` prefix and
//! `u32::from_str_radix(_, 16)` digits (either case, an optional `+`), base64
//! must be canonical (`base64::STANDARD`: padded, zero trailing bits), and
//! unknown fields are ignored. Re-emitting a Rust-written file reproduces its
//! bytes.

const std = @import("std");
const json_text = @import("json_text.zig");
const blake2_felt252 = @import("blake2_felt252.zig");

pub const n_digest_words: usize = 8;

/// Eight little-endian `u32` words of a Blake2s digest.
pub const DigestHex = struct {
    words: [n_digest_words]u32,

    pub fn fromBytes(bytes: [32]u8) DigestHex {
        var words: [n_digest_words]u32 = undefined;
        for (&words, 0..) |*word, index| word.* = std.mem.readInt(u32, bytes[index * 4 ..][0..4], .little);
        return .{ .words = words };
    }

    pub fn toBytes(self: DigestHex) [32]u8 {
        var bytes: [32]u8 = undefined;
        for (self.words, 0..) |word, index| std.mem.writeInt(u32, bytes[index * 4 ..][0..4], word, .little);
        return bytes;
    }

    pub fn eql(self: DigestHex, other: DigestHex) bool {
        return std.mem.eql(u32, &self.words, &other.words);
    }

    /// Reads the eight-string JSON array.
    pub fn fromJson(value: std.json.Value) json_text.ReadError!DigestHex {
        const items = try json_text.array(value);
        if (items.len != n_digest_words) return error.InvalidValue;
        var words: [n_digest_words]u32 = undefined;
        for (items, &words) |item, *word| word.* = try parseHexWord(try json_text.string(item));
        return .{ .words = words };
    }

    pub fn writeJson(self: DigestHex, writer: *json_text.Writer) json_text.Writer.Error!void {
        try writer.beginArray();
        for (self.words) |word| {
            var text: [10]u8 = undefined;
            try writer.stringValue(std.fmt.bufPrint(&text, "0x{x:0>8}", .{word}) catch unreachable);
        }
        try writer.endArray();
    }
};

/// `u32::from_str_radix(word.strip_prefix("0x").unwrap_or(word), 16)`.
fn parseHexWord(text: []const u8) json_text.ReadError!u32 {
    const unprefixed = if (std.mem.startsWith(u8, text, "0x")) text[2..] else text;
    const digits = if (std.mem.startsWith(u8, unprefixed, "+")) unprefixed[1..] else unprefixed;
    if (digits.len == 0) return error.InvalidValue;
    for (digits) |char| if (!std.ascii.isHex(char)) return error.InvalidValue;
    return std.fmt.parseInt(u32, digits, 16) catch error.InvalidValue;
}

/// `SerializedLeafProof`. `proof` holds the `CircuitSerialize` bytes.
pub const SerializedLeafProof = struct {
    circuit_preprocessed_root: DigestHex,
    circuit_hash: DigestHex,
    proof: []const u8,
};

/// `LeafInput`: a `SerializedLeafProof` plus its hashed-output preimage.
pub const LeafInput = struct {
    proof: SerializedLeafProof,
    output_preimage: []const []const u8,

    /// `LeafInput::output_digest`: the leaf circuit's output digest.
    pub fn outputDigest(self: LeafInput, allocator: std.mem.Allocator) blake2_felt252.Error![n_digest_words]u32 {
        return blake2_felt252.outputDigest(allocator, self.output_preimage);
    }
};

pub const ReadError = json_text.ReadError;

/// A parsed JSON document whose values borrow from `arena`.
pub fn Owned(comptime T: type) type {
    return struct {
        arena: std.heap.ArenaAllocator,
        value: T,

        pub fn deinit(self: *@This()) void {
            self.arena.deinit();
            self.* = undefined;
        }
    };
}

pub fn parseSerializedLeafProof(gpa: std.mem.Allocator, text: []const u8) ReadError!Owned(SerializedLeafProof) {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const allocator = arena.allocator();
    const root = try json_text.object((try json_text.parse(allocator, text)).value);
    return .{ .arena = arena, .value = try readLeafProofFields(allocator, root) };
}

pub fn parseLeafInput(gpa: std.mem.Allocator, text: []const u8) ReadError!Owned(LeafInput) {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const allocator = arena.allocator();
    const root = try json_text.object((try json_text.parse(allocator, text)).value);
    const preimage_items = try json_text.array(try json_text.field(root, "output_preimage"));
    const preimage = try allocator.alloc([]const u8, preimage_items.len);
    for (preimage_items, preimage) |item, *slot| slot.* = try json_text.string(item);
    return .{ .arena = arena, .value = .{
        .proof = try readLeafProofFields(allocator, root),
        .output_preimage = preimage,
    } };
}

/// The paths of `{"leaves": ["<path>", ...]}`, in fold order.
pub fn parseLeavesManifest(gpa: std.mem.Allocator, text: []const u8) ReadError!Owned([]const []const u8) {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const allocator = arena.allocator();
    const root = try json_text.object((try json_text.parse(allocator, text)).value);
    const items = try json_text.array(try json_text.field(root, "leaves"));
    const paths = try allocator.alloc([]const u8, items.len);
    for (items, paths) |item, *slot| slot.* = try json_text.string(item);
    return .{ .arena = arena, .value = paths };
}

fn readLeafProofFields(allocator: std.mem.Allocator, root: std.json.ObjectMap) ReadError!SerializedLeafProof {
    const encoded = try json_text.string(try json_text.field(root, "proof"));
    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(encoded) catch return error.InvalidValue;
    const proof = try allocator.alloc(u8, size);
    decoder.decode(proof, encoded) catch return error.InvalidValue;
    return .{
        .circuit_preprocessed_root = try DigestHex.fromJson(try json_text.field(root, "circuit_preprocessed_root")),
        .circuit_hash = try DigestHex.fromJson(try json_text.field(root, "circuit_hash")),
        .proof = proof,
    };
}

/// `serde_json::to_string_pretty(&SerializedLeafProof)`, no trailing newline.
pub fn writeSerializedLeafProof(out: *std.Io.Writer, leaf: SerializedLeafProof) std.Io.Writer.Error!void {
    var writer = json_text.Writer.init(out, true);
    try writer.beginObject();
    try writeLeafProofFields(&writer, leaf);
    try writer.endObject();
}

/// `serde_json::to_string_pretty(&LeafInput)`, no trailing newline.
pub fn writeLeafInput(out: *std.Io.Writer, leaf: LeafInput) std.Io.Writer.Error!void {
    var writer = json_text.Writer.init(out, true);
    try writer.beginObject();
    try writeLeafProofFields(&writer, leaf.proof);
    try writer.key("output_preimage");
    try writer.beginArray();
    for (leaf.output_preimage) |felt| try writer.stringValue(felt);
    try writer.endArray();
    try writer.endObject();
}

fn writeLeafProofFields(writer: *json_text.Writer, leaf: SerializedLeafProof) std.Io.Writer.Error!void {
    try writer.key("circuit_preprocessed_root");
    try leaf.circuit_preprocessed_root.writeJson(writer);
    try writer.key("circuit_hash");
    try leaf.circuit_hash.writeJson(writer);
    try writer.key("proof");
    try writer.beginVerbatimString();
    try std.base64.standard.Encoder.encodeWriter(writer.out, leaf.proof);
    try writer.endVerbatimString();
}

test "leaf proof json: DigestHex reads what serde reads" {
    const allocator = std.testing.allocator;
    var parsed = try json_text.parse(allocator, "[\"0x03020100\",\"7060504\",\"0XB\",\"0x+c\",\"0xFFFFFFFF\",\"0\",\"0x000000001\",\"0x0\"]");
    defer parsed.deinit();
    // "0XB" is not a `0x` prefix, so `X` is a digit: rejected, as in serde.
    try std.testing.expectError(error.InvalidValue, DigestHex.fromJson(parsed.value));

    var accepted = try json_text.parse(allocator, "[\"0x03020100\",\"7060504\",\"0xB\",\"0x+c\",\"0xFFFFFFFF\",\"0\",\"0x000000001\",\"0x0\"]");
    defer accepted.deinit();
    const digest = try DigestHex.fromJson(accepted.value);
    try std.testing.expectEqualSlices(u32, &.{ 0x03020100, 0x7060504, 0xb, 0xc, 0xffffffff, 0, 1, 0 }, &digest.words);

    var bytes: [32]u8 = undefined;
    for (&bytes, 0..) |*byte, index| byte.* = @intCast(index);
    try std.testing.expectEqual(@as(u32, 0x03020100), DigestHex.fromBytes(bytes).words[0]);
    try std.testing.expectEqualSlices(u8, &bytes, &DigestHex.fromBytes(bytes).toBytes());
}

test "leaf proof json: base64 must be canonical" {
    const allocator = std.testing.allocator;
    const head = "{\"circuit_preprocessed_root\":[\"0\",\"0\",\"0\",\"0\",\"0\",\"0\",\"0\",\"0\"]," ++
        "\"circuit_hash\":[\"0\",\"0\",\"0\",\"0\",\"0\",\"0\",\"0\",\"0\"],\"proof\":";
    var ok = try parseSerializedLeafProof(allocator, head ++ "\"8NU=\",\"extra\":1}");
    defer ok.deinit();
    try std.testing.expectEqualSlices(u8, &.{ 0xf0, 0xd5 }, ok.value.proof);
    // Missing padding, nonzero trailing bits, and a URL-safe alphabet.
    for ([_][]const u8{ "\"8NU\"}", "\"8NV=\"}", "\"-_-_\"}" }) |tail| {
        const text = try std.mem.concat(allocator, u8, &.{ head, tail });
        defer allocator.free(text);
        try std.testing.expectError(error.InvalidValue, parseSerializedLeafProof(allocator, text));
    }
    try std.testing.expectError(error.MissingField, parseSerializedLeafProof(allocator, "{}"));
}

test "leaf proof json: the leaves manifest keeps fold order" {
    const allocator = std.testing.allocator;
    var manifest = try parseLeavesManifest(allocator, "{\"leaves\":[\"b.json\",\"a.json\"]}");
    defer manifest.deinit();
    try std.testing.expectEqual(@as(usize, 2), manifest.value.len);
    try std.testing.expectEqualStrings("b.json", manifest.value[0]);
    try std.testing.expectError(error.InvalidValue, parseLeavesManifest(allocator, "{\"leaves\":[1]}"));
}
