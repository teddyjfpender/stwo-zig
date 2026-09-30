//! The inputs of `verify_circuit` besides the proof, as JSON.
//!
//! Upstream `verify_circuit` (`crates/circuit_verifier/src/verify.rs` of
//! https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230) takes the verified circuit's
//! `CircuitConfig` (its `PcsConfig` and preprocessed column log sizes in
//! commitment order), its preprocessed root and the output digest it claims.
//! This file is those four values in the format of the oracle's
//! `verify-circuit --request` (`tools/stwo-circuit-oracle-rs/src/verify_circuit.rs`,
//! serde's derive of `VerifyRequest`), so one request drives both
//! verifiers:
//!
//! ```text
//! {"pcs_config":{"fri_config":{...},"trace_lifting_log_size":N,"preprocessed_lifting_log_size":N},
//!  "preprocessed_column_log_sizes":[["id",log_size],...],
//!  "preprocessed_root":[8 u32],"output_digest":[8 u32]}
//! ```
//!
//! Digests are eight little-endian `u32` words of the Blake2s bytes.

const std = @import("std");
const core = @import("stwo_core");
const json_text = @import("json_text.zig");
const registry = @import("registry.zig");

const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;

pub const Column = struct {
    id: []const u8,
    log_size: u32,
};

pub const VerifyRequest = struct {
    pcs_config: PcsConfigV2,
    /// Commitment order.
    preprocessed_column_log_sizes: []const Column,
    preprocessed_root: [8]u32,
    output_digest: [8]u32,
};

pub const ReadError = json_text.ReadError;

/// A parsed request; its strings live in `arena`.
pub const OwnedRequest = struct {
    arena: std.heap.ArenaAllocator,
    request: VerifyRequest,

    pub fn deinit(self: *OwnedRequest) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub fn parseVerifyRequest(gpa: std.mem.Allocator, text: []const u8) ReadError!OwnedRequest {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const allocator = arena.allocator();
    const root = try json_text.object((try json_text.parse(allocator, text)).value);

    const pcs = try json_text.object(try json_text.field(root, "pcs_config"));
    const items = try json_text.array(try json_text.field(root, "preprocessed_column_log_sizes"));
    const columns = try allocator.alloc(Column, items.len);
    for (items, columns) |item, *column| {
        const pair = try json_text.array(item);
        if (pair.len != 2) return error.InvalidValue;
        column.* = .{ .id = try json_text.string(pair[0]), .log_size = try json_text.unsigned(u32, pair[1]) };
    }
    return .{ .arena = arena, .request = .{
        .pcs_config = .{
            .fri_config = try registry.readFriConfig(try json_text.object(try json_text.field(pcs, "fri_config"))),
            .trace_lifting_log_size = try json_text.unsigned(u32, try json_text.field(pcs, "trace_lifting_log_size")),
            .preprocessed_lifting_log_size = try json_text.unsigned(u32, try json_text.field(pcs, "preprocessed_lifting_log_size")),
        },
        .preprocessed_column_log_sizes = columns,
        .preprocessed_root = try readWords(try json_text.field(root, "preprocessed_root")),
        .output_digest = try readWords(try json_text.field(root, "output_digest")),
    } };
}

fn readWords(value: std.json.Value) ReadError![8]u32 {
    const items = try json_text.array(value);
    if (items.len != 8) return error.InvalidValue;
    var words: [8]u32 = undefined;
    for (items, &words) |item, *word| word.* = try json_text.unsigned(u32, item);
    return words;
}

/// `serde_json::to_string(&VerifyRequest)`: compact, fields in declaration
/// order.
pub fn writeVerifyRequest(out: *std.Io.Writer, request: VerifyRequest) std.Io.Writer.Error!void {
    var writer = json_text.Writer.init(out, false);
    try writer.beginObject();
    try writer.key("pcs_config");
    try writer.beginObject();
    try writer.key("fri_config");
    try registry.writeFriConfig(&writer, request.pcs_config.fri_config);
    try writer.key("trace_lifting_log_size");
    try writer.unsignedValue(request.pcs_config.trace_lifting_log_size);
    try writer.key("preprocessed_lifting_log_size");
    try writer.unsignedValue(request.pcs_config.preprocessed_lifting_log_size);
    try writer.endObject();
    try writer.key("preprocessed_column_log_sizes");
    try writer.beginArray();
    for (request.preprocessed_column_log_sizes) |column| {
        try writer.beginArray();
        try writer.stringValue(column.id);
        try writer.unsignedValue(column.log_size);
        try writer.endArray();
    }
    try writer.endArray();
    inline for (.{ "preprocessed_root", "output_digest" }) |name| {
        try writer.key(name);
        try writer.beginArray();
        for (@field(request, name)) |word| try writer.unsignedValue(word);
        try writer.endArray();
    }
    try writer.endObject();
}

test "verify request: round trip of the serde text" {
    const allocator = std.testing.allocator;
    const text =
        \\{"pcs_config":{"fri_config":{"pow_bits":10,"log_blowup_factor":1,"log_last_layer_degree_bound":0,"n_queries":3,"fold_step":1},"trace_lifting_log_size":21,"preprocessed_lifting_log_size":21},"preprocessed_column_log_sizes":[["eq_in0_address",4],["seq_16",16]],"preprocessed_root":[1,2,3,4,5,6,7,4294967295],"output_digest":[0,0,0,0,0,0,0,9]}
    ;
    var parsed = try parseVerifyRequest(allocator, text);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u32, 3), parsed.request.pcs_config.fri_config.n_queries);
    try std.testing.expectEqualStrings("seq_16", parsed.request.preprocessed_column_log_sizes[1].id);
    try std.testing.expectEqual(@as(u32, 0xffffffff), parsed.request.preprocessed_root[7]);
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    try writeVerifyRequest(&out.writer, parsed.request);
    try std.testing.expectEqualStrings(text, out.written());
    try std.testing.expectError(error.InvalidValue, parseVerifyRequest(allocator, "{\"pcs_config\":{},\"preprocessed_column_log_sizes\":[[\"a\"]]}"));
}
