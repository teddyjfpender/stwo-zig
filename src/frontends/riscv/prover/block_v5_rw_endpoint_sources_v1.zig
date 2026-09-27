//! Prechallenge public final-memory custody. Full-image root semantics retain
//! input words; source classification uses the independently pinned layout.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const initial = @import("block_v5_initial_sources_v1.zig");
const endpoint = @import("block_v5_rw_endpoint_interaction_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");
pub const RECORD_BYTES: usize = 16; // address LE4, final global clock LE8, value LE4
pub const Pins = struct {
    initial: initial.Pins,
    memory_plan_digest: [32]u8,
    expected_final_rw_root: [32]u8,
    endpoints: initial.FilePin,
    pub fn digest(self: Pins) ![32]u8 {
        try self.initial.validate();
        if (self.endpoints.records > initial.MAX_TOUCHES) return error.InvalidV5EndpointCensus;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig/block-v5/rw-endpoint-plan/v1\x00");
        hash.update(&(try self.initial.digest()));
        hash.update(&self.memory_plan_digest);
        hash.update(&self.expected_final_rw_root);
        hash.update(&self.endpoints.sha256);
        var count: [8]u8 = undefined;
        std.mem.writeInt(u64, &count, self.endpoints.records, .little);
        hash.update(&count);
        return hash.finalResult();
    }
};
pub const Sources = struct { initial: initial.Files, endpoints: std.fs.File };
pub const Claims = struct { sum: Q, count: u64, input_endpoints: u64, rw_endpoints: u64, final_root: [32]u8 };
/// These public sums become usable only inside a receiver that fresh-verifies
/// every same-root endpoint + sorted proof and closes exact count and sum.
pub fn check(a: std.mem.Allocator, pins: Pins, public_input: []const u8, files: Sources, v5_pins: seal.Pins, entries: []const seal.Entry, sealed: seal.Sealed) !Claims {
    const digest = try pins.digest();
    if (!std.meta.eql(digest, v5_pins.rw_endpoint_plan_digest) or !std.meta.eql(digest, sealed.rw_endpoint_plan_digest) or
        !std.meta.eql(pins.memory_plan_digest, v5_pins.memory_plan_digest) or
        !std.meta.eql(pins.expected_final_rw_root, v5_pins.expected_final_rw_root) or
        !std.meta.eql(try pins.initial.digest(), v5_pins.initial_source_plan_digest)) return error.UntrustedV5EndpointPlan;
    try sealed.require(v5_pins, entries);
    if (public_input.len != pins.initial.public_input_len or !std.meta.eql(initial.sha256(public_input), pins.initial.public_input_sha256)) return error.UntrustedV5PublicInput;
    const input = try initial.readPinned(a, files.initial.input_words, pins.initial.input_words, 8);
    defer a.free(input);
    const rw = try initial.readPinned(a, files.initial.rw_words, pins.initial.rw_words, 8);
    defer a.free(rw);
    const touches = try initial.readPinned(a, files.initial.first_touches, pins.initial.first_touches, 9);
    defer a.free(touches);
    const bytes = try initial.readPinned(a, files.endpoints, pins.endpoints, RECORD_BYTES);
    defer a.free(bytes);
    const initial_leaves = try loadInitial(a, pins.initial, public_input, input, rw);
    defer a.free(initial_leaves);
    const hasher = tree.TreeHasher.init(.memory);
    if (!std.meta.eql((try hasher.root(initial_leaves)).bytes, pins.initial.initial_rw_root)) return error.InvalidV5InitialRwRoot;
    const final_leaves = try a.alloc(tree.Leaf, initial_leaves.len + @as(usize, @intCast(pins.endpoints.records)));
    defer a.free(final_leaves);
    const elements = try endpoint.draw(a, sealed);
    var result = Claims{ .sum = Q.zero(), .count = pins.endpoints.records, .input_endpoints = 0, .rw_endpoints = 0, .final_root = undefined };
    var touch_at: usize = 0;
    var previous: ?u32 = null;
    var image_at: usize = 0;
    var final_at: usize = 0;
    var denominators: [1024]Q = undefined;
    var inverses: [1024]Q = undefined;
    var pending: usize = 0;
    for (0..@intCast(pins.endpoints.records)) |index| {
        const record = bytes[index * RECORD_BYTES ..][0..RECORD_BYTES];
        const address = initial.readWord(record[0..4]);
        const clock = readClock(record[4..12]);
        const value = initial.readWord(record[12..16]);
        const word_index = try tree.memoryIndex(address);
        if (previous != null and address <= previous.?) return error.DuplicateOrUnsortedV5Endpoint;
        previous = address;
        while (touch_at < touches.len and touches[touch_at] == 0) : (touch_at += 9) {}
        if (touch_at + 9 > touches.len or touches[touch_at] != 1 or initial.readWord(touches[touch_at + 1 ..][0..4]) != address) return error.InvalidV5EndpointTouchRoster;
        touch_at += 9;
        if (pins.initial.layout.isProgramAddr(address)) return error.ProgramEndpointRequiresVerifiedRomReceipt;
        if (pins.initial.layout.isInputAddr(address)) result.input_endpoints += 1 else if (pins.initial.layout.isRwAddr(address)) result.rw_endpoints += 1 else return error.UnclassifiedV5Endpoint;
        while (image_at < initial_leaves.len and initial_leaves[image_at].index < word_index) : (image_at += 1) {
            final_leaves[final_at] = initial_leaves[image_at];
            final_at += 1;
        }
        if (image_at < initial_leaves.len and initial_leaves[image_at].index == word_index) image_at += 1;
        if (value != 0) {
            final_leaves[final_at] = .{ .index = word_index, .value = value };
            final_at += 1;
        }
        denominators[pending] = try elements.combineBase(&tuple(address, clock, value));
        pending += 1;
        if (pending == denominators.len) {
            try flush(&result.sum, denominators[0..pending], inverses[0..pending]);
            pending = 0;
        }
    }
    while (touch_at < touches.len and touches[touch_at] == 0) : (touch_at += 9) {}
    if (touch_at != touches.len) return error.InvalidV5EndpointTouchRoster;
    while (image_at < initial_leaves.len) : (image_at += 1) {
        final_leaves[final_at] = initial_leaves[image_at];
        final_at += 1;
    }
    try flush(&result.sum, denominators[0..pending], inverses[0..pending]);
    result.final_root = (try hasher.root(final_leaves[0..final_at])).bytes;
    if (!std.meta.eql(result.final_root, pins.expected_final_rw_root)) return error.InvalidV5FinalRwRoot;
    return result;
}
fn loadInitial(a: std.mem.Allocator, pins: initial.Pins, public_input: []const u8, input: []const u8, rw: []const u8) ![]tree.Leaf {
    const leaves = try a.alloc(tree.Leaf, @intCast(pins.input_words.records + pins.rw_words.records));
    errdefer a.free(leaves);
    var at: usize = 0;
    var record_at: usize = 0;
    var address = pins.layout.input_base;
    while (@as(u64, address) < @as(u64, pins.layout.input_base) + public_input.len) : (address += 4) {
        const value = try initial.inputWord(pins, public_input, address);
        if (value == 0) continue;
        if (record_at + 8 > input.len or initial.readWord(input[record_at..][0..4]) != address or initial.readWord(input[record_at + 4 ..][0..4]) != value) return error.InvalidV5InputWordRoster;
        leaves[at] = .{ .index = try tree.memoryIndex(address), .value = value };
        at += 1;
        record_at += 8;
    }
    if (record_at != input.len) return error.InvalidV5InputWordRoster;
    var previous: ?u32 = null;
    for (0..@intCast(pins.rw_words.records)) |index| {
        const record = rw[index * 8 ..][0..8];
        const addr = initial.readWord(record[0..4]);
        const value = initial.readWord(record[4..8]);
        if (value == 0 or (previous != null and addr <= previous.?) or pins.layout.isInputAddr(addr) or pins.layout.isProgramAddr(addr) or !pins.layout.isRwAddr(addr)) return error.InvalidV5RwWordRoster;
        previous = addr;
        leaves[at] = .{ .index = try tree.memoryIndex(addr), .value = value };
        at += 1;
    }
    if (at != leaves.len) return error.InvalidV5InitialSourceLength;
    std.mem.sort(tree.Leaf, leaves, {}, lessLeaf);
    return leaves;
}
pub fn tuple(address: u32, clock: u64, value: u32) [endpoint.WIDTH]M {
    var result: [endpoint.WIDTH]M = undefined;
    result[0] = M.one();
    putBytes(result[1..5], address);
    putBytes(result[5..13], clock);
    putBytes(result[13..17], value);
    return result;
}
fn putBytes(out: []M, value: anytype) void {
    var rest: u64 = value;
    for (out) |*limb| {
        limb.* = M.fromCanonical(@intCast(rest & 255));
        rest >>= 8;
    }
}
fn readClock(bytes: []const u8) u64 {
    const raw: [8]u8 = bytes[0..8].*;
    return std.mem.readInt(u64, &raw, .little);
}
fn lessLeaf(_: void, left: tree.Leaf, right: tree.Leaf) bool {
    return left.index < right.index;
}
fn flush(sum: *Q, denominators: []Q, inverses: []Q) !void {
    if (denominators.len == 0) return;
    try core.fields.batchInverseInPlace(Q, denominators, inverses);
    for (inverses) |inverse| sum.* = sum.add(inverse);
}
