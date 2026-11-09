//! Length-owned BLAKE3 hash DAG, lowered to the canonical compression wires.
//! This is ordinary 32-byte hashing (not keyed hashing or extendable output).
const std = @import("std");
const core = @import("stwo_core");
const compression = core.crypto.blake3_compression;
const topology = @import("blake3_compression_plan.zig");
pub const Source = struct {
    wire: u32,
    value: union(enum) { constant: u32, input: struct { offset: usize, len: u3 } },
    pub fn read(self: Source, input: []const u8) !u32 {
        return switch (self.value) {
            .constant => |word| word,
            .input => |part| blk: {
                if (part.len == 0 or part.len > 4 or part.offset > input.len or part.len > input.len - part.offset) return error.InvalidBlake3Input;
                var bytes: [4]u8 = @splat(0);
                @memcpy(bytes[0..part.len], input[part.offset..][0..part.len]);
                break :blk std.mem.readInt(u32, &bytes, .little);
            },
        };
    }
};
pub const Call = struct { initial: [32]u32, output: [16]u32 };
pub const Plan = struct {
    allocator: std.mem.Allocator,
    input_len: usize,
    sources: []Source,
    calls: []Call,
    g: []topology.GCall,
    xor: []topology.XorCall,
    uses: []u32,
    output: [8]u32,
    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.sources);
        self.allocator.free(self.calls);
        self.allocator.free(self.g);
        self.allocator.free(self.xor);
        self.allocator.free(self.uses);
        self.* = undefined;
    }
};
pub fn build(allocator: std.mem.Allocator, input_len: usize) !Plan {
    // Conservative bound before allocation; every wire ID and multiplicity must
    // remain injectively representable in M31. Empty input still has one block.
    const chunks = @max(1, input_len / 1024 + @intFromBool(input_len % 1024 != 0));
    const blocks = @max(1, input_len / 64 + @intFromBool(input_len % 64 != 0));
    const count = std.math.add(usize, blocks, chunks - 1) catch return error.Blake3GraphTooLarge;
    if (count >= core.fields.m31.Modulus / topology.WIRE_COUNT) return error.Blake3GraphTooLarge;
    var builder = Builder{ .allocator = allocator, .input_len = input_len };
    defer builder.deinit();
    const output = try builder.subtree(0, chunks, true);
    for (output) |wire| builder.uses.items[wire] += 1;
    const sources = try builder.sources.toOwnedSlice(allocator);
    errdefer allocator.free(sources);
    const calls = try builder.calls.toOwnedSlice(allocator);
    errdefer allocator.free(calls);
    const g = try builder.g.toOwnedSlice(allocator);
    errdefer allocator.free(g);
    const xor = try builder.xor.toOwnedSlice(allocator);
    errdefer allocator.free(xor);
    return .{ .allocator = allocator, .input_len = input_len, .sources = sources, .calls = calls, .g = g, .xor = xor, .uses = try builder.uses.toOwnedSlice(allocator), .output = output };
}

/// CV of an independently admitted subtree inside an ORIGINAL hash. Chunk
/// counters are absolute original indices; neither chunk nor parent gets ROOT.
/// Existing build() and its allocation/equation path remain unchanged.
pub fn buildSubtreeAt(allocator: std.mem.Allocator, original_input_len: usize, first_chunk: usize, chunk_count: usize) !Plan {
    const chunks = @max(1, original_input_len / 1024 + @intFromBool(original_input_len % 1024 != 0));
    if (chunk_count == 0 or first_chunk >= chunks or chunk_count > chunks - first_chunk) return error.InvalidBlake3Subtree;
    const blocks = @max(1, original_input_len / 64 + @intFromBool(original_input_len % 64 != 0));
    const count = std.math.add(usize, blocks, chunks - 1) catch return error.Blake3GraphTooLarge;
    if (count >= core.fields.m31.Modulus / topology.WIRE_COUNT) return error.Blake3GraphTooLarge;
    var builder = Builder{ .allocator = allocator, .input_len = original_input_len };
    defer builder.deinit();
    const output = try builder.subtree(first_chunk, chunk_count, false);
    return finishAdditive(&builder, output);
}

/// Original chunk-zero + exact inner-to-outer frontier. Encoded input is the
/// first min(1024,original_input_len) bytes followed by one 32-byte CV per level.
/// Authentication of those CVs is a mandatory caller-owned AIR source route.
/// A CV is never hashed as a framed node or assigned a nonzero parent counter.
pub fn buildPrefixFold(allocator: std.mem.Allocator, original_input_len: usize) !Plan {
    const chunks = @max(1, original_input_len / 1024 + @intFromBool(original_input_len % 1024 != 0));
    const frontier_count = if (chunks == 1) @as(usize, 0) else std.math.log2_int_ceil(usize, chunks);
    const prefix_len = @min(1024, original_input_len);
    const synthetic_len = try std.math.add(usize, prefix_len, try std.math.mul(usize, 32, frontier_count));
    var builder = Builder{ .allocator = allocator, .input_len = prefix_len };
    defer builder.deinit();
    var output = try builder.chunk(0, frontier_count == 0);
    builder.input_len = synthetic_len;
    for (0..frontier_count) |i| {
        var right: [8]u32 = undefined;
        for (&right, 0..) |*wire, word| {
            wire.* = try builder.fresh();
            try builder.sources.append(allocator, .{ .wire = wire.*, .value = .{ .input = .{ .offset = prefix_len + i * 32 + word * 4, .len = 4 } } });
        }
        output = try builder.compress(try builder.iv(), output ++ right, 0, 64, 4 | (if (i + 1 == frontier_count) @as(u32, 8) else 0));
    }
    return finishAdditive(&builder, output);
}
fn finishAdditive(builder: *Builder, output: [8]u32) !Plan {
    const allocator = builder.allocator;
    for (output) |wire| builder.uses.items[wire] += 1;
    const sources = try builder.sources.toOwnedSlice(allocator);
    errdefer allocator.free(sources);
    const calls = try builder.calls.toOwnedSlice(allocator);
    errdefer allocator.free(calls);
    const gs = try builder.g.toOwnedSlice(allocator);
    errdefer allocator.free(gs);
    const xs = try builder.xor.toOwnedSlice(allocator);
    errdefer allocator.free(xs);
    return .{ .allocator = allocator, .input_len = builder.input_len, .sources = sources, .calls = calls, .g = gs, .xor = xs, .uses = try builder.uses.toOwnedSlice(allocator), .output = output };
}
const Builder = struct {
    allocator: std.mem.Allocator,
    input_len: usize,
    sources: std.ArrayList(Source) = .empty,
    calls: std.ArrayList(Call) = .empty,
    g: std.ArrayList(topology.GCall) = .empty,
    xor: std.ArrayList(topology.XorCall) = .empty,
    uses: std.ArrayList(u32) = .empty,
    fn deinit(self: *Builder) void {
        self.sources.deinit(self.allocator);
        self.calls.deinit(self.allocator);
        self.g.deinit(self.allocator);
        self.xor.deinit(self.allocator);
        self.uses.deinit(self.allocator);
    }
    fn fresh(self: *Builder) !u32 {
        if (self.uses.items.len >= core.fields.m31.Modulus) return error.Blake3GraphTooLarge;
        const wire: u32 = @intCast(self.uses.items.len);
        try self.uses.append(self.allocator, 0);
        return wire;
    }
    fn constant(self: *Builder, value: u32) !u32 {
        const wire = try self.fresh();
        try self.sources.append(self.allocator, .{ .wire = wire, .value = .{ .constant = value } });
        return wire;
    }
    fn iv(self: *Builder) ![8]u32 {
        var result: [8]u32 = undefined;
        for (&result, compression.IV) |*wire, word| wire.* = try self.constant(word);
        return result;
    }
    fn subtree(self: *Builder, first: usize, chunks: usize, root: bool) anyerror![8]u32 {
        if (chunks == 1) return self.chunk(first, root);
        const left_size = @as(usize, 1) << @intCast(std.math.log2_int(usize, chunks - 1));
        const left = try self.subtree(first, left_size, false);
        const right = try self.subtree(first + left_size, chunks - left_size, false);
        return self.compress(try self.iv(), left ++ right, 0, 64, 4 | (if (root) @as(u32, 8) else 0));
    }
    fn chunk(self: *Builder, index: usize, root: bool) ![8]u32 {
        const start = index * 1024;
        const len = @min(1024, self.input_len - start);
        const blocks = @max(1, len / 64 + @intFromBool(len % 64 != 0));
        var cv = try self.iv();
        for (0..blocks) |block_index| {
            const offset = start + block_index * 64;
            const block_len = @min(64, self.input_len - offset);
            var block: [16]u32 = undefined;
            for (&block, 0..) |*wire, i| {
                const byte = i * 4;
                if (byte >= block_len) {
                    wire.* = try self.constant(0);
                } else {
                    wire.* = try self.fresh();
                    try self.sources.append(self.allocator, .{ .wire = wire.*, .value = .{ .input = .{ .offset = offset + byte, .len = @intCast(@min(4, block_len - byte)) } } });
                }
            }
            const last = block_index + 1 == blocks;
            const flags: u32 = (if (block_index == 0) @as(u32, 1) else 0) | (if (last) @as(u32, 2) else 0) | (if (root and last) @as(u32, 8) else 0);
            cv = try self.compress(cv, block, @intCast(index), @intCast(block_len), flags);
        }
        return cv;
    }
    fn compress(self: *Builder, cv: [8]u32, block: [16]u32, counter: u64, len: u32, flags: u32) ![8]u32 {
        var initial: [32]u32 = undefined;
        initial[0..8].* = cv;
        for (initial[8..12], compression.IV[0..4]) |*wire, word| wire.* = try self.constant(word);
        const parameters = [4]u32{ @truncate(counter), @truncate(counter >> 32), len, flags };
        for (initial[12..16], parameters) |*wire, word| wire.* = try self.constant(word);
        initial[16..32].* = block;
        const local = topology.canonical();
        var map: [topology.WIRE_COUNT]u32 = undefined;
        map[0..32].* = initial;
        for (map[32..]) |*wire| wire.* = try self.fresh();
        for (local.g) |call| {
            var global: topology.GCall = undefined;
            for (&global.input, call.input) |*wire, id| {
                wire.* = map[id];
                self.uses.items[wire.*] += 1;
            }
            for (&global.output, call.output) |*wire, id| wire.* = map[id];
            try self.g.append(self.allocator, global);
        }
        for (local.xor) |call| {
            var global = topology.XorCall{ .input = undefined, .output = map[call.output] };
            for (&global.input, call.input) |*wire, id| {
                wire.* = map[id];
                self.uses.items[wire.*] += 1;
            }
            try self.xor.append(self.allocator, global);
        }
        var output: [16]u32 = undefined;
        for (&output, local.output) |*wire, id| wire.* = map[id];
        try self.calls.append(self.allocator, .{ .initial = initial, .output = output });
        return output[0..8].*;
    }
};
