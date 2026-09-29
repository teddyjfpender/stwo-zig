//! Versioned streaming import for canonical stwo-cairo adapted prover input.

const std = @import("std");
const builtin = @import("builtin");
const admission = @import("official_input/decode.zig");
const cpu = @import("../common/cpu.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const adapter = @import("mod.zig");
const opcodes = @import("opcodes.zig");
const memory_mod = @import("../common/memory.zig");
const CasmState = @import("../common/cpu.zig").CasmState;

pub const MAGIC = "STWZCPI\x00".*;
pub const VERSION: u32 = 1;
pub const MAX_ITEMS: usize = 1 << 30;

pub const Error = error{
    InvalidMagic,
    UnsupportedVersion,
    InvalidOpcodeCount,
    InvalidBoolean,
    NonCanonicalEncoding,
    InputNotRegularFile,
    EmptyInput,
    InputTooLarge,
    LengthOverflow,
    Truncated,
    TrailingData,
};

const Stream = struct {
    reader: *std.Io.Reader,
    consumed: u64 = 0,
    size: u64,

    fn readExact(self: *Stream, destination: []u8) !void {
        if (destination.len > self.size - self.consumed) return Error.Truncated;
        try self.reader.readSliceAll(destination);
        self.consumed += destination.len;
    }

    fn int(self: *Stream, comptime T: type) !T {
        var bytes: [@sizeOf(T)]u8 = undefined;
        try self.readExact(&bytes);
        return std.mem.readInt(T, &bytes, .little);
    }

    fn count(self: *Stream, maximum: usize, item_bytes: usize) !usize {
        const value = try self.int(u64);
        if (value > MAX_ITEMS or value > std.math.maxInt(usize)) return Error.LengthOverflow;
        if (value > maximum) return Error.InputTooLarge;
        if (item_bytes != 0 and value > (self.size - self.consumed) / item_bytes)
            return Error.Truncated;
        return @intCast(value);
    }

    fn zero(self: *Stream, comptime T: type) !void {
        if (try self.int(T) != 0) return Error.NonCanonicalEncoding;
    }

    fn array(self: *Stream, comptime T: type, values: []T) !void {
        try self.readExact(std.mem.sliceAsBytes(values));
        if (comptime builtin.cpu.arch.endian() == .big) {
            for (values) |*value| swap(T, value);
        }
    }
};

fn swap(comptime T: type, value: *T) void {
    switch (@typeInfo(T)) {
        .int => value.* = @byteSwap(value.*),
        .array => |info| for (value) |*item| swap(info.child, item),
        .@"struct" => |info| inline for (info.fields) |field| swap(field.type, &@field(value, field.name)),
        else => @compileError("unsupported compact input element"),
    }
}

fn readState(stream: *Stream) !CasmState {
    const pc = try stream.int(u32);
    const ap = try stream.int(u32);
    const fp = try stream.int(u32);
    if (pc >= cpu.MEMORY_ADDRESS_BOUND or ap >= cpu.MEMORY_ADDRESS_BOUND or
        fp >= cpu.MEMORY_ADDRESS_BOUND) return admission.Error.StateAddressOutOfRange;
    return .{ .pc = M31.fromCanonical(pc), .ap = M31.fromCanonical(ap), .fp = M31.fromCanonical(fp) };
}

fn readSegment(stream: *Stream) !?adapter.MemorySegmentAddresses {
    const present = try stream.int(u8);
    var padding: [7]u8 = undefined;
    try stream.readExact(&padding);
    const begin = try stream.int(u64);
    const stop = try stream.int(u64);
    if (present > 1) return Error.InvalidBoolean;
    if (!std.mem.allEqual(u8, &padding, 0)) return Error.NonCanonicalEncoding;
    if (begin > std.math.maxInt(usize) or stop > std.math.maxInt(usize)) return Error.LengthOverflow;
    if (present == 0) {
        if (begin != 0 or stop != 0) return Error.NonCanonicalEncoding;
        return null;
    }
    return .{ .begin_addr = @intCast(begin), .stop_ptr = @intCast(stop) };
}

pub fn readFile(allocator: std.mem.Allocator, path: []const u8) !adapter.ProverInput {
    return readFileWithLimits(allocator, path, .{});
}

pub fn readFileWithLimits(allocator: std.mem.Allocator, path: []const u8, limits: admission.Limits) !adapter.ProverInput {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const stat = try file.stat();
    if (stat.kind != .file) return Error.InputNotRegularFile;
    var reader_buffer: [256 * 1024]u8 = undefined;
    var file_reader = file.readerStreaming(&reader_buffer);
    return read(allocator, &file_reader.interface, stat.size, limits);
}

pub fn parseSlice(allocator: std.mem.Allocator, bytes: []const u8, limits: admission.Limits) !adapter.ProverInput {
    var reader = std.Io.Reader.fixed(bytes);
    return read(allocator, &reader, bytes.len, limits);
}

pub fn read(allocator: std.mem.Allocator, reader: *std.Io.Reader, file_size: u64, limits: admission.Limits) !adapter.ProverInput {
    if (file_size == 0) return Error.EmptyInput;
    if (file_size > limits.max_file_bytes) return Error.InputTooLarge;
    var stream = Stream{ .reader = reader, .size = file_size };

    var magic: [MAGIC.len]u8 = undefined;
    try stream.readExact(&magic);
    if (!std.mem.eql(u8, &magic, &MAGIC)) return Error.InvalidMagic;
    if (try stream.int(u32) != VERSION) return Error.UnsupportedVersion;
    try stream.zero(u32); // flags

    const initial_state = try readState(&stream);
    const final_state = try readState(&stream);
    const pc_count = try stream.count(limits.max_states, 0);
    const public_mask = try stream.int(u16);
    if (public_mask >> adapter.N_PUBLIC_SEGMENTS != 0) return Error.NonCanonicalEncoding;
    try stream.zero(u16);
    try stream.zero(u32);
    if (try stream.int(u32) != opcodes.N_OPCODES) return Error.InvalidOpcodeCount;
    try stream.zero(u32);

    var grouped = opcodes.CasmStatesByOpcode.init(allocator);
    errdefer grouped.deinit(allocator);
    var state_count: usize = 0;
    for (&grouped.states) |*states| {
        const len = try stream.count(limits.max_states - state_count, @sizeOf(CasmState));
        state_count += len;
        try states.resize(allocator, len);
        try stream.array(CasmState, states.items);
    }

    const small_max_low = try stream.int(u64);
    const small_max_high = try stream.int(u64);
    const log_small_value_capacity = try stream.int(u32);
    try stream.zero(u32);
    const address_count = try stream.count(limits.max_memory_addresses, @sizeOf(u32));
    const f252_count = try stream.count(limits.max_memory_values, @sizeOf(memory_mod.F252));
    const small_count = try stream.count(limits.max_memory_values, @sizeOf(u128));

    // Counts are individually bounded above. Check their combined payload
    // before allocating any table, so mutually impossible lengths cannot each
    // reserve a file-sized buffer before the decoder discovers truncation.
    const memory_bytes = @as(u64, address_count) * @sizeOf(u32) +
        @as(u64, f252_count) * @sizeOf(memory_mod.F252) +
        @as(u64, small_count) * @sizeOf(u128);
    if (memory_bytes > stream.size - stream.consumed) return Error.Truncated;

    const address_to_id = try allocator.alloc(memory_mod.EncodedMemoryValueId, address_count);
    errdefer allocator.free(address_to_id);
    try stream.array(memory_mod.EncodedMemoryValueId, address_to_id);
    const f252_values = try allocator.alloc(memory_mod.F252, f252_count);
    errdefer allocator.free(f252_values);
    try stream.array(memory_mod.F252, f252_values);
    const small_values = try allocator.alloc(u128, small_count);
    errdefer allocator.free(small_values);
    try stream.array(u128, small_values);

    const public_count = try stream.count(limits.max_public_memory_addresses, @sizeOf(u32));
    const public_memory_addresses = try allocator.alloc(u32, public_count);
    errdefer allocator.free(public_memory_addresses);
    try stream.array(u32, public_memory_addresses);

    const builtin_segments = adapter.BuiltinSegments{
        .add_mod_builtin = try readSegment(&stream),
        .bitwise_builtin = try readSegment(&stream),
        .output = try readSegment(&stream),
        .mul_mod_builtin = try readSegment(&stream),
        .pedersen_builtin = try readSegment(&stream),
        .poseidon_builtin = try readSegment(&stream),
        .range_check96_builtin = try readSegment(&stream),
        .range_check_builtin = try readSegment(&stream),
        .ec_op_builtin = try readSegment(&stream),
    };
    var public_segment_context: adapter.PublicSegmentContext = undefined;
    for (&public_segment_context, 0..) |*present, bit| present.* = (public_mask & (@as(u16, 1) << @intCast(bit))) != 0;

    if (stream.consumed != file_size) return Error.TrailingData;
    const input = adapter.ProverInput{
        .state_transitions = .{
            .initial_state = initial_state,
            .final_state = final_state,
            .casm_states_by_opcode = grouped,
        },
        .memory = .{
            .config = .{
                .small_max = @as(u128, small_max_high) << 64 | small_max_low,
                .log_small_value_capacity = log_small_value_capacity,
            },
            .address_to_id = address_to_id,
            .f252_values = f252_values,
            .small_values = small_values,
        },
        .pc_count = pc_count,
        .public_memory_addresses = public_memory_addresses,
        .builtin_segments = builtin_segments,
        .public_segment_context = public_segment_context,
    };
    try admission.validateOwned(allocator, &input, limits);
    return input;
}
