//! Independent public-input/ELF admission for a standalone original macro.
//! Public call bounds are external statement parameters, never witness hints.
//! This is not authorization to replace native rows in a complete VM proof.
const std = @import("std");
const core = @import("stwo_core");
const Initial = @import("block_v7_initial_intervals_v1.zig");
const Image = @import("block_v7_program_image_v1.zig");
const C = @import("../air/guest_precompile/bulk_memcpy_byte_loop_certificate_v1.zig");
const A = @import("bulk_memcpy_byte_loop_components_v1.zig");
const Endpoint = @import("block_v8_ram_endpoint_kernel_v1.zig");
const T = @import("block_v7_memory_trace_v1.zig");
const M = core.fields.m31.M31;
pub const production_active = false;
pub const whole_source_qualified = false;
pub const Public = struct {
    cohort_ordinal: u32 = 0,
    pc: u32,
    call: C.Call,
    previous_register_clocks: [4]u32,
    initial_scratch: u32,
    last_byte: u8,
    source_previous_clocks: []const u32,
    destination_previous_clocks: []const u32,
};
pub const Trusted = struct { elf: []const u8, elf_sha256: [32]u8, profile: @import("../air/program/decode.zig").ExecutionProfile, config: core.pcs.PcsConfig, public: Public };
pub const Scope = struct {
    allocator: std.mem.Allocator,
    initialized: Initial.Owned,
    image: Image.Owned,
    certificate: C.Certificate,
    trusted: Trusted,
    source_words: u32,
    destination_words: u32,
    source_log: u32,
    destination_log: u32,
    value_requests: u32,
    byte_requests: u32,
    endpoint_count: u32,
    endpoint_log: u32,
    endpoint_policy: Endpoint.Policy,
    pub fn create(a: std.mem.Allocator, trusted: Trusted) !*Scope {
        const p = trusted.public;
        try p.call.validate();
        if (p.call.length > 1 << 16) return error.ByteLoopResourceLimit;
        const source_words = try p.call.sourceWordCount();
        const destination_words = try p.call.destinationWordCount();
        if (p.source_previous_clocks.len != source_words or p.destination_previous_clocks.len != destination_words) return error.InvalidByteLoopBoundaryClocks;
        var initialized = try Initial.Owned.derive(a, trusted.elf, trusted.elf_sha256, trusted.profile, .{});
        errdefer initialized.deinit();
        var image = try Image.Owned.init(a, trusted.elf, &initialized, .{});
        errdefer image.deinit();
        const certificate = try C.Certificate.fromProgramImage(&image, p.pc);
        const first_register = try p.call.firstRegisterClocks();
        for (p.previous_register_clocks, first_register) |previous, first| if (previous >= first or (previous != 0 and previous % 4 == 0)) return error.InvalidByteLoopRegisterPredecessor;
        var value_requests: u32 = 0;
        for (0..destination_words) |i| {
            const plan = try p.call.destinationWordPlan(@intCast(i));
            value_requests += @intFromBool(plan.source_low_word != null) + @as(u32, @intFromBool(plan.source_high_word != null));
        }
        for ([_]bool{ true, false }) |source| {
            const first_address = (if (source) p.call.source else p.call.destination) & ~@as(u32, 3);
            const predecessors = if (source) p.source_previous_clocks else p.destination_previous_clocks;
            for (predecessors, 0..) |previous, i| {
                const address = first_address + 4 * @as(u32, @intCast(i));
                if (!initialized.info.memory_layout.isRwAddr(address) or initialized.info.memory_layout.isProgramAddr(address)) return error.InvalidByteLoopRwSpan;
                // Conservative nonterminal macro admission. Ordinary RV32
                // handles every span that touches the independently derived flag.
                if (address == initialized.info.halt_flag) return error.UnsupportedByteLoopHaltWord;
                if (previous >= try p.call.firstWordClock(source, address) or (previous != 0 and previous % 4 != 3)) return error.InvalidByteLoopBoundaryClocks;
            }
        }
        const self = try a.create(Scope);
        errdefer a.destroy(self);
        self.* = .{ .allocator = a, .initialized = initialized, .image = image, .certificate = certificate, .trusted = trusted, .source_words = source_words, .destination_words = destination_words, .source_log = rowLog(source_words), .destination_log = rowLog(destination_words), .value_requests = value_requests, .byte_requests = 12 * source_words + 16 * destination_words, .endpoint_count = source_words + destination_words, .endpoint_log = rowLog(source_words + destination_words), .endpoint_policy = .{ .source_ordinal = p.cohort_ordinal, .max_local_clock = @intCast(@import("../access_clock.zig").maximum(p.call.max_instruction_cycle)) } };
        try self.endpoint_policy.validate();
        return self;
    }
    pub const EndpointCoordinate = struct { source: bool, index: usize, address: u32, before_clock: u32, last_clock: u32 };
    pub fn endpointAt(self: *const Scope, ordinal: usize) !EndpointCoordinate {
        if (ordinal >= self.endpoint_count) return error.InvalidByteLoopEndpoint;
        const p = self.trusted.public;
        const source_first = p.call.source < p.call.destination;
        const first_count = if (source_first) self.source_words else self.destination_words;
        const source = if (ordinal < first_count) source_first else !source_first;
        const index = if (ordinal < first_count) ordinal else ordinal - first_count;
        const address = ((if (source) p.call.source else p.call.destination) & ~@as(u32, 3)) + 4 * @as(u32, @intCast(index));
        return .{ .source = source, .index = index, .address = address, .before_clock = (if (source) p.source_previous_clocks else p.destination_previous_clocks)[index], .last_clock = try p.call.finalWordClock(source, address) };
    }
    pub fn deinit(self: *Scope) void {
        self.image.deinit();
        self.initialized.deinit();
        self.allocator.destroy(self);
    }
    pub fn mix(self: *const Scope, channel: anytype) void {
        const p = self.trusted.public;
        const call = p.call;
        channel.mixU32s(&.{ 0x42384d53, 1, 13, @intFromEnum(self.trusted.profile) });
        self.trusted.config.mixInto(channel);
        channel.mixRoot(self.trusted.elf_sha256);
        channel.mixRoot(self.certificate.program_root);
        channel.mixU32s(&.{ p.pc, call.entry_cycle, call.source, call.destination, call.destination_end, call.length, call.max_instruction_cycle, p.initial_scratch, p.last_byte, p.cohort_ordinal });
        channel.mixU32s(&p.previous_register_clocks);
        channel.mixU32s(p.source_previous_clocks);
        channel.mixU32s(p.destination_previous_clocks);
        channel.mixU32s(&.{ self.source_words, self.destination_words, self.value_requests, self.byte_requests, self.endpoint_count });
    }
};
pub fn rowLog(count: u32) u32 {
    return @max(@as(u32, 4), std.math.log2_int_ceil(u32, @max(count, 1)));
}
pub const Matrices = struct {
    destination: T.Matrix,
    source: T.Matrix,
    bytes: T.Matrix,
    boundary: T.Matrix,
    endpoints: T.Matrix,
    range16: T.Matrix,
    pub fn deinit(self: *Matrices) void {
        self.range16.deinit();
        self.endpoints.deinit();
        self.boundary.deinit();
        self.bytes.deinit();
        self.source.deinit();
        self.destination.deinit();
    }
};
pub fn fixed(a: std.mem.Allocator, scope: *const Scope) !Matrices {
    var destination = try T.Matrix.init(a, scope.destination_log, A.Spec(.destination).FIXED_COUNT + A.Spec(.destination).MAIN_COUNT, 64 << 20);
    errdefer destination.deinit();
    var source = try T.Matrix.init(a, scope.source_log, A.Spec(.source).FIXED_COUNT + A.Spec(.source).MAIN_COUNT, 64 << 20);
    errdefer source.deinit();
    var bytes = try T.Matrix.init(a, 8, A.Spec(.bytes).FIXED_COUNT + A.Spec(.bytes).MAIN_COUNT, 64 << 20);
    errdefer bytes.deinit();
    var boundary = try T.Matrix.init(a, 4, A.Spec(.boundary).FIXED_COUNT + A.Spec(.boundary).MAIN_COUNT, 64 << 20);
    errdefer boundary.deinit();
    var endpoints = try T.Matrix.init(a, scope.endpoint_log, A.EndpointSpec.FIXED_COUNT + A.EndpointSpec.MAIN_COUNT, 64 << 20);
    errdefer endpoints.deinit();
    var range16 = try T.Matrix.init(a, 16, A.RangeSpec.FIXED_COUNT + A.RangeSpec.MAIN_COUNT, 64 << 20);
    errdefer range16.deinit();
    const p = scope.trusted.public;
    for (0..scope.destination_words) |i| {
        const plan = try p.call.destinationWordPlan(@intCast(i));
        destination.set(0, i, M.one());
        destination.set(1, i, M.fromCanonical(@intFromBool(i + 1 == scope.destination_words)));
        destination.set(2 + @as(usize, plan.start), i, M.one());
        destination.set(6 + @as(usize, plan.end) - 1, i, M.one());
        destination.set(10 + @as(usize, plan.shift), i, M.one());
        destination.set(14, i, M.fromCanonical(plan.destination_word));
        destination.set(15, i, M.fromCanonical(plan.source_low_word orelse 0));
        destination.set(16, i, M.fromCanonical(plan.source_high_word orelse 0));
        destination.set(17, i, M.fromCanonical(@intFromBool(plan.source_low_word != null)));
        destination.set(18, i, M.fromCanonical(@intFromBool(plan.source_high_word != null)));
        destination.set(19, i, M.fromCanonical(p.destination_previous_clocks[i]));
        destination.set(20, i, M.fromCanonical(plan.final_store_clock));
    }
    for (0..scope.source_words) |i| {
        const address = (p.call.source & ~@as(u32, 3)) + 4 * @as(u32, @intCast(i));
        source.set(0, i, M.one());
        source.set(1, i, M.fromCanonical(address));
        source.set(2, i, M.fromCanonical(p.source_previous_clocks[i]));
        source.set(3, i, M.fromCanonical(try p.call.finalWordClock(true, address)));
    }
    for (0..256) |i| {
        bytes.set(0, i, M.one());
        bytes.set(1, i, M.fromCanonical(@intCast(i)));
    }
    for (try scope.certificate.fetches(p.call.length), 0..) |fetch, i| {
        boundary.set(0, i, M.one());
        boundary.set(3, i, M.fromCanonical(core.fields.m31.Modulus - fetch.count));
        for (fetch.tuple, 0..) |value, j| boundary.set(4 + j, i, M.fromCanonical(value));
    }
    boundary.set(1, 5, M.one());
    boundary.set(3, 5, M.fromCanonical(core.fields.m31.Modulus - 1));
    boundary.set(4, 5, M.fromCanonical(p.pc));
    boundary.set(5, 5, M.fromCanonical(p.call.entry_cycle));
    boundary.set(1, 6, M.one());
    boundary.set(3, 6, M.one());
    boundary.set(4, 6, M.fromCanonical(try p.call.nextPc(scope.certificate)));
    boundary.set(5, 6, M.fromCanonical(try p.call.nextCycle()));
    const initial_values = [4]u32{ p.call.source, p.call.destination, p.initial_scratch, p.call.destination_end };
    const final_values = try p.call.finalRegisterValues(p.last_byte);
    const final_clocks = try p.call.finalRegisterClocks();
    for (C.registers, initial_values, final_values, p.previous_register_clocks, final_clocks, 0..) |reg, before, after, previous, final_clock, i| {
        for (0..2) |side| {
            const row = 7 + 2 * i + side;
            const value = if (side == 0) before else after;
            boundary.set(2, row, M.one());
            boundary.set(3, row, if (side == 0) M.fromCanonical(core.fields.m31.Modulus - 1) else M.one());
            boundary.set(4, row, M.zero());
            boundary.set(5, row, M.fromCanonical(reg));
            boundary.set(6, row, M.fromCanonical(if (side == 0) previous else final_clock));
            for (0..4) |byte| boundary.set(7 + byte, row, M.fromCanonical((value >> @as(u5, @intCast(8 * byte))) & 255));
        }
    }
    for (0..scope.endpoint_count) |i| {
        const point = try scope.endpointAt(i);
        const word = point.address / 4;
        endpoints.set(0, i, M.one());
        endpoints.set(1, i, M.fromCanonical(@intFromBool(i == 0)));
        endpoints.set(2, i, M.fromCanonical(point.before_clock));
        endpoints.set(3, i, M.fromCanonical(word & 65535));
        endpoints.set(4, i, M.fromCanonical(word >> 16));
    }
    for (0..65536) |i| {
        range16.set(0, i, M.one());
        range16.set(1, i, M.fromCanonical(@intCast(i)));
    }
    return .{ .destination = destination, .source = source, .bytes = bytes, .boundary = boundary, .endpoints = endpoints, .range16 = range16 };
}
