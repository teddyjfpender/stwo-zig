//! Compact public authority for the new native-GKR format only. The producer
//! and recursive verifier share this ordered visitor; no request digest is a
//! freely guessed substitute for the actual AIR public values.
const std = @import("std");
const Canon = @import("../../ethereum/canon_native.zig");
const Worker = @import("../gkr_local/worker_protocol.zig");
const Mass = @import("../gkr_local/mass_authority.zig");
const Plan = @import("../gkr_local/cpu_components.zig").Plan;
const Setup = @import("../roster.zig").CpuSetup;
const Request = @import("../protocol.zig").Request;
const T = @import("../types.zig");
pub const DOMAIN = "rv64/native-gkr/cpu-publics/v2";
pub fn domainDigest() [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(DOMAIN, &out, .{});
    return out;
}
pub const Header = struct {
    domain: [32]u8,
    class_key: [32]u8,
    program: [32]u8,
    config_identity: [32]u8,
    fixed_identity: [32]u8,
    fixed_root: [32]u8,
};
pub const Metadata = struct { ordinal: u32, execution: [32]u8, mass: Mass.Globals, relations: u32 };
pub const Inputs = struct {
    steps: u32, epoch: u32,
    initial_pc: [4]u32, final_pc: [4]u32,
    initial_registers: [32][4]u32, final_registers: [32][4]u32,
    register_clocks: [32]u32, sponge_first: u32,
    rows: []u32, calls: []u32, first_ids: []u32,
    pub fn deinit(self: *Inputs, a: std.mem.Allocator) void {
        a.free(self.rows); a.free(self.calls); a.free(self.first_ids);
        self.* = undefined;
    }
};
/// Header and metadata may contain native values or circuit handles. Lengths
/// are immutable class topology; all list contents are public scalar witnesses.
pub fn emit(header: anytype, inputs: anytype, metadata: anytype, h: anytype) void {
    h.digest(header.domain);
    inline for (.{ "class_key", "program", "config_identity", "fixed_identity", "fixed_root" }) |name| h.digest(@field(header, name));
    h.word(metadata.ordinal);
    h.digest(metadata.execution);
    h.words(&.{ inputs.steps, inputs.epoch });
    h.words(&inputs.initial_pc); h.words(&inputs.final_pc);
    for (inputs.initial_registers) |r| h.words(&r);
    for (inputs.final_registers) |r| h.words(&r);
    h.words(&inputs.register_clocks);
    h.word(inputs.sponge_first);
    h.constantWord(@intCast(inputs.rows.len));
    // Interleave each slot's scalars: the Plan fixes this exact component order.
    for (inputs.rows, inputs.calls, inputs.first_ids) |rows, calls, first| h.words(&.{rows, calls, first});
    inline for (.{ "ram", "kio", "wire" }) |name| {
        h.int64(@field(metadata.mass, name).positive);
        h.int64(@field(metadata.mass, name).negative);
    }
    h.word(metadata.relations);
}
pub fn digest(header: Header, inputs: Inputs, metadata: Metadata) ![32]u8 {
    if (!std.mem.eql(u8, &header.domain, &domainDigest())) return error.NativeGkrStatementDomain;
    if (inputs.rows.len != inputs.calls.len or inputs.rows.len != inputs.first_ids.len) return error.NativeGkrStatementShape;
    var h = NativeWriter{ .inner = Canon.Hasher.init(.stmt) };
    emit(header, inputs, metadata, &h);
    return h.inner.final();
}
const NativeWriter = struct {
    inner: Canon.Hasher,
    pub fn constantWord(s: *@This(), value: u32) void { s.inner.word(value); }
    pub fn word(s: *@This(), value: u32) void { s.inner.word(value); }
    pub fn words(s: *@This(), values: []const u32) void { s.inner.words(values); }
    pub fn int64(s: *@This(), value: u64) void { s.inner.int64(value); }
    pub fn digest(s: *@This(), value: [32]u8) void { s.inner.digest(value); }
};
pub fn configIdentity(config: Worker.PcsConfig) ![32]u8 {
    try Worker.validateCandidateConfig(config);
    var h = Canon.Hasher.init(.stmt);
    var tag: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash("rv64/native-gkr/config/v2", &tag, .{});
    h.digest(tag);
    h.words(&.{ config.pow_bits, config.fri_config.log_blowup_factor, config.fri_config.log_last_layer_degree_bound, config.fri_config.n_queries, config.fri_config.fold_step });
    return h.final();
}
fn limbs(value: u64) [4]u32 {
    var out: [4]u32 = undefined;
    for (&out, 0..) |*v, i| v.* = @as(u16, @truncate(value >> @as(u6, @intCast(16*i))));
    return out;
}
/// Build from the same request/Plan authority used by role_oods and cpu_leaf.
/// Boundary *counts* enter AIR public rows; boundary cell values are bound by
/// the typed root RAM target and are deliberately absent from this compact hash.
pub fn fromRequest(a: std.mem.Allocator, setup: *const Setup, plan: *const Plan, request: Request, first: [T.FAMILIES]u32) !Inputs {
    const rows = try a.alloc(u32, plan.slots.len); errdefer a.free(rows);
    const calls = try a.alloc(u32, plan.slots.len); errdefer a.free(calls);
    const first_ids = try a.alloc(u32, plan.slots.len); errdefer a.free(first_ids);
    const cpu = request.base.cpu;
    var out = Inputs{ .steps = cpu.steps, .epoch = request.base.epoch, .initial_pc = limbs(cpu.initial_pc), .final_pc = limbs(cpu.final_pc), .initial_registers = undefined, .final_registers = undefined, .register_clocks = cpu.register_clocks, .sponge_first = request.sponge.first_id, .rows = rows, .calls = calls, .first_ids = first_ids };
    for (0..32) |r| { out.initial_registers[r] = limbs(cpu.initial_registers[r]); out.final_registers[r] = limbs(cpu.final_registers[r]); }
    const ls = try setup.materials.geometry.lsCounts(request.base.memory.ls_count);
    const dw = try T.dwordCounts(setup.bridges, request.ls_dword);
    for (plan.slots, rows, calls, first_ids) |slot, *row, *call, *id| {
        row.* = 0; call.* = 0; id.* = 1;
        switch (slot.origin) {
            .core => |role| row.* = switch (role) {
                .initial => @intCast(request.base.memory.initial.len), .terminal => @intCast(request.base.memory.terminal.len),
                .ls => ls.head, .ls_tail => ls.tail, .multiplication => request.base.multiplication_requests, .division => request.base.division_requests, else => 0,
            },
            .bridge => |family| { call.* = request.calls[@intFromEnum(family)]; id.* = first[@intFromEnum(family)]; },
            .bulk => |kind| row.* = request.bulk.rows(kind),
            .sponge => |kind| row.* = request.sponge.rows(kind),
            .dword => |index| row.* = dw[index],
        }
    }
    return out;
}

test "compact native public visitor binds all AIR public coordinates and signed masses" {
    const a = std.testing.allocator;
    var rows = [_]u32{0, 3}; var calls = [_]u32{0, 5}; var first = [_]u32{1, 9};
    var input = Inputs{ .steps = 9, .epoch = 2, .initial_pc = @splat(0), .final_pc = @splat(1), .initial_registers = @splat(@splat(0)), .final_registers = @splat(@splat(1)), .register_clocks = @splat(3), .sponge_first = 1, .rows = &rows, .calls = &calls, .first_ids = &first };
    const header = Header{ .domain = domainDigest(), .class_key = @splat(1), .program = @splat(2), .config_identity = @splat(3), .fixed_identity = @splat(4), .fixed_root = @splat(5) };
    var metadata = Metadata{ .ordinal = 3, .execution = @splat(7), .mass = .{ .ram = .{ .positive = 13, .negative = 11 } }, .relations = 1 };
    const original = try digest(header, input, metadata);
    const Capture = struct {
        words_out: std.ArrayList(u32) = .empty, allocator: std.mem.Allocator,
        pub fn word(s: *@This(), x: u32) void { s.words_out.append(s.allocator, x) catch @panic("oom"); }
        pub fn constantWord(s: *@This(), x: u32) void { s.word(x); }
        pub fn words(s: *@This(), xs: []const u32) void { for (xs) |x| s.word(x); }
        pub fn int64(s: *@This(), x: u64) void { s.word(@truncate(x)); s.word(@truncate(x >> 32)); }
        pub fn digest(s: *@This(), x: [32]u8) void { for (0..8) |i| s.word(std.mem.readInt(u32, x[4*i..][0..4], .little)); }
    };
    var capture = Capture{ .allocator = a }; defer capture.words_out.deinit(a);
    emit(header, input, metadata, &capture);
    // A circuit writer sees exactly these words; every coordinate must affect
    // the producer digest, including zero and high limbs of signed u64 masses.
    for (capture.words_out.items, 0..) |_, changed| {
        var h = Canon.Hasher.init(.stmt);
        for (capture.words_out.items, 0..) |word, i| h.word(word ^ @as(u32, @intFromBool(i == changed)));
        try std.testing.expect(!std.mem.eql(u8, &original, &h.final()));
    }
    input.rows = rows[0..1]; try std.testing.expectError(error.NativeGkrStatementShape, digest(header, input, metadata));
    input.rows = &rows;
    metadata.mass.ram.positive += @as(u64, 1) << 32;
    try std.testing.expect(!std.mem.eql(u8, &original, &try digest(header, input, metadata)));
}
