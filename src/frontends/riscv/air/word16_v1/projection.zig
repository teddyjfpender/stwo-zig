//! Exact committed-cell projection for a finite dominant subset. SOURCE ONLY.
//! Every view is an affine alias of THESE cells or a constant zero. No new
//! range/table/clock authority, original proof or verification key is provided.
const std = @import("std");
const A = @import("abi.zig");
const Arithmetic = @import("arithmetic.zig");
const LS = @import("load_store.zig");
const W = @import("writer.zig");
pub const Profile = enum(u32) { add = 0, sub = 1, addi = 10, lw = 21, sw = 26 };
pub const VERSION: u32 = 1;
pub const production_active = false;
pub const fixed_columns = [_][]const u8{ "active_prefix", "domain_first", "domain_last" };
pub const register_columns = [_][]const u8{
    "clock",     "pc",        "rd",         "rd_before_lo",       "rd_before_hi", "rd_previous_clock", "rd_after_lo", "rd_after_hi",
    "rs1",       "rs1_lo",    "rs1_hi",     "rs1_previous_clock", "rs2",          "rs2_lo",            "rs2_hi",      "rs2_previous_clock",
    "result_lo", "result_hi", "rd_nonzero", "rd_inverse",
};
pub const immediate_columns = [_][]const u8{
    "clock",      "pc",     "rd",     "rd_before_lo",       "rd_before_hi",     "rd_previous_clock", "rd_after_lo", "rd_after_hi",
    "rs1",        "rs1_lo", "rs1_hi", "rs1_previous_clock", "signed_immediate", "result_lo",         "result_hi",   "rd_nonzero",
    "rd_inverse",
};
pub const load_columns = [_][]const u8{
    "clock",         "pc",             "rd",         "rd_before_lo",       "rd_before_hi",       "rd_previous_clock", "rd_after_lo", "rd_after_hi",
    "rs1",           "rs1_lo",         "rs1_hi",     "rs1_previous_clock", "ram_previous_clock", "ram_lo",            "ram_hi",      "signed_immediate",
    "quarter_low14", "quarter_high14", "rd_nonzero", "rd_inverse",         "halt_hit",           "halt_inverse",
};
pub const store_columns = [_][]const u8{
    "clock",              "pc",            "rs1",           "rs1_lo",           "rs1_hi",        "rs1_previous_clock", "rs2",      "rs2_lo",       "rs2_hi", "rs2_previous_clock",
    "ram_previous_clock", "ram_before_lo", "ram_before_hi", "signed_immediate", "quarter_low14", "quarter_high14",     "halt_hit", "halt_inverse",
};
pub fn names(comptime profile: Profile) []const []const u8 {
    return switch (profile) {
        .add, .sub => &register_columns,
        .addi => &immediate_columns,
        .lw => &load_columns,
        .sw => &store_columns,
    };
}
pub fn Cells(comptime S: type, comptime profile: Profile) type {
    return [names(profile).len]S;
}
pub fn Semantic(comptime S: type, comptime profile: Profile) type {
    return switch (profile) {
        .add, .sub => Arithmetic.RegisterRow(S),
        .addi => Arithmetic.ImmediateRow(S),
        .lw => LS.LoadRow(S),
        .sw => LS.StoreRow(S),
    };
}
pub fn Fixed(comptime S: type) type {
    return struct { active_prefix: S, domain_first: S, domain_last: S };
}
fn word(comptime S: type, lo: S, hi: S) A.Word(S) {
    return .{ .lo = lo, .hi = hi };
}
/// Exactly one finite opcode is admitted per component. There is no committed
/// opcode flag or caller-chosen activation. A future receiver must derive the
/// fixed active/first/last columns and profile from ELF/shape/key authority.
pub fn expand(comptime S: type, comptime profile: Profile, x: Cells(S, profile)) Semantic(S, profile) {
    switch (profile) {
        .add, .sub => return .{
            .clock = x[0],
            .pc = x[1],
            .destination = .{ .address = x[2], .before = word(S, x[3], x[4]), .previous_clock = x[5], .after = word(S, x[6], x[7]) },
            .lhs = .{ .address = x[8], .value = word(S, x[9], x[10]), .previous_clock = x[11] },
            .rhs = .{ .address = x[12], .value = word(S, x[13], x[14]), .previous_clock = x[15] },
            .result = word(S, x[16], x[17]),
            .rd_nonzero = x[18],
            .rd_inverse = x[19],
        },
        .addi => return .{
            .clock = x[0],
            .pc = x[1],
            .destination = .{ .address = x[2], .before = word(S, x[3], x[4]), .previous_clock = x[5], .after = word(S, x[6], x[7]) },
            .source = .{ .address = x[8], .value = word(S, x[9], x[10]), .previous_clock = x[11] },
            .immediate = x[12],
            .result = word(S, x[13], x[14]),
            .rd_nonzero = x[15],
            .rd_inverse = x[16],
        },
        .lw => return .{
            .clock = x[0],
            .pc = x[1],
            .destination = .{ .address = x[2], .before = word(S, x[3], x[4]), .previous_clock = x[5], .after = word(S, x[6], x[7]) },
            .base = .{ .address = x[8], .value = word(S, x[9], x[10]), .previous_clock = x[11] },
            .memory = .{ .address = x[16].mul(A.c(S, 4)).add(x[17].mul(A.c(S, 65536))), .previous_clock = x[12], .value = word(S, x[13], x[14]) },
            .immediate = x[15],
            .address = .{ .quarter_low14 = x[16], .quarter_high14 = x[17], .offset_bits = .{ S.zero(), S.zero() } },
            .memory_bytes = @splat(S.zero()),
            .selected = S.zero(),
            .sign = S.zero(),
            .result = word(S, x[13], x[14]),
            .rd_nonzero = x[18],
            .rd_inverse = x[19],
            .halt_auxiliary = .{ x[20], x[21] },
        },
        .sw => return .{
            .clock = x[0],
            .pc = x[1],
            .base = .{ .address = x[2], .value = word(S, x[3], x[4]), .previous_clock = x[5] },
            .source = .{ .address = x[6], .value = word(S, x[7], x[8]), .previous_clock = x[9] },
            .memory = .{ .address = x[14].mul(A.c(S, 4)).add(x[15].mul(A.c(S, 65536))), .previous_clock = x[10], .before = word(S, x[11], x[12]), .after = word(S, x[7], x[8]) },
            .immediate = x[13],
            .address = .{ .quarter_low14 = x[14], .quarter_high14 = x[15], .offset_bits = .{ S.zero(), S.zero() } },
            .source_bytes = @splat(S.zero()),
            .before_bytes = @splat(S.zero()),
            .after_bytes = @splat(S.zero()),
            .halt_auxiliary = .{ x[16], x[17] },
        },
    }
}
/// ONE source of equations and events: lowering never duplicates arithmetic,
/// x0, sign, range, address, RAM/ROM/clock or per-access HALT logic.
pub fn evaluate(comptime S: type, comptime profile: Profile, x: Cells(S, profile), fixed: Fixed(S), halt: LS.Halt, constraints: anytype, events: anytype) void {
    const row = expand(S, profile, x);
    switch (profile) {
        .add => Arithmetic.register(S, .add, row, fixed.active_prefix, constraints, events),
        .sub => Arithmetic.register(S, .sub, row, fixed.active_prefix, constraints, events),
        .addi => Arithmetic.immediate(S, row, fixed.active_prefix, constraints, events),
        .lw => LS.load(S, .lw, row, fixed.active_prefix, halt, constraints, events),
        .sw => LS.store(S, .sw, row, fixed.active_prefix, halt, constraints, events),
    }
}
/// Host hygiene only. All proof obligations are emitted by evaluate directly
/// from compact cells, even for a malicious prover that never calls pack.
pub fn pack(comptime profile: Profile, row: Semantic(A.M, profile)) !Cells(A.M, profile) {
    const x: Cells(A.M, profile) = switch (profile) {
        .add, .sub => .{ row.clock, row.pc, row.destination.address, row.destination.before.lo, row.destination.before.hi, row.destination.previous_clock, row.destination.after.lo, row.destination.after.hi, row.lhs.address, row.lhs.value.lo, row.lhs.value.hi, row.lhs.previous_clock, row.rhs.address, row.rhs.value.lo, row.rhs.value.hi, row.rhs.previous_clock, row.result.lo, row.result.hi, row.rd_nonzero, row.rd_inverse },
        .addi => .{ row.clock, row.pc, row.destination.address, row.destination.before.lo, row.destination.before.hi, row.destination.previous_clock, row.destination.after.lo, row.destination.after.hi, row.source.address, row.source.value.lo, row.source.value.hi, row.source.previous_clock, row.immediate, row.result.lo, row.result.hi, row.rd_nonzero, row.rd_inverse },
        .lw => .{ row.clock, row.pc, row.destination.address, row.destination.before.lo, row.destination.before.hi, row.destination.previous_clock, row.destination.after.lo, row.destination.after.hi, row.base.address, row.base.value.lo, row.base.value.hi, row.base.previous_clock, row.memory.previous_clock, row.memory.value.lo, row.memory.value.hi, row.immediate, row.address.quarter_low14, row.address.quarter_high14, row.rd_nonzero, row.rd_inverse, row.halt_auxiliary[0], row.halt_auxiliary[1] },
        .sw => .{ row.clock, row.pc, row.base.address, row.base.value.lo, row.base.value.hi, row.base.previous_clock, row.source.address, row.source.value.lo, row.source.value.hi, row.source.previous_clock, row.memory.previous_clock, row.memory.before.lo, row.memory.before.hi, row.immediate, row.address.quarter_low14, row.address.quarter_high14, row.halt_auxiliary[0], row.halt_auxiliary[1] },
    };
    if (!std.meta.eql(row, expand(A.M, profile, x))) return error.NoncanonicalWord16Projection;
    return x;
}
pub const Inventory = struct {
    main: u32,
    fixed: u32 = 3,
    max_total_degree: u32 = 4,
    /// Raw source-obligation fractions. No positive provider is included.
    register_events: u32,
    ram_events: u32,
    clock_events: u32,
    range16_events: u32,
    rom_events: u32 = 1,
    cpu_events: u32 = 2,
    /// Source-counted expected sink calls BEFORE algebraic zero/DCE. The
    /// dormant replay test must measure these before any profile is qualified.
    semantic_residuals: u32,
};
pub fn inventory(comptime profile: Profile) Inventory {
    return switch (profile) {
        .add, .sub => .{ .main = 20, .register_events = 6, .ram_events = 0, .clock_events = 3, .range16_events = 2, .semantic_residuals = 29 },
        .addi => .{ .main = 17, .register_events = 4, .ram_events = 0, .clock_events = 2, .range16_events = 2, .semantic_residuals = 26 },
        .lw => .{ .main = 22, .register_events = 4, .ram_events = 2, .clock_events = 3, .range16_events = 4, .semantic_residuals = 61 },
        .sw => .{ .main = 18, .register_events = 4, .ram_events = 2, .clock_events = 3, .range16_events = 4, .semantic_residuals = 62 },
    };
}
/// Model of ONLY source interaction columns if a future AIR pairs at most two
/// fractions WITHIN each independently closed relation domain and uses four
/// base columns per secure accumulator. No provider/clock witness is included.
/// This is not a generated or qualified interaction trace.
pub fn sourceInteractionColumnModel(comptime profile: Profile) u32 {
    const i = inventory(profile);
    var batches: u32 = 0;
    inline for (.{ "register_events", "ram_events", "clock_events", "range16_events", "rom_events", "cpu_events" }) |field| batches += (@field(i, field) + 1) / 2;
    return 4 * batches;
}
pub fn writeRegister(comptime profile: Profile, clock: u32, pc: u32, left: W.Read, right: W.Read, destination: W.Destination, limits: W.Limits) !Cells(A.M, profile) {
    if (profile != .add and profile != .sub) @compileError("not a register arithmetic profile");
    return pack(profile, try W.arithmetic(if (profile == .add) .add else .sub, clock, pc, left, right, destination, limits));
}
pub fn writeAddi(clock: u32, pc: u32, source: W.Read, destination: W.Destination, immediate: i32, limits: W.Limits) !Cells(A.M, .addi) {
    return pack(.addi, try W.addi(clock, pc, source, destination, immediate, limits));
}
pub fn writeLoadWord(clock: u32, pc: u32, base: W.Read, destination: W.Destination, immediate: i32, memory: W.Memory, halt: LS.Halt, limits: W.Limits) !Cells(A.M, .lw) {
    return pack(.lw, try W.load(.lw, clock, pc, base, destination, immediate, memory, halt, limits));
}
pub fn writeStoreWord(clock: u32, pc: u32, base: W.Read, source: W.Read, immediate: i32, memory: W.Memory, halt: LS.Halt, limits: W.Limits) !Cells(A.M, .sw) {
    return pack(.sw, try W.store(.sw, clock, pc, base, source, immediate, memory, halt, limits));
}
/// One bounded final column-major allocation; semantic structs are never
/// retained as a wide intermediate matrix. No PCS commitment is implemented.
pub fn Matrix(comptime profile: Profile) type {
    return struct {
        a: std.mem.Allocator,
        storage: []A.M,
        n_rows: usize,
        active_count: usize = 0,
        sealed: bool = false,
        const Self = @This();
        pub fn init(a: std.mem.Allocator, n_rows: usize, limits: W.Limits) !Self {
            if (n_rows == 0 or !std.math.isPowerOfTwo(n_rows) or n_rows > limits.max_rows or n_rows > (1 << 24)) return error.InvalidWord16ProjectionRows;
            const cells = try std.math.mul(usize, n_rows, names(profile).len);
            if (try std.math.mul(usize, cells, @sizeOf(A.M)) > limits.max_bytes) return error.Word16ProjectionBudgetExceeded;
            return .{ .a = a, .storage = try a.alloc(A.M, cells), .n_rows = n_rows };
        }
        pub fn append(self: *Self, cells: Cells(A.M, profile)) !void {
            if (self.sealed) return error.SealedWord16Projection;
            if (self.active_count == self.n_rows) return error.Word16ProjectionCapacityExceeded;
            for (cells, 0..) |value, column_index| self.storage[column_index * self.n_rows + self.active_count] = value;
            self.active_count += 1;
        }
        pub fn seal(self: *Self) !void {
            if (self.sealed) return error.SealedWord16Projection;
            if (self.active_count == 0) return error.EmptyWord16Projection;
            for (0..names(profile).len) |column_index| @memset(self.storage[column_index * self.n_rows + self.active_count .. (column_index + 1) * self.n_rows], A.M.zero());
            self.sealed = true;
        }
        pub fn column(self: *const Self, index: usize) ![]const A.M {
            if (!self.sealed) return error.UnsealedWord16Projection;
            if (index >= names(profile).len) return error.InvalidWord16ProjectionColumn;
            return self.storage[index * self.n_rows ..][0..self.n_rows];
        }
        /// Fixed prefix and domain endpoints are independently regenerated by
        /// the future receiver, not nominated by an untrusted matrix owner.
        pub fn fixedAt(self: *const Self, index: usize) !Fixed(A.M) {
            if (!self.sealed) return error.UnsealedWord16Projection;
            if (index >= self.n_rows) return error.InvalidWord16ProjectionRow;
            return .{ .active_prefix = A.c(A.M, @intFromBool(index < self.active_count)), .domain_first = A.c(A.M, @intFromBool(index == 0)), .domain_last = A.c(A.M, @intFromBool(index == self.n_rows - 1)) };
        }
        pub fn deinit(self: *Self) void {
            self.a.free(self.storage);
            self.* = undefined;
        }
    };
}
