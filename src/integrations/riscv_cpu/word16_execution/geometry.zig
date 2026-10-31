//! Concrete physical roster dimensions, independent of execution/request counts.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const B = front.rv64_air.word16_v1;
const A = front.rv64_air.arithmetic;
const Ram = front.rv64_air.memory.closed_ram.layout;
const LS = front.rv64_air.memory.load_store_v2.layout;
pub const ROLE_COUNT = 17;
const P = @import("program.zig").Program;
pub const Geometry = struct {
    cpu_log: u32,
    alu_log: u32 = 5,
    binary_log: u32 = 5,
    shift_log: u32 = 5,
    jalr_log: u32 = 5,
    division_log: u32 = 5,
    /// Explicit count-zero physical class. Omission never changes the CPU
    /// FUNCTION bus; the canonical core transcript is independently versioned.
    omit_empty_division: bool = false,
    multiplication_log: u32 = 5,
    ls_log: u32 = 5,
    boundary_log: u32 = 5,
    /// Optional independently sized RAM boundary roles. Null preserves the
    /// historical shared geometry, immutable roots and transcript exactly.
    initial_log: ?u32 = null,
    terminal_log: ?u32 = null,
    pub fn initialLog(self: Geometry) u32 {
        return self.initial_log orelse self.boundary_log;
    }
    pub fn terminalLog(self: Geometry) u32 {
        return self.terminal_log orelse self.boundary_log;
    }
    pub fn validate(self: Geometry) !void {
        if (self.omit_empty_division and self.division_log != 5) return error.InvalidOmittedDivisionGeometry;
        for ([_]u32{ self.cpu_log, self.alu_log, self.binary_log, self.shift_log, self.jalr_log, self.division_log, self.multiplication_log, self.ls_log, self.boundary_log, self.initialLog(), self.terminalLog() }) |log| if (log < 5 or log > 22) return error.InvalidExecutionGeometry;
        _ = try B.function_bus.admitPositiveMass(&.{try self.range16Mass()});
        _ = try B.function_bus.admitPositiveMass(&.{3 * rows(self.cpu_log) + 32});
        _ = try B.function_bus.admitPositiveMass(&.{try self.range8Mass()});
        _ = try B.function_bus.admitPositiveMass(&.{rows(self.cpu_log) + 2 * rows(self.jalr_log)});
        _ = try B.binary_source.massForLog(self.binary_log);
        _ = try B.shift_word_packed_experiment.source.massForLog(self.shift_log);
    }
    /// Counts include padding for every always-present physical provider.
    /// Future service rosters must extend this admission BEFORE allocation.
    pub fn range16Mass(self: Geometry) !u64 {
        var total = try std.math.add(u64, 3 * rows(self.cpu_log), 20 * rows(self.alu_log));
        total = try std.math.add(u64, total, 9 * rows(self.shift_log));
        total = try std.math.add(u64, total, LS.U16.len * rows(self.ls_log));
        return std.math.add(u64, total, Ram.B_U16.len * (rows(self.initialLog()) + rows(self.terminalLog())));
    }
    pub fn range8Mass(self: Geometry) !u64 {
        var total = try std.math.add(u64, 3 * rows(self.cpu_log), A.multiplication.layout.BYTE_QUERIES * rows(self.multiplication_log));
        total = try std.math.add(u64, total, LS.U8.len * rows(self.ls_log));
        return std.math.add(u64, total, Ram.B_U8.len * (rows(self.initialLog()) + rows(self.terminalLog())));
    }
};
pub fn rows(log: u32) u64 {
    return @as(u64, 1) << @intCast(log);
}
/// Structural roster tags, not runtime semantic/CPU policy alternatives.
pub const Role = enum { cpu, rom, boundary, alu, binary, shift, jalr, division, multiplication, shift_table, and_table, range16, range8, ls, initial, terminal, selection };
pub const Shape = struct {
    role: Role,
    log: u32,
    widths: [3]usize,
    offsets: [3]usize,
    pub fn present(self: Shape) bool {
        return self.widths[0] != 0 or self.widths[1] != 0 or self.widths[2] != 0;
    }
};
pub fn componentCount(actual: []const Shape) usize {
    var count: usize = 0;
    for (actual) |shape| if (shape.present()) {
        count += 1;
    };
    return count;
}
pub fn shapes(program: *const P, geometry: Geometry) [ROLE_COUNT]Shape {
    var result: [ROLE_COUNT]Shape = undefined;
    var offsets: [3]usize = @splat(0);
    for (std.enums.values(Role), &result) |role, *shape| {
        const widths: [3]usize = switch (role) {
            .cpu => .{ 3, 53, 40 },
            .rom => .{ 32, 1, 8 },
            .boundary => .{ 34, 0, 8 },
            .alu => .{ 2, B.alu_experiment.lookup.MAIN, B.alu_experiment.lookup.INTERACTION },
            .binary => .{ 2, B.binary_lookup.MAIN, B.binary_lookup.INTERACTION },
            .shift => .{ 2, B.shift_word_packed_experiment.lookup.MAIN, B.shift_word_packed_experiment.lookup.INTERACTION },
            .jalr => .{ 2, 18, 12 },
            .division => if (geometry.omit_empty_division) .{ 0, 0, 0 } else .{ A.division.layout.FIXED, A.division.layout.MAIN, A.division.layout.INTERACTION },
            .multiplication => .{ A.multiplication.layout.FIXED, A.multiplication.layout.MAIN, A.multiplication.degree3_layout.INTERACTION },
            .shift_table => .{ 18, 16, 36 },
            .and_table => .{ 5, 1, 8 },
            .range16, .range8 => .{ 3, 1, 8 },
            .ls => LS.widths(.ls),
            .initial, .terminal => .{ 3, 23, 48 },
            .selection => .{ 6, 2, 8 },
        };
        const log = switch (role) {
            .cpu => geometry.cpu_log,
            .rom => program.log_size,
            .alu => geometry.alu_log,
            .binary => geometry.binary_log,
            .shift => geometry.shift_log,
            .jalr => geometry.jalr_log,
            .division => geometry.division_log,
            .multiplication => geometry.multiplication_log,
            .shift_table, .and_table, .range16 => 16,
            .range8 => 8,
            .boundary => 5,
            .ls => geometry.ls_log,
            .initial => geometry.initialLog(),
            .terminal => geometry.terminalLog(),
            .selection => 16,
        };
        shape.* = .{ .role = role, .log = log, .widths = widths, .offsets = offsets };
        for (&offsets, widths) |*offset, width| offset.* += width;
    }
    return result;
}
pub const Cells = struct { fixed: u64 = 0, main: u64 = 0, interaction: u64 = 0 };
pub fn cells(actual: []const Shape) !Cells {
    var sums: [3]u64 = @splat(0);
    for (actual) |shape| {
        if (shape.log > 30) return error.InvalidExecutionGeometry;
        for (&sums, shape.widths) |*sum, width| sum.* = try std.math.add(u64, sum.*, try std.math.mul(u64, width, rows(shape.log)));
    }
    return .{ .fixed = sums[0], .main = sums[1], .interaction = sums[2] };
}

/// Native constraint kernels keep their independently sized evaluation domains.
/// All concrete roles now use native2n/split1, without weighted extension.
pub const Domain = struct { role: Role, present: bool = true, native_evaluation_log: u32, composition_contribution_bound_log: u32, weighted_quotient_extension_logs: u8 };
pub fn domains(actual: [ROLE_COUNT]Shape) [ROLE_COUNT]Domain {
    var out: [ROLE_COUNT]Domain = undefined;
    for (actual, &out) |shape, *domain| {
        if (!shape.present()) {
            domain.* = .{ .role = shape.role, .present = false, .native_evaluation_log = 0, .composition_contribution_bound_log = 0, .weighted_quotient_extension_logs = 0 };
            continue;
        }
        domain.* = .{ .role = shape.role, .native_evaluation_log = shape.log + 1, .composition_contribution_bound_log = shape.log + 1, .weighted_quotient_extension_logs = 0 };
    }
    return out;
}
