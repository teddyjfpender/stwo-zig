//! Concrete physical roster dimensions, independent of execution/request counts.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const B = front.rv64_air.word16_v1;
const A = front.rv64_air.arithmetic;
const LS = front.rv64_air.memory.load_store_v2.layout;
pub const ROLE_COUNT = @typeInfo(Role).@"enum".fields.len;
const P = @import("program.zig").Program;
pub const Geometry = struct {
    cpu_log: u32,
    alu_log: u32 = 5,
    alu_tail_log: ?u32 = null,
    binary_log: u32 = 5,
    binary_tail_log: ?u32 = null,
    shift_log: u32 = 5,
    shift_tail_log: ?u32 = null,
    jalr_log: u32 = 5,
    division_log: u32 = 5,
    /// Explicit count-zero physical class. Omission never changes the CPU
    /// FUNCTION bus; the canonical core transcript is independently versioned.
    omit_empty_division: bool = false,
    multiplication_log: u32 = 5,
    ls_log: u32 = 5,
    /// Optional second LS instance in the SAME PCS. Null supplies no columns.
    ls_tail_log: ?u32 = null,
    boundary_log: u32 = 5,
    /// Optional independently sized RAM boundary roles. Null preserves the
    /// historical shared geometry, immutable roots and transcript exactly.
    initial_log: ?u32 = null,
    terminal_log: ?u32 = null,
    /// Opt-in fused-tail CPU interaction (36 instead of 40 columns, same LogUp
    /// statement). False preserves the historical CPU AIR, transcript and
    /// bundle JSON byte-for-byte (the field is omitted from JSON when false).
    cpu_fused_tail: bool = false,
    /// Opt-in byte-pair CPU lookups (requires cpu_fused_tail): the three gap8
    /// U8 queries become two pair queries (gap8_0, gap8_1) and (gap8_2, 0) of
    /// the tagged tuple (x, y, 0, 1) in the AND relation, served by a second
    /// multiplicity column of the AND table. CPU interaction 36 -> 32 columns.
    cpu_u8_pairs: bool = false,
    /// Opt-in compact decode CPU MAIN (requires cpu_u8_pairs): the row PC is
    /// read from the previous row's single-felt next PC, immediates live in
    /// the operand slot the instruction does not use, AUIPC/JAL fold to static
    /// constants. CPU MAIN 47 -> 37; ROM keeps its 30 coordinates.
    cpu_compact_decode: bool = false,
    /// Opt-in MUL byte-pair lookups (requires cpu_u8_pairs, whose AND table
    /// carries the pair multiplicity column): the 96 MUL BYTE queries become
    /// 48 tagged pair queries (x, y, 0, 1) of the AND relation, two per strict
    /// inverse column, and the FUNCTION fraction is fused into the prefix.
    /// MUL interaction 200 -> 100 columns (multiplication.pairs_layout).
    mul_u8_pairs: bool = false,
    /// Opt-in fused-tail + byte-pair LS32 layout (requires cpu_u8_pairs): LS
    /// interaction 32 -> 20 columns (RAM fraction fused into its prefix; the
    /// four U8 queries become two tagged AND-relation byte pairs fused into
    /// the local prefix; other local slots are degree-one fractions) and
    /// INIT/TEARDOWN 8 -> 4 (fused single). load_store_v2.layout.fused.
    ls_fused_pairs: bool = false,
    /// Opt-in fused-tail ALU (head and tail instances) interaction: 32 -> 28
    /// columns, the same LogUp statement (alu_lookup.fused).
    alu_fused_tail: bool = false,
    /// Opt-in fused-pair LS-D64 services bridge (requires cpu_u8_pairs):
    /// interaction 28 -> 16 (load_store_dword.layout.fused). Only the services
    /// roster has an LS-D64 role; its AND pair mass is admitted there.
    ls_dword_fused_pairs: bool = false,
    /// Omits the opt-in layout flags when false so legacy bundle.json bytes are unchanged.
    pub fn jsonStringify(self: Geometry, jws: anytype) !void {
        try jws.beginObject();
        inline for (std.meta.fields(Geometry)) |field| {
            const value = @field(self, field.name);
            const omitted = if (comptime isLayoutFlag(field.name))
                !value
            else if (comptime @typeInfo(field.type) == .optional)
                value == null and !jws.options.emit_null_optional_fields
            else
                false;
            if (!omitted) {
                try jws.objectField(field.name);
                try jws.write(value);
            }
        }
        try jws.endObject();
    }
    /// CPU log 23 selects the wide-clock CPU encoding (see layout.wideClock).
    pub fn wideClock(self: Geometry) bool {
        return front.rv64_air.word16_execution.layout.wideClock(self.cpu_log);
    }
    /// Opt-in layout flags: Boolean, default false, omitted from JSON when false.
    pub fn isLayoutFlag(comptime name: []const u8) bool {
        return std.mem.eql(u8, name, "cpu_fused_tail") or std.mem.eql(u8, name, "cpu_u8_pairs") or std.mem.eql(u8, name, "mul_u8_pairs") or std.mem.eql(u8, name, "ls_fused_pairs") or std.mem.eql(u8, name, "alu_fused_tail") or std.mem.eql(u8, name, "ls_dword_fused_pairs") or std.mem.eql(u8, name, "cpu_compact_decode");
    }
    pub fn initialLog(self: Geometry) u32 {
        return self.initial_log orelse self.boundary_log;
    }
    pub fn terminalLog(self: Geometry) u32 {
        return self.terminal_log orelse self.boundary_log;
    }
    pub fn validate(self: Geometry) !void {
        if (self.omit_empty_division and self.division_log != 5) return error.InvalidOmittedDivisionGeometry;
        // The pair encoding is defined only on top of the fused tail.
        if (self.cpu_u8_pairs and !self.cpu_fused_tail) return error.InvalidCpuPairGeometry;
        // Compact decode is defined only on top of the byte-pair encoding.
        if (self.cpu_compact_decode and !self.cpu_u8_pairs) return error.InvalidCpuCompactGeometry;
        // CPU log 23 is admitted only with the wide-clock encoding, which is
        // defined on the fused tail without byte pairs (layout.wideClock).
        if (self.cpu_log > 22 and (self.cpu_log > front.rv64_air.word16_execution.layout.MAX_LOG or !self.cpu_fused_tail or self.cpu_u8_pairs)) return error.InvalidExecutionGeometry;
        // MUL pairs are served by the pair column that only the CPU pair layout provides.
        if (self.mul_u8_pairs and !self.cpu_u8_pairs) return error.InvalidMulPairGeometry;
        if (self.ls_fused_pairs and !self.cpu_u8_pairs) return error.InvalidLsPairGeometry;
        if (self.ls_dword_fused_pairs and !self.cpu_u8_pairs) return error.InvalidLsPairGeometry;
        for ([_]u32{ @min(self.cpu_log, 22), self.alu_log, self.binary_log, self.shift_log, self.jalr_log, self.division_log, self.ls_log, self.boundary_log, self.initialLog(), self.terminalLog() }) |log| if (log < 5 or log > 22) return error.InvalidExecutionGeometry;
        if (self.multiplication_log < 5 or self.multiplication_log > A.multiplication.degree3_layout.MAX_LOG) return error.InvalidExecutionGeometry;
        for ([_]?u32{ self.ls_tail_log, self.alu_tail_log, self.binary_tail_log, self.shift_tail_log }) |optional| {
            if (optional) |log| if (log < 5 or log > 22) return error.InvalidExecutionGeometry;
        }
        _ = try B.function_bus.admitPositiveMass(&.{try self.range16Mass()});
        _ = try B.function_bus.admitPositiveMass(&.{3 * rows(self.cpu_log) + 32});
        _ = try B.function_bus.admitPositiveMass(&.{try self.range8Mass()});
        _ = try B.function_bus.admitPositiveMass(&.{rows(self.cpu_log) + 2 * rows(self.jalr_log) + (if (self.omit_empty_division) @as(u64, 0) else 2 * rows(self.division_log))});
        // AND relation: BINARY AND queries plus, in pair mode, two tagged CPU pair queries per row.
        _ = try B.function_bus.admitPositiveMass(&.{try self.andMass()});
        _ = try B.function_bus.admitPositiveMass(&.{B.shift_word_packed_experiment.equations.TABLE_QUERIES * familyRows(self.shift_log, self.shift_tail_log)});
    }
    pub const LsCounts = struct { head: u32, tail: u32 };
    /// Every present LS instance needs a trailing inactive row. Tail is used
    /// only after the head's N-1 capacity; counts are receiver-derived.
    pub fn lsCounts(self: Geometry, total: u32) !LsCounts {
        if (self.ls_log < 5 or self.ls_log > 22) return error.InvalidExecutionGeometry;
        const head: u32 = @intCast(@min(total, rows(self.ls_log) - 1));
        const tail = total - head;
        if (self.ls_tail_log) |log| {
            if (log < 5 or log > 22) return error.InvalidExecutionGeometry;
            if (tail == 0 or tail >= rows(log)) return error.InvalidLsTailCapacity;
        } else if (tail != 0) return error.InvalidLsTailCapacity;
        return .{ .head = head, .tail = tail };
    }
    pub fn lsRows(self: Geometry) u64 {
        return rows(self.ls_log) + if (self.ls_tail_log) |log| rows(log) else @as(u64, 0);
    }
    /// Counts include padding for every always-present physical provider.
    /// Future service rosters must extend this admission BEFORE allocation.
    pub fn range16Mass(self: Geometry) !u64 {
        // Wide clock: the three gap8 queries are scaled U16 queries too.
        const cpu_queries: u64 = if (self.wideClock()) 6 else 3;
        var total = try std.math.add(u64, cpu_queries * rows(self.cpu_log), B.alu_experiment.equations.RANGE_QUERIES * familyRows(self.alu_log, self.alu_tail_log));
        total = try std.math.add(u64, total, B.shift_word_packed_experiment.equations.RANGE_QUERIES * familyRows(self.shift_log, self.shift_tail_log));
        total = try std.math.add(u64, total, LS.U16.len * self.lsRows());
        // Public INIT/TEARDOWN chips own no range16 queries (receiver-anchored).
        if (!self.omit_empty_division) total = try std.math.add(u64, total, A.division.word16_product.layout.RANGE_QUERIES * rows(self.division_log));
        return total;
    }
    /// AND relation: BINARY AND queries plus, in pair mode, the tagged byte
    /// pair queries (two per CPU row, 48 per MUL row), padding included.
    pub fn andMass(self: Geometry) !u64 {
        var total = 8 * familyRows(self.binary_log, self.binary_tail_log);
        if (self.cpu_u8_pairs) total = try std.math.add(u64, total, 2 * rows(self.cpu_log));
        if (self.mul_u8_pairs) total = try std.math.add(u64, total, A.multiplication.pairs_layout.PAIR_QUERIES * rows(self.multiplication_log));
        if (self.ls_fused_pairs) total = try std.math.add(u64, total, LS.fused.PAIR_QUERIES * self.lsRows());
        return total;
    }
    pub fn range8Mass(self: Geometry) !u64 {
        // Pair mode moves the CPU's three gap8 queries (and, with mul_u8_pairs,
        // the 96 MUL BYTE queries) to the AND relation. Wide clock moves the
        // CPU's gap8 queries to range16 (scaled by WIDE_GAP_SCALE).
        const cpu: u64 = if (self.cpu_u8_pairs or self.wideClock()) 0 else 3 * rows(self.cpu_log);
        const mul: u64 = if (self.mul_u8_pairs) 0 else A.multiplication.layout.BYTE_QUERIES * rows(self.multiplication_log);
        var total = try std.math.add(u64, cpu, mul);
        if (!self.ls_fused_pairs) total = try std.math.add(u64, total, LS.U8_QUERIES * self.lsRows());
        return total;
    }
};
fn aluInteraction(geometry: Geometry) usize {
    return if (geometry.alu_fused_tail) B.alu_experiment.lookup.fused.INTERACTION else B.alu_experiment.lookup.INTERACTION;
}
pub fn rows(log: u32) u64 {
    return @as(u64, 1) << @intCast(log);
}
/// Structural roster tags, not runtime semantic/CPU policy alternatives.
pub const Role = enum { cpu, rom, boundary, alu, binary, shift, jalr, division, multiplication, shift_table, and_table, range16, range8, ls, initial, terminal, selection, ls_tail, alu_tail, binary_tail, shift_tail };
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
    return shapesForProgramLog(program.log_size, geometry);
}
/// Pure descriptor authority; no program rows, setup commitments or witnesses
/// are allocated. The receiver supplies the trusted program ROM log.
pub fn shapesForProgramLog(program_log: u32, geometry: Geometry) [ROLE_COUNT]Shape {
    var result: [ROLE_COUNT]Shape = undefined;
    var offsets: [3]usize = @splat(0);
    for (std.enums.values(Role), &result) |role, *shape| {
        const widths: [3]usize = switch (role) {
            .cpu => .{ 3, front.rv64_air.word16_execution.layout.mainCount(geometry.cpu_compact_decode), front.rv64_air.word16_execution.layout.interCountFor(geometry.cpu_fused_tail, geometry.cpu_u8_pairs) },
            .rom => .{ 32, 1, 8 },
            .boundary => .{ 34, 0, 8 },
            .alu => .{ 2, B.alu_experiment.lookup.MAIN, aluInteraction(geometry) },
            .alu_tail => if (geometry.alu_tail_log != null) .{ 2, B.alu_experiment.lookup.MAIN, aluInteraction(geometry) } else .{ 0, 0, 0 },
            .binary => .{ 2, B.binary_lookup.MAIN, B.binary_lookup.INTERACTION },
            .binary_tail => if (geometry.binary_tail_log != null) .{ 2, B.binary_lookup.MAIN, B.binary_lookup.INTERACTION } else .{ 0, 0, 0 },
            .shift => .{ 2, B.shift_word_packed_experiment.lookup.MAIN, B.shift_word_packed_experiment.lookup.INTERACTION },
            .shift_tail => if (geometry.shift_tail_log != null) .{ 2, B.shift_word_packed_experiment.lookup.MAIN, B.shift_word_packed_experiment.lookup.INTERACTION } else .{ 0, 0, 0 },
            .jalr => .{ front.rv64_air.word16_execution.jalr_equations.FIXED, front.rv64_air.word16_execution.jalr_equations.MAIN, front.rv64_air.word16_execution.jalr_equations.INTERACTION },
            .division => if (geometry.omit_empty_division) .{ 0, 0, 0 } else .{ A.division.word16_product.layout.FIXED, A.division.word16_product.layout.MAIN, A.division.word16_product.layout.INTERACTION },
            .multiplication => .{ A.multiplication.layout.FIXED, A.multiplication.layout.MAIN, if (geometry.mul_u8_pairs) A.multiplication.pairs_layout.INTERACTION else A.multiplication.degree3_layout.INTERACTION },
            .shift_table => .{ 18, 16, 36 },
            .and_table => .{ 5, if (geometry.cpu_u8_pairs) 2 else 1, 8 },
            .range16, .range8 => .{ 3, 1, 8 },
            .ls => LS.widthsFor(.ls, geometry.ls_fused_pairs),
            .ls_tail => if (geometry.ls_tail_log != null) LS.widthsFor(.ls, geometry.ls_fused_pairs) else .{ 0, 0, 0 },
            .initial => LS.widthsFor(.initial, geometry.ls_fused_pairs),
            .terminal => LS.widthsFor(.terminal, geometry.ls_fused_pairs),
            .selection => .{ 6, 2, 8 },
        };
        const log = switch (role) {
            .cpu => geometry.cpu_log,
            .rom => program_log,
            .alu => geometry.alu_log,
            .alu_tail => geometry.alu_tail_log orelse 5,
            .binary => geometry.binary_log,
            .binary_tail => geometry.binary_tail_log orelse 5,
            .shift => geometry.shift_log,
            .shift_tail => geometry.shift_tail_log orelse 5,
            .jalr => geometry.jalr_log,
            .division => geometry.division_log,
            .multiplication => geometry.multiplication_log,
            .shift_table, .and_table, .range16 => 16,
            .range8 => 8,
            .boundary => 5,
            .ls => geometry.ls_log,
            .ls_tail => geometry.ls_tail_log orelse 5,
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

pub fn familyRows(head_log: u32, tail_log: ?u32) u64 {
    return rows(head_log) + if (tail_log) |log| rows(log) else @as(u64, 0);
}
pub const FactCounts = struct { head: usize, tail: usize };
/// Producer partition of unordered true facts, NOT receiver coverage authority.
/// Pure truth providers allow all N rows active; no mandatory padding row.
pub fn factCounts(total: usize, head_log: u32, tail_log: ?u32) !FactCounts {
    if (head_log < 5 or head_log > 22) return error.InvalidExecutionGeometry;
    const head: usize = @intCast(@min(total, rows(head_log)));
    const tail = total - head;
    if (tail_log) |log| {
        if (log < 5 or log > 22) return error.InvalidExecutionGeometry;
        if (tail == 0 or tail > rows(log)) return error.InvalidProviderTailCapacity;
    } else if (tail != 0) return error.InvalidProviderTailCapacity;
    return .{ .head = head, .tail = tail };
}
