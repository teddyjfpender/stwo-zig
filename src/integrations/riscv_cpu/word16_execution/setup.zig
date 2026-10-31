//! Rootless immutable program/geometry materials. The complete joined roster
//! owns ONE final fixed commitment; constructing materials commits no tree.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const air = @import("stwo_riscv_frontend").rv64_air;
const W = air.word16_cpu;
const B = air.word16_v1;
const Full = @import("../rv64_full.zig");
pub const Program = @import("program.zig").Program;
pub const G = @import("geometry.zig");
pub const Geometry = G.Geometry;
pub const Role = G.Role;
pub const Shape = G.Shape;
const M = core.fields.m31.M31;
const Column = engine.pcs.ColumnEvaluation;
pub const Materials = struct {
    allocator: std.mem.Allocator,
    geometry: Geometry,
    program: Program,
    cpu_fixed: []M,
    boundary_fixed: []M,
    alu_fixed: []M,
    binary_fixed: []M,
    shift_fixed: []M,
    jalr_fixed: []M,
    division_fixed: []M,
    multiplication_fixed: []M,
    range16_fixed: []M,
    range8_fixed: []M,
    ls_fixed: []M,
    ls_tail_fixed: []M,
    memory_boundary_fixed: []M,
    memory_terminal_fixed: ?[]M = null,
    selection_fixed: []M,
    shift_table: B.shift_word_packed_experiment.table.Setup,
    and_table: air.providers.tables.Setup,
    pub fn init(a: std.mem.Allocator, expected: air.program.setup.Program, geometry: Geometry) !Materials {
        try geometry.validate();
        var program = try Program.init(a, expected);
        errdefer program.deinit();
        return fromProgram(a, program, geometry);
    }
    pub fn initWithAuthority(a: std.mem.Allocator, authority: *const Full.ProgramAuthority, geometry: Geometry) !Materials {
        try geometry.validate();
        var program = try Program.initWithAuthority(a, authority);
        errdefer program.deinit();
        return fromProgram(a, program, geometry);
    }
    fn fromProgram(a: std.mem.Allocator, program: Program, geometry: Geometry) !Materials {
        const cpu = try W.fixed.cpu(a, geometry.cpu_log);
        errdefer a.free(cpu);
        const boundary = try W.fixed.boundary(a);
        errdefer a.free(boundary);
        const alu = try B.alu_experiment.source.fixedForLog(a, geometry.alu_log);
        errdefer a.free(alu);
        const binary = try B.binary_source.fixedForLog(a, geometry.binary_log);
        errdefer a.free(binary);
        const shift = try B.shift_word_packed_experiment.source.fixedForLog(a, geometry.shift_log);
        errdefer a.free(shift);
        const jalr = try B.binary_source.fixedForLog(a, geometry.jalr_log);
        errdefer a.free(jalr);
        const division: []M = if (geometry.omit_empty_division) &.{} else try air.arithmetic.division.trace.fixedColumns(a, 0, geometry.division_log);
        errdefer a.free(division);
        const multiplication = try air.arithmetic.multiplication.trace.fixedColumnsForLog(a, geometry.multiplication_log);
        errdefer a.free(multiplication);
        const range16 = try W.fixed.range(a, 16);
        errdefer a.free(range16);
        const range8 = try W.fixed.range(a, 8);
        errdefer a.free(range8);
        const ls = try air.memory.load_store_v2.source.fixed(a, geometry.ls_log);
        errdefer a.free(ls);
        const ls_tail = if (geometry.ls_tail_log) |log| try air.memory.load_store_v2.source.fixed(a, log) else try a.alloc(M, 0);
        errdefer a.free(ls_tail);
        const memory_boundary = try air.memory.load_store_v2.source.fixed(a, geometry.initialLog());
        errdefer a.free(memory_boundary);
        const memory_terminal = if (geometry.initialLog() != geometry.terminalLog()) try air.memory.load_store_v2.source.fixed(a, geometry.terminalLog()) else null;
        errdefer if (memory_terminal) |data| a.free(data);
        const selection = try selectionFixed(a);
        errdefer a.free(selection);
        var shifts = try B.shift_word_packed_experiment.table.Setup.init(a);
        errdefer shifts.deinit();
        var and_ = try air.providers.tables.Setup.init(a, .byte_and);
        errdefer and_.deinit();
        return .{ .allocator = a, .geometry = geometry, .program = program, .cpu_fixed = cpu, .boundary_fixed = boundary, .alu_fixed = alu, .binary_fixed = binary, .shift_fixed = shift, .jalr_fixed = jalr, .division_fixed = division, .multiplication_fixed = multiplication, .range16_fixed = range16, .range8_fixed = range8, .ls_fixed = ls, .ls_tail_fixed = ls_tail, .memory_boundary_fixed = memory_boundary, .memory_terminal_fixed = memory_terminal, .selection_fixed = selection, .shift_table = shifts, .and_table = and_ };
    }
    pub fn deinit(self: *Materials) void {
        if (self.memory_terminal_fixed) |data| self.allocator.free(data);
        self.and_table.deinit();
        self.shift_table.deinit();
        for ([_][]M{ self.cpu_fixed, self.boundary_fixed, self.alu_fixed, self.binary_fixed, self.shift_fixed, self.jalr_fixed, self.division_fixed, self.multiplication_fixed, self.range16_fixed, self.range8_fixed, self.ls_fixed, self.ls_tail_fixed, self.memory_boundary_fixed, self.selection_fixed }) |fixed| self.allocator.free(fixed);
        self.program.deinit();
        self.* = undefined;
    }
    pub fn shapes(self: *const Materials) [G.ROLE_COUNT]Shape {
        return G.shapes(&self.program, self.geometry);
    }
    pub fn shape(self: *const Materials, role: Role) Shape {
        return self.shapes()[@intFromEnum(role)];
    }
    pub fn logs(self: *const Materials, a: std.mem.Allocator, tree: usize) ![]u32 {
        if (tree > 2) return error.InvalidExecutionTree;
        const actual = self.shapes();
        var count: usize = 0;
        for (actual) |s| count += s.widths[tree];
        const out = try a.alloc(u32, count);
        for (actual) |s| @memset(out[s.offsets[tree]..][0..s.widths[tree]], s.log);
        return out;
    }
    pub fn fixedColumns(self: *const Materials, a: std.mem.Allocator) ![]Column {
        const actual = self.shapes();
        var count: usize = 0;
        for (actual) |s| count += s.widths[0];
        const out = try a.alloc(Column, count);
        errdefer a.free(out);
        for (actual) |s| {
            if (s.widths[0] == 0) continue;
            const data: []const M = switch (s.role) {
                .cpu => self.cpu_fixed,
                .rom => self.program.fixed,
                .boundary => self.boundary_fixed,
                .alu => self.alu_fixed,
                .binary => self.binary_fixed,
                .shift => self.shift_fixed,
                .jalr => self.jalr_fixed,
                .division => self.division_fixed,
                .multiplication => self.multiplication_fixed,
                .shift_table => self.shift_table.fixed,
                .and_table => self.and_table.fixed,
                .range16 => self.range16_fixed,
                .range8 => self.range8_fixed,
                .ls => self.ls_fixed,
                .ls_tail => self.ls_tail_fixed,
                .initial => self.memory_boundary_fixed,
                .terminal => self.memory_terminal_fixed orelse self.memory_boundary_fixed,
                .selection => self.selection_fixed,
            };
            try @import("../word16/cpu_materials.zig").fillColumns(out[s.offsets[0]..][0..s.widths[0]], data, s.log);
        }
        return out;
    }
};

fn selectionFixed(a: std.mem.Allocator) ![]M {
    const n = 1 << 16;
    const out = try a.alloc(M, 6 * n);
    @memset(out, M.zero());
    for (0..n) |i| {
        const pos = air.memory.closed_ram.trace.physical(i, 16);
        for (air.memory.load_store_v1.selection.fixedFact(i), 0..) |v, c| out[c * n + pos] = M.fromCanonical(v);
    }
    out[4 * n + air.memory.closed_ram.trace.physical(0, 16)] = M.one();
    out[5 * n + air.memory.closed_ram.trace.physical(n - 1, 16)] = M.one();
    return out;
}

pub const T = @import("../rv64_distributed_v1/manifest.zig").T;
/// Complete immutable physical-roster fixed-key owner. Request counts, RAM
/// boundary contents, register endpoints and epoch never enter these columns.
pub const Setup = struct {
    materials: Materials,
    fixed_root: T.CommitmentRoot,
    fixed_tree: T.Scheme.CommittedTree,
    pub fn init(a: std.mem.Allocator, program: air.program.setup.Program, geometry: Geometry) !Setup {
        var materials = try Materials.init(a, program, geometry);
        errdefer materials.deinit();
        return seal(a, materials);
    }
    /// Consumes the already decoded program on success AND failure.
    pub fn initOwnedProgram(a: std.mem.Allocator, program: Program, geometry: Geometry) !Setup {
        geometry.validate() catch |err| {
            var owned = program;
            owned.deinit();
            return err;
        };
        var materials = Materials.fromProgram(a, program, geometry) catch |err| {
            var owned = program;
            owned.deinit();
            return err;
        };
        errdefer materials.deinit();
        return seal(a, materials);
    }
    pub fn initWithAuthority(a: std.mem.Allocator, authority: *const Full.ProgramAuthority, geometry: Geometry) !Setup {
        var materials = try Materials.initWithAuthority(a, authority, geometry);
        errdefer materials.deinit();
        return seal(a, materials);
    }
    fn seal(a: std.mem.Allocator, materials: Materials) !Setup {
        const columns = try materials.fixedColumns(a);
        defer a.free(columns);
        var scheme = try T.Scheme.init(a, T.P.config());
        defer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(5);
        var channel = T.P.Channel{};
        try scheme.commitBorrowedStreaming(a, columns, 8, &channel);
        var roots = try scheme.roots(a);
        defer roots.deinit(a);
        try scheme.trees.items[0].share(a);
        return .{ .materials = materials, .fixed_root = .{ .value = roots.items[0] }, .fixed_tree = scheme.trees.pop().? };
    }
    /// A separate request transcript receives a retained immutable tree lease.
    /// The setup allocator must outlive all leases; no request channel is cached.
    pub fn appendFixed(self: *const Setup, a: std.mem.Allocator, scheme: *T.Scheme, channel: *T.P.Channel) !void {
        if (scheme.trees.items.len != 0 or scheme.pending_commit != null or !std.meta.eql(scheme.config, T.P.config())) return error.InvalidExecutionFixedPhase;
        var lease = self.fixed_tree.retainShared();
        errdefer lease.deinit(self.materials.allocator);
        try scheme.appendCommittedTree(a, lease, channel);
    }
    pub fn deinit(self: *Setup) void {
        self.fixed_tree.deinit(self.materials.allocator);
        self.materials.deinit();
        self.* = undefined;
    }
};
