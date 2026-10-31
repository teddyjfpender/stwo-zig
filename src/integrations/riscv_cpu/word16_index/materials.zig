//! Independently derived index authority, geometry and reusable fixed lease.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const air = @import("stwo_riscv_frontend").rv64_air;
const I = air.word16_index_control;
const W = air.word16_cpu;
const B = air.word16_v1;
const T = @import("../rv64_distributed_v1/manifest.zig").T;
const Column = engine.pcs.ColumnEvaluation;
const M = core.fields.m31.M31;
pub const Pair = struct { id: u64, pc: u64 };
pub const Geometry = struct {
    cpu_log: u32,
    alu_log: u32 = 5,
    binary_log: u32 = 5,
    pub fn validate(self: Geometry) !void {
        for ([_]u32{ self.cpu_log, self.alu_log, self.binary_log }) |log| if (log < 5 or log > 22) return error.InvalidIndexGeometry;
        _ = try B.function_bus.admitPositiveMass(&.{3 * (@as(u64, 1) << @intCast(self.cpu_log)) + 20 * (@as(u64, 1) << @intCast(self.alu_log))});
        _ = try B.binary_source.massForLog(self.binary_log);
    }
};
pub const Role = enum { cpu, rom, boundary, alu, binary, and_table, range16, range8, map_queries };
pub const Shape = struct { role: Role, log: u32, widths: [3]usize, offsets: [3]usize };
pub const Materials = struct {
    allocator: std.mem.Allocator,
    geometry: Geometry,
    authority: I.authority.Authority,
    cpu_fixed: []M,
    boundary_fixed: []M,
    alu_fixed: []M,
    binary_fixed: []M,
    range16_fixed: []M,
    range8_fixed: []M,
    map_fixed: []M,
    and_table: air.providers.tables.Setup,
    fixed_tree: T.Scheme.CommittedTree,
    fixed_root: T.CommitmentRoot,
    pub fn init(a: std.mem.Allocator, program: air.program.setup.Program, g: Geometry) !Materials {
        try g.validate();
        var authority = try I.authority.Authority.init(a, program);
        errdefer authority.deinit();
        const cpu_fixed = try W.fixed.cpu(a, g.cpu_log);
        errdefer a.free(cpu_fixed);
        const boundary_fixed = try W.fixed.boundary(a);
        errdefer a.free(boundary_fixed);
        const alu_fixed = try B.alu_experiment.source.fixedForLog(a, g.alu_log);
        errdefer a.free(alu_fixed);
        const binary_fixed = try B.binary_source.fixedForLog(a, g.binary_log);
        errdefer a.free(binary_fixed);
        const range16_fixed = try W.fixed.range(a, 16);
        errdefer a.free(range16_fixed);
        const range8_fixed = try W.fixed.range(a, 8);
        errdefer a.free(range8_fixed);
        const map_fixed = try B.binary_component.expectedMainFixed(a);
        errdefer a.free(map_fixed);
        var and_table = try air.providers.tables.Setup.init(a, .byte_and);
        errdefer and_table.deinit();
        var result = Materials{ .allocator = a, .geometry = g, .authority = authority, .cpu_fixed = cpu_fixed, .boundary_fixed = boundary_fixed, .alu_fixed = alu_fixed, .binary_fixed = binary_fixed, .range16_fixed = range16_fixed, .range8_fixed = range8_fixed, .map_fixed = map_fixed, .and_table = and_table, .fixed_tree = undefined, .fixed_root = undefined };
        const columns = try result.fixedColumns(a);
        defer a.free(columns);
        var scheme = try T.Scheme.init(a, T.P.config());
        defer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(5);
        var channel = T.P.Channel{};
        try scheme.commitBorrowedStreaming(a, columns, 8, &channel);
        result.fixed_root = .{ .value = scheme.trees.items[0].root() };
        try scheme.trees.items[0].share(a);
        result.fixed_tree = scheme.trees.pop().?;
        return result;
    }
    pub fn deinit(self: *Materials) void {
        self.fixed_tree.deinit(self.allocator);
        self.and_table.deinit();
        self.authority.deinit();
        for ([_][]M{ self.cpu_fixed, self.boundary_fixed, self.alu_fixed, self.binary_fixed, self.range16_fixed, self.range8_fixed, self.map_fixed }) |data| self.allocator.free(data);
        self.* = undefined;
    }
    pub fn shapes(self: *const Materials) [9]Shape {
        var result: [9]Shape = undefined;
        var offsets: [3]usize = @splat(0);
        for (std.enums.values(Role), &result) |role, *s| {
            const widths: [3]usize = switch (role) {
                .cpu => .{ 3, 40, 56 },
                .rom => .{ 23, 2, 16 },
                .boundary => .{ 34, 0, 8 },
                .alu => .{ 2, B.alu_experiment.lookup.MAIN, B.alu_experiment.lookup.INTERACTION },
                .binary => .{ 2, 42, 28 },
                .and_table => .{ 5, 1, 8 },
                .range16, .range8 => .{ 3, 1, 8 },
                .map_queries => .{ 34, 14, 8 },
            };
            const log: u32 = switch (role) {
                .cpu => self.geometry.cpu_log,
                .rom => self.authority.log_size,
                .alu => self.geometry.alu_log,
                .binary => self.geometry.binary_log,
                .and_table, .range16 => 16,
                .range8 => 8,
                .boundary, .map_queries => 5,
            };
            s.* = .{ .role = role, .log = log, .widths = widths, .offsets = offsets };
            for (&offsets, widths) |*o, width| o.* += width;
        }
        return result;
    }
    pub fn shape(self: *const Materials, role: Role) Shape {
        return self.shapes()[@intFromEnum(role)];
    }
    pub fn logs(self: *const Materials, a: std.mem.Allocator, tree: usize) ![]u32 {
        if (tree > 2) return error.InvalidIndexTree;
        const shapes_ = self.shapes();
        var count: usize = 0;
        for (shapes_) |s| count += s.widths[tree];
        const logs_ = try a.alloc(u32, count);
        for (shapes_) |s| @memset(logs_[s.offsets[tree]..][0..s.widths[tree]], s.log);
        return logs_;
    }
    pub fn fixedColumns(self: *const Materials, a: std.mem.Allocator) ![]Column {
        const shapes_ = self.shapes();
        var count: usize = 0;
        for (shapes_) |s| count += s.widths[0];
        const out = try a.alloc(Column, count);
        errdefer a.free(out);
        for (shapes_) |s| {
            const data: []const M = switch (s.role) {
                .cpu => self.cpu_fixed,
                .rom => self.authority.fixed,
                .boundary => self.boundary_fixed,
                .alu => self.alu_fixed,
                .binary => self.binary_fixed,
                .and_table => self.and_table.fixed,
                .range16 => self.range16_fixed,
                .range8 => self.range8_fixed,
                .map_queries => self.map_fixed,
            };
            try @import("../word16/cpu_materials.zig").fillColumns(out[s.offsets[0]..][0..s.widths[0]], data, s.log);
        }
        return out;
    }
    pub fn appendFixed(self: *const Materials, a: std.mem.Allocator, scheme: *T.Scheme, channel: *T.P.Channel) !void {
        if (scheme.trees.items.len != 0 or scheme.pending_commit != null) return error.InvalidIndexFixedPhase;
        var lease = self.fixed_tree.retainShared();
        errdefer lease.deinit(self.allocator);
        try scheme.appendCommittedTree(a, lease, channel);
    }
    pub fn validatePublic(self: *const Materials, state: W.public.Public, pairs: []const Pair) !I.equations.Public {
        if (pairs.len > 32) return error.IndexAddressQueryLimit;
        for (pairs) |pair| try self.authority.validatePair(pair.id, pair.pc);
        return I.equations.resolve(&self.authority, state, self.geometry.cpu_log);
    }
};
