//! Immutable program/geometry materials for the concrete three-opcode CPU.
//! Public steps/PCs/registers/clocks never enter these fixed polynomials.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const air = @import("stwo_riscv_frontend").rv64_air;
const W = air.word16_cpu;
const Profile = W.profile;
const Binary = air.word16_v1;
const Tables = air.providers.tables;
const D = @import("../rv64_distributed_v1/manifest.zig");
pub const T = D.T;
const M = core.fields.m31.M31;
const Column = engine.pcs.ColumnEvaluation;
pub const Mode = enum(u32) { local_binary = 1, open_function = 2 };
pub const Geometry = struct {
    cpu_log: u32,
    binary_log: u32 = 5,
    mode: Mode = .local_binary,
    profile: Profile.Profile = .binary_v1,
    alu_log: u32 = 5,
    pub fn validate(self: Geometry) !void {
        if (self.cpu_log < 5 or self.cpu_log > 22 or self.binary_log < 5 or self.binary_log > 22 or (self.mode == .open_function and self.binary_log != 5)) return error.InvalidThinCpuGeometry;
        if (self.alu_log < 5 or self.alu_log > 22 or (self.profile == .binary_v1 and self.alu_log != 5) or (self.profile == .alu_binary_v2 and self.mode == .open_function)) return error.UnsupportedThinCpuProfile;
        const range_mass = 3 * (@as(u64, 1) << @intCast(self.cpu_log)) + (if (self.profile == .alu_binary_v2) 20 * (@as(u64, 1) << @intCast(self.alu_log)) else 0);
        _ = try Binary.function_bus.admitPositiveMass(&.{range_mass});
        _ = try Binary.function_bus.admitPositiveMass(&.{@as(u64, 1) << @intCast(self.cpu_log)});
        _ = try Binary.function_bus.admitPositiveMass(&.{3 * (@as(u64, 1) << @intCast(self.cpu_log)) + 32});
        if (self.mode == .local_binary) _ = try Binary.binary_source.massForLog(self.binary_log);
    }
};
pub const Role = enum { cpu, rom, boundary, alu, binary, and_table, range16, range8 };
pub const Shape = struct { role: Role, log: u32, widths: [3]usize, offsets: [3]usize };
pub const Shapes = struct {
    values: [8]Shape = undefined,
    len: usize = 0,
    pub fn slice(self: *const Shapes) []const Shape {
        return self.values[0..self.len];
    }
};
pub const Materials = struct {
    allocator: std.mem.Allocator,
    geometry: Geometry,
    program: W.rom.Setup,
    cpu_fixed: []M,
    boundary_fixed: []M,
    range16_fixed: []M,
    range8_fixed: []M,
    binary_fixed: []M,
    alu_fixed: []M,
    and_table: ?Tables.Setup,
    main_logs: []u32,
    fixed_root: T.CommitmentRoot,
    // Independent immutable fixed commitment; every request gets a lease and
    // a fresh transcript, rather than rebuilding these coefficients/tree.
    fixed_tree: T.Scheme.CommittedTree,
    pub fn initOpen(a: std.mem.Allocator, program: air.program.setup.Program, cpu_log: u32) !Materials {
        return init(a, program, .{ .cpu_log = cpu_log, .mode = .open_function });
    }
    pub fn init(a: std.mem.Allocator, expected: air.program.setup.Program, geometry: Geometry) !Materials {
        try geometry.validate();
        var program = try W.rom.Setup.initWithProfile(a, expected, geometry.profile);
        errdefer program.deinit();
        const cpu_fixed = try W.fixed.cpu(a, geometry.cpu_log);
        errdefer a.free(cpu_fixed);
        const boundary_fixed = try W.fixed.boundary(a);
        errdefer a.free(boundary_fixed);
        const range16_fixed = try W.fixed.range(a, 16);
        errdefer a.free(range16_fixed);
        const range8_fixed = try W.fixed.range(a, 8);
        errdefer a.free(range8_fixed);
        const binary_fixed = if (geometry.mode == .local_binary) try Binary.binary_source.fixedForLog(a, geometry.binary_log) else try a.alloc(M, 0);
        errdefer a.free(binary_fixed);
        const alu_fixed = if (geometry.profile == .alu_binary_v2) try Binary.binary_source.fixedForLog(a, geometry.alu_log) else try a.alloc(M, 0);
        errdefer a.free(alu_fixed);
        var and_table: ?Tables.Setup = if (geometry.mode == .local_binary) try Tables.Setup.init(a, .byte_and) else null;
        errdefer if (and_table) |*table| table.deinit();
        var result = Materials{ .allocator = a, .geometry = geometry, .program = program, .cpu_fixed = cpu_fixed, .boundary_fixed = boundary_fixed, .range16_fixed = range16_fixed, .range8_fixed = range8_fixed, .binary_fixed = binary_fixed, .alu_fixed = alu_fixed, .and_table = and_table, .main_logs = &.{}, .fixed_root = undefined, .fixed_tree = undefined };
        result.main_logs = try result.logs(a, 1);
        errdefer a.free(result.main_logs);
        const columns = try result.fixedColumns(a);
        defer a.free(columns);
        var scheme = try T.Scheme.init(a, T.P.config());
        defer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(5);
        var channel = T.P.Channel{};
        try scheme.commitBorrowedStreaming(a, columns, 8, &channel);
        var roots = try scheme.roots(a);
        defer roots.deinit(a);
        result.fixed_root = .{ .value = roots.items[0] };
        try scheme.trees.items[0].share(a);
        result.fixed_tree = scheme.trees.pop().?; // move owner out before scheme teardown
        return result;
    }
    pub fn deinit(self: *Materials) void {
        self.fixed_tree.deinit(self.allocator);
        self.program.deinit();
        self.allocator.free(self.cpu_fixed);
        self.allocator.free(self.boundary_fixed);
        self.allocator.free(self.range16_fixed);
        self.allocator.free(self.range8_fixed);
        self.allocator.free(self.binary_fixed);
        self.allocator.free(self.alu_fixed);
        self.allocator.free(self.main_logs);
        if (self.and_table) |*table| table.deinit();
        self.* = undefined;
    }
    /// Transfer one immutable lease on success; failure releases only that lease.
    /// The owner allocator must outlive all request leases. No channel is cached.
    pub fn appendFixed(self: *const Materials, a: std.mem.Allocator, scheme: *T.Scheme, channel: *T.P.Channel) !void {
        if (scheme.trees.items.len != 0 or scheme.pending_commit != null or !std.meta.eql(scheme.config, T.P.config())) return error.InvalidThinCpuFixedPhase;
        var lease = self.fixed_tree.retainShared();
        errdefer lease.deinit(self.allocator);
        try scheme.appendCommittedTree(a, lease, channel);
    }
    pub fn shapes(self: *const Materials) Shapes {
        var result = Shapes{};
        var offsets: [3]usize = @splat(0);
        const roles = [_]Role{ .cpu, .rom, .boundary, .alu, .binary, .and_table, .range16, .range8 };
        for (roles) |role| {
            if (role == .alu and self.geometry.profile != .alu_binary_v2) continue;
            if (self.geometry.mode == .open_function and (role == .binary or role == .and_table)) continue;
            const widths: [3]usize = switch (role) {
                .cpu => .{ 3, Profile.mainCount(self.geometry.profile), 56 },
                .rom => .{ self.program.fixedCount(), 1, 8 },
                .boundary => .{ 34, 0, 8 },
                .alu => .{ 2, Binary.alu_experiment.lookup.MAIN, Binary.alu_experiment.lookup.INTERACTION },
                .binary => .{ 2, 42, 28 },
                .and_table => .{ 5, 1, 8 },
                .range16, .range8 => .{ 3, 1, 8 },
            };
            const log = switch (role) {
                .cpu => self.geometry.cpu_log,
                .rom => self.program.log_size,
                .boundary => 5,
                .binary => self.geometry.binary_log,
                .alu => self.geometry.alu_log,
                .and_table, .range16 => 16,
                .range8 => 8,
            };
            result.values[result.len] = .{ .role = role, .log = log, .widths = widths, .offsets = offsets };
            result.len += 1;
            for (&offsets, widths) |*offset, width| offset.* += width;
        }
        return result;
    }
    pub fn shape(self: *const Materials, role: Role) !Shape {
        const all = self.shapes();
        for (all.slice()) |value| if (value.role == role) return value;
        return error.OmittedThinCpuRole;
    }
    pub fn logs(self: *const Materials, a: std.mem.Allocator, tree: usize) ![]u32 {
        if (tree > 2) return error.InvalidThinCpuTree;
        const all = self.shapes();
        var count: usize = 0;
        for (all.slice()) |value| count += value.widths[tree];
        const result = try a.alloc(u32, count);
        for (all.slice()) |value| @memset(result[value.offsets[tree]..][0..value.widths[tree]], value.log);
        return result;
    }
    pub fn fixedColumns(self: *const Materials, a: std.mem.Allocator) ![]Column {
        const all = self.shapes();
        var count: usize = 0;
        for (all.slice()) |value| count += value.widths[0];
        const columns = try a.alloc(Column, count);
        errdefer a.free(columns);
        for (all.slice()) |value| {
            const data: []const M = switch (value.role) {
                .cpu => self.cpu_fixed,
                .rom => self.program.fixed,
                .boundary => self.boundary_fixed,
                .binary => self.binary_fixed,
                .alu => self.alu_fixed,
                .and_table => self.and_table.?.fixed,
                .range16 => self.range16_fixed,
                .range8 => self.range8_fixed,
            };
            try fillColumns(columns[value.offsets[0]..][0..value.widths[0]], data, value.log);
        }
        return columns;
    }
    pub fn descriptor(self: *const Materials, ordinal: u32, first_step: u64, public: W.public.Public, job: T.Digest) !T.Spec {
        if (self.geometry.mode != .open_function) return error.ExpectedOpenThinCpuMaterials;
        try public.validate(self.geometry.cpu_log);
        _ = std.math.add(u64, first_step, public.steps) catch return error.InvalidThinCpuSpan;
        return .{ .ordinal = ordinal, .role = .cpu, .schema = schemaForProfile(self.geometry.profile), .job_witness = job, .public_statement = try W.public.digest(public, self.geometry.cpu_log), .instance_epoch = @as(u64, ordinal) + 1, .first_request = first_step, .request_count = public.steps, .expected_fixed = self.fixed_root, .column_logs = self.main_logs };
    }
};
pub fn schema() T.Digest {
    return schemaForProfile(.binary_v1);
}
pub fn schemaForProfile(profile: Profile.Profile) T.Digest {
    var result: T.Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(if (profile == .binary_v1) "rv64.word16.thin-binary-register-cpu.v1.main44.inter56.ROM16.REG6.FUNCTION13.clocks24-reset0.D3" else "rv64.word16.thin-alu-binary-cpu.v2.main46.inter56.ROM23-edge.REG6.FUNCTION13-unified.ALU60-52.clocks24-reset0.D3", &result, .{});
    return result;
}
pub fn validateSpec(materials: *const Materials, public: W.public.Public, spec: T.Spec) !void {
    const expected = try materials.descriptor(spec.ordinal, spec.first_request, public, spec.job_witness);
    if (!std.mem.eql(u8, &T.specDigest(spec), &T.specDigest(expected))) return error.InvalidThinCpuDescriptor;
}
pub fn fillColumns(columns: []Column, data: []const M, log: u32) !void {
    const n = @as(usize, 1) << @intCast(log);
    if (data.len != columns.len * n) return error.InvalidThinCpuColumnShape;
    for (columns, 0..) |*column, i| column.* = .{ .log_size = log, .values = data[i * n ..][0..n] };
}
