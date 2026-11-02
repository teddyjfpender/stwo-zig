//! Concrete canonical main roster for authenticated RV64 execution. This helper
//! admits geometry before allocation and never copies a wide witness matrix.
const std = @import("std");
const Auth = @import("rv64_authenticated_execution.zig");
const Core = @import("rv64_keccak_cpu.zig");
const Raw = @import("rv64_main_arena.zig");
const rv = Auth.rv;
const T = Auth.T;
const M = Auth.core.fields.m31.M31;
pub const Column = Raw.Column;
pub const Layout = struct {
    specs: [Raw.ROLE_COUNT]Raw.Spec = undefined,
    len: usize = 0,
    pub fn slice(self: *const Layout) []const Raw.Spec {
        return self.specs[0..self.len];
    }
    fn add(self: *Layout, role: Raw.Role, log: u32, width: usize) void {
        std.debug.assert(self.len < self.specs.len);
        self.specs[self.len] = .{ .role = role, .log_size = log, .width = width };
        self.len += 1;
    }
    fn validateLogs(self: *const Layout, logs: []const u32) !void {
        var at: usize = 0;
        for (self.slice()) |spec| {
            if (at > logs.len or spec.width > logs.len - at) return error.AuthenticatedMainRosterMismatch;
            for (logs[at..][0..spec.width]) |log| if (log != spec.log_size) return error.AuthenticatedMainRosterMismatch;
            at += spec.width;
        }
        if (at != logs.len) return error.AuthenticatedMainRosterMismatch;
    }
};

/// Public component rosters and immutable prepared geometry are the authority;
/// observed witness counts never select a provider or change its fixed key.
pub fn deriveCoreSpecs(setup: *const Core.PreparedMaterials, public: Core.Public) !Layout {
    try setup.validate(public);
    var result = Layout{};
    result.add(.cpu, setup.base.log_size, setup.base.plan.main_count + rv.full.frame.widthWithControl(public.execution_profile, public.control_policy));
    result.add(.rom, setup.base.program.log_size, 1);
    result.add(.bytes, 8, 1);
    if (setup.base.and_table != null) result.add(.byte_and, 16, 1);
    if (setup.base.shift_table != null) result.add(.byte_shift, 11, 1);
    if (setup.division_fixed != null) result.add(.division, setup.division_log, rv.arithmetic.division.layout.MAIN);
    if (setup.multiplication_fixed != null) result.add(.multiplication, setup.multiplication_log, rv.arithmetic.multiplication.layout.MAIN);
    if (setup.crypto != null) {
        result.add(.keccak, setup.keccak_log, rv.crypto.keccak.layout.MAIN);
        result.add(.chi, 13, 1);
        result.add(.xor5, 10, 1);
        result.add(.keccak_bridge, setup.bridge_log, rv.crypto.keccak.bridge.layout.MAIN);
    }
    const roles = [2][3]Raw.Role{ .{ .secp_add_product, .secp_add_linear, .secp_add_bridge }, .{ .secp_double_product, .secp_double_linear, .secp_double_bridge } };
    for (public.secp.groups(), roles) |group, group_roles| if (group.roster == .present) {
        result.add(group_roles[0], group.geometry.product_log, rv.crypto.secp256k1.layout.main(.product));
        result.add(group_roles[1], group.geometry.linear_log, rv.crypto.secp256k1.layout.main(.linear));
        result.add(group_roles[2], group.geometry.bridge_log, rv.crypto.secp256k1.bridge.layout.MAIN);
    };
    return result;
}
pub fn deriveSpecs(setup: *const Auth.Prepared, public: Auth.Public) !Layout {
    try setup.validate(public);
    return deriveSpecsForLayout(setup, public.layout());
}
pub fn deriveSpecsForLayout(setup: *const Auth.Prepared, public: Auth.Layout) !Layout {
    try setup.validateLayout(public);
    var result = try deriveCoreSpecs(&setup.cpu, public.cpu);
    if (public.ram) |counts| {
        const shape = try counts.shapes(public.geometry);
        for (T.TABLES, RAM_ROLES) |table, role| result.add(role, T.tableLog(shape, table), T.mainWidth(table));
        result.add(.ram_poseidon, shape.provider_log, 303);
        result.add(.ram_policy, setup.ram.?.policy.shape.log_size, 1);
    }
    return result;
}
const RAM_ROLES = [8]Raw.Role{ .ram_chunk, .ram_common_cells, .ram_edge_cells, .ram_leaf, .ram_node, .ram_side, .ram_common_permits, .ram_edge_permits };
fn narrow(role: Raw.Role) bool {
    return switch (role) {
        .rom, .bytes, .byte_and, .byte_shift, .ram_policy => true,
        else => false,
    };
}
pub const MainArena = struct {
    arena: Raw.Arena,
    layout: Layout,
    pub fn init(a: std.mem.Allocator, setup: *const Auth.Prepared, public: Auth.Public) !MainArena {
        try setup.validate(public);
        return initForLayout(a, setup, public.layout());
    }
    pub fn initForLayout(a: std.mem.Allocator, setup: *const Auth.Prepared, public: Auth.Layout) !MainArena {
        const layout = try deriveSpecsForLayout(setup, public);
        const logs = try setup.logsForLayout(a, public, 1);
        defer a.free(logs);
        try layout.validateLogs(logs);
        return .{ .arena = try Raw.Arena.init(a, layout.slice()), .layout = layout };
    }
    pub fn initCore(a: std.mem.Allocator, setup: *const Core.PreparedMaterials, public: Core.Public) !MainArena {
        const layout = try deriveCoreSpecs(setup, public);
        const logs = try setup.logs(a, public, 1);
        defer a.free(logs);
        try layout.validateLogs(logs);
        return .{ .arena = try Raw.Arena.init(a, layout.slice()), .layout = layout };
    }
    pub fn deinit(self: *MainArena) void {
        self.arena.deinit();
    }
    fn values(self: *MainArena, role: Raw.Role) ![]M {
        return (try self.arena.matrix(role)).values;
    }
    fn optional(self: *MainArena, role: Raw.Role) !?[]M {
        if (self.arena.spans[@intFromEnum(role)] == null) return null;
        return try self.values(role);
    }
    pub fn cpuMain(self: *MainArena) ![]M {
        return self.values(.cpu);
    }
    pub fn coreBuffers(self: *MainArena) !Core.BorrowedMain {
        var result = Core.BorrowedMain{};
        result.arithmetic = .{ .division = try self.optional(.division), .multiplication = try self.optional(.multiplication) };
        if (self.arena.spans[@intFromEnum(Raw.Role.keccak)] != null) result.keccak = .{ .permutation = try self.values(.keccak), .chi = try self.values(.chi), .xor5 = try self.values(.xor5), .bridge = try self.values(.keccak_bridge) };
        const roles = [2][3]Raw.Role{ .{ .secp_add_product, .secp_add_linear, .secp_add_bridge }, .{ .secp_double_product, .secp_double_linear, .secp_double_bridge } };
        for (roles, 0..) |group, i| if (self.arena.spans[@intFromEnum(group[0])] != null) {
            result.secp[i] = .{ .product = try self.values(group[0]), .linear = try self.values(group[1]), .bridge = try self.values(group[2]) };
        };
        return result;
    }
    pub fn ramBuffers(self: *MainArena) !T.MainBuffers {
        var callers: [8][]M = undefined;
        for (RAM_ROLES, 0..) |role, i| callers[i] = try self.values(role);
        return .{ .callers = callers, .provider = try self.values(.ram_poseidon), .policy_tail = try self.values(.ram_policy), .byte_tail = try self.values(.bytes) };
    }
    /// Validate ALL headers before writing or publishing any role. Only narrow
    /// multiplicity vectors may arrive from separate owners. Every wide column
    /// must already be the exact admitted arena slice; no fallback copy exists.
    pub fn sealFromColumns(self: *MainArena, actual: []const Column) !void {
        if (self.arena.phase != .building or self.arena.remaining != self.layout.len or actual.len != self.arena.column_count) return error.InvalidMainPhase;
        var at: usize = 0;
        for (self.layout.slice()) |spec| {
            const matrix = try self.arena.matrix(spec.role);
            const n = @as(usize, 1) << @intCast(spec.log_size);
            for (0..spec.width) |col| {
                const header = actual[at + col];
                const expected = matrix.values[col * n ..][0..n];
                if (header.log_size != spec.log_size or header.values.len != n) return error.AuthenticatedMainHeaderMismatch;
                if (!narrow(spec.role) and header.values.ptr != expected.ptr) return error.AuthenticatedWideMainCopyForbidden;
                if (narrow(spec.role) and header.values.ptr != expected.ptr) {
                    const source_start = @intFromPtr(header.values.ptr);
                    const source_end = try std.math.add(usize, source_start, try std.math.mul(usize, n, @sizeOf(M)));
                    const raw_start = @intFromPtr(self.arena.raw.ptr);
                    const raw_end = raw_start + self.arena.raw.len * @sizeOf(M);
                    if (source_start < raw_end and raw_start < source_end) return error.AliasedMainMultiplicitySource;
                }
            }
            at += spec.width;
        }
        at = 0;
        for (self.layout.slice()) |spec| {
            if (narrow(spec.role)) {
                const matrix = try self.arena.matrix(spec.role);
                const n = @as(usize, 1) << @intCast(spec.log_size);
                for (0..spec.width) |col| {
                    const target = matrix.values[col * n ..][0..n];
                    if (target.ptr != actual[at + col].values.ptr) @memcpy(target, actual[at + col].values);
                }
            }
            at += spec.width;
        }
        for (self.layout.slice()) |spec| self.arena.markInitialized(spec.role) catch unreachable;
    }
    pub fn takeForCommit(self: *MainArena, a: std.mem.Allocator) !Raw.Commit {
        return self.arena.takeForCommit(a);
    }
};
