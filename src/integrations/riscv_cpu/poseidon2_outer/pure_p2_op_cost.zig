//! Witness-free OP capture accounting. Source-derived rows/widths are diagnostic;
//! actual allocation admission stays with SharedHostBudget and bound parking.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const G = @import("../word16_execution/geometry.zig");
const P = @import("../word16_global_execution/services/protocol.zig");
const T = @import("../word16_global_execution/services/types.zig");
const Wire = @import("../word16_global_execution/services/wire.zig");
const Frame = @import("../word16_global_execution/services/gkr_local/frame.zig");
const Meta = @import("../word16_global_execution/services/gkr_local/shape_metadata.zig");
const Bounds = @import("../word16_global_execution/services/gkr_local/source_bounds.zig");
const Advice = @import("../word16_global_execution/services/collector.zig").Advice;
const Native = @import("../word16_execution/prepared.zig").Prepared;
const Program = @import("../word16_execution/program.zig").Program;
const Hash = @import("pure_p2_worker_protocol.zig").W.H.Hash;
pub const Role = struct { origin: Frame.Origin, log: u32, active_rows: u64, padded_rows: u64, static_provider: bool, widths: [3]usize };
pub const Cpu = struct { ordinal: usize, steps: u32, roles: []Role, main_coefficient_bytes: u64, interaction_bytes: u64, merkle_node_bytes: u64 };
pub const Truth = struct { declaration: Wire.TruthDeclaration, active_primary_rows: ?u64, padded_primary_rows: u64, merkle_node_upper_bytes: u64 };
pub const Miller = struct { declaration: Bounds.OpTowerTruthDeclaration, frontier_active_rows: u64, frontier_padded_rows: u64, arithmetic_active_rows: u64, arithmetic_padded_rows: u64 };
pub const Report = struct {
    allocator: std.mem.Allocator,
    cpus: []Cpu,
    truths: []Truth,
    miller: []Miller,
    main_coefficient_bytes: u64,
    merkle_node_upper_bytes: u64,
    disk_upper_bytes: u64,
    max_cpu_restore_bytes: u64,
    fixed_classes: usize,
    fixed_coefficient_bytes: u64,
    fixed_merkle_node_upper_bytes: u64,
    combined_disk_upper_bytes: u64,
    pub fn deinit(self: *Report) void {
        for (self.cpus) |cpu| self.allocator.free(cpu.roles);
        self.allocator.free(self.cpus);
        self.allocator.free(self.truths);
        self.allocator.free(self.miller);
        self.* = undefined;
    }
};
fn rows(log: u32) u64 {
    return @as(u64, 1) << @intCast(log);
}
fn nodes(log: u32, blowup: u32) !u64 {
    return std.math.mul(u64, try std.math.sub(u64, try std.math.mul(u64, rows(try std.math.add(u32, log, blowup)), 2), 1), @sizeOf(Hash));
}
fn addRole(a: std.mem.Allocator, out: *std.ArrayList(Role), origin: Frame.Origin, log: u32, active: u64, static: bool, fixed: ?usize, main: ?usize) !void {
    var shape = try Meta.forOrigin(origin);
    if (fixed) |n| shape.widths[0] = n;
    if (main) |n| shape.widths[1] = n;
    if (active > rows(log)) return error.OpCostActiveRowsOverflow;
    try out.append(a, .{ .origin = origin, .log = log, .active_rows = active, .padded_rows = rows(log) - active, .static_provider = static, .widths = shape.widths });
}
pub fn derive(a: std.mem.Allocator, program: *const Program, declarations: []const Wire.CpuDeclaration, requests: []const P.Request, spans: []const T.OpTowerSpan, native: []const *Native, advice: *const Advice, truth: []const Wire.TruthDeclaration, miller: []const Bounds.OpTowerTruthDeclaration, main_cells: u64, blowup: u32) !Report {
    if (declarations.len != requests.len or native.len != requests.len or spans.len != requests.len) return error.InvalidOpNativeInventory;
    const cpus = try a.alloc(Cpu, declarations.len);
    errdefer a.free(cpus);
    var done: usize = 0;
    errdefer for (cpus[0..done]) |cpu| a.free(cpu.roles);
    var merkle: u64 = 0;
    var max_restore: u64 = 0;
    for (declarations, requests, spans, native, cpus, 0..) |d, r, span, n, *cpu, i| {
        var roles = std.ArrayList(Role).empty;
        errdefer roles.deinit(a);
        const alu = try G.factCounts(n.alu.facts.len, d.geometry.alu_log, d.geometry.alu_tail_log);
        const binary = try G.factCounts(n.binary.facts.len, d.geometry.binary_log, d.geometry.binary_tail_log);
        const shift = try G.factCounts(n.shift.len, d.geometry.shift_log, d.geometry.shift_tail_log);
        const ls = try d.geometry.lsCounts(r.base.memory.ls_count);
        for (G.shapesForProgramLog(program.log_size, d.geometry)) |part| {
            if (!part.present()) continue;
            const active: u64 = switch (part.role) {
                .cpu => r.base.cpu.steps,
                .rom => program.entries.len,
                .boundary => 32,
                .alu => alu.head,
                .alu_tail => alu.tail,
                .binary => binary.head,
                .binary_tail => binary.tail,
                .shift => shift.head,
                .shift_tail => shift.tail,
                .jalr => if (n.jalr) |j| j.facts.len else 0,
                .division => n.division.len,
                .multiplication => n.multiplication.len,
                .ls => ls.head,
                .ls_tail => ls.tail,
                .initial => r.base.memory.initial.len,
                .terminal => r.base.memory.terminal.len,
                else => rows(part.log),
            };
            const static = switch (part.role) {
                .range16, .range8, .and_table, .shift_table, .selection => true,
                else => false,
            };
            try addRole(a, &roles, .{ .core = part.role }, part.log, active, static, part.widths[0], part.widths[1]);
        }
        for (std.enums.values(T.Family)) |family| if (d.bridges.at(family)) |log| {
            const active = try std.math.mul(u64, r.calls[@intFromEnum(family)], if (family == .keccak) 25 else A.crypto.secp256k1.word16_bridge.types.coordinates(T.bridgeKind(family)));
            try addRole(a, &roles, .{ .bridge = family }, log, active, false, null, null);
        };
        inline for (T.bulk_kinds) |kind| if (d.bridges.bulk.at(kind)) |log| try addRole(a, &roles, .{ .bulk = kind }, log, r.bulk.rows(kind), kind == .jtab, null, null);
        inline for (T.sponge_kinds) |kind| if (d.bridges.sponge.at(kind)) |log| try addRole(a, &roles, .{ .sponge = kind }, log, r.sponge.rows(kind), false, null, null);
        const dwords = try T.dwordCounts(d.bridges, r.ls_dword);
        for (0..T.DWORD_INSTANCES) |k| if (d.bridges.dwordLog(k)) |log| try addRole(a, &roles, .{ .dword = @intCast(k) }, log, dwords[k], false, null, null);
        if (d.bridges.tower) |log| try addRole(a, &roles, .{ .tower = {} }, log, try std.math.mul(u64, span.calls, 32), false, null, null);
        if (d.bridges.zbb != null) return error.UnqualifiedOpCostZbb;
        var main_bytes: u64 = 0;
        var inter_bytes: u64 = 0;
        var max_log: u32 = 0;
        for (roles.items) |role| {
            main_bytes = try std.math.add(u64, main_bytes, try std.math.mul(u64, try std.math.mul(u64, rows(role.log), role.widths[1]), 4));
            inter_bytes = try std.math.add(u64, inter_bytes, try std.math.mul(u64, try std.math.mul(u64, rows(role.log), role.widths[2]), 4));
            if (role.widths[1] != 0) max_log = @max(max_log, role.log);
        }
        const tree = try nodes(max_log, blowup);
        merkle = try std.math.add(u64, merkle, tree);
        max_restore = @max(max_restore, try std.math.add(u64, main_bytes, tree));
        cpu.* = .{ .ordinal = i, .steps = r.base.cpu.steps, .roles = try roles.toOwnedSlice(a), .main_coefficient_bytes = main_bytes, .interaction_bytes = inter_bytes, .merkle_node_bytes = tree };
        done += 1;
    }
    const truths = try a.alloc(Truth, truth.len);
    errdefer a.free(truths);
    for (truth, truths) |d, *out| {
        const active: ?u64 = if (d.family == .keccak) try std.math.mul(u64, (@as(u64, d.calls) + 1) / 2, (try Wire.keccakPolicy(d.logs[1])).geometry().rowsPerPair()) else if (d.family == .add or d.family == .double) (if (Wire.isSecpRow(d)) d.calls else null) else d.calls;
        // Legacy truth providers may carry local tables up to log16. This
        // explicit floor is conservative, not a measured allocation claim.
        const tree = try nodes(@max(16, @max(d.logs[0], if ((d.family == .add or d.family == .double) and !Wire.isSecpRow(d)) d.logs[1] else 0)), blowup);
        merkle = try std.math.add(u64, merkle, tree);
        out.* = .{ .declaration = d, .active_primary_rows = active, .padded_primary_rows = rows(d.logs[0]), .merkle_node_upper_bytes = tree };
    }
    const towers = try a.alloc(Miller, miller.len);
    errdefer a.free(towers);
    for (miller, towers) |d, *out| {
        merkle = try std.math.add(u64, merkle, try nodes(@max(d.frontier_log, d.arithmetic_log), blowup));
        out.* = .{ .declaration = d, .frontier_active_rows = 20 * @as(u64, d.calls), .frontier_padded_rows = rows(d.frontier_log), .arithmetic_active_rows = 32 * @as(u64, d.calls), .arithmetic_padded_rows = rows(d.arithmetic_log) };
    }
    _ = advice;
    var fixed_classes: usize = 0;
    var fixed_coefficients: u64 = 0;
    var fixed_merkle: u64 = 0;
    for (declarations, cpus, 0..) |declaration, cpu, i| {
        var reused = false;
        for (declarations[0..i]) |prior| if (std.meta.eql(prior, declaration)) {
            reused = true;
            break;
        };
        if (reused) continue;
        fixed_classes += 1;
        var max_log: u32 = 0;
        for (cpu.roles) |role| if (role.widths[0] != 0) {
            fixed_coefficients = try std.math.add(u64, fixed_coefficients, try std.math.mul(u64, try std.math.mul(u64, rows(role.log), role.widths[0]), 4));
            max_log = @max(max_log, role.log);
        };
        fixed_merkle = try std.math.add(u64, fixed_merkle, try nodes(max_log, blowup));
    }
    const coefficients = try std.math.mul(u64, main_cells, 4);
    const rounding = try std.math.mul(u64, cpus.len + truths.len + towers.len, std.heap.pageSize() - 1);
    const main_disk = try std.math.add(u64, try std.math.add(u64, coefficients, merkle), rounding);
    const fixed_rounding = try std.math.mul(u64, fixed_classes, std.heap.pageSize() - 1);
    const combined_disk = try std.math.add(u64, main_disk, try std.math.add(u64, try std.math.add(u64, fixed_coefficients, fixed_merkle), fixed_rounding));
    return .{ .allocator = a, .cpus = cpus, .truths = truths, .miller = towers, .main_coefficient_bytes = coefficients, .merkle_node_upper_bytes = merkle, .disk_upper_bytes = main_disk, .max_cpu_restore_bytes = max_restore, .fixed_classes = fixed_classes, .fixed_coefficient_bytes = fixed_coefficients, .fixed_merkle_node_upper_bytes = fixed_merkle, .combined_disk_upper_bytes = combined_disk };
}
