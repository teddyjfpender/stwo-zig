//! Receiver-derived physical CPU roster. Original MAIN columns appear once;
//! local GKR bindings and global debts use independently sized role domains.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const O = core.fields.om31.OM31;
const R = @import("../roster.zig");
const P = @import("../protocol.zig");
const Frame = @import("frame.zig");
const Global = @import("global_cpu.zig");
const Manifest = @import("manifest.zig");
const Main = A.main_only.authority;
const Geo = @import("../../../word16_execution/geometry.zig");
const Role = @import("role.zig");
const Table = @import("table_role.zig");
const Boundary = @import("boundary_role.zig");
const Service = @import("service_role.zig");
pub const Slot = struct { origin: Frame.Origin, log: u32, fixed_offset: usize, main_offset: usize, inter_offset: usize, binding_index: ?usize, claim_offset: usize };
pub const Plan = struct {
    allocator: std.mem.Allocator,
    slots: []Slot,
    inter_columns: usize,
    claim_count: usize,
    binding_count: usize,
    pub fn init(a: std.mem.Allocator, setup: *const R.CpuSetup) !Plan {
        try @import("bulk_scope.zig").setup(setup);
        var slots = std.ArrayList(Slot).empty;
        errdefer slots.deinit(a);
        var inter: usize = 0;
        var claims: usize = 0;
        var bindings: usize = 0;
        for (setup.materials.shapes()) |shape| {
            if (!shape.present()) continue;
            const origin = Frame.Origin{ .core = shape.role };
            const has_binding = @import("roster.zig").terms(shape.role) != 0;
            try slots.append(a, .{ .origin = origin, .log = shape.log, .fixed_offset = shape.offsets[0], .main_offset = shape.offsets[1], .inter_offset = inter, .binding_index = if (has_binding) bindings else null, .claim_offset = claims });
            inter = try std.math.add(usize, inter, (if (has_binding) @as(usize, 16) else 0) + Global.layout(origin).width());
            claims = try std.math.add(usize, claims, Global.claimCount(origin));
            bindings += @intFromBool(has_binding);
        }
        for (std.enums.values(@import("../types.zig").Family)) |family| if (setup.bridges.at(family)) |log| {
            const origin = Frame.Origin{ .bridge = family };
            try slots.append(a, .{ .origin = origin, .log = log, .fixed_offset = setup.offset(family, 0), .main_offset = setup.offset(family, 1), .inter_offset = inter, .binding_index = bindings, .claim_offset = claims });
            inter = try std.math.add(usize, inter, 16 + Global.layout(origin).width());
            claims = try std.math.add(usize, claims, Global.claimCount(origin));
            bindings += 1;
        };
        inline for (@import("../types.zig").bulk_kinds) |kind| if (setup.bridges.bulk.at(kind)) |log| {
            const origin = Frame.Origin{ .bulk = kind };
            try slots.append(a, .{ .origin = origin, .log = log, .fixed_offset = setup.bulkOffset(kind, 0), .main_offset = setup.bulkOffset(kind, 1), .inter_offset = inter, .binding_index = bindings, .claim_offset = claims });
            inter = try std.math.add(usize, inter, 16 + Global.layout(origin).width());
            claims = try std.math.add(usize, claims, Global.claimCount(origin));
            bindings += 1;
        };
        return .{ .allocator = a, .slots = try slots.toOwnedSlice(a), .inter_columns = inter, .claim_count = claims, .binding_count = bindings };
    }
    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.slots);
        self.* = undefined;
    }
    pub fn interLogs(self: *const Plan, a: std.mem.Allocator) ![]u32 {
        const out = try a.alloc(u32, self.inter_columns);
        for (self.slots) |slot| {
            const width = (if (slot.binding_index != null) @as(usize, 16) else 0) + Global.layout(slot.origin).width();
            @memset(out[slot.inter_offset..][0..width], slot.log);
        }
        return out;
    }
};
pub const Item = union(enum) { arithmetic: Role.Component, table: Table.Component, boundary: Boundary.Component, service: Service.Component, bulk: @import("bulk_role.zig").Component };
pub const Set = struct {
    allocator: std.mem.Allocator,
    items: []Item,
    pub fn init(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, first_ids: [3]u32, plan: *const Plan, pending: *const @import("child.zig").Pending, shared: Manifest.Shared, values: []const O) !Set {
        if (values.len != plan.claim_count or pending.artifact.claims_to_verify_by_instance.len != plan.binding_count) return error.InvalidWideCpuClaims;
        try setup.materials.geometry.validate();
        try @import("../../../word16_execution/protocol.zig").validateArithmeticRequests(setup.materials.geometry, request.base);
        const ls_counts = try setup.materials.geometry.lsCounts(request.base.memory.ls_count);
        const instances = try @import("roster.zig").fromSetup(a, setup);
        defer a.free(instances);
        const items = try a.alloc(Item, plan.slots.len);
        errdefer a.free(items);
        for (items, plan.slots) |*item, slot| {
            const nclaims = Global.claimCount(slot.origin);
            const claims = try Global.claimsFromVector(O, slot.origin, values[slot.claim_offset..][0..nclaims]);
            if (slot.origin == .bulk) {
                item.* = .{ .bulk = .{ .data = try Role.Data.init(instances[slot.binding_index.?], pending, slot.binding_index.?), .rows = request.bulk.rows(slot.origin.bulk), .offsets = .{ slot.fixed_offset, slot.main_offset }, .inter_offset = slot.inter_offset, .shared = shared, .claims = claims } };
                try item.bulk.validate();
                continue;
            }
            if (slot.origin == .bridge) {
                const family = slot.origin.bridge;
                const index = @intFromEnum(family);
                item.* = .{ .service = .{ .data = try Role.Data.init(instances[slot.binding_index.?], pending, slot.binding_index.?), .span = .{ .calls = request.calls[index], .first_id = first_ids[index] }, .offsets = .{ slot.fixed_offset, slot.main_offset }, .inter_offset = slot.inter_offset, .shared = shared, .claims = claims } };
                try item.service.validate();
                continue;
            }
            const role = slot.origin.core;
            if (role == .initial or role == .terminal) {
                item.* = .{ .boundary = .{ .origin = slot.origin, .log = slot.log, .count = @intCast(if (role == .initial) request.base.memory.initial.len else request.base.memory.terminal.len), .offsets = .{ slot.fixed_offset, slot.main_offset }, .inter_offset = slot.inter_offset, .shared = shared, .claim = claims.ram } };
                try item.boundary.validate();
                continue;
            }
            const data = try Role.Data.init(instances[slot.binding_index.?], pending, slot.binding_index.?);
            switch (role) {
                .rom, .boundary, .range16, .range8, .and_table, .shift_table, .selection => {
                    const kind = try Table.kindForRole(role);
                    item.* = .{ .table = .{ .kind = kind, .data = data, .inter_offset = slot.inter_offset, .boundary = if (role == .boundary) .{ .value = request.base.cpu, .cpu_log = setup.materials.geometry.cpu_log } else null } };
                    try item.table.validate();
                },
                else => {
                    const public: Main.PublicFor(O) = switch (role) {
                        .cpu => blk: {
                            const old = try A.word16_execution.types.inputs(request.base.cpu, request.base.epoch, slot.log);
                            break :blk .{ .cpu = .{ .steps = old.steps, .initial_pc = old.initial_pc, .final_pc = old.final_pc, .epoch = old.epoch } };
                        },
                        .alu, .alu_tail => .{ .alu = {} },
                        .binary, .binary_tail => .{ .binary = {} },
                        .shift, .shift_tail => .{ .shift = {} },
                        .jalr => .{ .jalr = {} },
                        .division => .{ .div = .{ .count = request.base.division_requests } },
                        .multiplication => .{ .mul = .{ .count = request.base.multiplication_requests } },
                        .ls => .{ .ls = .{ .count = ls_counts.head } },
                        .ls_tail => .{ .ls = .{ .count = ls_counts.tail } },
                        else => return error.InvalidWideCpuRoster,
                    };
                    item.* = .{ .arithmetic = .{ .main = .{ .log_size = slot.log, .public = public, .offsets = .{ slot.fixed_offset, slot.main_offset } }, .data = data, .inter_offset = slot.inter_offset, .epoch = request.base.epoch, .global = if (Global.layout(slot.origin).width() != 0) .{ .shared = shared, .claims = claims } else null } };
                    try item.arithmetic.validate();
                },
            }
        }
        return .{ .allocator = a, .items = items };
    }
    pub fn deinit(self: *Set) void {
        self.allocator.free(self.items);
        self.* = undefined;
    }
    pub fn provers(self: *const Set, a: std.mem.Allocator) ![]engine.air.component_prover.ForField(O).ComponentProver {
        const out = try a.alloc(engine.air.component_prover.ForField(O).ComponentProver, self.items.len);
        for (out, self.items) |*handle, *item| handle.* = switch (item.*) {
            inline else => |*c| c.asProverComponent(),
        };
        return out;
    }
    pub fn verifiers(self: *const Set, a: std.mem.Allocator) ![]core.air.components.ForField(O).Component {
        const out = try a.alloc(core.air.components.ForField(O).Component, self.items.len);
        for (out, self.items) |*handle, *item| handle.* = switch (item.*) {
            inline else => |*c| c.asVerifierComponent(),
        };
        return out;
    }
    pub fn aggregate(plan: *const Plan, values: []const O) !Manifest.Claims {
        if (values.len != plan.claim_count) return error.InvalidWideCpuClaims;
        var sum = Manifest.Claims{ .ram = O.zero(), .kio = O.zero(), .wire = O.zero() };
        for (plan.slots) |slot| {
            const n = Global.claimCount(slot.origin);
            const claim = try Global.claimsFromVector(O, slot.origin, values[slot.claim_offset..][0..n]);
            sum.ram = sum.ram.add(claim.ram);
            sum.kio = sum.kio.add(claim.kio);
            sum.wire = sum.wire.add(claim.wire);
        }
        return sum;
    }
};
