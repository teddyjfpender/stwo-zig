//! Concrete packed M31/OM31 execution of the receiver-owned hybrid polynomial.
//! Base inputs have one coordinate; public carry inputs retain all eight.
//! Parameters and their invariant expressions are evaluated once per proof.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const IR = engine.air.secure_polynomial_program_v2;
const O = core.fields.om31.OM31;
const M = core.fields.m31;
const Pack = core.fields.packed_om31;
const F = Pack.PackedOM31;
const V = M.PackedM31;

pub const Input = union(enum) {
    zero,
    base: struct { values: []const M.M31, log: u32, offset: i8 = 0 },
    secure: struct { values: [8][]const M.M31, offset: i8 = 0 },

    inline fn baseAt(self: *const Input, row: usize, log: u32) V {
        return switch (self.*) {
            .zero => @splat(0),
            .secure => unreachable,
            .base => |source| blk: {
                if (source.offset == 0 and source.log == log + 1) break :blk M.loadPacked(source.values[row..].ptr);
                var out: V = undefined;
                inline for (0..M.PACK_WIDTH) |lane| {
                    const at = core.utils.offsetBitReversedCircleDomainIndex(row + lane, log, log + 1, source.offset);
                    const index = ((at >> @intCast(log + 2 - source.log)) << 1) + (at & 1);
                    out[lane] = source.values[index].v;
                }
                break :blk out;
            },
        };
    }
    inline fn secureAt(self: *const Input, row: usize, log: u32) F {
        const source = self.secure;
        var coordinates: [8]V = undefined;
        inline for (0..8) |j| {
            if (source.offset == 0) {
                coordinates[j] = M.loadPacked(source.values[j][row..].ptr);
            } else inline for (0..M.PACK_WIDTH) |lane| {
                const at = core.utils.offsetBitReversedCircleDomainIndex(row + lane, log, log + 1, source.offset);
                coordinates[j][lane] = source.values[j][at].v;
            }
        }
        return Pack.fromCoordinates(coordinates);
    }
};

pub const Plan = struct {
    allocator: std.mem.Allocator,
    program: *const IR.ProgramFor(O),
    inputs: []const Input,
    parameters: []const O,
    log: u32,
    sorts: []IR.Sort,
    slots: []u32,
    invariant: []bool,
    steps: []u32,
    initial: Workspace,

    pub fn init(a: std.mem.Allocator, program: *const IR.ProgramFor(O), inputs: []const Input, parameters: []const O, log: u32) !Plan {
        try program.validate();
        if (log < 4 or log >= 30 or inputs.len != program.inputs.len or parameters.len != program.parameters.len) return error.InvalidHybridCpuGeometry;
        const n = @as(usize, 1) << @intCast(log + 1);
        for (inputs) |input| switch (input) {
            .zero => {},
            .base => |source| if (source.log == 0 or source.log > log + 1 or source.values.len != @as(usize, 1) << @intCast(source.log)) return error.InvalidHybridCpuInput,
            .secure => |source| for (source.values) |values| if (values.len != n) return error.InvalidHybridCpuInput,
        };
        const sorts = try program.sorts(a);
        errdefer a.free(sorts);
        const slots = try a.alloc(u32, program.nodes.len);
        errdefer a.free(slots);
        const invariant = try a.alloc(bool, program.nodes.len);
        errdefer a.free(invariant);
        var dynamic: std.ArrayList(u32) = .empty;
        defer dynamic.deinit(a);
        var base_count: u32 = 0;
        var secure_count: u32 = 0;
        for (program.nodes, sorts, invariant, slots, 0..) |node, *sort, *fixed, *slot, i| {
            sort.* = switch (node.op) {
                .input => if (inputs[node.value] == .secure) .secure else .base,
                .add, .sub, .mul => if (sorts[node.lhs] == .secure or sorts[node.rhs] == .secure) .secure else .base,
                .neg => sorts[node.lhs],
                else => sort.*,
            };
            fixed.* = switch (node.op) {
                .constant, .parameter => true,
                .input => false,
                .add, .sub, .mul => invariant[node.lhs] and invariant[node.rhs],
                .neg => invariant[node.lhs],
                .fraction, .range_fraction => unreachable,
            };
            if (!fixed.*) try dynamic.append(a, @intCast(i));
            if (sort.* == .base) {
                slot.* = base_count;
                base_count += 1;
            } else {
                slot.* = secure_count;
                secure_count += 1;
            }
        }
        const steps = try dynamic.toOwnedSlice(a);
        errdefer a.free(steps);
        const base = try a.alloc(V, base_count);
        errdefer a.free(base);
        const secure = try a.alloc(F, secure_count);
        errdefer a.free(secure);
        @memset(base, @splat(0));
        @memset(secure, Pack.splat(O.zero()));
        var out = Plan{ .allocator = a, .program = program, .inputs = inputs, .parameters = parameters, .log = log, .sorts = sorts, .slots = slots, .invariant = invariant, .steps = steps, .initial = .{ .allocator = a, .base = base, .secure = secure } };
        for (program.nodes, invariant, 0..) |_, fixed, i| if (fixed) out.initial.step(&out, @intCast(i), 0);
        return out;
    }
    pub fn deinit(self: *Plan) void {
        self.initial.deinit();
        self.allocator.free(self.sorts);
        self.allocator.free(self.slots);
        self.allocator.free(self.invariant);
        self.allocator.free(self.steps);
        self.* = undefined;
    }
};

pub const Workspace = struct {
    allocator: std.mem.Allocator,
    base: []V,
    secure: []F,
    pub fn init(a: std.mem.Allocator, plan: *const Plan) !Workspace {
        const base = try a.dupe(V, plan.initial.base);
        errdefer a.free(base);
        return .{ .allocator = a, .base = base, .secure = try a.dupe(F, plan.initial.secure) };
    }
    pub fn deinit(self: *Workspace) void {
        self.allocator.free(self.base);
        self.allocator.free(self.secure);
        self.* = undefined;
    }
    pub fn evaluate(self: *Workspace, plan: *const Plan, row: usize) !void {
        const n = @as(usize, 1) << @intCast(plan.log + 1);
        if (row % M.PACK_WIDTH != 0 or row > n or M.PACK_WIDTH > n - row) return error.InvalidHybridCpuGeometry;
        for (plan.steps) |index| self.step(plan, index, row);
    }
    pub inline fn baseValue(self: *const Workspace, plan: *const Plan, index: u32) V {
        return self.base[plan.slots[index]];
    }
    pub inline fn value(self: *const Workspace, plan: *const Plan, index: u32) F {
        if (plan.sorts[index] == .secure) return self.secure[plan.slots[index]];
        return Pack.fromCoordinates(.{ self.baseValue(plan, index), @splat(0), @splat(0), @splat(0), @splat(0), @splat(0), @splat(0), @splat(0) });
    }
    inline fn step(self: *Workspace, plan: *const Plan, index: u32, row: usize) void {
        const node = plan.program.nodes[index];
        const slot = plan.slots[index];
        if (plan.sorts[index] == .base) {
            self.base[slot] = switch (node.op) {
                .constant => @splat(plan.program.constants[node.value][0]),
                .input => plan.inputs[node.value].baseAt(row, plan.log),
                .add => M.addPacked(self.baseValue(plan, node.lhs), self.baseValue(plan, node.rhs)),
                .sub => M.subPacked(self.baseValue(plan, node.lhs), self.baseValue(plan, node.rhs)),
                .mul => M.mulPacked(self.baseValue(plan, node.lhs), self.baseValue(plan, node.rhs)),
                .neg => M.subPacked(@splat(0), self.baseValue(plan, node.lhs)),
                .parameter, .fraction, .range_fraction => unreachable,
            };
            return;
        }
        self.secure[slot] = switch (node.op) {
            .constant => Pack.splat(plan.program.constantValue(node.value)),
            .parameter => Pack.splat(plan.parameters[node.value]),
            .input => plan.inputs[node.value].secureAt(row, plan.log),
            .neg => self.value(plan, node.lhs).neg(),
            .add => if (plan.sorts[node.lhs] == .base) addBase(self.value(plan, node.rhs), self.baseValue(plan, node.lhs)) else if (plan.sorts[node.rhs] == .base) addBase(self.value(plan, node.lhs), self.baseValue(plan, node.rhs)) else self.value(plan, node.lhs).add(self.value(plan, node.rhs)),
            .sub => if (plan.sorts[node.lhs] == .base) addBase(self.value(plan, node.rhs).neg(), self.baseValue(plan, node.lhs)) else if (plan.sorts[node.rhs] == .base) subBase(self.value(plan, node.lhs), self.baseValue(plan, node.rhs)) else self.value(plan, node.lhs).sub(self.value(plan, node.rhs)),
            .mul => if (plan.sorts[node.lhs] == .base) self.value(plan, node.rhs).mulBase(self.baseValue(plan, node.lhs)) else if (plan.sorts[node.rhs] == .base) self.value(plan, node.lhs).mulBase(self.baseValue(plan, node.rhs)) else Pack.mul(self.value(plan, node.lhs), self.value(plan, node.rhs)),
            .fraction, .range_fraction => unreachable,
        };
    }
};
inline fn addBase(value: F, base: V) F {
    var out = value;
    out.c0.c0.a = M.addPacked(out.c0.c0.a, base);
    return out;
}
inline fn subBase(value: F, base: V) F {
    var out = value;
    out.c0.c0.a = M.subPacked(out.c0.c0.a, base);
    return out;
}
