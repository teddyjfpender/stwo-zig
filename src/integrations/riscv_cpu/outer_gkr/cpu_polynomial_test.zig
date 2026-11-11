const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Outer = @import("stwo_circuit_cpu_integration");
const H = @import("hybrid_air.zig");
const P = @import("profile.zig");
const C = @import("cpu_polynomial.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31;
const a = std.testing.allocator;
const n = 64;
fn word(seed: usize) M.M31 {
    return M.M31.fromU64(if (seed & 1 == 0) seed + 1 else 2 * @as(u64, M.Modulus) - seed);
}
fn secure(seed: usize) O {
    var coordinates: [8]M.M31 = undefined;
    for (&coordinates, 0..) |*v, j| v.* = word(seed + 61 * j);
    return O.fromM31Array(coordinates);
}
pub const Inputs = struct {
    values: []C.Input,
    buffers: std.ArrayList([]M.M31) = .empty,
    pub fn init(artifact: *const H.Artifact) !Inputs {
        var self = Inputs{ .values = try a.alloc(C.Input, artifact.program.inputs.len) };
        errdefer self.deinit();
        for (artifact.program.inputs, self.values, 0..) |input, *out, i| {
            if (P.gkrBound(artifact.component) and input.tree == 2 and input.column >= 19) {
                out.* = .zero;
            } else if (P.gkrBound(artifact.component) and input.tree == 2 and input.column == 18) {
                var planes: [8][]const M.M31 = undefined;
                for (&planes, 0..) |*buffer, j| buffer.* = try self.plane(n, i + 137 * j);
                out.* = .{ .secure = .{ .values = planes, .offset = input.offset } };
            } else {
                const log: u32 = if (i & 1 == 0) 6 else 5;
                out.* = .{ .base = .{ .values = try self.plane(@as(usize, 1) << @intCast(log), i), .log = log, .offset = input.offset } };
            }
        }
        return self;
    }
    pub fn plane(self: *Inputs, count: usize, seed: usize) ![]M.M31 {
        const values = try a.alloc(M.M31, count);
        errdefer a.free(values);
        for (values, 0..) |*v, j| v.* = word(17 + seed * 177 + j * 61);
        try self.buffers.append(a, values);
        return values;
    }
    pub fn deinit(self: *Inputs) void {
        for (self.buffers.items) |buffer| a.free(buffer);
        self.buffers.deinit(a);
        a.free(self.values);
    }
    pub fn scalar(self: *const Inputs, index: usize, row: usize) !O {
        return switch (self.values[index]) {
            .zero => O.zero(),
            .base => |source| blk: {
                const at = core.utils.offsetBitReversedCircleDomainIndex(row, 5, 6, source.offset);
                const poly = engine.air.component_trace.Poly{ .log_size = source.log, .values = source.values };
                break :blk O.fromBase(try poly.valueAtLiftingPosition(6, at));
            },
            .secure => |source| blk: {
                var coordinates: [8]M.M31 = undefined;
                const at = core.utils.offsetBitReversedCircleDomainIndex(row, 5, 6, source.offset);
                for (&coordinates, source.values) |*v, buffer| v.* = buffer[at];
                break :blk O.fromM31Array(coordinates);
            },
        };
    }
};
fn allocationCase(allocator: std.mem.Allocator, artifact: *const H.Artifact, inputs: []const C.Input, parameters: []const O) !void {
    var plan = try C.Plan.init(allocator, &artifact.program, inputs, parameters, 5);
    defer plan.deinit();
    var workspace = try C.Workspace.init(allocator, &plan);
    defer workspace.deinit();
    try workspace.evaluate(&plan, 0);
}

test "outer GKR CPU polynomial preserves scalar IR across fields lifts carry and fresh parameters" {
    const bytes = try std.fs.cwd().readFileAlloc(a, Outer.air.bundle_path, 64 << 20);
    defer a.free(bytes);
    var bundle = try Outer.air.parse(a, bytes);
    defer bundle.deinit();
    var components: usize = 0;
    for (bundle.components, 0..) |*source, kind| {
        var artifact = try H.record(a, source, @enumFromInt(kind));
        defer artifact.deinit();
        var inputs = try Inputs.init(&artifact);
        defer inputs.deinit();
        const parameters = try a.alloc(O, artifact.program.parameters.len);
        defer a.free(parameters);
        const scalar_inputs = try a.alloc(O, inputs.values.len);
        defer a.free(scalar_inputs);
        for (0..2) |invocation| {
            for (parameters, 0..) |*v, j| v.* = secure(137 + 199 * invocation + j * 177);
            var plan = try C.Plan.init(a, &artifact.program, inputs.values, parameters, 5);
            defer plan.deinit();
            try std.testing.expect(plan.steps.len < artifact.program.nodes.len);
            var workspace = try C.Workspace.init(a, &plan);
            defer workspace.deinit();
            var row: usize = 0;
            while (row < n) : (row += M.PACK_WIDTH) {
                try workspace.evaluate(&plan, row);
                for (0..M.PACK_WIDTH) |lane| {
                    for (scalar_inputs, 0..) |*v, i| v.* = try inputs.scalar(i, row + lane);
                    const expected = try artifact.evaluateFor(O, a, scalar_inputs, parameters);
                    defer a.free(expected);
                    for (artifact.program.roots, expected) |root, want| try std.testing.expect(core.fields.packed_om31.lane(workspace.value(&plan, root), lane).eql(want));
                }
            }
            try std.testing.expectError(error.InvalidHybridCpuGeometry, workspace.evaluate(&plan, n));
            try std.testing.expectError(error.InvalidHybridCpuGeometry, workspace.evaluate(&plan, 1));
        }
        if (kind == 0) {
            try std.testing.checkAllAllocationFailures(a, allocationCase, .{ &artifact, inputs.values, parameters });
            const budget = try engine.host_budget_allocator.SharedHostBudget.create(a, 64 << 20);
            defer budget.destroy();
            try allocationCase(budget.allocator(), &artifact, inputs.values, parameters);
            try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
            try std.testing.expectError(error.InvalidHybridCpuGeometry, C.Plan.init(budget.allocator(), &artifact.program, inputs.values, parameters[0 .. parameters.len - 1], 5));
            try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
        }
        components += 1;
    }
    try std.testing.expectEqual(@as(usize, 11), components);
    std.debug.print("HYBRID_CPU_POLYNOMIAL components=11 scalar_IR_exact=true carry_all_eight=true fresh_parameters=2 invariant_hoisting=true\n", .{});
}
