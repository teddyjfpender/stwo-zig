//! Shared typed page-binding kernel; schemas fix exact original source
//! inventory and grammar. No host/source descriptor grants proof authority.
const std = @import("std");
const core = @import("stwo_core");
const Placement = @import("../air/block/memory_component_trace.zig");

pub fn ForSchema(comptime Schema: type) type {
    return struct {
        //! Page supplier prefixes: two exact wire requests per plane, degree3.
        const M = core.fields.m31.M31;
        const Q = core.fields.qm31.QM31;
        const Air = Schema.BindingAir;
        const Columns = Schema.Columns;
        const Routing = Schema.BindingPlan;
        pub const Claim = struct { sums: [Air.PAIRS]Q, total_uses: u64 };
        pub fn normalize(claim: Claim, plan: *const Routing.Plan) ![Air.PAIRS]Q {
            if (claim.total_uses != plan.total_uses or claim.total_uses >= core.fields.m31.Modulus or plan.rows() >= core.fields.m31.Modulus) return error.InvalidMemorySourceBindingClaim;
            const inverse = try M.fromCanonical(@intCast(plan.rows())).inv();
            var out: [Air.PAIRS]Q = undefined;
            for (&out, claim.sums) |*value, sum| value.* = sum.mulM31(inverse);
            return out;
        }
        pub const Generated = struct {
            allocator: std.mem.Allocator,
            cells: []M,
            claim: Claim,
            pub fn deinit(self: *Generated) void {
                self.allocator.free(self.cells);
                self.* = undefined;
            }
        };
        pub fn generate(a: std.mem.Allocator, source: *const Columns.Columns, plan: *const Routing.Plan, challenge: Air.Algebra(Q).Challenge, max_cells: usize) !Generated {
            if (!std.meta.eql(source.page, plan.first.page) or source.written != source.page.chunks) return error.UntrustedMemorySourceBindingPage;
            const rows = plan.rows();
            const count = try std.math.mul(usize, rows, Air.INTERACTION_COUNT);
            if (count > max_cells) return error.MemorySourceBindingResourceLimit;
            const cells = try a.alloc(M, count);
            errdefer a.free(cells);
            var claim = Claim{ .sums = @splat(Q.zero()), .total_uses = plan.total_uses };
            // First pass computes plane totals. No per-row fraction buffer is kept.
            for (0..source.page.chunks) |logical| {
                const physical = Placement.committedRow(logical, source.page.row_log);
                for (0..Air.PAIRS) |pair| claim.sums[pair] = claim.sums[pair].add(try contribution(source, plan, physical, pair, challenge));
            }
            const shifts = try normalize(claim, plan);
            var running: [Air.PAIRS]Q = @splat(Q.zero());
            for (0..rows) |logical| {
                const physical = Placement.committedRow(logical, source.page.row_log);
                for (0..Air.PAIRS) |pair| {
                    const value = if (logical < source.page.chunks) try contribution(source, plan, physical, pair, challenge) else Q.zero();
                    running[pair] = running[pair].add(value).sub(shifts[pair]);
                    const coordinates = running[pair].toM31Array();
                    for (coordinates, 0..) |coordinate, i| cells[(4 * pair + i) * rows + physical] = coordinate;
                }
            }
            return .{ .allocator = a, .cells = cells, .claim = claim };
        }
        fn contribution(source: *const Columns.Columns, plan: *const Routing.Plan, physical: usize, pair: usize, c: Air.Algebra(Q).Challenge) !Q {
            const circuit = Q.fromBase(plan.column(0)[physical]);
            var result = Q.zero();
            for (0..2) |lane| {
                const bit = 2 * pair + lane;
                const weight = plan.column(2 + 2 * bit)[physical];
                if (weight.isZero()) continue;
                const denominator = Air.Algebra(Q).denominator(c, circuit, Q.fromBase(plan.column(1 + 2 * bit)[physical]), Q.fromBase(source.mainColumn(bit)[physical]));
                result = result.add((try denominator.inv()).mulM31(weight));
            }
            return result;
        }
    };
}
