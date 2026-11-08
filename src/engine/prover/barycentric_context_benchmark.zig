//! Paired setup benchmark. This measures context construction, not proof latency.
const std = @import("std");
const core = @import("stwo_core");
const evaluation = @import("poly/circle/evaluation.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;

const Reference = struct {
    domain_points: []core.circle.CirclePointQM31,
    si_values: []Q,
    fn deinit(self: *Reference, a: std.mem.Allocator) void {
        a.free(self.domain_points);
        a.free(self.si_values);
    }
};
fn reference(a: std.mem.Allocator, log: u32) !Reference {
    const coset = core.poly.circle.canonic.CanonicCoset.new(log);
    const domain = coset.circleDomain();
    const points = try a.alloc(core.circle.CirclePointQM31, domain.size());
    errdefer a.free(points);
    const si = try a.alloc(Q, domain.size());
    errdefer a.free(si);
    const generated = core.circle.Coset.new(core.circle.CirclePointIndex.generator(), log);
    for (points, si, 0..) |*p, *s, i| {
        const base = domain.at(core.utils.bitReverseIndex(i, log));
        p.* = .{ .x = Q.fromBase(base.x), .y = Q.fromBase(base.y) };
        s.* = Q.fromBase(M.fromCanonical(2)).neg().mul(p.y).mul(core.constraints.cosetVanishingDerivative(Q, generated, p.*));
    }
    return .{ .domain_points = points, .si_values = si };
}

pub fn main() !void {
    const a = std.heap.page_allocator;
    const writer = std.fs.File.stdout().deprecatedWriter();
    for ([_]u32{ 12, 16 }) |log| {
        for (0..4) |sample| {
            // Alternate order; sample zero is retained as an explicit warmup.
            var timer = try std.time.Timer.start();
            var old: Reference = undefined;
            var new: evaluation.BarycentricContext = undefined;
            var old_ns: u64 = undefined;
            var new_ns: u64 = undefined;
            if (sample % 2 == 0) {
                old = try reference(a, log);
                old_ns = timer.lap();
                new = try evaluation.BarycentricContext.init(a, log);
                new_ns = timer.read();
            } else {
                new = try evaluation.BarycentricContext.init(a, log);
                new_ns = timer.lap();
                old = try reference(a, log);
                old_ns = timer.read();
            }
            defer old.deinit(a);
            defer new.deinit(a);
            for (old.domain_points, old.si_values, 0..) |op, os, i| {
                if (!op.eql(new.pointAt(i)) or !os.eql(new.derivativeAt(i))) return error.ContextMismatch;
            }
            try writer.print("{{\"log_size\":{d},\"sample\":{d},\"warmup\":{},\"reference_ns\":{d},\"optimized_ns\":{d},\"exact_match\":true}}\n", .{ log, sample, sample == 0, old_ns, new_ns });
        }
    }
}
