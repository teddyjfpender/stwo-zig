//! Experimental array-compute backend. Construct explicitly with a pinned native
//! executable. Not exported from the aggregate or selected by a production CLI.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const backend = @import("stwo_backend_contracts");
const M31 = core.fields.m31.M31;
const Domain = core.poly.circle.domain.CircleDomain;
const Twiddles = prover.poly.twiddles.TwiddleTree([]const M31);
const work = prover.work_profile;
pub const abi = @import("abi.zig");
pub const runtime = @import("runtime.zig");
pub const circle = @import("circle.zig");
pub const fri = @import("fri.zig");

/// No Merkle/storage/FRI capability is claimed. All Circle operations execute
/// Bend and then compare against Zig; parity failures propagate to the caller.
pub fn BendBackend(comptime config: runtime.Config) type {
    return struct {
        pub const capabilities: backend.Capabilities = .{ .circle_transform = true };
        pub fn ColumnType(comptime F: type) type {
            return []F;
        }
        pub fn transformCircleBuffers(a: std.mem.Allocator, values: []const []M31, domain: Domain, t: backend.circle_ops.Twiddles, direction: backend.circle_ops.Direction) !void {
            return circle.transform(a, config, values, domain, Twiddles.init(t.root_coset, t.twiddles, t.itwiddles), direction == .interpolate);
        }
        pub fn interpolateCircleBuffers(a: std.mem.Allocator, values: []const []M31, domain: Domain, tree: Twiddles) !work.M31InterpolationExecution {
            try circle.transform(a, config, values, domain, tree, true);
            return .{ .log_size = domain.logSize(), .column_count = values.len, .batch_count = values.len };
        }
        pub fn evaluateCircleBuffers(a: std.mem.Allocator, values: []const []M31, domain: Domain, tree: Twiddles) !work.M31ForwardFftExecution {
            try circle.transform(a, config, values, domain, tree, false);
            return .{ .log_size = domain.logSize(), .column_count = values.len };
        }
        pub fn interpolateAndEvaluateCircleBuffers(a: std.mem.Allocator, source: []const []const M31, base: []const []M31, extended: []const []M31, buffer: []M31, start: usize, stride: usize, base_domain: Domain, base_tree: Twiddles, extended_domain: Domain, extended_tree: Twiddles) !work.M31CircleLdeExecution {
            _ = buffer;
            _ = start;
            _ = stride;
            if (source.len == 0 or source.len != base.len or source.len != extended.len or extended_domain.logSize() <= base_domain.logSize()) return error.InvalidColumns;
            for (source, base, extended) |s, b, e| {
                if (s.len != base_domain.size() or b.len != s.len or e.len != extended_domain.size()) return error.InvalidColumns;
            }
            for (source, base) |s, b| if (s.ptr != b.ptr) {
                @memmove(b, s);
            };
            const interpolation = try interpolateCircleBuffers(a, base, base_domain, base_tree);
            for (base, extended) |b, e| {
                @memmove(e[0..b.len], b);
                @memset(e[b.len..], M31.zero());
            }
            const forward = try evaluateCircleBuffers(a, extended, extended_domain, extended_tree);
            return .{ .interpolation = interpolation, .forward = forward };
        }
    };
}

test "bend: compute backend claims Circle only" {
    const B = BendBackend(.{ .executable = "/not-installed" });
    comptime backend.assertBackend(B);
    try std.testing.expect(!B.capabilities.fri_folding);
    try std.testing.expect(!@hasDecl(B, "MerkleTree"));
    _ = runtime;
}
