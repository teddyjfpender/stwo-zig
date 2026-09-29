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

/// Complete experimental prover backend: Bend Circle/FRI with explicit host
/// commitments and generic composition. Every Bend result is checked against Zig.
pub fn BendBackend(comptime config: runtime.Config) type {
    return BendBackendWithHost(config, void);
}

/// Integrations inject their host composition provider without a backend-to-backend
/// package dependency. Circle and FRI arithmetic always execute Bend.
pub fn BendBackendWithHost(comptime config: runtime.Config, comptime Host: type) type {
    return struct {
        pub const capabilities: backend.Capabilities = .{ .circle_transform = true, .fri_folding = true, .fri_multi_fold = true };
        // Complete prover plumbing stays on the established host implementation.
        // These are explicit host services, never presented as Bend kernels.
        pub const MerkleTree = prover.vcs_lifted.prover.MerkleProverLifted;
        pub fn commitMerkle(comptime H: type, a: std.mem.Allocator, columns: []const []const M31) !MerkleTree(H) {
            return MerkleTree(H).commit(a, columns);
        }
        pub fn commitLazyMerkle(comptime H: type, a: std.mem.Allocator, provider: anytype, column: anytype) !MerkleTree(H) {
            return MerkleTree(H).commitWithLazyQuotients(a, provider, column);
        }
        pub const computeCompositionEvaluation = if (Host == void) declineComposition else Host.computeCompositionEvaluation;
        pub const computeCompositionEvaluationWithExecution = if (Host == void) declineCompositionWithExecution else Host.computeCompositionEvaluationWithExecution;
        pub const reuses_constant_merkle_parents = true;
        pub const lazy_merkle_reuses_constant_parents = false;
        pub const combined_base_in_place = true;
        pub const combined_commit_min_columns: usize = 1;
        pub const combined_commit_max_columns: usize = 256;
        pub fn warmup() !void {}
        pub fn interpolateSecureComposition(a: std.mem.Allocator, values: *prover.secure_column.SecureColumnByCoords, domain: Domain, tree: Twiddles) !work.M31InterpolationBackendResult {
            if (values.representation == .coefficients) return .already_coefficients;
            const receipt = try interpolateCircleBuffers(a, &values.columns, domain, tree);
            values.representation = .coefficients;
            return .{ .transformed = receipt };
        }
        pub fn foldCircleIntoLine(a: std.mem.Allocator, dst: []core.fields.qm31.QM31, src: [4][]const M31, domain: Domain, alpha: core.fields.qm31.QM31, workspace: *core.fri.FoldCircleWorkspace) !void {
            try fri.circle(a, config, dst, src, domain, alpha, workspace);
        }
        pub fn foldLine(a: std.mem.Allocator, values: []core.fields.qm31.QM31, domain: core.poly.line.LineDomain, alpha: core.fields.qm31.QM31, workspace: *core.fri.FoldLineWorkspace) !core.fri.FoldLineResult {
            return fri.line(a, config, values, domain, alpha, workspace, core.fri.FOLD_STEP);
        }
        pub fn foldLineN(a: std.mem.Allocator, values: []core.fields.qm31.QM31, domain: core.poly.line.LineDomain, alpha: core.fields.qm31.QM31, workspace: *core.fri.FoldLineWorkspace, n: u32) !core.fri.FoldLineResult {
            return fri.line(a, config, values, domain, alpha, workspace, n);
        }
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
            const forward = if (extended_domain.logSize() == base_domain.logSize() + 1) blk: {
                try circle.evaluateExtension(a, config, extended, extended_domain, extended_tree);
                break :blk work.M31ForwardFftExecution{ .log_size = extended_domain.logSize(), .column_count = extended.len, .skipped_layers = 1 };
            } else try evaluateCircleBuffers(a, extended, extended_domain, extended_tree);
            return .{ .interpolation = interpolation, .forward = forward };
        }
    };
}

test "bend: proving backend claims Circle and FRI with host commitments" {
    const B = BendBackend(.{ .executable = "/not-installed" });
    comptime backend.assertBackend(B);
    try std.testing.expect(B.capabilities.fri_folding);
    comptime backend.assertBackendForChannel(B, core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher);
    _ = runtime;
}

fn declineComposition(a: anytype, components: anytype, random: anytype, trace: anytype, residency: anytype, twiddles: anytype) !?prover.secure_column.SecureColumnByCoords {
    _ = a;
    _ = components;
    _ = random;
    _ = trace;
    _ = residency;
    _ = twiddles;
    return null;
}
fn declineCompositionWithExecution(a: anytype, components: anytype, random: anytype, trace: anytype, residency: anytype, twiddles: anytype, execution: anytype) !?prover.secure_column.SecureColumnByCoords {
    _ = execution;
    return declineComposition(a, components, random, trace, residency, twiddles);
}
