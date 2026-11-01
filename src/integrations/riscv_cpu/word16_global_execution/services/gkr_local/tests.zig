const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const O = core.fields.om31.OM31;
const F = @import("fractions.zig");
const Frame = @import("frame.zig");
const Resource = @import("resource.zig");
const Closure = @import("closure.zig");
const Sink = struct {
    count: usize = 0,
    pub fn emit(self: *Sink, relation: F.Relation, tuple: anytype, weight: anytype) void {
        std.debug.assert(tuple.len == relation.arity());
        _ = weight;
        self.count += 1;
    }
};
test "local fraction authority covers actual CPU and all chip projections" {
    const z = O.zero();
    const main = [_]O{z} ** 256;
    const fixed = [_]O{z} ** 64;
    var sink = Sink{};
    F.cpuFor(O, &fixed, &main, z, &sink);
    try std.testing.expectEqual(15, sink.count);
    F.aluFor(O, &main, &sink);
    F.binaryFor(O, &main, &sink);
    F.shiftFor(O, &main, &sink);
    F.jalrFor(O, &main, &sink);
    F.lsFor(O, main[0..A.memory.load_store_v2.layout.MAIN], &sink);
    F.divisionFor(O, &main, &sink);
    const mul = [_]O{z} ** A.arithmetic.multiplication.layout.MAIN;
    F.multiplicationFor(O, &mul, &sink);
    try std.testing.expectEqual(184, sink.count);
}
test "table and service bridges emit only admitted local fractions" {
    const z = O.zero();
    const main = [_]O{z} ** 256;
    const fixed = [_]O{z} ** 64;
    var sink = Sink{};
    F.romFor(O, &fixed, &main, &sink);
    F.scalarTableFor(O, .range16, &fixed, &main, &sink);
    F.scalarTableFor(O, .range8, &fixed, &main, &sink);
    F.andTableFor(O, &fixed, &main, &sink);
    F.shiftTableFor(O, &fixed, &main, &sink);
    F.selectionTableFor(O, &fixed, &main, &sink);
    F.keccakBridgeFor(O, &fixed, &main, &sink);
    F.secpBridgeFor(O, .add, &fixed, &main, &sink);
    F.secpBridgeFor(O, .double, &fixed, &main, &sink);
    try std.testing.expectEqual(264, sink.count);
}
test "mixed-height GKR uses suffix before row lane split" {
    const x = Frame.Instance{ .origin = .{ .core = .cpu }, .row_log = 5, .terms = 3, .fixed_offset = 0, .main_offset = 0 };
    const point = [_]O{O.zero()} ** 10;
    const split = try Frame.splitPoint(x, &point, 7);
    try std.testing.expect(split.rows.ptr == point[3..].ptr);
    try std.testing.expectEqual(5, split.rows.len);
    try std.testing.expectEqual(2, split.lanes.len);
    try std.testing.expectError(error.LocalGkrPointGeometryMismatch, Frame.splitPoint(x, &point, 6));
}
test "whole local allocation plan rejects before fact allocations" {
    const x = [_]Frame.Instance{.{ .origin = .{ .core = .cpu }, .row_log = 5, .terms = 15, .fixed_offset = 0, .main_offset = 0 }};
    const p = try Resource.Plan.forInstances(&x, 1 << 20);
    try std.testing.expectEqual(512 * 36, p.input_bytes);
    try std.testing.expectError(error.LocalGkrBudgetExceeded, Resource.Plan.forInstances(&x, p.peak_bytes - 1));
    try std.testing.expectError(error.MissingLocalGkrBudget, Resource.Plan.forInstances(&x, 0));
}
test "whole local closure rejects zero-weight poles and unbalanced claims" {
    const pair1 = [_]O{ O.one(), O.one() };
    const pair2 = [_]O{ O.one().neg(), O.one() };
    const pole = [_]O{ O.zero(), O.zero() };
    try Closure.close(std.testing.allocator, &.{ &pair1, &pair2 });
    try std.testing.expectError(error.UnclosedLocalGkr, Closure.close(std.testing.allocator, &.{&pair1}));
    try std.testing.expectError(error.LocalGkrPole, Closure.close(std.testing.allocator, &.{ &pair1, &pair2, &pole }));
}
test "actual services metadata provider rejects global-only role without MAIN access" {
    const R = @import("../roster.zig");
    var source: R.Sources = undefined;
    const provider = @import("native_provider.zig").Provider{ .source = &source };
    const Ch = @import("challenges.zig").For(O);
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    const challenges = Ch.draw(&channel);
    var n: [1]core.fields.m31.M31 = undefined;
    var d: [1]O = undefined;
    var sink = @import("inputs.zig").RowSink{ .challenges = &challenges, .numerator = &n, .denominator = &d };
    const instance = Frame.Instance{ .origin = .{ .core = .initial }, .row_log = 5, .terms = 1, .fixed_offset = 0, .main_offset = 0 };
    try std.testing.expectError(error.GlobalOnlyRoleHasNoLocalGkr, provider.emit(instance, 0, &sink));
}
test "native local fractions and weighted row projection agree including padding" {
    const Ch = @import("challenges.zig").For(O);
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    const challenges = Ch.draw(&channel);
    const main = [_]O{O.zero()} ** 256;
    var n: [13]core.fields.m31.M31 = undefined;
    var d: [13]O = undefined;
    var sink = @import("inputs.zig").RowSink{ .challenges = &challenges, .numerator = &n, .denominator = &d };
    F.aluFor(O, &main, &sink);
    try std.testing.expect(!sink.invalid);
    var weights: [16]O = undefined;
    for (&weights, 0..) |*v, i| v.* = O.fromBase(core.fields.m31.M31.fromCanonical(@intCast(i + 1)));
    var projection = @import("binding.zig").ProjectionFor(O){ .challenges = &challenges, .lane_weights = &weights, .terms = 13 };
    F.aluFor(O, &main, &projection);
    try projection.finish();
    var expectedN = O.zero();
    var expectedD = O.zero();
    for (n, d, weights[0..13]) |ni, di, eq| {
        expectedN = expectedN.add(eq.mulM31(ni));
        expectedD = expectedD.add(eq.mul(di));
    }
    for (weights[13..]) |eq| expectedD = expectedD.add(eq);
    try std.testing.expectEqual(expectedN, projection.numerator);
    try std.testing.expectEqual(expectedD, projection.denominator);
}

const BalancedMetadata = struct {
    pub fn emit(_: @This(), instance: Frame.Instance, logical: usize, sink: *@import("inputs.zig").RowSink) !void {
        const M = core.fields.m31.M31;
        const weight = if (instance.origin.core == .alu) M.one() else M.one().neg();
        sink.emitBase(.range16, [1]M{M.fromCanonical(@intCast(logical))}, weight);
    }
};
test "bounded local child fresh verifies with terminal obligation still explicit" {
    const Child = @import("child.zig");
    const a = std.testing.allocator;
    const instances = [_]Frame.Instance{
        .{ .origin = .{ .core = .alu }, .row_log = 5, .terms = 1, .fixed_offset = 0, .main_offset = 0 },
        .{ .origin = .{ .core = .range16 }, .row_log = 5, .terms = 1, .fixed_offset = 2, .main_offset = 47 },
    };
    const scope = @import("receipt.zig").Scope{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .ordinal = 0 };
    const admitted = try Resource.Plan.forInstances(&instances, std.math.maxInt(usize));
    const child = try Child.Unbound.prove(a, admitted.peak_bytes, scope, &instances, BalancedMetadata{});
    defer child.deinit();
    try std.testing.expect(child.peak_gkr_owned_bytes <= child.plan.peak_bytes);
    var pending = try Child.verifyPending(a, scope, &instances, &child.result.proof, child.digest);
    defer pending.deinit(a);
    try std.testing.expect(child.peak_gkr_owned_bytes <= 1 << 20);
    var wrong_scope = scope;
    wrong_scope.main[0] ^= 1;
    const refused = Child.verifyPending(a, wrong_scope, &instances, &child.result.proof, child.digest);
    if (refused) |value| {
        var unexpected = value;
        unexpected.deinit(a);
        return error.TamperAccepted;
    } else |_| {}
    var wrong_digest = child.digest;
    wrong_digest[0] ^= 1;
    try std.testing.expectError(error.LocalGkrReceiptMismatch, Child.verifyPending(a, scope, &instances, &child.result.proof, wrong_digest));
}
test {
    _ = @import("metadata_test.zig");
}
fn lifecycleAllocationCase(a: std.mem.Allocator) !void {
    const instances = [_]Frame.Instance{
        .{ .origin = .{ .core = .alu }, .row_log = 5, .terms = 1, .fixed_offset = 0, .main_offset = 0 },
        .{ .origin = .{ .core = .range16 }, .row_log = 5, .terms = 1, .fixed_offset = 2, .main_offset = 47 },
    };
    const scope = @import("receipt.zig").Scope{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .ordinal = 0 };
    const Child = @import("child.zig");
    const admitted = try Resource.Plan.forInstances(&instances, std.math.maxInt(usize));
    const child = try Child.Unbound.prove(a, admitted.peak_bytes, scope, &instances, BalancedMetadata{});
    defer child.deinit();
    try std.testing.expect(child.peak_gkr_owned_bytes <= child.plan.peak_bytes);
    var pending = try Child.verifyPending(a, scope, &instances, &child.result.proof, child.digest);
    defer pending.deinit(a);
    const owned = try child.takeBindingCommit(&instances);
    defer owned.deinit(a);
}
test "local GKR owner and pending receiver clean up every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, lifecycleAllocationCase, .{});
}
fn readBinding(data: []const core.fields.m31.M31, rows: usize, offset: usize, p: usize) O {
    var coords: [8]core.fields.m31.M31 = undefined;
    for (&coords, 0..) |*v, i| v.* = data[(offset + i) * rows + p];
    return O.fromM31Array(coords);
}
test "Eq recurrence and cyclic prefix bind each terminal pair without cancellation" {
    const Child = @import("child.zig");
    const Binding = @import("binding.zig");
    const M = core.fields.m31.M31;
    const instances = [_]Frame.Instance{
        .{ .origin = .{ .core = .alu }, .row_log = 5, .terms = 1, .fixed_offset = 0, .main_offset = 0 },
        .{ .origin = .{ .core = .range16 }, .row_log = 5, .terms = 1, .fixed_offset = 2, .main_offset = 47 },
    };
    const scope = @import("receipt.zig").Scope{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .ordinal = 0 };
    const a = std.testing.allocator;
    const admitted = try Resource.Plan.forInstances(&instances, std.math.maxInt(usize));
    const child = try Child.Unbound.prove(a, admitted.peak_bytes, scope, &instances, BalancedMetadata{});
    defer child.deinit();
    try std.testing.expect(child.peak_gkr_owned_bytes <= child.plan.peak_bytes);
    var pending = try Child.verifyPending(a, scope, &instances, &child.result.proof, child.digest);
    defer pending.deinit(a);
    for (instances, child.binding.columns, pending.artifact.claims_to_verify_by_instance, 0..) |instance, data, claims, index| {
        const split = try Frame.splitPoint(instance, pending.artifact.ood_point, pending.artifact.n_variables_by_instance[index]);
        const point = try @import("../../../logup_gkr/mle_point.zig").MleEvalPointFor(O).init(split.rows);
        const rows = try instance.rows();
        const uniform = claims[0].add(pending.eta.mul(claims[1])).mulM31(try M.fromCanonical(@intCast(rows)).inv());
        for (0..rows) |logical| {
            const p = A.witness.physical(logical, instance.row_log);
            const pprev = A.witness.physical((logical + rows - 1) % rows, instance.row_log);
            const pnext = A.witness.physical((logical + 2) % rows, instance.row_log);
            const tuple = [1]O{O.fromBase(M.fromCanonical(@intCast(logical)))};
            const denominator = pending.challenges.denominatorFor(O, .range16, tuple);
            const projection = (if (index == 0) O.one() else O.one().neg()).add(pending.eta.mul(denominator));
            const t: usize = @ctz(~(logical / 2));
            var residuals: [3]O = undefined;
            var sink = A.evaluation.SinkFor(O){ .values = &residuals };
            Binding.emitFor(O, .{ .eq = readBinding(data, rows, 0, p), .eq_next2 = readBinding(data, rows, 0, pnext), .prefix = readBinding(data, rows, 8, p), .prefix_previous = readBinding(data, rows, 8, pprev) }, .{ .first = if (logical == 0) O.one() else O.zero(), .second = if (logical == 1) O.one() else O.zero(), .carry = if (logical % 2 == 0) point.hc0[t] else point.hc1[t], .eq0 = point.eq0, .eq1 = point.eq1 }, projection, uniform, &sink);
            for (residuals) |r| try std.testing.expect(r.isZero());
            if (logical == 3) {
                const bad = Binding.prefixResidualFor(O, readBinding(data, rows, 8, p).add(O.one()), readBinding(data, rows, 8, pprev), readBinding(data, rows, 0, p), projection, uniform);
                try std.testing.expect(!bad.isZero());
            }
        }
    }
}
test {
    _ = @import("role_test.zig");
}
fn omValue(seed: usize) O {
    var c: [8]core.fields.m31.M31 = undefined;
    for (&c, 0..) |*v, i| v.* = core.fields.m31.M31.fromCanonical(@intCast((seed * 719 + i * 79 + 3) % 65521));
    return O.fromM31Array(c);
}
test "all eight actual role terminal bindings have degree at most three" {
    const Role = @import("role.zig");
    const Main = A.main_only.authority;
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    const challenges = @import("challenges.zig").For(O).draw(&channel);
    var weights: [128]O = undefined;
    for (&weights, 0..) |*v, i| v.* = omValue(i + 331);
    for (std.enums.values(Main.Role)) |role| {
        const core_role: @import("../../../word16_execution/geometry.zig").Role = switch (role) {
            .cpu => .cpu,
            .alu => .alu,
            .binary => .binary,
            .shift => .shift,
            .ls => .ls,
            .jalr => .jalr,
            .mul => .multiplication,
            .div => .division,
        };
        const terms = @import("roster.zig").terms(core_role);
        const lanes: usize = @as(usize, 1) << @intCast(std.math.log2_int_ceil(u32, terms));
        var values: [5]O = undefined;
        for (&values, 0..) |*out, t| {
            const x = O.fromBase(core.fields.m31.M31.fromCanonical(@intCast(t)));
            var main: [256]O = undefined;
            var fixed: [64]O = undefined;
            for (&main, 0..) |*v, i| v.* = omValue(i + 11).add(omValue(i + 211).mul(x));
            for (&fixed, 0..) |*v, i| v.* = omValue(i + 31).add(omValue(i + 311).mul(x));
            var projection = @import("binding.zig").ProjectionFor(O){ .challenges = &challenges, .lane_weights = weights[0..lanes], .terms = terms };
            Role.emitLocalFor(O, role, fixed[0..Main.shape(role).fixed], main[0..Main.shape(role).main], O.one(), &projection);
            try projection.finish();
            out.* = projection.combine(omValue(771)).mul(omValue(991).add(omValue(191).mul(x)));
        }
        for (0..3) |order| for (0..4 - order) |t| {
            values[t] = values[t + 1].sub(values[t]);
        };
        try std.testing.expect(values[1].sub(values[0]).isZero());
    }
}
fn wireAllocationCase(a: std.mem.Allocator, instances: []const Frame.Instance, proof: *const @import("stwo_prover_engine").lookups.gkr_verifier.ForField(O).GkrBatchProof) !void {
    const W = @import("wire.zig");
    const bytes = try W.encode(a, instances, proof);
    defer a.free(bytes);
    var decoded = try W.decode(a, instances, bytes);
    defer decoded.deinit();
}
test "local OM child wire preserves canonical transcript rejects aliases and releases all partial decodes" {
    const Child = @import("child.zig");
    const W = @import("wire.zig");
    const a = std.testing.allocator;
    const instances = [_]Frame.Instance{
        .{ .origin = .{ .core = .alu }, .row_log = 5, .terms = 1, .fixed_offset = 0, .main_offset = 0 },
        .{ .origin = .{ .core = .range16 }, .row_log = 5, .terms = 1, .fixed_offset = 2, .main_offset = 47 },
    };
    const scope = @import("receipt.zig").Scope{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .ordinal = 0 };
    const admitted = try Resource.Plan.forInstances(&instances, std.math.maxInt(usize));
    const child = try Child.Unbound.prove(a, admitted.peak_bytes, scope, &instances, BalancedMetadata{});
    defer child.deinit();
    const bytes = try W.encode(a, &instances, &child.result.proof);
    defer a.free(bytes);
    var decoded = try W.decode(a, &instances, bytes);
    defer decoded.deinit();
    var pending = try Child.verifyPending(a, scope, &instances, &decoded.proof, child.digest);
    defer pending.deinit(a);
    const bad = try a.dupe(u8, bytes);
    defer a.free(bad);
    bad[0] ^= 1;
    try std.testing.expectError(error.LocalGkrWireProfile, W.decode(a, &instances, bad));
    bad[0] ^= 1;
    std.mem.writeInt(u32, bad[20..][0..4], core.fields.m31.Modulus, .little);
    try std.testing.expectError(error.NoncanonicalLocalGkrCoordinate, W.decode(a, &instances, bad));
    try std.testing.expectError(error.TruncatedLocalGkrProof, W.decode(a, &instances, bytes[0 .. bytes.len - 1]));
    const trailing = try a.alloc(u8, bytes.len + 1);
    defer a.free(trailing);
    @memcpy(trailing[0..bytes.len], bytes);
    trailing[bytes.len] = 0;
    try std.testing.expectError(error.TrailingLocalGkrBytes, W.decode(a, &instances, trailing));
    try std.testing.checkAllAllocationFailures(a, wireAllocationCase, .{ &instances, &child.result.proof });
}

test {
    _ = @import("manifest_test.zig");
    _ = @import("manifest_wire_test.zig");
    _ = @import("table_role_test.zig");
}

test "binding owned commit transfer is failure atomic and retains its parent allocator" {
    const Child = @import("child.zig");
    const a = std.testing.allocator;
    const instances = [_]Frame.Instance{
        .{ .origin = .{ .core = .alu }, .row_log = 5, .terms = 1, .fixed_offset = 0, .main_offset = 0 },
        .{ .origin = .{ .core = .range16 }, .row_log = 5, .terms = 1, .fixed_offset = 2, .main_offset = 47 },
    };
    const scope = @import("receipt.zig").Scope{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .ordinal = 0 };
    var failing = std.testing.FailingAllocator.init(a, .{});
    const parent = failing.allocator();
    const child = try Child.Unbound.prove(parent, 1 << 20, scope, &instances, BalancedMetadata{});
    defer child.deinit();
    const original = child.binding.columns[0].ptr;
    const reserved = child.budget.external_live_bytes;
    try std.testing.expect(reserved > 0);
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, child.takeBindingCommit(&instances));
    try std.testing.expectEqual(original, child.binding.columns[0].ptr);
    try std.testing.expectEqual(reserved, child.budget.external_live_bytes);
    failing.fail_index = std.math.maxInt(usize);
    const owned = try child.takeBindingCommit(&instances);
    defer owned.deinit(parent);
    try std.testing.expectEqual(original, owned.backings[0].ptr);
    try std.testing.expectEqual(0, child.budget.external_live_bytes);
    try std.testing.expectError(error.LocalGkrBindingUnavailable, child.takeBindingCommit(&instances));
}
test {
    _ = @import("global_cpu_test.zig");
}
test {
    _ = @import("cpu_worker_test.zig");
}
test {
    _ = @import("domain_pool_test.zig");
}

test {
    _ = @import("prepared_projection_test.zig");
}

// Keep binding-kernel tests explicitly reachable under focused test filters.
test {
    _ = @import("witness.zig");
    _ = @import("worker_protocol_test.zig");
}
test {
    _ = @import("query_metadata.zig");
}
test {
    _ = @import("source_bounds_test.zig");
}
