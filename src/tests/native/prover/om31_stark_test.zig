//! Actual small boolean M31 AIR through OM31 composition, PCS, FRI and core receiver.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const S = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Point = core.circle.CirclePoint(S);
const A = std.testing.allocator;
const P = engine.air.component_prover.ForField(S);
const D = engine.air.accumulation.ForField(S);
const K = core.air.components.ForField(S);
const Acc = core.air.accumulation.ForField(S);
const PCS = engine.pcs.ForField(S);
const CP = core.pcs.ForField(S);
const CPU = @import("stwo_cpu_backend").CpuBackend;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const C = core.channel.raw_mod_m31.Om31Channel;
const MC = struct {
    pub fn mixRoot(c: *C, root: H.Hash) void {
        core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel.mixRoot(&c.inner, root);
    }
};
const E = engine.engine.ForField(S).ProverEngine(CPU, H, MC, C);
const Air = struct {
    log: u32 = 4,
    main_index: usize = 0,
    const Adapter = core.air.derive.ForField(S).ComponentAdapter(@This(), P.ComponentProver, P.Trace, D.DomainEvaluationAccumulator);
    pub fn nConstraints(_: *const @This()) usize {
        return 2;
    }
    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log + 1;
    }
    pub fn traceLogDegreeBounds(self: *const @This(), a: std.mem.Allocator) !K.TraceLogDegreeBounds {
        const trees = try a.alloc([]u32, 2);
        errdefer a.free(trees);
        trees[0] = try a.alloc(u32, 0);
        errdefer a.free(trees[0]);
        trees[1] = try a.dupe(u32, &.{self.log});
        return K.TraceLogDegreeBounds.initOwned(trees);
    }
    pub fn maskPoints(_: *const @This(), a: std.mem.Allocator, point: Point, _: u32) !K.MaskPoints {
        const trees = try a.alloc([][]Point, 2);
        errdefer a.free(trees);
        trees[0] = try a.alloc([]Point, 0);
        errdefer a.free(trees[0]);
        trees[1] = try a.alloc([]Point, 1);
        errdefer a.free(trees[1]);
        trees[1][0] = try a.dupe(Point, &.{point});
        return K.MaskPoints.initOwned(trees);
    }
    pub fn preprocessedColumnIndices(_: *const @This(), a: std.mem.Allocator) ![]usize {
        return a.alloc(usize, 0);
    }
    fn quotient(self: *const @This(), point: Point, v: S) !S {
        const z = core.constraints.cosetVanishing(S, core.poly.circle.canonic.CanonicCoset.new(self.log).coset(), point);
        return v.mul(v.sub(S.one())).div(z);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: Point, mask: *const K.MaskValues, acc: *Acc.PointEvaluationAccumulator, max_log: u32) !void {
        if (max_log < self.log) return error.InvalidStructure;
        const native_point = point.repeatedDouble(max_log - self.log);
        const q = try self.quotient(native_point, mask.items[1][self.main_index][0]);
        acc.accumulate(q);
        acc.accumulate(q);
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const P.Trace, acc: *D.DomainEvaluationAccumulator) !void {
        const poly = trace.polys.items[1][self.main_index].coefficients orelse return error.MissingCoefficients;
        const log = self.log + 1;
        const domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
        var col = try engine.secure_column.SecureColumnByCoordsFor(S).uninitialized(acc.allocator, domain.size());
        defer col.deinit(acc.allocator);
        for (0..domain.size()) |i| {
            const p = domain.at(core.utils.bitReverseIndex(i, log));
            const point = Point{ .x = S.fromBase(p.x), .y = S.fromBase(p.y) };
            col.set(i, try self.quotient(point, poly.evalAtPointFor(S, point)));
        }
        try acc.accumulateColumn(log, &col);
        try acc.accumulateColumn(log, &col);
    }
};
fn configWithFold(fold: u32) !CP.PcsConfig {
    var c = CP.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.ForField(S).FriConfig.init(0, 1, 12) };
    c.fri_config.fold_step = fold;
    return c;
}
fn produce(a: std.mem.Allocator) !E.ExtendedProof {
    return produceTrace(a, false);
}
fn produceTrace(a: std.mem.Allocator, invalid: bool) !E.ExtendedProof {
    return produceTraceWithFold(a, invalid, 1);
}
pub fn produceTraceWithFold(a: std.mem.Allocator, invalid: bool, fold: u32) !E.ExtendedProof {
    return produceTraceWithStorage(a, invalid, fold, false, null);
}
pub fn produceTraceWithStorage(a: std.mem.Allocator, invalid: bool, fold: u32, compact: bool, byte_limit: ?usize) !E.ExtendedProof {
    const cfg = try configWithFold(fold);
    var channel = C.init();
    cfg.mixInto(&channel);
    var scheme = try E.init(a, cfg);
    scheme.compact_polynomial_storage = compact;
    scheme.compact_polynomial_min_log_size = 0;
    scheme.wide_quotient_group_byte_limit = byte_limit;
    var owns = true;
    errdefer if (owns) scheme.deinit(a);
    try scheme.commit(a, &.{}, &channel);
    var values: [16]M = undefined;
    for (&values, 0..) |*v, i| v.* = M.fromCanonical(@intCast((i * i + i / 3) & 1));
    if (invalid) values[3] = M.fromCanonical(2);
    try scheme.commit(a, &.{.{ .log_size = 4, .values = &values }}, &channel);
    const air = Air{};
    const components = [_]P.ComponentProver{Air.Adapter.asProverComponent(&air)};
    owns = false;
    return E.prove(a, &components, &channel, scheme, .{});
}
fn verify(a: std.mem.Allocator, proof: core.proof.ForField(S).StarkProof(H)) !void {
    return verifyFold(a, proof, 1);
}
pub fn verifyFold(a: std.mem.Allocator, proof: core.proof.ForField(S).StarkProof(H), fold: u32) !void {
    var owned = proof;
    var owns = true;
    defer if (owns) owned.deinit(a);
    if (proof.commitment_scheme_proof.commitments.items.len != 3) return error.InvalidStructure;
    const cfg = try configWithFold(fold);
    var channel = C.init();
    cfg.mixInto(&channel);
    var receiver = try CP.verifier.CommitmentSchemeVerifier(H, MC).init(a, cfg);
    defer receiver.deinit(a);
    try receiver.commit(a, proof.commitment_scheme_proof.commitments.items[0], &.{}, &channel);
    try receiver.commit(a, proof.commitment_scheme_proof.commitments.items[1], &.{4}, &channel);
    const air = Air{};
    const component = Air.Adapter.asVerifierComponent(&air);
    owns = false;
    try core.verifier.ForField(S).verify(H, MC, a, &.{component}, &channel, &receiver, proof);
}
test "OM31 STARK actual boolean AIR full prover and fresh receiver" {
    var proof = try produce(A);
    defer proof.aux.deinit(A);
    try std.testing.expectEqual(@as(usize, 16), proof.proof.commitment_scheme_proof.sampled_values.items[2].len);
    try std.testing.expect(!proof.proof.commitment_scheme_proof.sampled_values.items[1][0][0].c1.isZero());
    try verify(A, proof.proof);
}

fn exercise(a: std.mem.Allocator) !void {
    var p = try produce(a);
    defer p.aux.deinit(a);
    try verify(a, p.proof);
}
test "OM31 STARK allocation failures release all pipeline owners" {
    try std.testing.checkAllAllocationFailures(A, exercise, .{});
}
test "OM31 STARK rejects altered samples openings root and terminal" {
    const Mutation = enum { main_sample, composition_sample, opening, root, terminal, shape };
    for (std.enums.values(Mutation)) |kind| {
        var p = try produce(A);
        defer p.aux.deinit(A);
        const proof = &p.proof.commitment_scheme_proof;
        switch (kind) {
            .main_sample => {
                proof.sampled_values.items[1][0][0] = proof.sampled_values.items[1][0][0].add(S.basis());
            },
            .composition_sample => {
                proof.sampled_values.items[2][0][0] = proof.sampled_values.items[2][0][0].add(S.basis());
            },
            .opening => {
                proof.queried_values.items[1][0][0] = proof.queried_values.items[1][0][0].add(M.one());
            },
            .root => {
                proof.commitments.items[1][0] ^= 1;
            },
            .terminal => {
                proof.fri_proof.last_layer_poly.coeffs[0] = proof.fri_proof.last_layer_poly.coeffs[0].add(S.basis());
            },
            .shape => {
                A.free(proof.sampled_values.items[2][0]);
                proof.sampled_values.items[2][0] = &.{};
            },
        }
        verify(A, p.proof) catch |err| {
            switch (err) {
                error.InvalidStructure, error.OodsNotMatching, error.RootMismatch, error.InvalidQueryShape, error.FirstLayerCommitmentInvalid, error.FirstLayerEvaluationsInvalid, error.InnerLayerCommitmentInvalid, error.InnerLayerEvaluationsInvalid, error.LastLayerDegreeInvalid, error.LastLayerEvaluationsInvalid, error.InvalidNumFriLayers, error.WitnessTooShort, error.WitnessTooLong => {},
                else => return err,
            }
            std.debug.print("OM31_STARK_REJECT {s} {s}\n", .{ @tagName(kind), @errorName(err) });
            continue;
        };
        std.debug.print("accepted mutation {s}\n", .{@tagName(kind)});
        return error.ExpectedRejection;
    }
}

test "OM31 STARK rejects an invalid boolean trace before returning a proof" {
    var proof = produceTrace(A, true) catch |err| switch (err) {
        error.ConstraintsNotSatisfied, error.InvalidLastLayerDegree => return,
        else => return err,
    };
    proof.deinit(A);
    return error.ExpectedRejection;
}

test "OM31 STARK complete fold4 profile verifies through wide lazy PCS" {
    var proof = try produceTraceWithFold(A, false, 4);
    defer proof.aux.deinit(A);
    try verifyFold(A, proof.proof, 4);
}

pub fn produceMixedWithStorage(a: std.mem.Allocator, fold: u32, compact: bool, byte_limit: ?usize) !E.ExtendedProof {
    return produceMixedWithStorageThreshold(a, fold, compact, byte_limit, 0);
}
pub fn produceMixedWithStorageThreshold(a: std.mem.Allocator, fold: u32, compact: bool, byte_limit: ?usize, minimum_log: u32) !E.ExtendedProof {
    const cfg = try configWithFold(fold);
    var channel = C.init();
    cfg.mixInto(&channel);
    var scheme = try E.init(a, cfg);
    scheme.compact_polynomial_storage = compact;
    scheme.compact_polynomial_min_log_size = minimum_log;
    scheme.wide_quotient_group_byte_limit = byte_limit;
    var owns = true;
    errdefer if (owns) scheme.deinit(a);
    try scheme.commit(a, &.{}, &channel);
    var small: [32]M = undefined;
    var large: [64]M = undefined;
    for (&small, 0..) |*v, i| v.* = M.fromCanonical(@intCast((i * i + i / 3) & 1));
    for (&large, 0..) |*v, i| v.* = M.fromCanonical(@intCast((i + i / 5) & 1));
    try scheme.commit(a, &.{ .{ .log_size = 5, .values = &small }, .{ .log_size = 6, .values = &large } }, &channel);
    const roles = [_]Air{ .{ .log = 5, .main_index = 0 }, .{ .log = 6, .main_index = 1 } };
    const components = [_]P.ComponentProver{ Air.Adapter.asProverComponent(&roles[0]), Air.Adapter.asProverComponent(&roles[1]) };
    owns = false;
    return E.prove(a, &components, &channel, scheme, .{});
}

pub fn verifyMixed(a: std.mem.Allocator, proof: core.proof.ForField(S).StarkProof(H), fold: u32) !void {
    const cfg = try configWithFold(fold);
    const roles = [_]Air{ .{ .log = 5, .main_index = 0 }, .{ .log = 6, .main_index = 1 } };
    var owned_proof = proof;
    var owned = true;
    defer if (owned) owned_proof.deinit(a);
    var fresh = C.init();
    cfg.mixInto(&fresh);
    var receiver = try CP.verifier.CommitmentSchemeVerifier(H, MC).init(a, cfg);
    defer receiver.deinit(a);
    try receiver.commit(a, proof.commitment_scheme_proof.commitments.items[0], &.{}, &fresh);
    try receiver.commit(a, proof.commitment_scheme_proof.commitments.items[1], &.{ 5, 6 }, &fresh);
    const verify_components = [_]K.Component{ Air.Adapter.asVerifierComponent(&roles[0]), Air.Adapter.asVerifierComponent(&roles[1]) };
    owned = false;
    try core.verifier.ForField(S).verify(H, MC, a, &verify_components, &fresh, &receiver, proof);
}
fn mixed(a: std.mem.Allocator, fold: u32) !void {
    var proof = try produceMixedWithStorage(a, fold, false, null);
    defer proof.aux.deinit(a);
    try verifyMixed(a, proof.proof, fold);
}

test "OM31 STARK mixed log5 log6 MAIN baseline folds samples per column" {
    try mixed(A, 1);
    try mixed(A, 4);
}
