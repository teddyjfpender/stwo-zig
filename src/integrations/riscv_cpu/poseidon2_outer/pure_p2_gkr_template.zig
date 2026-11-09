//! Bounded GKR wire-shape advice, never a proof. Instance/layer/round/mask counts
//! come solely from the trusted roster. Only original legal coefficient lengths
//! (0..4) vary; retain them because native polynomials trim leading zeroes.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const O = @import("stwo_core").fields.om31.OM31;
const Frame = @import("../word16_global_execution/services/gkr_local/frame.zig");
const GV = engine.lookups.gkr_verifier.ForField(O);
const SC = engine.lookups.sumcheck.ForField(O);
const Poly = engine.lookups.utils.UnivariatePoly(O);
pub const MAX_LAYERS: usize = 30;
pub const MAX_COEFFICIENT_LENGTHS = MAX_LAYERS * (MAX_LAYERS - 1) / 2;
pub fn layers(instances: []const Frame.Instance) !usize {
    return layersImpl(instances);
}
pub fn count(instances: []const Frame.Instance) !usize {
    return countImpl(instances);
}
pub fn validate(instances: []const Frame.Instance, lengths: []const u8) !void {
    return validateImpl(instances, lengths);
}
pub fn fromProof(a: std.mem.Allocator, instances: []const Frame.Instance, proof: *const GV.GkrBatchProof) ![]u8 {
    return fromProofImpl(a, instances, proof);
}
pub fn skeleton(a: std.mem.Allocator, instances: []const Frame.Instance, lengths: []const u8) !GV.GkrBatchProof {
    return skeletonImpl(a, instances, lengths);
}
pub const Truth = struct {
    pub fn layers(instances: []const @import("../word16_global_execution/services/gkr_local/truth_frame.zig").Instance) !usize {
        return layersImpl(instances);
    }
    pub fn count(instances: []const @import("../word16_global_execution/services/gkr_local/truth_frame.zig").Instance) !usize {
        return countImpl(instances);
    }
    pub fn validate(instances: []const @import("../word16_global_execution/services/gkr_local/truth_frame.zig").Instance, lengths: []const u8) !void {
        return validateImpl(instances, lengths);
    }
    pub fn fromProof(a: std.mem.Allocator, instances: []const @import("../word16_global_execution/services/gkr_local/truth_frame.zig").Instance, proof: *const GV.GkrBatchProof) ![]u8 {
        return fromProofImpl(a, instances, proof);
    }
    pub fn skeleton(a: std.mem.Allocator, instances: []const @import("../word16_global_execution/services/gkr_local/truth_frame.zig").Instance, lengths: []const u8) !GV.GkrBatchProof {
        return skeletonImpl(a, instances, lengths);
    }
};
fn layersImpl(instances: anytype) !usize {
    if (instances.len == 0 or instances.len > 128) return error.InvalidOpGkrTemplateRoster;
    var n: usize = 0;
    for (instances) |instance| n = @max(n, try instance.variables());
    if (n > MAX_LAYERS) return error.InvalidOpGkrTemplateLayers;
    return n;
}
fn countImpl(instances: anytype) !usize {
    const n = try layersImpl(instances);
    return n * (n - 1) / 2;
}
fn validateImpl(instances: anytype, lengths: []const u8) !void {
    if (lengths.len != try countImpl(instances)) return error.InvalidOpGkrTemplateLength;
    for (lengths) |n| if (n > 4) return error.InvalidOpGkrTemplateDegree;
}
fn fromProofImpl(a: std.mem.Allocator, instances: anytype, proof: *const GV.GkrBatchProof) ![]u8 {
    const n = try layersImpl(instances);
    if (proof.sumcheck_proofs.len != n or proof.layer_masks_by_instance.len != instances.len or proof.output_claims_by_instance.len != instances.len) return error.InvalidOpGkrTemplateShape;
    for (instances, proof.layer_masks_by_instance, proof.output_claims_by_instance) |instance, masks, outputs| {
        if (masks.len != try instance.variables() or outputs.len != 2) return error.InvalidOpGkrTemplateShape;
        for (masks) |mask| if (mask.columns.len != 2) return error.InvalidOpGkrTemplateShape;
    }
    const lengths = try a.alloc(u8, try countImpl(instances));
    errdefer a.free(lengths);
    var at: usize = 0;
    for (proof.sumcheck_proofs, 0..) |sumcheck, layer| {
        if (sumcheck.round_polys.len != layer) return error.InvalidOpGkrTemplateShape;
        for (sumcheck.round_polys) |poly| {
            const width = poly.coeffsSlice().len;
            if (width > 4) return error.InvalidOpGkrTemplateDegree;
            lengths[at] = @intCast(width);
            at += 1;
        }
    }
    try validateImpl(instances, lengths);
    return lengths;
}
/// Caller-owned arena. These zero elements are used ONLY by trace-only circuit
/// construction; this API must never enter a native proof acceptance path.
fn skeletonImpl(a: std.mem.Allocator, instances: anytype, lengths: []const u8) !GV.GkrBatchProof {
    try validateImpl(instances, lengths);
    const n = try layersImpl(instances);
    const sumchecks = try a.alloc(SC.SumcheckProof, n);
    var at: usize = 0;
    for (sumchecks, 0..) |*sumcheck, layer| {
        sumcheck.round_polys = try a.alloc(Poly, layer);
        for (sumcheck.round_polys) |*poly| {
            const width = lengths[at];
            at += 1;
            const coeffs = try a.alloc(O, width);
            @memset(coeffs, O.zero());
            // Deliberately preserve the admitted native wire length: using
            // initOwned would trim these placeholder values and change the AST.
            poly.* = .{ .coeffs = coeffs, .len = width, .owns_coeffs = true };
        }
    }
    const masks = try a.alloc([]GV.GkrMask, instances.len);
    const outputs = try a.alloc([]O, instances.len);
    for (instances, masks, outputs) |instance, *instance_masks, *instance_outputs| {
        instance_masks.* = try a.alloc(GV.GkrMask, try instance.variables());
        for (instance_masks.*) |*mask| {
            mask.columns = try a.alloc([2]O, 2);
            @memset(mask.columns, .{ O.zero(), O.zero() });
        }
        instance_outputs.* = try a.alloc(O, 2);
        @memset(instance_outputs.*, O.zero());
    }
    return .{ .sumcheck_proofs = sumchecks, .layer_masks_by_instance = masks, .output_claims_by_instance = outputs };
}

test "OP pure P2 GKR template derives all dimensions from roster and bounds coefficient advice" {
    const a = std.testing.allocator;
    const instances = [_]Frame.Instance{.{ .origin = .{ .core = .cpu }, .row_log = 5, .terms = 3, .fixed_offset = 0, .main_offset = 0 }};
    const lengths = try a.alloc(u8, try count(&instances));
    defer a.free(lengths);
    for (lengths, 0..) |*length, i| length.* = @intCast(i % 5);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var proof = try skeleton(arena.allocator(), &instances, lengths);
    const extracted = try fromProof(a, &instances, &proof);
    defer a.free(extracted);
    try std.testing.expectEqualSlices(u8, lengths, extracted);
    try std.testing.expectError(error.InvalidOpGkrTemplateLength, validate(&instances, lengths[1..]));
    lengths[0] = 5;
    try std.testing.expectError(error.InvalidOpGkrTemplateDegree, validate(&instances, lengths));
    lengths[0] = 0;
    proof.output_claims_by_instance[0] = proof.output_claims_by_instance[0][0..1];
    try std.testing.expectError(error.InvalidOpGkrTemplateShape, fromProof(a, &instances, &proof));
}

// The producer's polynomial constructor trims zeroes; the native wire decoder
// intentionally does NOT. Verify the actual accepted wire/kernel semantics.
test "OP pure P2 native and circuit sumcheck preserve trailing-zero declared vector" {
    const C = @import("../rv64_recursion/om31_poseidon/common.zig");
    const Native = @import("pure_p2_native.zig");
    const Q = C.Q;
    const K = engine.lookups.verifier_kernel;
    const a = std.testing.allocator;
    var coeffs = [_]O{ O.zero(), O.zero() };
    var polys = [_]Poly{.{ .coeffs = &coeffs, .len = 2, .owns_coeffs = false }};
    var native_proof = SC.SumcheckProof{ .round_polys = &polys };
    var native_channel = Native.Channel.init();
    var native = try K.verifySumcheck(O, a, O.zero(), &native_proof, &native_channel, GV.NativeChecks{});
    defer native.deinit(a);
    var owner = try C.PoseidonContext.init(a, 1);
    defer owner.deinit();
    C.begin(&owner);
    var active = true;
    defer if (active) C.finish() catch {};
    const ctx = owner.algebra();
    const Polynomial = struct {
        coefficients: []C.F,
        pub fn degree(self: @This()) usize {
            return self.coefficients.len - 1;
        }
        pub fn coeffsSlice(self: @This()) []const C.F {
            return self.coefficients;
        }
    };
    var wire_coeffs = [_]C.F{ try C.F.guess(ctx, O.zero()), try C.F.guess(ctx, O.zero()) };
    var wire_polys = [_]Polynomial{.{ .coefficients = &wire_coeffs }};
    var proof = struct { round_polys: []Polynomial }{ .round_polys = &wire_polys };
    const Channel = struct {
        ctx: *C.Context,
        inner: C.Channel,
        failure: ?anyerror = null,
        pub fn mixFelts(self: *@This(), values: []const C.F) void {
            self.inner.mixFelts(self.ctx, values) catch |err| {
                self.failure = err;
            };
        }
        pub fn drawSecureFelt(self: *@This()) C.F {
            return self.inner.draw(self.ctx) catch |err| {
                self.failure = err;
                return C.F.zero();
            };
        }
    };
    const Checks = struct {
        ctx: *C.Context,
        pub fn requireEq(self: @This(), x: C.F, y: C.F, _: K.Check) !void {
            try C.eq(self.ctx, x, y);
        }
    };
    var channel = Channel{ .ctx = ctx, .inner = try C.Channel.init(ctx) };
    var constrained = try K.verifySumcheck(C.F, a, C.F.zero(), &proof, &channel, Checks{ .ctx = ctx });
    defer constrained.deinit(a);
    if (channel.failure) |err| return err;
    try std.testing.expect(native.assignment[0].eql(constrained.assignment[0].value()));
    const out = constrained.assignment[0].c0.v;
    try C.finish();
    active = false;
    try owner.setOutputs(&.{out});
    try owner.finalize();
    try std.testing.expect(try owner.isCircuitValid());
    const saved = ctx.get(wire_coeffs[1].c0.v);
    ctx.value_table.items[wire_coeffs[1].c0.v.idx] = saved.add(Q.one());
    try std.testing.expect(!try owner.isCircuitValid());
    ctx.value_table.items[wire_coeffs[1].c0.v.idx] = saved;
}

test "OP R6 truth GKR template preserves source-specific query bounds" {
    const a = std.testing.allocator;
    const TF = @import("../word16_global_execution/services/gkr_local/truth_frame.zig");
    const instances = [_]TF.Instance{.{ .role = .keccak, .row_log = 5, .queries = 2048 }};
    try std.testing.expectEqual(@as(usize, 16), try Truth.layers(&instances));
    const lengths = try a.alloc(u8, try Truth.count(&instances));
    defer a.free(lengths);
    @memset(lengths, 4);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const proof = try Truth.skeleton(arena.allocator(), &instances, lengths);
    const retained = try Truth.fromProof(a, &instances, &proof);
    defer a.free(retained);
    try std.testing.expectEqualSlices(u8, lengths, retained);
    var bad = instances;
    bad[0].queries = 2049;
    try std.testing.expectError(error.InvalidTruthGkrQueries, Truth.layers(&bad));
    bad = instances;
    bad[0].row_log = 22;
    try std.testing.expectError(error.InvalidTruthGkrGeometry, Truth.layers(&bad));
    lengths[0] = 5;
    try std.testing.expectError(error.InvalidOpGkrTemplateDegree, Truth.validate(&instances, lengths));
}
