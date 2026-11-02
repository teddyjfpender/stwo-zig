//! Experimental circuit adapter for the SAME numerical GKR verifier used by
//! native QM31. No production receiver selects this module. Witness proof
//! values are guesses; the native Blake transcript is evaluated in circuit.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const lane = @import("../rv64_recursion/circuit_lane.zig");
pub const F = lane.Lane;
pub const Q = core.fields.qm31.QM31;
pub const Context = lane.Context;
pub const kernel = engine.lookups.verifier_kernel;
const native_channel = circuit.native_verifier.channel;
const Error = circuit.builder.context.Error;
const Var = circuit.builder.Var;

pub const Polynomial = struct {
    coefficients: []F,
    pub fn degree(self: Polynomial) usize {
        return if (self.coefficients.len == 0) 0 else self.coefficients.len - 1;
    }
    pub fn coeffsSlice(self: Polynomial) []const F {
        return self.coefficients;
    }
};
pub const Mask = struct { columns: [][2]F };
pub const Sumcheck = struct { round_polys: []Polynomial };
pub const Proof = struct {
    sumcheck_proofs: []Sumcheck,
    layer_masks_by_instance: [][]Mask,
    output_claims_by_instance: [][]F,
};

pub const Checks = struct {
    context: *Context,
    pub fn requireEq(self: Checks, lhs: F, rhs: F, _: kernel.Check) Error!void {
        try self.context.eq(lhs.v, rhs.v);
    }
};

/// The kernel's existing channel interface is infallible. Like circuit_lane,
/// latch builder errors and report them after emission; never accept a partial
/// graph. Caller may only deinit a context after an allocation failure.
pub const Channel = struct {
    context: *Context,
    inner: native_channel.NativeChannel,
    failure: ?Error = null,
    pub fn init(context: *Context) Error!Channel {
        return .{ .context = context, .inner = try native_channel.NativeChannel.init(Q, context) };
    }
    pub fn mixFelts(self: *Channel, values: []const F) void {
        if (self.failure != null) return;
        const wires = self.context.scratch().alloc(Var, values.len) catch |err| {
            self.failure = err;
            return;
        };
        for (wires, values) |*wire, value| wire.* = value.v;
        self.inner.mixFelts(Q, self.context, wires) catch |err| {
            self.failure = err;
        };
    }
    pub fn drawSecureFelt(self: *Channel) F {
        if (self.failure != null) return F.zero();
        return F.wire(self.inner.drawSecureFelt(Q, self.context) catch |err| {
            self.failure = err;
            return F.zero();
        });
    }
    pub fn finish(self: *const Channel) Error!void {
        if (self.failure) |err| return err;
    }
};

/// Scratch-owned topology views; all supplied proof field elements are actual
/// guessed wires. Coefficient lengths are explicit structural shape, not a
/// value-based trim in the circuit. Caller must admit a fixed production shape
/// before using this experimental adapter as part of a recursive receiver.
pub fn wireProof(context: *Context, native: *const engine.lookups.gkr_verifier.GkrBatchProof) !Proof {
    const a = context.scratch();
    const sc = try a.alloc(Sumcheck, native.sumcheck_proofs.len);
    for (sc, native.sumcheck_proofs) |*out, source| {
        out.round_polys = try a.alloc(Polynomial, source.round_polys.len);
        for (out.round_polys, source.round_polys) |*poly, value| {
            poly.coefficients = try a.alloc(F, value.coeffsSlice().len);
            for (poly.coefficients, value.coeffsSlice()) |*wire, coefficient|
                wire.* = F.wire(try context.guess(coefficient));
        }
    }
    const masks = try a.alloc([]Mask, native.layer_masks_by_instance.len);
    for (masks, native.layer_masks_by_instance) |*out, source| {
        out.* = try a.alloc(Mask, source.len);
        for (out.*, source) |*mask, value| {
            mask.columns = try a.alloc([2]F, value.columns.len);
            for (mask.columns, value.columns) |*column, input| {
                for (0..2) |i| column[i] = F.wire(try context.guess(input[i]));
            }
        }
    }
    const claims = try a.alloc([]F, native.output_claims_by_instance.len);
    for (claims, native.output_claims_by_instance) |*out, source| {
        out.* = try a.alloc(F, source.len);
        for (out.*, source) |*wire, value| wire.* = F.wire(try context.guess(value));
    }
    return .{ .sumcheck_proofs = sc, .layer_masks_by_instance = masks, .output_claims_by_instance = claims };
}

pub fn verify(context: *Context, gates: []const engine.lookups.gkr_verifier.Gate, proof: *const Proof, channel: *Channel) !kernel.Artifact(F) {
    const artifact = try kernel.partiallyVerifyBatch(F, context.gpa, gates, proof, channel, Checks{ .context = context });
    errdefer {
        var owned = artifact;
        owned.deinit(context.gpa);
    }
    try channel.finish();
    return artifact;
}
