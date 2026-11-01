//! Shared numerical GKR verification authority. Native QM31 and recursive
//! circuit wires execute the same arithmetic, transcript order and checks.
//! Proof shape is structural; witness values are never inspected for branching.
const std = @import("std");
const core = @import("stwo_core");
const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const utils = @import("utils.zig");
pub const GkrError = error{ MalformedProof, InvalidMask, NumInstancesMismatch, InvalidSumcheck, CircuitCheckFailure, ShapeMismatch };
pub const MAX_DEGREE: usize = 3;
pub const Check = enum { sum, gate, terminal };
pub fn Artifact(comptime F: type) type {
    return struct {
        ood_point: []F,
        claims_to_verify_by_instance: [][]F,
        n_variables_by_instance: []usize,
        pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
            a.free(self.ood_point);
            for (self.claims_to_verify_by_instance) |v| a.free(v);
            a.free(self.claims_to_verify_by_instance);
            a.free(self.n_variables_by_instance);
            self.* = undefined;
        }
    };
}
pub fn SumcheckArtifact(comptime F: type) type {
    return struct {
        assignment: []F,
        claimed_eval: F,
        pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
            a.free(self.assignment);
            self.* = undefined;
        }
    };
}
pub fn verifySumcheck(comptime F: type, a: std.mem.Allocator, initial: F, proof: anytype, channel: anytype, checks: anytype) !SumcheckArtifact(F) {
    var claim = initial;
    var assignment: std.ArrayList(F) = .empty;
    defer assignment.deinit(a);
    for (proof.round_polys) |poly| {
        if (poly.degree() > MAX_DEGREE) return error.DegreeInvalid;
        const coefficients = poly.coeffsSlice();
        const sum = utils.hornerEval(F, coefficients, F.zero()).add(utils.hornerEval(F, coefficients, F.one()));
        try checks.requireEq(claim, sum, .sum);
        channel.mixFelts(coefficients);
        const challenge = channel.drawSecureFelt();
        claim = utils.hornerEval(F, coefficients, challenge);
        try assignment.append(a, challenge);
    }
    return .{ .assignment = try assignment.toOwnedSlice(a), .claimed_eval = claim };
}
pub fn evalGate(comptime F: type, a: std.mem.Allocator, gate: anytype, columns: []const [2]F) GkrError![]F {
    return switch (gate) {
        .LogUp => blk: {
            if (columns.len != 2) return error.InvalidMask;
            const out = a.alloc(F, 2) catch return error.ShapeMismatch;
            out[0] = columns[0][0].mul(columns[1][1]).add(columns[0][1].mul(columns[1][0]));
            out[1] = columns[1][0].mul(columns[1][1]);
            break :blk out;
        },
        .GrandProduct => blk: {
            if (columns.len != 1) return error.InvalidMask;
            const out = a.alloc(F, 1) catch return error.ShapeMismatch;
            out[0] = columns[0][0].mul(columns[0][1]);
            break :blk out;
        },
    };
}
fn reduceMask(comptime F: type, a: std.mem.Allocator, columns: []const [2]F, x: F) ![]F {
    const out = try a.alloc(F, columns.len);
    for (columns, 0..) |column, i| out[i] = x.mul(column[1].sub(column[0])).add(column[0]);
    return out;
}
pub fn partiallyVerifyBatch(
    comptime F: type,
    allocator: std.mem.Allocator,
    gate_by_instance: anytype,
    proof: anytype,
    channel: anytype,
    checks: anytype,
) !Artifact(F) {
    if (proof.layer_masks_by_instance.len != proof.output_claims_by_instance.len) {
        return GkrError.MalformedProof;
    }

    const n_instances = proof.layer_masks_by_instance.len;
    var n_layers: usize = 0;
    for (proof.layer_masks_by_instance) |masks| {
        n_layers = @max(n_layers, masks.len);
    }

    if (n_layers != proof.sumcheck_proofs.len) return GkrError.MalformedProof;
    if (gate_by_instance.len != n_instances) return GkrError.NumInstancesMismatch;

    var ood_point = try allocator.alloc(F, 0);
    errdefer allocator.free(ood_point);

    var claims_to_verify_by_instance = try allocator.alloc(?[]F, n_instances);
    errdefer {
        for (claims_to_verify_by_instance) |maybe_claims| {
            if (maybe_claims) |claims| allocator.free(claims);
        }
        allocator.free(claims_to_verify_by_instance);
    }
    @memset(claims_to_verify_by_instance, null);

    for (proof.sumcheck_proofs, 0..) |*sumcheck_proof, layer| {
        const n_remaining_layers = n_layers - layer;

        for (0..n_instances) |instance| {
            if (proof.layer_masks_by_instance[instance].len == n_remaining_layers) {
                const fresh_claims = try allocator.dupe(
                    F,
                    proof.output_claims_by_instance[instance],
                );
                try replaceClaim(
                    F,
                    allocator,
                    &claims_to_verify_by_instance[instance],
                    fresh_claims,
                );
            }
        }

        for (claims_to_verify_by_instance) |maybe_claims| {
            if (maybe_claims) |claims| channel.mixFelts(claims);
        }

        const sumcheck_alpha = channel.drawSecureFelt();
        const instance_lambda = channel.drawSecureFelt();

        var sumcheck_claims = std.ArrayList(F).empty;
        defer sumcheck_claims.deinit(allocator);

        var sumcheck_instances = std.ArrayList(usize).empty;
        defer sumcheck_instances.deinit(allocator);

        for (claims_to_verify_by_instance, 0..) |maybe_claims, instance| {
            if (maybe_claims) |claims| {
                const n_unused_variables = n_layers - proof.layer_masks_by_instance[instance].len;
                const claim = scaleBase(F, utils.hornerEval(F, claims, instance_lambda), pow2Base(n_unused_variables));
                try sumcheck_claims.append(allocator, claim);
                try sumcheck_instances.append(allocator, instance);
            }
        }

        const sumcheck_claim = utils.hornerEval(F, sumcheck_claims.items, sumcheck_alpha);

        var sumcheck_artifact = verifySumcheck(
            F,
            allocator,
            sumcheck_claim,
            sumcheck_proof,
            channel,
            checks,
        ) catch |err| switch (err) {
            std.mem.Allocator.Error.OutOfMemory => return error.OutOfMemory,
            error.DegreeInvalid => return GkrError.InvalidSumcheck,
            else => |other| return other,
        };
        defer sumcheck_artifact.deinit(allocator);

        var layer_evals = std.ArrayList(F).empty;
        defer layer_evals.deinit(allocator);

        for (sumcheck_instances.items) |instance| {
            const n_unused = n_layers - proof.layer_masks_by_instance[instance].len;
            if (layer < n_unused) return GkrError.MalformedProof;
            const instance_layer = layer - n_unused;
            if (instance_layer >= proof.layer_masks_by_instance[instance].len) {
                return GkrError.MalformedProof;
            }

            const mask = &proof.layer_masks_by_instance[instance][instance_layer];
            const gate_output = evalGate(F, allocator, gate_by_instance[instance], mask.columns) catch |err| switch (err) {
                GkrError.InvalidMask => return GkrError.InvalidMask,
                else => |other| return other,
            };
            defer allocator.free(gate_output);

            const eq_eval = utils.eq(
                F,
                ood_point[n_unused..],
                sumcheck_artifact.assignment[n_unused..],
            ) catch return GkrError.ShapeMismatch;

            try layer_evals.append(
                allocator,
                eq_eval.mul(utils.hornerEval(F, gate_output, instance_lambda)),
            );
        }

        const layer_eval = utils.hornerEval(F, layer_evals.items, sumcheck_alpha);
        try checks.requireEq(sumcheck_artifact.claimed_eval, layer_eval, .gate);

        for (sumcheck_instances.items) |instance| {
            const n_unused = n_layers - proof.layer_masks_by_instance[instance].len;
            const instance_layer = layer - n_unused;
            const mask = &proof.layer_masks_by_instance[instance][instance_layer];
            const flattened = try flattenMaskColumns(F, allocator, mask.columns);
            defer allocator.free(flattened);
            channel.mixFelts(flattened);
        }

        const challenge = channel.drawSecureFelt();
        const next_ood = try allocator.alloc(F, sumcheck_artifact.assignment.len + 1);
        @memcpy(next_ood[0..sumcheck_artifact.assignment.len], sumcheck_artifact.assignment);
        next_ood[sumcheck_artifact.assignment.len] = challenge;
        allocator.free(ood_point);
        ood_point = next_ood;

        for (sumcheck_instances.items) |instance| {
            const n_unused = n_layers - proof.layer_masks_by_instance[instance].len;
            const instance_layer = layer - n_unused;
            const mask = &proof.layer_masks_by_instance[instance][instance_layer];
            const reduced = try reduceMask(F, allocator, mask.columns, challenge);
            try replaceClaim(F, allocator, &claims_to_verify_by_instance[instance], reduced);
        }
    }

    // Validate before transferring ownership so any allocation failure keeps
    // every claim under the existing errdefer (no partially transferred leak).
    for (claims_to_verify_by_instance) |claims| if (claims == null) return GkrError.MalformedProof;
    const n_variables_by_instance = try allocator.alloc(usize, n_instances);
    errdefer allocator.free(n_variables_by_instance);
    const finalized_claims = try allocator.alloc([]F, n_instances);
    errdefer allocator.free(finalized_claims);
    for (claims_to_verify_by_instance, 0..) |claims, i| {
        finalized_claims[i] = claims.?;
        claims_to_verify_by_instance[i] = null;
        n_variables_by_instance[i] = proof.layer_masks_by_instance[i].len;
    }

    allocator.free(claims_to_verify_by_instance);
    return .{
        .ood_point = ood_point,
        .claims_to_verify_by_instance = finalized_claims,
        .n_variables_by_instance = n_variables_by_instance,
    };
}

fn replaceClaim(
    comptime F: type,
    allocator: std.mem.Allocator,
    slot: *?[]F,
    next: []F,
) !void {
    if (slot.*) |old| allocator.free(old);
    slot.* = next;
}

fn flattenMaskColumns(comptime F: type, allocator: std.mem.Allocator, columns: []const [2]F) ![]F {
    const out = try allocator.alloc(F, columns.len * 2);
    for (columns, 0..) |column, i| {
        out[2 * i] = column[0];
        out[2 * i + 1] = column[1];
    }
    return out;
}

fn pow2Base(n: usize) M31 {
    var out = M31.one();
    var i: usize = 0;
    while (i < n) : (i += 1) {
        out = out.add(out);
    }
    return out;
}

/// Final input claims must be connected to authenticated input-expression
/// evaluations. Exposing the artifact alone is NOT a complete GKR verifier.
pub fn verifyTerminalInputs(comptime F: type, artifact: *const Artifact(F), expected: anytype, checks: anytype) !void {
    if (expected.len != artifact.claims_to_verify_by_instance.len) return error.ShapeMismatch;
    for (artifact.claims_to_verify_by_instance, expected) |claims, inputs| {
        if (claims.len != inputs.len) return error.ShapeMismatch;
        for (claims, inputs) |claim, input| try checks.requireEq(claim, input, .terminal);
    }
}

fn scaleBase(comptime F: type, value: F, scale: M31) F {
    if (F == QM31) return value.mulM31(scale);
    return value.mul(F.fromBase(scale));
}
