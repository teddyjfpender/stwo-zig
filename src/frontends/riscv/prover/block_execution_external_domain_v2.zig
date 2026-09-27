//! Domain-side quotient evaluation for SHA/Keccak caller access components.
//! The sampled source polynomials are the replayed, root-pinned native trees.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const canonic = core.poly.circle.canonic;
const support = @import("../air/memory_commitment/hash_component_prepared_support.zig");
const integer = @import("block_execution_integer_bridge_v2.zig");
const sidecar_eval = @import("block_execution_sidecar_stark_eval_v2.zig");
const v5_eval = @import("block_v5_opcode_sidecar_eval_v1.zig");
const external = @import("block_execution_external_access_bridge_v2.zig");
const sha = @import("../air/guest_precompile/sha256_memory_caller.zig");
const signer = @import("../air/guest_precompile/secp256k1_recovery_caller.zig");
const keccak = @import("../air/guest_precompile/keccakf_caller.zig");
const keccak_trace = @import("../air/guest_precompile/keccakf_trace.zig");

pub fn evaluate(self: anytype, source: *const engine.air.component_prover.Trace, accumulator: *engine.air.accumulation.DomainEvaluationAccumulator) !void {
    const descriptor = self.external_source orelse return error.MissingExternalAccessDescriptor;
    const a = accumulator.allocator;
    if (descriptor.slot >= descriptor.count()) return error.InvalidExternalAccessDescriptor;
    if (source.polys.items.len != 4) return error.InvalidExternalAccessTrees;
    const trees = source.polys.items;
    const fixed_count: usize = if (descriptor.kind == .sha) 1 else 0;
    const caller_count: usize = switch (descriptor.kind) {
        .sha => sha.PHYSICAL_MAIN_COLUMN_COUNT,
        .keccak => keccak.Layout.main_columns,
        .signer => signer.Layout.main_columns,
    };
    // Each Keccak memory component depends on one word, and its register
    // pointer component depends on none. The complete descriptor/tree span
    // below and the PCS sample masks remain unchanged. Every selected source
    // polynomial still passes the same full-LDE degree recovery checks.
    const state_count: usize = if (descriptor.kind == .keccak and descriptor.slot != 0) 32 else 0;
    const interaction_count: usize = if (self.v5_universal != null) v5_eval.INTERACTION_COUNT else sidecar_eval.INTERACTION_COUNT;
    if (trees[0].len < descriptor.fixed_offset + fixed_count or
        trees[1].len < descriptor.main_offset + descriptor.mainWidth() or
        trees[2].len < self.witness_offset + integer.COLUMN_COUNT or
        trees[3].len < self.interaction_offset + interaction_count)
        return error.InvalidExternalAccessColumns;
    const caller_offset = descriptor.main_offset + (if (descriptor.kind == .keccak) keccak_trace.Layout.caller else @as(usize, 0));
    const state_offset = descriptor.main_offset + keccak_trace.Layout.state;
    const witness_index = fixed_count + caller_count + state_count;
    const interaction_index = witness_index + integer.COLUMN_COUNT;
    const count = interaction_index + interaction_count;
    const polys = try a.alloc(engine.air.component_prover.Poly, count);
    defer a.free(polys);
    if (fixed_count != 0) polys[0] = trees[0][descriptor.fixed_offset];
    for (0..caller_count) |i| polys[fixed_count + i] = trees[1][caller_offset + i];
    for (0..state_count) |i| polys[fixed_count + caller_count + i] = trees[1][state_offset + (descriptor.slot - 1) * 32 + i];
    for (0..integer.COLUMN_COUNT) |i| polys[witness_index + i] = trees[2][self.witness_offset + i];
    for (0..interaction_count) |i| polys[interaction_index + i] = trees[3][self.interaction_offset + i];

    const eval_log = self.log_size + 2;
    const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
    const eval_size = domain.size();
    var owned_count: usize = 0;
    const packed_support = @import("../recursion/air/universal_typed_component_contract.zig");
    for (polys) |poly| owned_count += @intFromBool(if (self.v5_packed != null)
        try packed_support.sourceNeedsExtension(poly, self.log_size, eval_log)
    else
        try support.sourceNeedsExtension(poly, self.log_size, eval_log));
    const owned = try a.alloc([]M, owned_count);
    var initialized: usize = 0;
    defer {
        for (owned[0..initialized]) |column| a.free(column);
        a.free(owned);
    }
    const values = try a.alloc([]const M, count);
    defer a.free(values);
    var twiddles: ?engine.poly.twiddles.TwiddleTree([]M) = if (owned.len != 0) try engine.poly.twiddles.precomputeM31(a, domain.half_coset) else null;
    defer if (twiddles) |*t| engine.poly.twiddles.deinitM31(a, t);
    const transform: ?engine.poly.twiddles.TwiddleTree([]const M) = if (twiddles) |t| .init(t.root_coset, t.twiddles, t.itwiddles) else null;
    // Warm packed callers lease LDE-only trees. Reconstruct the entire source
    // polynomial and reject high degree before reusing quotient scratch.
    for (polys, values, 0..) |poly, *out, index| {
        // Common caller columns and SHA's fixed selector are used by every
        // access slot. Selected Keccak word columns and own witness/interaction
        // columns are unique to a slot and remain in bounded local scratch.
        if (index < fixed_count + caller_count) if (self.quotient_cache) |cache| {
            if (try cache.get(if (self.v5_packed != null) .packed_word else .retained, poly, self.log_size, eval_log, transform)) |shared| {
                out.* = shared;
                continue;
            }
        };
        out.* = if (self.v5_packed != null)
            try packed_support.evaluationValues(a, poly, self.log_size, eval_log, eval_size, transform, owned, &initialized)
        else
            try support.evaluationValues(a, poly, eval_log, eval_size, owned, &initialized);
    }
    if (initialized != 0) try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned[0..initialized], domain, transform.?);
    var inverses: [4]M = undefined;
    const trace_coset = canonic.CanonicCoset.new(self.log_size).coset();
    for (&inverses, 0..) |*value, i| value.* = try core.constraints.cosetVanishing(M, trace_coset, domain.at(core.utils.bitReverseIndex(i, 2))).inv();
    const output = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = self.nConstraints() }});
    defer a.free(output);
    var result = output[0];
    const shift: std.math.Log2Int(usize) = @intCast(self.log_size);
    for (0..eval_size) |row| {
        const previous_row = core.utils.previousBitReversedCircleDomainIndex(row, self.log_size, eval_log);
        const pair = if (descriptor.kind == .sha) blk: {
            var caller: [sha.PHYSICAL_MAIN_COLUMN_COUNT]Q = undefined;
            for (&caller, 0..) |*value, i| value.* = Q.fromBase(values[fixed_count + i][row]);
            break :blk try external.shaPair(Q, &caller, Q.fromBase(values[0][row]), descriptor.slot);
        } else if (descriptor.kind == .signer) blk: {
            var caller: [signer.Layout.main_columns]Q = undefined;
            for (&caller, 0..) |*value, i| value.* = Q.fromBase(values[i][row]);
            break :blk try external.signerPair(Q, &caller, descriptor.slot);
        } else blk: {
            var caller: [keccak.Layout.main_columns]Q = undefined;
            for (&caller, 0..) |*value, i| value.* = Q.fromBase(values[i][row]);
            var input: [32]Q = @splat(Q.zero());
            var output_state: [32]Q = @splat(Q.zero());
            const output_row = core.utils.offsetBitReversedCircleDomainIndex(row, self.log_size, eval_log, 27);
            for (0..state_count) |i| {
                const column = values[caller_count + i];
                input[i] = Q.fromBase(column[row]);
                output_state[i] = Q.fromBase(column[output_row]);
            }
            break :blk try external.keccakPairFromWordBits(Q, &caller, input, output_state, descriptor.slot);
        };
        var witness: [integer.COLUMN_COUNT]Q = undefined;
        for (&witness, 0..) |*value, i| value.* = Q.fromBase(values[witness_index + i][row]);
        var interaction: [v5_eval.INTERACTION_COUNT]Q = undefined;
        var previous: [v5_eval.INTERACTION_COUNT]Q = undefined;
        for (0..interaction_count) |i| {
            interaction[i] = Q.fromBase(values[interaction_index + i][row]);
            previous[i] = Q.fromBase(values[interaction_index + i][previous_row]);
        }
        var residuals: [v5_eval.CONSTRAINT_COUNT]Q = undefined;
        if (self.v5_universal != null) {
            const current = try v5_eval.evaluatePair(self, pair, witness, interaction, previous);
            @memcpy(residuals[0..current.len], &current);
        } else {
            var old_interaction: [sidecar_eval.INTERACTION_COUNT]Q = undefined;
            var old_previous: [sidecar_eval.INTERACTION_COUNT]Q = undefined;
            @memcpy(&old_interaction, interaction[0..sidecar_eval.INTERACTION_COUNT]);
            @memcpy(&old_previous, previous[0..sidecar_eval.INTERACTION_COUNT]);
            const current = try sidecar_eval.evaluatePair(self, pair, witness, old_interaction, old_previous);
            @memcpy(residuals[0..current.len], &current);
        }
        var folded = Q.zero();
        const powers = result.random_coeff_powers;
        for (residuals[0..self.nConstraints()], 0..) |residual, index| folded = folded.add(powers[powers.len - 1 - index].mul(residual));
        result.accumulate(row, folded.mulM31(inverses[row >> shift]));
    }
}
