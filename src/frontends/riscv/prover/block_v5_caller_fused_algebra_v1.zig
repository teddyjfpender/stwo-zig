//! Canonical caller projections and external access sample reader. The scalar
//! verifier and recursive recorder share these exact tuple/recurrence bodies.
const std = @import("std");
const core = @import("stwo_core");
const Program = @import("block_v5_program_extension_source_v1.zig");
const State = @import("block_v5_precompile_state_request_source_v1.zig");
const Slots = @import("block_v5_program_extension_slots_v1.zig");
const Tables = @import("block_v5_precompile_lookup_source_v1.zig");
const External = @import("block_execution_external_trace_v2.zig");
const Bridge = @import("block_execution_external_access_bridge_v2.zig");
pub fn programResidual(comptime S: type, state: bool, slot: Slots.Slot, fixed: []const S, main: []const S, current: [4]S, previous: [4]S, normalized_claim: S, relations: anytype) !S {
    const delta = S.fromPartialEvals(current).sub(S.fromPartialEvals(previous)).add(normalized_claim);
    if (state) {
        const request = try State.fromCommittedCallerFor(S, slot.kind, fixed, main);
        const bus = relations.get(.registers_state);
        const consume = try bus.combineSecure(&request.consumed);
        const emit = try bus.combineSecure(&request.emitted);
        return delta.mul(consume.mul(emit)).sub(request.active.mul(consume.sub(emit)));
    }
    const request = try Program.fromCommittedCallerFor(S, slot.kind, fixed, main);
    const denominator = try relations.get(.program_access).combineSecure(&request.tuple);
    return delta.mul(denominator).sub(request.numerator);
}
pub fn tableResidual(comptime S: type, owner: *const Tables.Owner, slot: Tables.Slot, fixed: []const S, main: []const S, current: [4]S, previous: [4]S, normalized_claim: S, relations: anytype) !S {
    const request = try owner.pairFor(S, slot, fixed, main, relations);
    return S.fromPartialEvals(current).sub(S.fromPartialEvals(previous)).add(normalized_claim).mul(request.d1.mul(request.d2)).sub(request.n1.mul(request.d2).add(request.n2.mul(request.d1)));
}
/// Samples are addressed by their actual mask ordinal. Keccak output is the
/// original +27 opening, not the previous-row opening used by interactions.
pub fn externalPair(comptime S: type, descriptor: External.Descriptor, samples: anytype) !@import("block_execution_access_bridge_v2.zig").Pair(S) {
    const Sha = @import("../air/guest_precompile/sha256_memory_caller.zig");
    const Signer = @import("../air/guest_precompile/secp256k1_recovery_caller.zig");
    const Keccak = @import("../air/guest_precompile/keccakf_caller.zig");
    const Trace = @import("../air/guest_precompile/keccakf_trace.zig");
    if (descriptor.kind == .sha) {
        var caller: [Sha.PHYSICAL_MAIN_COLUMN_COUNT]S = undefined;
        for (&caller, 0..) |*out, i| out.* = try samples.at(1, descriptor.main_offset + i, 0);
        return Bridge.shaPair(S, &caller, try samples.at(0, descriptor.fixed_offset, 0), descriptor.slot);
    }
    if (descriptor.kind == .signer) {
        var caller: [Signer.Layout.main_columns]S = undefined;
        for (&caller, 0..) |*out, i| out.* = try samples.at(1, descriptor.main_offset + i, 0);
        return Bridge.signerPair(S, &caller, descriptor.slot);
    }
    var caller: [Keccak.Layout.main_columns]S = undefined;
    for (&caller, 0..) |*out, i| out.* = try samples.at(1, descriptor.main_offset + Trace.Layout.caller + i, 0);
    const cells = @import("../air/guest_precompile/keccakf_witness.zig").state_cell_count;
    var before: [cells]S = undefined;
    var after: [cells]S = undefined;
    for (&before, &after, 0..) |*input, *output, i| {
        input.* = try samples.at(1, descriptor.main_offset + Trace.Layout.state + i, 0);
        output.* = try samples.at(1, descriptor.main_offset + Trace.Layout.state + i, 1);
    }
    return Bridge.keccakPair(S, &caller, &before, &after, descriptor.slot);
}
