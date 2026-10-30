//! Typed complete B6JP-v3 native verifier statement, including physical claims.
//! Native semantics and relation checks are one child; global providers stay open.
const std = @import("std");
const Fused = @import("../prover/block_v5_native_projection_fused_proof_v2.zig");
const Memory = @import("../prover/block_v5_opcode_memory_sidecar_proof_v1.zig");
const ClaimInput = struct { projection: []const Fused.Claim, memory: []const Memory.Claim };
pub const Claims = ClaimInput;
const Policy = struct {
    pub const Admission = @import("../prover/block_v6_partitioned_recursive_admission_v1.zig");
    pub const Capture = @import("../prover/block_v6_partitioned_recursive_capture_v1.zig").VerifiedCapture;
    pub const Claims = ClaimInput;
    pub const Statement = @import("air/block_v6_partitioned_statement_v1.zig");
    pub const IDENTITY_TAG: u32 = 0x42365249; // B6RI
    pub const SCHEDULE_TAG: u32 = 0x42365257; // B6RW
    pub fn rootsCount(admitted: *const Admission.Prepared) usize {
        return admitted.tree_count - 1;
    }
    pub fn claims(capture: *const Capture) ClaimInput {
        return .{ .projection = capture.metadata.claims, .memory = capture.metadata.memory_claims };
    }
    pub fn validateClaims(admitted: *const Admission.Prepared, proposed: ClaimInput) !void {
        var channel = @import("stwo_core").proof_suites.Blake3.Channel{};
        try Fused.mixClaims(&channel, admitted.binding.template_id, admitted.binding.instance_id, admitted.native.index, admitted.projections, admitted.slots, proposed.projection, proposed.memory);
    }
    pub fn statement(a: std.mem.Allocator, admitted: *const Admission.Prepared, proposed: ClaimInput) !Statement.Statement {
        // The original native statement owns exact pre-allocation extent
        // admission and every first/claim invocation boundary unchanged.
        return Statement.Statement.initClaims(a, admitted, proposed.projection, proposed.memory);
    }
    pub fn publicInputs(a: std.mem.Allocator, admitted: *const Admission.Prepared, proposed: ClaimInput) ![]@import("stwo_core").fields.qm31.QM31 {
        return @import("air/block_v6_partitioned_composition_v1.zig").publicInputsFromClaims(a, admitted, proposed.projection, proposed.memory);
    }
};
pub const API = @import("block_v5_recursive_fused_public_bus_v1.zig").ForFamily(Policy);
pub const VERSION = API.VERSION;
pub const PUBLIC_CIRCUIT = API.PUBLIC_CIRCUIT;
pub const MAX_WIRES = API.MAX_WIRES;
pub const Source = API.Source;
pub const Wire = API.Wire;
pub const Values = API.Values;
pub const Prepared = API.Prepared;
pub const scheduleDigest = API.scheduleDigest;
pub const supply = API.supply;
pub const prepare = API.prepare;

/// Decode the authenticated public vector into the original typed block ledger.
/// This conversion is not a verifier; its caller must first verify the parent
/// proof with exactly these public values and the independently admitted key.
pub fn exportsFromValues(a: std.mem.Allocator, admitted: *const Policy.Admission.Prepared, values: Values) !@import("../prover/block_v6_partitioned_native_proof_v1.zig").Open {
    const core = @import("stwo_core");
    const Protocol = @import("../prover/block_v6_partitioned_native_proof_v1.zig");
    const Q = core.fields.qm31.QM31;
    try admitted.validate(admitted.template_id);
    try values.validate();
    if (!std.meta.eql(values.template, admitted.template_id) or values.public.len != try @import("air/block_v6_partitioned_composition_v1.zig").publicCount(admitted.projections.len, admitted.slots.len)) return error.UntrustedPartitionedPublicExports;
    const claims = try a.alloc(Fused.Claim, admitted.projections.len);
    defer a.free(claims);
    for (claims, admitted.projections, 0..) |*claim, slot, i| claim.* = .{ .sum = values.public[8 + i], .row_count = slot.n_rows };
    const memory = try a.alloc(Memory.Claim, admitted.slots.len);
    defer a.free(memory);
    for (memory, admitted.slots, 0..) |*claim, slot, i| {
        const offset = 8 + admitted.projections.len + 10 * i;
        const count = values.public[offset + 2];
        const limbs = count.toM31Array();
        if (!count.eql(Q.fromBase(limbs[0])) or limbs[0].toU32() > (@as(u32, 1) << @intCast(slot.log_size))) return error.UntrustedPartitionedPublicCensus;
        claim.* = .{ .transition_sum = values.public[offset], .universal_sum = values.public[offset + 1], .active_count = limbs[0].toU32(), .range_claims = values.public[offset + 3 ..][0..7].* };
    }
    var expected = try Values.init(a, admitted, .{ .projection = claims, .memory = memory });
    defer expected.deinit();
    if (values.roots_count != expected.roots_count or !std.mem.eql(u32, values.statement.words, expected.statement.words) or values.statement.felts.len != expected.statement.felts.len or values.public.len != expected.public.len) return error.UntrustedPartitionedPublicExports;
    for (values.statement.felts, expected.statement.felts) |got, want| if (!got.eql(want)) return error.UntrustedPartitionedPublicExports;
    for (values.public, expected.public) |got, want| if (!got.eql(want)) return error.UntrustedPartitionedPublicExports;
    // Step arrays and offsets select routed values and are part of the exact
    // statement policy, even when all underlying scalar storage matches.
    if (!std.meta.eql(values.statement.roots_offset, expected.statement.roots_offset) or values.statement.sealed_offset != expected.statement.sealed_offset or values.statement.first.len != expected.statement.first.len or values.statement.claims.len != expected.statement.claims.len) return error.UntrustedPartitionedPublicExports;
    for (values.statement.first, expected.statement.first) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedPartitionedPublicExports;
    for (values.statement.claims, expected.statement.claims) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedPartitionedPublicExports;
    const layout = @import("../prover/block_v6_relation_layout_v1.zig").Layout{ .a = a, .slots = admitted.projections, .digest = admitted.layout_digest };
    const native = try Protocol.nativeExports(a, admitted.native.shape, admitted.binding, admitted.native.sealed, &layout, claims);
    var companion = try Fused.deriveOpenReceipts(a, claims, memory, admitted.projections, &admitted.binding, admitted.witness_root, admitted.native.index, admitted.native.sealed);
    errdefer companion.deinit(a);
    if (companion.memory) |receipt| {
        if (receipt.event_count != admitted.memory.expected_events) return error.UntrustedPartitionedPublicCensus;
    } else if (admitted.memory.expected_events != 0) return error.UntrustedPartitionedPublicCensus;
    return .{ .native = native, .companion = companion };
}
