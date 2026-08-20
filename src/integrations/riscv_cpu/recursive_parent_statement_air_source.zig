//! CPU continuation from independently verified outer proofs to the binary
//! parent statement AIR source.
//!
//! `VerifiedOuterProofV1` remains the only proof-custody input. Its canonical
//! statement words are published transactionally by the successful native
//! verifier, then decoded and bound to the exact receipt/capture/source
//! identity before evaluating or committing the AIR.
//!
//! Construction is fused with parent-source authentication. The canonical
//! pair is authenticated once (55 measured scalar Poseidon permutations,
//! versus the original 229-permutation static call tree), then the local
//! authenticated value flows directly through publication and AIR creation.
//! Trace fills perform no pair reauthentication.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const parent_adapter = @import("recursive_parent_statement_source.zig");

const recursion = frontend.recursion;
const air_source = recursion.outer_parent_statement_air_source;
const fixed_wire = recursion.fixed_wire;
const pair_node = recursion.pair_node;
const parent_source = recursion.outer_parent_statement_source;
const segment_source = recursion.segment_statement_outer_source;

pub const COMPLETE_PARENT_STARK_VERIFIED = false;
pub const NATIVE_VERIFIER_PUBLISHES_STATEMENT_WORDS = true;
pub const EXTERNAL_STATEMENT_PREIMAGE_BINDING = false;

pub const HEAP_ALLOCATIONS_PER_PREPARE =
    air_source.COLD_HEAP_ALLOCATIONS_PER_PREPARED;
pub const PAIR_AUTHENTICATIONS_PER_PREPARE =
    air_source.FUSED_PAIR_AUTHENTICATIONS_PER_PREPARE;
pub const PAIR_REAUTHENTICATIONS_AVOIDED =
    air_source.FUSED_PAIR_REAUTHENTICATIONS_AVOIDED;
pub const PAIR_PERMUTATIONS_PER_AUTHENTICATION =
    pair_node.AuthenticationPermutationCostV1.successful_prepared_root;
pub const PAIR_PERMUTATIONS_AVOIDED =
    air_source.FUSED_PAIR_PERMUTATIONS_AVOIDED;
pub const PRIOR_STATIC_PAIR_PERMUTATION_ESTIMATE =
    pair_node.AuthenticationPermutationCostV1.prior_audit_static_estimate;
pub const HOT_PAIR_AUTHENTICATIONS_PER_TRACE_FILL =
    air_source.HOT_PAIR_AUTHENTICATIONS_PER_TRACE_FILL;
pub const HOT_TRACE_HEAP_ALLOCATIONS =
    air_source.HOT_TRACE_HEAP_ALLOCATIONS;

pub fn Prepared(comptime dimensions: fixed_wire.Dimensions) type {
    return air_source.AuthenticatedPrepared(dimensions);
}

/// Fuses exact verifier-owned child custody, canonical parent authentication,
/// verifier-owned statement publication, and parent AIR preparation into one
/// failure-atomic return value.
pub fn prepare(
    comptime dimensions: fixed_wire.Dimensions,
    allocator: std.mem.Allocator,
    authority: *const segment_source.Authority,
    workspace: *air_source.Workspace,
    encoding_scratch: []u8,
    parent_inputs: parent_source.AuthorityInputsV1,
    children: [parent_source.CHILD_COUNT]parent_adapter.VerifiedChildInput(dimensions),
) !Prepared(dimensions) {
    return Prepared(dimensions).init(
        allocator,
        authority,
        workspace,
        encoding_scratch,
        parent_inputs,
        parent_adapter.childBundles(dimensions, children),
    );
}

comptime {
    if (COMPLETE_PARENT_STARK_VERIFIED or
        !NATIVE_VERIFIER_PUBLISHES_STATEMENT_WORDS or
        EXTERNAL_STATEMENT_PREIMAGE_BINDING or
        air_source.COMPLETE_PARENT_STARK_VERIFIED or
        !air_source.NATIVE_VERIFIER_PUBLISHES_STATEMENT_WORDS or
        parent_source.COMPLETE_PARENT_STARK_VERIFIED or
        PAIR_AUTHENTICATIONS_PER_PREPARE != 1 or
        PAIR_PERMUTATIONS_PER_AUTHENTICATION != 55 or
        PRIOR_STATIC_PAIR_PERMUTATION_ESTIMATE != 229 or
        PAIR_REAUTHENTICATIONS_AVOIDED != 3 or
        PAIR_PERMUTATIONS_AVOIDED != 165 or
        HOT_PAIR_AUTHENTICATIONS_PER_TRACE_FILL != 0 or
        HOT_TRACE_HEAP_ALLOCATIONS != 0)
    {
        @compileError("recursive parent statement AIR CPU boundary drifted");
    }
}
