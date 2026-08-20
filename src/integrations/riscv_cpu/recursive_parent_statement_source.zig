//! CPU custody adapter for the authenticated recursive-parent statement source.
//!
//! The backend-neutral source cannot import an integration-owned verifier
//! result without inverting the package dependency graph. This adapter is the
//! one narrow conversion from the exact `VerifiedOuterProofV1` publication to
//! the frontend custody bundle. No proof field is decoded, copied into a new
//! authority type, or blessed by the caller.

const frontend = @import("stwo_riscv_frontend");
const outer = @import("recursive_fri_outer.zig");

const recursion = frontend.recursion;
const admission = recursion.outer_parent_child_admission;
const fixed_wire = recursion.fixed_wire;
const source = recursion.outer_parent_statement_source;

pub const COMPLETE_PARENT_STARK_VERIFIED = false;
pub const HEAP_ALLOCATIONS_PER_PREPARE: usize = 0;

pub fn VerifiedChildInput(comptime dimensions: fixed_wire.Dimensions) type {
    dimensions.validate();
    return struct {
        verified: *const outer.VerifiedOuterProofV1,
        wire: *const admission.FixedOuterProofWireV1(dimensions),
        candidate: *const admission.BinaryPairCandidateV1,
        binding: admission.PairChildInputsV1,
    };
}

pub fn prepareInto(
    comptime dimensions: fixed_wire.Dimensions,
    destination: *source.Prepared(dimensions),
    encoding_scratch: []u8,
    authority: source.AuthorityInputsV1,
    children: [source.CHILD_COUNT]VerifiedChildInput(dimensions),
) !void {
    const bundles = childBundles(dimensions, children);
    try source.Prepared(dimensions).prepareInto(
        destination,
        encoding_scratch,
        authority,
        bundles,
    );
}

/// The single exact-type conversion shared by the parent custody source and
/// its statement-AIR continuation. The returned bundles only borrow verifier
/// publications; neither adapter decodes or copies proof-controlled vectors.
pub fn childBundles(
    comptime dimensions: fixed_wire.Dimensions,
    children: [source.CHILD_COUNT]VerifiedChildInput(dimensions),
) [source.CHILD_COUNT]source.ChildBundle(dimensions) {
    var bundles: [source.CHILD_COUNT]source.ChildBundle(dimensions) = undefined;
    for (&bundles, children) |*target, child| target.* = .{
        .capture = &child.verified.capture,
        .receipt = &child.verified.receipt,
        .seal = child.verified.seal,
        .statement_words = &child.verified.statement_words,
        .wire = child.wire,
        .candidate = child.candidate,
        .binding = child.binding,
    };
    return bundles;
}

comptime {
    if (source.COMPLETE_PARENT_STARK_VERIFIED or
        admission.RECURSIVE_PARENT_PRODUCTION or
        COMPLETE_PARENT_STARK_VERIFIED or
        HEAP_ALLOCATIONS_PER_PREPARE != 0)
    {
        @compileError("recursive parent statement adapter production boundary drifted");
    }
}
