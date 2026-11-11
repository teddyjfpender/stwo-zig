//! Immutable proof identities, status codes and request-slab wire declarations.
const std = @import("std");

pub const contract_version: u32 = 2;
pub const slab_magic: u32 = 0x4e475652; // "RVGN" little-endian

pub const Verdict = struct {
    pub const unset: u32 = 0xffff_ffff;
    pub const accepted: u32 = 0;
    /// Reject code: high half = check id, low half = check-specific detail
    /// (nonzero). Never equals `accepted` or `unset`.
    pub fn reject(check: Check, detail: u16) u32 {
        const d: u32 = if (detail == 0) 1 else detail;
        return (@as(u32, @intFromEnum(check)) << 16) | d;
    }
    pub fn checkOf(word: u32) ?Check {
        if (word == unset or word == accepted) return null;
        return std.meta.intToEnum(Check, @as(u16, @truncate(word >> 16))) catch null;
    }
};

/// Status-word ids. Ranges: 0x01xx driver, 0x02xx native, 0x03xx recursion,
/// so a stream adds ids inside its range without colliding (append only;
/// values are stable, they appear in receipts).
pub const Check = enum(u16) {
    // driver (0x01xx): transcript and request-level
    channel_order = 0x0101, // device channel step/chain protocol latch
    exchange_complete = 0x0102, // every peer root/claim slot written once
    global_seal = 0x0103, // global chi / manifest closure over all segments
    encode_bounds = 0x0104, // every encoder wrote <= its region capacity
    // native (0x02xx): one set per native segment proof
    witness_status = 0x0201, // device witness generation (range/shape flags)
    binding_authority = 0x0202, // GKR terminal state == binding authority (was NB.checkAuthority)
    global_status = 0x0203, // global interaction witness status (was job.global_status loop)
    composition_accept = 0x0204, // composition role status (was native_stage2.accept)
    oods_constraint = 0x0205, // composition(OODS) == extracted eval (was host evalCompositionPolynomialAtPoint)
    public_claims = 0x0206, // device publicClaims reduction (was CW.publicClaims)
    pcs_status = 0x0207, // enqueue-only PCS pipeline status plane
    root_match = 0x0208, // FIXED/MAIN roots equal the class/statement roots
    local_receipt = 0x0209, // canonical local-GKR receipt and child wire
    // recursion (0x03xx): truth proofs and outer nodes
    truth_status = 0x0301, // truth_source / truth_composition / truth_pcs
    lookup_sum = 0x0302, // outer node LogUp sum == 0 (was host lookup status)
    node_oods_constraint = 0x0303, // outer node composition at OODS (was assemble's host check)
    node_pcs_status = 0x0304,
    seed_tape = 0x0305, // device seed fill from child slab matches class template
    child_binding = 0x0306, // node statement binds its children's encoded proofs
    // r-truth addition (M8-INTERFACES "m8-gpu-r-truth"): a truth's stage 1
    // (witness accepted, MAIN root published to Exchange.truthRoot). Stage 2
    // re-derives MAIN and its truth_status rejects a root that differs.
    truth_root = 0x0307,
    // gn-truth addition (M8-INTERFACES "m8-gn-truth"): a truth's composition
    // at the OODS point (device point program over the PCS samples) equals
    // the value its composition samples reconstruct (was the host
    // evalCompositionPolynomialAtPoint in truth finish). Truth extra check.
    truth_oods = 0x0308,
    class_unpack = 0x0309,
};

/// Status checks every proof of a kind must carry (the driver reserves these
/// words in the directory entry; extra checks may be appended by the owner).
pub fn requiredChecks(kind: ProofKind) []const Check {
    return switch (kind) {
        .native_segment => &.{ .channel_order, .witness_status, .binding_authority, .global_status, .composition_accept, .oods_constraint, .public_claims, .pcs_status, .root_match, .encode_bounds },
        .truth => &.{ .channel_order, .truth_status, .pcs_status, .encode_bounds },
        .leaf, .fold, .root => &.{ .channel_order, .seed_tape, .child_binding, .lookup_sum, .node_oods_constraint, .node_pcs_status, .encode_bounds },
        .request => &.{ .global_seal, .exchange_complete },
    };
}

// ---------------------------------------------------------------------------
// Proofs of a request
// ---------------------------------------------------------------------------

pub const ProofKind = enum(u8) {
    /// Request-level pseudo-proof: carries the request status words only.
    request = 0,
    native_segment = 1,
    truth = 2,
    leaf = 3,
    fold = 4,
    root = 5,
};

pub const ProofId = struct {
    kind: ProofKind,
    ordinal: u32,
    pub fn eql(a: ProofId, b: ProofId) bool {
        return a.kind == b.kind and a.ordinal == b.ordinal;
    }
};

/// What a stream declares per proof class (from its ClassCache entry):
/// the worst-case encoded size and any status words beyond `requiredChecks`.
pub const ProofSpec = struct {
    id: ProofId,
    /// GPU that produces (and whose slab segment holds) this proof.
    device: u32,
    /// Upper bound of the encoded proof bytes (class constant).
    max_encoded_bytes: usize,
    extra_checks: []const Check = &.{},
};

pub const header_words: usize = 16;
/// Header word the batch tail of each GPU fills on the device with the
/// request's `Exchange.flagTag(generation)` after every job of the batch;
/// `publish` requires it, so a mirror whose D2H never landed (stale data of
/// an earlier request in that parity) is refused even though the host wrote
/// the rest of the header itself.
pub const header_completion_word: usize = 12;
pub const entry_words: usize = 8;
pub const region_align: usize = 64;

pub const Entry = extern struct {
    kind: u32,
    ordinal: u32,
    status_first: u32, // word offset of the first status word (segment relative)
    status_count: u32,
    encoded_offset: u32, // word offset of the length word; bytes follow
    encoded_capacity_words: u32,
    first_check: u32, // index into the segment's check-id table (host side)
    reserved: u32 = 0,
};

comptime {
    if (@sizeOf(Entry) != entry_words * 4) @compileError("Entry must be 8 words");
}
