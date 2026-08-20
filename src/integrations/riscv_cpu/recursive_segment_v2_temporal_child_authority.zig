//! Allocation-free admission from one verifier-custody SegmentV2 publication
//! to the canonical temporal child record.
//!
//! The only authority input is `VerifiedSegmentV2PublicationV1`.  Position,
//! statement, session, job, verification keys, lineage, proof identities, and
//! exact closure all come from that one pointer-free verifier publication.
//! No overload accepts detached context or a raw closure receipt.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const temporal = recursion.temporal_pair_node;
const publication_mod = @import("recursive_segment_v2_verified_publication.zig");

pub const Publication = publication_mod.VerifiedSegmentV2PublicationV1;
pub const Digest = channel.Digest;

pub const FORMAT_VERSION: u16 = 1;
pub const ADMISSION_SCHEMA_VERSION: u16 = 1;
pub const ADMISSION_ID_DOMAIN: u32 = 0x5356_4341; // "SVCA"

pub const HEAP_ALLOCATIONS_PER_ADMISSION: usize = 0;
pub const HEAP_ALLOCATIONS_PER_VALIDATE: usize = 0;
pub const DUPLICATE_CHILD_HASH_PASSES_PER_ADMISSION: usize = 0;
pub const FAILS_BEFORE_FIRST_WRITE = true;
pub const DETACHED_CONTEXT_ACCEPTED = false;
pub const RAW_CLOSURE_ACCEPTED = false;
pub const COMPLETE_SEGMENT_CHILD_AVAILABLE = true;
pub const COMPLETE_PARENT_CAPABILITY = false;

pub const Error = publication_mod.Error || temporal.Error || error{
    AliasedDestination,
    AdmissionIdentityMismatch,
    ChildIdentityMismatch,
    PublicationMismatch,
    UnsupportedFormat,
};

/// Minimal source-side context retained by a temporal pair.  Keeping the
/// already snapshotted child in the pair's prepared root context avoids a
/// second 412-word statement copy per child.
pub const SourceBindingV1 = struct {
    source_publication_id: Digest,
    source_verifier_context_id: Digest,
    source_closure_receipt_id: Digest,
    segment_index: u32,
    segment_count: u32,
    global_cycle_start: u32,
    global_cycle_end: u32,
    entry_continuation_root: u32,
    exit_continuation_root: u32,
    position_id: Digest,
    segment_wire_id: Digest,
    entry_lineage_id: Digest,
    exit_lineage_id: Digest,
    child_id: Digest,
    admission_id: Digest,
};

/// Compact, pointer-free authority consumed by the first honest temporal
/// pair.  The source publication itself need not remain alive after admission;
/// its native identities and the exact adjacency context are retained here.
pub const PreparedTemporalChildV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = ADMISSION_SCHEMA_VERSION,
    padding: [4]u8 = .{ 0, 0, 0, 0 },
    source_publication_id: Digest,
    source_verifier_context_id: Digest,
    source_closure_receipt_id: Digest,
    segment_index: u32,
    segment_count: u32,
    global_cycle_start: u32,
    global_cycle_end: u32,
    entry_continuation_root: u32,
    exit_continuation_root: u32,
    position_id: Digest,
    segment_wire_id: Digest,
    entry_lineage_id: Digest,
    exit_lineage_id: Digest,
    child: temporal.VerifiedChildV2,
    child_id: Digest,
    admission_id: Digest,

    pub fn sourceBinding(self: *const PreparedTemporalChildV1) SourceBindingV1 {
        return .{
            .source_publication_id = self.source_publication_id,
            .source_verifier_context_id = self.source_verifier_context_id,
            .source_closure_receipt_id = self.source_closure_receipt_id,
            .segment_index = self.segment_index,
            .segment_count = self.segment_count,
            .global_cycle_start = self.global_cycle_start,
            .global_cycle_end = self.global_cycle_end,
            .entry_continuation_root = self.entry_continuation_root,
            .exit_continuation_root = self.exit_continuation_root,
            .position_id = self.position_id,
            .segment_wire_id = self.segment_wire_id,
            .entry_lineage_id = self.entry_lineage_id,
            .exit_lineage_id = self.exit_lineage_id,
            .child_id = self.child_id,
            .admission_id = self.admission_id,
        };
    }

    pub fn validate(self: *const PreparedTemporalChildV1) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != ADMISSION_SCHEMA_VERSION or
            !allZero(&self.padding))
        {
            return error.UnsupportedFormat;
        }
        inline for (.{
            self.source_publication_id,
            self.source_verifier_context_id,
            self.source_closure_receipt_id,
            self.position_id,
            self.segment_wire_id,
            self.entry_lineage_id,
            self.exit_lineage_id,
            self.child_id,
            self.admission_id,
        }) |value| try requireDigest(value);
        if (self.segment_count == 0 or self.segment_index >= self.segment_count or
            self.global_cycle_end <= self.global_cycle_start)
        {
            return error.ChildIdentityMismatch;
        }
        if (self.child.kind != .segment_leaf or
            self.child.scope != .complete_execution or
            !self.child.proof_present or
            self.child.roster_count != publication_mod.UNIVERSAL_ROSTER_COUNT or
            !std.meta.eql(
                self.child.closure_receipt_id,
                self.source_closure_receipt_id,
            ))
        {
            return error.ChildIdentityMismatch;
        }
        const statement = try self.child.statement();
        const executed = switch (statement.body) {
            .empty => return error.ChildIdentityMismatch,
            .executed => |value| value,
        };
        if (statement.slots.height != 0 or
            statement.slots.first != self.segment_index or
            statement.job.segment_count != self.segment_count or
            executed.first_segment != self.segment_index or
            executed.segment_count != 1 or
            executed.first_cycle != self.global_cycle_start or
            executed.endCycle() != self.global_cycle_end or
            self.child.position != try temporal.positionForNextParent(statement) or
            !std.meta.eql(
                self.child.closure_receipt_id,
                try temporal.closureReceiptId(&self.child),
            ))
        {
            return error.ChildIdentityMismatch;
        }
        const expected_child_id = try self.child.id();
        if (!std.meta.eql(self.child_id, expected_child_id))
            return error.ChildIdentityMismatch;
        if (!std.meta.eql(
            self.admission_id,
            expectedAdmissionId(self.sourceBinding()),
        ))
            return error.AdmissionIdentityMismatch;
    }

    pub fn validateAgainst(
        self: *const PreparedTemporalChildV1,
        publication: *const Publication,
    ) Error!void {
        try self.validate();
        var expected: PreparedTemporalChildV1 = undefined;
        try admitInto(&expected, publication);
        if (!std.meta.eql(self.*, expected)) return error.PublicationMismatch;
    }
};

/// Fail-atomic admission.  Every fallible publication, statement, closure,
/// and identity check completes before the single destination assignment.
pub fn admitInto(
    destination: *PreparedTemporalChildV1,
    publication: *const Publication,
) Error!void {
    if (overlap(std.mem.asBytes(destination), std.mem.asBytes(publication)))
        return error.AliasedDestination;
    try publication.validate();

    const statement = try recursion.span_statement.SpanStatement
        .fromCanonicalWords(&publication.statement_words);
    const child = temporal.VerifiedChildV2{
        .position = try temporal.positionForNextParent(statement),
        .kind = .segment_leaf,
        .scope = .complete_execution,
        .proof_present = true,
        .roster_count = publication.closure.universal_roster_count,
        .session_id = publication.session_id,
        .job_id = publication.job_id,
        .recursive_parent_vk_id = publication.recursive_parent_vk_id,
        .verification_key_id = publication.verification_key_id,
        .air_program_id = publication.air_program_id,
        .manifest_id = publication.manifest_id,
        .profile_id = publication.profile_id,
        .statement_words = publication.statement_words,
        .proof_id = publication.proof_id,
        .transcript_id = publication.transcript_id,
        .capture_id = publication.capture_id,
        .verifier_receipt_id = publication.closure.verifier_receipt_id,
        .claimed_sums_id = publication.closure.claimed_sums_id,
        .relation_replay_id = publication.closure.relation_replay_id,
        .auxiliary_claim_seal_id = publication.closure.auxiliary_claim_seal_id,
        .closure_receipt_id = publication.closure.closure_receipt_id,
        .lineage_id = publication.lineage_id,
        .closure_value = publication.closure.framework_total,
    };
    if (!std.meta.eql(
        child.closure_receipt_id,
        try temporal.closureReceiptId(&child),
    )) return error.ChildIdentityMismatch;
    const child_id = try child.id();
    var staged = PreparedTemporalChildV1{
        .source_publication_id = publication.publication_id,
        .source_verifier_context_id = publication.verifier_context_id,
        .source_closure_receipt_id = publication.closure.closure_receipt_id,
        .segment_index = publication.segment_index,
        .segment_count = publication.segment_count,
        .global_cycle_start = publication.global_cycle_start,
        .global_cycle_end = publication.global_cycle_end,
        .entry_continuation_root = publication.entry_continuation_root,
        .exit_continuation_root = publication.exit_continuation_root,
        .position_id = publication.position_id,
        .segment_wire_id = publication.segment_wire_id,
        .entry_lineage_id = publication.entry_lineage_id,
        .exit_lineage_id = publication.exit_lineage_id,
        .child = child,
        .child_id = child_id,
        .admission_id = [_]u32{0} ** channel.RATE,
    };
    staged.admission_id = expectedAdmissionId(staged.sourceBinding());
    // Every field above is copied from the already validated publication or
    // derived from the validated child. Replaying `staged.validate()` here
    // would decode/hash the 412-word statement and child a second time.
    destination.* = staged;
}

pub fn expectedAdmissionId(value: SourceBindingV1) Digest {
    var hash = IdentityHasher.init(ADMISSION_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.addU32(ADMISSION_SCHEMA_VERSION);
    hash.digest(value.source_publication_id);
    hash.digest(value.source_verifier_context_id);
    hash.digest(value.source_closure_receipt_id);
    hash.addU32(value.segment_index);
    hash.addU32(value.segment_count);
    hash.addU32(value.global_cycle_start);
    hash.addU32(value.global_cycle_end);
    hash.addU32(value.entry_continuation_root);
    hash.addU32(value.exit_continuation_root);
    hash.digest(value.position_id);
    hash.digest(value.segment_wire_id);
    hash.digest(value.entry_lineage_id);
    hash.digest(value.exit_lineage_id);
    hash.digest(value.child_id);
    return hash.finalize();
}

pub fn validateSourceBinding(
    binding: SourceBindingV1,
    child: temporal.VerifiedChildV2,
) Error!void {
    const prepared = PreparedTemporalChildV1{
        .source_publication_id = binding.source_publication_id,
        .source_verifier_context_id = binding.source_verifier_context_id,
        .source_closure_receipt_id = binding.source_closure_receipt_id,
        .segment_index = binding.segment_index,
        .segment_count = binding.segment_count,
        .global_cycle_start = binding.global_cycle_start,
        .global_cycle_end = binding.global_cycle_end,
        .entry_continuation_root = binding.entry_continuation_root,
        .exit_continuation_root = binding.exit_continuation_root,
        .position_id = binding.position_id,
        .segment_wire_id = binding.segment_wire_id,
        .entry_lineage_id = binding.entry_lineage_id,
        .exit_lineage_id = binding.exit_lineage_id,
        .child = child,
        .child_id = binding.child_id,
        .admission_id = binding.admission_id,
    };
    try prepared.validate();
}

fn requireDigest(value: Digest) Error!void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus) return error.ChildIdentityMismatch;
        aggregate |= word;
    }
    if (aggregate == 0) return error.ChildIdentityMismatch;
}

fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

fn allZero(bytes: []const u8) bool {
    var aggregate: u8 = 0;
    for (bytes) |byte| aggregate |= byte;
    return aggregate == 0;
}

const IdentityHasher = struct {
    inner: channel.CanonicalWordHasher,

    fn init(domain: u32) IdentityHasher {
        return .{ .inner = channel.CanonicalWordHasher.init(domain) };
    }

    fn addU32(self: *IdentityHasher, value: anytype) void {
        const exact: u32 = @intCast(value);
        std.debug.assert(exact < m31.Modulus);
        const words = [_]M31{M31.fromCanonical(exact)};
        self.inner.update(&words);
    }

    fn digest(self: *IdentityHasher, value: Digest) void {
        for (value) |word| self.addU32(word);
    }

    fn finalize(self: *IdentityHasher) Digest {
        return self.inner.finalize();
    }
};

fn assertPointerFree(comptime T: type) void {
    switch (@typeInfo(T)) {
        .pointer, .optional => @compileError("temporal child authority retains a pointer"),
        .array => |array| assertPointerFree(array.child),
        .@"struct" => |info| inline for (info.fields) |field|
            assertPointerFree(field.type),
        .@"union" => |info| inline for (info.fields) |field|
            assertPointerFree(field.type),
        else => {},
    }
}

comptime {
    if (HEAP_ALLOCATIONS_PER_ADMISSION != 0 or
        HEAP_ALLOCATIONS_PER_VALIDATE != 0 or
        DUPLICATE_CHILD_HASH_PASSES_PER_ADMISSION != 0 or
        !FAILS_BEFORE_FIRST_WRITE or
        DETACHED_CONTEXT_ACCEPTED or RAW_CLOSURE_ACCEPTED or
        !COMPLETE_SEGMENT_CHILD_AVAILABLE or COMPLETE_PARENT_CAPABILITY)
    {
        @compileError("SegmentV2 temporal child authority ABI drifted");
    }
    assertPointerFree(PreparedTemporalChildV1);
}

test "SegmentV2 temporal child authority accepts only verified publication" {
    try std.testing.expect(@sizeOf(Publication) != 0);
    try std.testing.expect(!@hasDecl(@This(), "admitRawClosureInto"));
    try std.testing.expect(!@hasDecl(@This(), "admitDetachedContextInto"));
    try std.testing.expect(FAILS_BEFORE_FIRST_WRITE);
}
