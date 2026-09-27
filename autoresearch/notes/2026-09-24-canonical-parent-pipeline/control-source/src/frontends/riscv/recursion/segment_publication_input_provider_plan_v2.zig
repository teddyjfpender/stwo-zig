//! Exact fail-closed plan for the missing SegmentV2 publication-input
//! producer.
//!
//! Source component 37 consumes 55
//! `recursion_verifier_input_word(2, LUP2, index, 0, value)` tuples and emits
//! the circuit-44 custody bridge.  The current SegmentV2 transcript program is
//! verifier 0 only and has no LUP2 instruction, so those consumes do not yet
//! have an in-proof producer.  This module freezes the only admissible 55-row
//! producer plan and provides allocation-free materialization/parity checks.
//!
//! It intentionally does *not* claim AIR authority: production remains false
//! until rows 1--5 (or a dedicated typed source component) constrain these
//! emissions and the cohort/global closure includes them.  A host-generated
//! event list is an integration oracle, never a proof.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const relation = @import("../air/lang/relation.zig");
const source_v2 = @import("segment_leaf_authority_v2.zig");
const channel = @import("poseidon2_channel.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const VERIFIER_ID: u32 = source_v2.SEGMENT_V2_VERIFIER_ID;
pub const SOURCE_KIND: u32 = source_v2.PUBLIC_LOGUP_V2_KIND;
pub const WORD_COUNT: usize = source_v2.LOGUP_PUBLICATION_WORD_COUNT;
pub const PLAN_ID_DOMAIN: u32 = 0x5032_4950; // "P2IP"

pub const HOT_HEAP_ALLOCATIONS: usize = 0;
pub const WRITES_FAIL_BEFORE_FIRST_WRITE = true;
pub const EXISTING_TRANSCRIPT_PROVIDER_AVAILABLE = false;
pub const TYPED_AIR_PROVIDER_AVAILABLE = false;
pub const PRODUCTION_ACTIVATION = false;

pub const Error = source_v2.Error || error{
    AliasedDestination,
    DestinationLengthMismatch,
    InvalidProviderEvent,
    MissingTypedProvider,
    ProviderPlanMismatch,
};

pub const RequiredIntegrationV2 = struct {
    transcript_program_lup2_instruction: bool = false,
    transcript_payload_lup2_source_kind: bool = false,
    transcript_rows_configurable_verifier_id: bool = false,
    transcript_frame_and_payload_rows_bound: bool = false,
    cohort_manifest_includes_provider_rows: bool = false,
    global_relation_closure_includes_emits: bool = false,

    pub fn productionReady(self: RequiredIntegrationV2) bool {
        return self.transcript_program_lup2_instruction and
            self.transcript_payload_lup2_source_kind and
            self.transcript_rows_configurable_verifier_id and
            self.transcript_frame_and_payload_rows_bound and
            self.cohort_manifest_includes_provider_rows and
            self.global_relation_closure_includes_emits;
    }
};

pub const REQUIRED_INTEGRATION = RequiredIntegrationV2{};

pub const ProviderEventV2 = struct {
    domain: relation.Domain = .recursion_verifier_input_word,
    role: relation.Role = .emit,
    tuple: [5]M31,

    pub fn validate(self: ProviderEventV2, index: usize) Error!void {
        if (index >= WORD_COUNT or
            self.domain != .recursion_verifier_input_word or
            self.role != .emit or
            !self.tuple[0].eql(M31.fromCanonical(VERIFIER_ID)) or
            !self.tuple[1].eql(M31.fromCanonical(SOURCE_KIND)) or
            !self.tuple[2].eql(M31.fromCanonical(@intCast(index))) or
            !self.tuple[3].isZero())
        {
            return error.InvalidProviderEvent;
        }
    }
};

/// Pointer-free, exact plan.  The words are verifier-known values copied only
/// after the native publication validates.
pub const PreparedProviderPlanV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    verifier_id: u32 = VERIFIER_ID,
    source_kind: u32 = SOURCE_KIND,
    word_count: u16 = WORD_COUNT,
    typed_air_bound: bool = false,
    production_ready: bool = false,
    publication_id: source_v2.Digest,
    words: [WORD_COUNT]M31,
    plan_id: source_v2.Digest,

    pub fn validateAgainst(
        self: *const PreparedProviderPlanV2,
        publication: *const source_v2.VerifiedNativePublicLogUpPublicationV2,
    ) Error!void {
        try publication.validate();
        const words = try publication.canonicalWords();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.verifier_id != VERIFIER_ID or self.source_kind != SOURCE_KIND or
            self.word_count != WORD_COUNT or self.typed_air_bound or
            self.production_ready or
            !std.meta.eql(self.publication_id, publication.identity) or
            !m31WordsEqual(&self.words, &words) or
            !std.meta.eql(self.plan_id, planId(self)))
        {
            return error.ProviderPlanMismatch;
        }
    }

    pub fn productionReady(_: *const PreparedProviderPlanV2) bool {
        return false;
    }
};

pub fn prepareInto(
    destination: *PreparedProviderPlanV2,
    publication: *const source_v2.VerifiedNativePublicLogUpPublicationV2,
) Error!void {
    if (overlap(std.mem.asBytes(destination), std.mem.asBytes(publication)))
        return error.AliasedDestination;
    try publication.validate();
    var staged = PreparedProviderPlanV2{
        .publication_id = publication.identity,
        .words = try publication.canonicalWords(),
        .plan_id = undefined,
    };
    staged.plan_id = planId(&staged);
    try staged.validateAgainst(publication);
    destination.* = staged;
}

/// Exact-size, allocation-free and destination-fail-atomic producer oracle.
/// These events gain proof authority only after the required typed integration
/// above is complete.
pub fn writeEmitsInto(
    prepared: *const PreparedProviderPlanV2,
    publication: *const source_v2.VerifiedNativePublicLogUpPublicationV2,
    destination: []ProviderEventV2,
) Error!void {
    if (destination.len != WORD_COUNT)
        return error.DestinationLengthMismatch;
    const output = std.mem.sliceAsBytes(destination);
    if (overlap(output, std.mem.asBytes(prepared)) or
        overlap(output, std.mem.asBytes(publication)))
    {
        return error.AliasedDestination;
    }
    try prepared.validateAgainst(publication);
    for (destination, prepared.words, 0..) |*event, word, index| {
        event.* = .{ .tuple = .{
            M31.fromCanonical(VERIFIER_ID),
            M31.fromCanonical(SOURCE_KIND),
            M31.fromCanonical(@intCast(index)),
            M31.zero(),
            word,
        } };
    }
}

/// Diagnostic parity only.  This proves the planned producer is exactly the
/// opposite of row37's consumers; it does not substitute for a typed AIR row.
pub fn requireExactConsumerParity(
    emits: []const ProviderEventV2,
    consumes: []const source_v2.VerifierInputEventV2,
) Error!void {
    if (emits.len != WORD_COUNT or consumes.len != WORD_COUNT)
        return error.DestinationLengthMismatch;
    for (emits, consumes, 0..) |emit, consume, index| {
        try emit.validate(index);
        if (consume.domain != emit.domain or consume.role != .consume or
            !m31WordsEqual(&consume.tuple, &emit.tuple))
        {
            return error.ProviderPlanMismatch;
        }
    }
}

fn planId(plan: *const PreparedProviderPlanV2) source_v2.Digest {
    var hash = channel.CanonicalWordHasher.init(PLAN_ID_DOMAIN);
    hash.update(&.{
        M31.fromCanonical(plan.format_version),
        M31.fromCanonical(plan.schema_version),
        M31.fromCanonical(plan.verifier_id),
        M31.fromCanonical(plan.source_kind),
        M31.fromCanonical(plan.word_count),
        M31.fromCanonical(@intFromBool(plan.typed_air_bound)),
        M31.fromCanonical(@intFromBool(plan.production_ready)),
    });
    var publication_words: [channel.RATE]M31 = undefined;
    for (&publication_words, plan.publication_id) |*destination, word|
        destination.* = M31.fromCanonical(word);
    hash.update(&publication_words);
    hash.update(&plan.words);
    return hash.finalize();
}

fn m31WordsEqual(left: anytype, right: anytype) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!a.eql(b)) return false;
    return true;
}

fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

comptime {
    if (VERIFIER_ID != 2 or SOURCE_KIND != 0x4c55_5032 or WORD_COUNT != 55 or
        HOT_HEAP_ALLOCATIONS != 0 or !WRITES_FAIL_BEFORE_FIRST_WRITE or
        EXISTING_TRANSCRIPT_PROVIDER_AVAILABLE or TYPED_AIR_PROVIDER_AVAILABLE or
        PRODUCTION_ACTIVATION or REQUIRED_INTEGRATION.productionReady() or
        relation.universalDescriptor(.recursion_verifier_input_word).arity != 5)
    {
        @compileError("SegmentV2 publication-input provider gap contract drifted");
    }
}
