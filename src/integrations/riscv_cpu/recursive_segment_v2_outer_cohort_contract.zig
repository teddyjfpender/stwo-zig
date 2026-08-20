const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const leaf_outer = @import("recursive_segment_v2_leaf_outer.zig");
const noncore_mod = @import("recursive_segment_v2_noncore_owner.zig");
const core_mod = @import("recursive_fri_outer.zig");
const tuple_diagnostic = @import("recursive_segment_v2_tuple_closure_diagnostic.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;
const air = recursion.air;
const composition_v3 = recursion.recursion_air_composition_circuit_v3;
const manifest_mod = air.segment_outer_adapter_manifest_v2;
const cohort_protocol = recursion.segment_outer_cohort_v2;

pub const FORMAT_VERSION: u16 = 1;
pub const GENERATED_FORMAT_VERSION: u16 = 1;
pub const AUTHORITY_TRANSCRIPT_DOMAIN: u32 = 0x5343_5632; // "SCV2"
pub const COMPONENT_COUNT: usize = manifest_mod.COMPONENT_COUNT;
pub const UNIVERSAL_COMPONENT_COUNT: usize =
    air.universal_roster.COMPONENT_COUNT;
pub const CORE_FIRST_ROW: usize = core_mod.NATIVE_V2_CORE_FIRST_ROW;
pub const CORE_LAST_ROW: usize = core_mod.NATIVE_V2_CORE_LAST_ROW;
pub const CORE_ROW_COUNT: usize = core_mod.NATIVE_V2_CORE_ROW_COUNT;
pub const CORE_ROW_MASK: u64 = rangeMask(CORE_FIRST_ROW, CORE_LAST_ROW + 1);
pub const ALL_COMPONENT_MASK: u64 = cohort_protocol.ALL_COMPONENT_MASK;

/// Only cold initialization and interaction preparation allocate. Once both
/// retained trees exist, publication into caller-owned trees is copy-only.
pub const HOT_COHORT_TREE_OVERHEAD_HEAP_ALLOCATIONS = [_]usize{ 0, 0, 0 };
pub const HOT_TREE_HEAP_ALLOCATIONS = [_]usize{ 0, 0, 0 };
pub const INTERACTION_GENERATION_IS_COLD = true;
pub const FAILS_AT_WHOLE_TREE_BOUNDARY = true;
pub const SHARED_ROW34_PROVIDER_INSTANCE_COUNT: usize = 1;
pub const RED_TUPLE_DOMAIN_MASK = tuple_diagnostic.RED_DOMAIN_MASK;
pub const PUBLIC_WIRE_BOUNDARY_TRANSCRIPT_DOMAIN: u32 = 0x5742_5632; // "WBV2"

pub const Error = error{
    ArithmeticOverflow,
    AuthorityIdentityMismatch,
    ComponentCoverageMismatch,
    CrossCustodyMismatch,
    DestinationAlias,
    DestinationNotFresh,
    DestinationShapeMismatch,
    GeneratedIdentityMismatch,
    ManifestGeometryMismatch,
    ProviderScheduleMismatch,
    RosterOrderMismatch,
};

pub const AuthorityInputs = *const leaf_outer.PreparedNativeV2LeafOuter;

/// Pointer-free interaction publication. Claims and audits occur exactly once
/// inside their authenticated source receipts; this envelope never duplicates
/// either array as detached authority.
pub const GeneratedInteractionsV2 = struct {
    format_version: u16 = GENERATED_FORMAT_VERSION,
    padding: [6]u8 = [_]u8{0} ** 6,
    cohort_id: [32]u8,
    manifest_seal: [32]u8,
    noncore: noncore_mod.GeneratedInteractionsV2,
    core: core_mod.NativeSegmentCoreGeneratedV2,
    identity: [32]u8,
};

/// Exact verifier-local values needed to replay the source-specific
/// SegmentV2 transcript prefix after child admission. Aggregate manifest,
/// plan, and cohort seals remain owned by the verified publication.
pub const RecursiveTranscriptPrefixSourceV1 = struct {
    noncore_authority_sha_id: [32]u8,
    core_authority_sha_id: [32]u8,
    core_layout_sha_id: [32]u8,
    core_call_buffer_sha_id: [32]u8,
    core_total_call_count: u32,
    public_wire_boundary: cohort_protocol.PublicWireBoundaryV2,
};

/// Exact verifier-owned terms needed to admit the resulting 39-claim outer
/// proof as a child of the next recursion layer. `input_wire` is the complete
/// authenticated 39-claim aggregate, not row 37 in isolation. These values
/// stay distinct because deriving one from another would erase source/sign
/// custody even though their successful closure is algebraically zero.
pub const OuterAdmissionBoundariesV2 = struct {
    input_wire: QM31,
    public_wire: QM31,
    verifier_input: QM31,

    pub fn validate(self: OuterAdmissionBoundariesV2) !void {
        try requireCanonicalQm31(self.input_wire);
        try requireCanonicalQm31(self.public_wire);
        try requireCanonicalQm31(self.verifier_input);
        if (!self.input_wire.add(self.public_wire).isZero())
            return error.ClaimClosureMismatch;
    }
};

pub const Components = struct {
    noncore: noncore_mod.Components,
    core: core_mod.NativeSegmentCoreComponentsV2,

    pub fn deinit(self: *Components) void {
        self.core.deinit();
        self.noncore.deinit();
        self.* = undefined;
    }

    /// Exact proof order: non-core rows 0--17, native core rows 18--34,
    /// followed by non-core range/boundary/provider rows 35--38.
    pub fn appendToGate(
        self: *const Components,
        manifest: *const manifest_mod.Manifest,
        gate: *manifest_mod.ProofGate,
    ) !void {
        if (gate.count != 0) return error.RosterOrderMismatch;
        try self.noncore.appendRows0Through17ToGate(manifest, gate);
        if (gate.count != CORE_FIRST_ROW) return error.RosterOrderMismatch;
        try self.core.appendToGate(manifest, gate);
        if (gate.count != CORE_LAST_ROW + 1)
            return error.RosterOrderMismatch;
        try self.noncore.appendRows35Through38ToGate(manifest, gate);
        if (gate.count != COMPONENT_COUNT) return error.RosterOrderMismatch;
    }

    /// Replays this already-admitted concrete cohort into the V3 shared
    /// recursion graph.  Runtime types are inferred from the initialized
    /// adapters, so this boundary contains no parallel AIR/relation dispatch
    /// table and cannot silently drift from proof-gate order.
    pub fn recordCompositionV3(
        self: *const Components,
        program: *composition_v3.segment_recorder_v3.SegmentProgramRecorderV3,
    ) !composition_v3.segment_recorder_v3.ProgramResultV3 {
        return program.recordCompleteCohort(self);
    }
};

pub const PublicationAuthorityV1 = struct {
    context: recursion.segment_leaf_authority_v2.NativeTemporalContextV2,
    statement_words: recursion.span_statement.StatementWords,
    prepared_leaf_sha_id: [32]u8,
    cohort_authority_sha_id: [32]u8,
    manifest_sha_id: [32]u8,
    catalog_sha_id: [32]u8,
    relation_registry_sha_id: [32]u8,
    plan_sha_id: [32]u8,
};

comptime {
    if (COMPONENT_COUNT != 39 or CORE_FIRST_ROW != 18 or
        CORE_LAST_ROW != 34 or CORE_ROW_COUNT != 17 or
        noncore_mod.UNIVERSAL_OWNED_ROW_MASK & CORE_ROW_MASK != 0 or
        noncore_mod.OWNED_ROW_MASK & CORE_ROW_MASK != 0 or
        noncore_mod.OWNED_ROW_MASK | CORE_ROW_MASK != ALL_COMPONENT_MASK or
        noncore_mod.BOUNDARY_ROW_MASK != rangeMask(36, 38) or
        noncore_mod.VERIFIER_INPUT_PROVIDER_ROW_MASK != componentBit(38) or
        !@import("std").meta.eql(
            noncore_mod.HOT_TREE_HEAP_ALLOCATIONS,
            [_]usize{ 0, 0, 0 },
        ) or
        !@import("std").meta.eql(
            core_mod.NATIVE_V2_CORE_HOT_TREE_HEAP_ALLOCATIONS,
            [_]usize{ 0, 0, 0 },
        ) or
        !noncore_mod.INTERACTION_GENERATION_IS_COLD or
        noncore_mod.HOT_GENERATED_VALIDATION_HEAP_ALLOCATIONS != 0 or
        noncore_mod.COLD_INDEPENDENT_AUDIT_REPLAYS_PER_GENERATION != 1 or
        noncore_mod.RETAINS_SELF_POINTERS or
        core_mod.NATIVE_V2_CORE_RETAINS_SELF_POINTERS or
        cohort_protocol.MEASURED_TOTAL_POSEIDON_CALLS != 1_193)
    {
        @compileError("SegmentV2 concrete cohort ownership/performance ABI drifted");
    }
}

fn requireCanonicalQm31(value: QM31) !void {
    for (value.toM31Array()) |word|
        if (word.toU32() >= m31.Modulus) return error.NonCanonicalField;
}

fn componentBit(index: anytype) u64 {
    return @as(u64, 1) << @intCast(index);
}

fn rangeMask(comptime first: usize, comptime end: usize) u64 {
    var result: u64 = 0;
    inline for (first..end) |index| result |= componentBit(index);
    return result;
}
