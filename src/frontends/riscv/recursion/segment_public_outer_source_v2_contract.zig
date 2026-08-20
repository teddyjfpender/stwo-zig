//! Internal segment public outer source v2 authority shard; use segment_public_outer_source_v2.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const m31 = stwo_core.fields.m31;
pub const M31 = m31.M31;
pub const QM31 = stwo_core.fields.qm31.QM31;

pub const public_data_v2 = @import("../air/public_data_v2.zig");
pub const public_logup_v2 = @import("../air/public_logup_v2.zig");
pub const native_relations = @import("../air/relation_challenges.zig");
pub const statement_v1 = @import("../air/statement.zig");
pub const statement_v2 = @import("../air/statement_v2.zig");
pub const relation = @import("../air/lang/relation.zig");
pub const source_v2 = @import("segment_leaf_authority_v2.zig");
pub const channel = @import("poseidon2_channel.zig");
pub const roster = @import("air/universal_roster.zig");
pub const universal = @import("air/universal_challenges.zig");
pub const relation_challenge_witness = @import("air/relation_challenge_witness.zig");
pub const schedule = @import("air/verifier_schedule.zig");
pub const control_v2 = @import("air/vm_public_logup_control_v2.zig");
pub const control_relation_v2 = @import("air/vm_public_logup_control_relation_v2.zig");
pub const control_witness_v2 = @import("air/vm_public_logup_control_witness_v2.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 2;
pub const MANIFEST_VERSION: u16 = 4;
pub const FIRST_ROW: usize = @intFromEnum(roster.Component.vm_public_claim_input);
pub const ROW_COUNT: usize = 6;
pub const LAST_ROW: usize = FIRST_ROW + ROW_COUNT - 1;
pub const MIN_LOG_SIZE: u8 = 4;
pub const MAX_LOG_SIZE: u8 = 30;

pub const NATIVE_SUM_CIRCUIT_ID: u32 = 42;
pub const CONTROL_RELAY_CIRCUIT_ID: u32 = 43;
pub const PUBLICATION_BRIDGE_CIRCUIT_ID: u32 =
    source_v2.PUBLICATION_BRIDGE_CIRCUIT_ID;
pub const BOUNDARY_BRIDGE_CIRCUIT_ID: u32 = 45;
pub const CONTROL_TAG: u32 = 0x5032_4354; // "P2CT"
pub const MANIFEST_ID_DOMAIN: u32 = 0x5032_4d46; // "P2MF"
pub const SOURCE_ID_DOMAIN: u32 = 0x5032_5352; // "P2SR"
pub const LOWERING_OBLIGATION_ID_DOMAIN: u32 = 0x5032_4c4f; // "P2LO"
pub const ARITHMETIC_BINDING_FORMAT_VERSION: u16 = 1;
pub const ARITHMETIC_BINDING_ID_DOMAIN =
    "stwo-zig/typed-air/segment-public-v2/arithmetic-binding/v1\x00";
pub const TRANSCRIPT_VERIFIER_ID: u32 = 0;
pub const CHALLENGE_COUNT: usize = 4;
pub const CHALLENGE_WORDS_PER_RELATION: usize = 8;
pub const CHALLENGE_WORD_COUNT: usize =
    CHALLENGE_COUNT * CHALLENGE_WORDS_PER_RELATION;
pub const PUBLICATION_WORD_COUNT: usize = source_v2.LOGUP_PUBLICATION_WORD_COUNT;
pub const PUBLICATION_HEADER_WORD_COUNT: usize = 3 + 3 * channel.RATE;
pub const NATIVE_PUBLIC_SUM_WORD_COUNT: usize = 4 * 4;
pub const PUBLICATION_SEAL_WORD_COUNT: usize = 4 + channel.RATE;
pub const PUBLICATION_SUM_START: usize = PUBLICATION_HEADER_WORD_COUNT;
pub const PUBLICATION_SEAL_START: usize =
    PUBLICATION_SUM_START + NATIVE_PUBLIC_SUM_WORD_COUNT;
pub const CONTROL_PUBLICATION_INDEX: usize = PUBLICATION_WORD_COUNT - 1;
pub const NATIVE_TOTAL_WORD_COUNT: usize = 4;
pub const ARITHMETIC_PUBLICATION_WORD_COUNT: usize =
    NATIVE_PUBLIC_SUM_WORD_COUNT + NATIVE_TOTAL_WORD_COUNT;
pub const CONTROL_LOGICAL_ROW_COUNT: usize =
    control_witness_v2.LOGICAL_ROW_COUNT;
pub const CONTROL_RELATION_EVENT_COUNT: usize =
    control_witness_v2.ACTIVE_RELATION_EVENT_COUNT;
pub const AUTHORITY_BIND_EVENT_COUNT: usize = 1;

pub const HOT_HEAP_ALLOCATIONS: usize = 0;
pub const TRACE_WRITES_FAIL_BEFORE_FIRST_WRITE = true;
pub const RELATION_WRITES_FAIL_BEFORE_FIRST_WRITE = true;
pub const NATIVE_PUBLIC_SUM_CAPTURE_PARITY_CHECKED = true;
pub const ALL_55_PUBLICATION_BRIDGE_WORDS_CONSUMED = true;
pub const SHARED_CHALLENGE_WORDS_CONSUMED = true;
pub const BASE_DOMAIN_OUTER_EVENTS_EMITTED = false;
pub const SOURCE_36_BOUNDARY_BRIDGE_AVAILABLE = true;
pub const SOURCE_37_PUBLICATION_BRIDGE_REQUIRED = true;
pub const SOURCE_37_PUBLICATION_BRIDGE_AVAILABLE = true;
pub const FROZEN_V1_ROW_COMPATIBLE = false;
pub const PRODUCTION_ACTIVATION = false;

pub const Digest = channel.Digest;
pub const Sha256Digest = [32]u8;
pub const ControlLogicalRowV2 = control_relation_v2.Row;

/// Exact capabilities intentionally absent from this source-only lane.
pub const MissingIntegrationCapability = enum(u8) {
    tree0_preprocessing_writers,
    tree1_main_writers,
    tree2_logup_and_claims,
    universal_component_adapters,
    v2_manifest_placement,
    native_sum_recomputation_graph,
    arithmetic_input_use_count_binding,
    global_47_domain_closure,
    complete_outer_proof_gate,
    independent_outer_prove_verify,
};

pub const MISSING_INTEGRATION_CAPABILITIES = [_]MissingIntegrationCapability{
    .tree0_preprocessing_writers,
    .tree1_main_writers,
    .tree2_logup_and_claims,
    .universal_component_adapters,
    .v2_manifest_placement,
    .native_sum_recomputation_graph,
    .arithmetic_input_use_count_binding,
    .global_47_domain_closure,
    .complete_outer_proof_gate,
    .independent_outer_prove_verify,
};

pub const CapabilityLedgerV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    source_rows_available: bool = true,
    native_sum_capture_parity_checked: bool = true,
    universal_relation_abis_pinned: bool = true,
    base_domain_outer_events_absent: bool = true,
    zero_allocation_hot_write: bool = true,
    production_ready: bool = false,
    missing_count: u8 = MISSING_INTEGRATION_CAPABILITIES.len,

    pub fn validate(self: CapabilityLedgerV2) Error!void {
        if (self.format_version != FORMAT_VERSION or
            !self.source_rows_available or
            !self.native_sum_capture_parity_checked or
            !self.universal_relation_abis_pinned or
            !self.base_domain_outer_events_absent or
            !self.zero_allocation_hot_write or self.production_ready or
            self.missing_count != MISSING_INTEGRATION_CAPABILITIES.len)
        {
            return error.InvalidCapabilityLedger;
        }
    }
};

pub const CAPABILITY_LEDGER = CapabilityLedgerV2{};

pub const Error = source_v2.Error || statement_v2.Error ||
    public_data_v2.Error || schedule.Error || control_witness_v2.Error || error{
    AliasedDestination,
    ArithmeticBindingMismatch,
    ArithmeticOverflow,
    AuthorityMismatch,
    DestinationLengthMismatch,
    InvalidCapabilityLedger,
    InvalidClosureLedger,
    InvalidManifest,
    InvalidProgramAnchor,
    InvalidRelationEvent,
    InvalidTraceShape,
    NonCanonicalSourceWord,
    PublicSumEventMismatch,
    SourceMismatch,
    UnsupportedVersion,
};

pub const CountsV2 = struct {
    publication_header: usize,
    native_public_sums: usize,
    publication_seal: usize,
    boundary_bridge: usize,
    native_challenges: usize,
    control_relay: usize,
    relay_relation_events: usize,
    authority_relation_events: usize,
    control_relation_events: usize,
    relation_events: usize,

    pub fn asRows(self: CountsV2) [ROW_COUNT]usize {
        return .{
            self.publication_header,
            self.native_public_sums,
            self.publication_seal,
            self.boundary_bridge,
            self.native_challenges,
            self.control_relay,
        };
    }
};

/// Auditable producer/consumer table for every recursion-local edge touched
/// by rows 12--17. Source components 36 and 37 now publish both custody
/// bridges; arithmetic consumers remain deliberately fail-closed until the
/// complete 38-row graph binds their use counts.
pub const ClosureLedgerV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    source37_verifier_input_consumes: u32 = PUBLICATION_WORD_COUNT,
    source37_publication_bridge_emits: u32 = PUBLICATION_WORD_COUNT,
    rows12_14_publication_bridge_consumes: u32 = PUBLICATION_WORD_COUNT,
    source36_statement_word_emits: u32,
    row11_statement_word_consumes: u32,
    row11_boundary_bridge_emits: u32,
    row15_boundary_bridge_consumes: u32,
    row8_challenge_word_emits: u32 = CHALLENGE_WORD_COUNT,
    row16_challenge_word_consumes: u32 = CHALLENGE_WORD_COUNT,
    rows13_16_arithmetic_wire_emits: u32,
    row14_control_wire_emits: u32 = 1,
    row17_control_wire_consumes: u32 = 1,
    row17_recursion_step_consumes: u32 = CONTROL_LOGICAL_ROW_COUNT,
    base_domain_event_count: u32 = 0,
    range_check_event_count: u32 = 0,
    source36_bridge_producer_bound: bool = true,
    source37_bridge_producer_bound: bool = true,
    arithmetic_graph_consumers_bound: bool = false,

    pub fn validate(self: ClosureLedgerV2) Error!void {
        const expected_arithmetic = try checkedAddU32(
            self.row15_boundary_bridge_consumes,
            ARITHMETIC_PUBLICATION_WORD_COUNT + CHALLENGE_WORD_COUNT,
        );
        if (self.format_version != FORMAT_VERSION or
            self.source37_verifier_input_consumes != PUBLICATION_WORD_COUNT or
            self.source37_publication_bridge_emits !=
                self.source37_verifier_input_consumes or
            self.rows12_14_publication_bridge_consumes !=
                self.source37_publication_bridge_emits or
            self.source36_statement_word_emits !=
                self.row11_statement_word_consumes or
            self.row11_boundary_bridge_emits !=
                self.row11_statement_word_consumes or
            self.row15_boundary_bridge_consumes !=
                self.row11_boundary_bridge_emits or
            self.row8_challenge_word_emits != CHALLENGE_WORD_COUNT or
            self.row16_challenge_word_consumes !=
                self.row8_challenge_word_emits or
            self.rows13_16_arithmetic_wire_emits != expected_arithmetic or
            self.row14_control_wire_emits != 1 or
            self.row17_control_wire_consumes != self.row14_control_wire_emits or
            self.row17_recursion_step_consumes != CONTROL_LOGICAL_ROW_COUNT or
            self.base_domain_event_count != 0 or
            self.range_check_event_count != 0 or
            !self.source36_bridge_producer_bound or
            !self.source37_bridge_producer_bound or
            self.arithmetic_graph_consumers_bound)
        {
            return error.InvalidClosureLedger;
        }
    }
};

pub const ManifestV2 = struct {
    format_version: u16 = MANIFEST_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    frozen_v1_compatible: bool = false,
    first_roster_row: u8 = FIRST_ROW,
    row_count: u8 = ROW_COUNT,
    logical_rows: [ROW_COUNT]u32,
    log_sizes: [ROW_COUNT]u8,
    relation_event_count: u32,
    publication_word_count: u16 = PUBLICATION_WORD_COUNT,
    challenge_word_count: u16 = CHALLENGE_WORD_COUNT,
    wire_word_count: u32,
    statement_source_id: Digest,
    publication_id: Digest,
    native_public_sums_id: Digest,
    relation_context_id: Digest,
    lowering_obligation_id: Digest,
    authority_hash_plan_id: Digest,
    authority_poseidon_call_count: u32,
    control_source_id: Sha256Digest,
    native_sum_circuit_id: u32 = NATIVE_SUM_CIRCUIT_ID,
    control_relay_circuit_id: u32 = CONTROL_RELAY_CIRCUIT_ID,
    publication_bridge_circuit_id: u32 = PUBLICATION_BRIDGE_CIRCUIT_ID,
    boundary_bridge_circuit_id: u32 = BOUNDARY_BRIDGE_CIRCUIT_ID,
    identity: Digest,

    pub fn validate(self: *const ManifestV2) Error!void {
        if (self.format_version != MANIFEST_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.frozen_v1_compatible or self.first_roster_row != FIRST_ROW or
            self.row_count != ROW_COUNT or
            self.publication_word_count != PUBLICATION_WORD_COUNT or
            self.challenge_word_count != CHALLENGE_WORD_COUNT or
            self.native_sum_circuit_id != NATIVE_SUM_CIRCUIT_ID or
            self.control_relay_circuit_id != CONTROL_RELAY_CIRCUIT_ID or
            self.publication_bridge_circuit_id != PUBLICATION_BRIDGE_CIRCUIT_ID or
            self.boundary_bridge_circuit_id != BOUNDARY_BRIDGE_CIRCUIT_ID or
            self.logical_rows[rowIndex(.vm_public_claim_input)] !=
                PUBLICATION_HEADER_WORD_COUNT or
            self.logical_rows[rowIndex(.vm_public_claim_hash)] != @max(
                NATIVE_PUBLIC_SUM_WORD_COUNT,
                self.authority_poseidon_call_count,
            ) or
            self.authority_poseidon_call_count == 0 or
            allZeroBytes(std.mem.asBytes(&self.authority_hash_plan_id)) or
            self.logical_rows[rowIndex(.vm_public_io_hash)] !=
                PUBLICATION_SEAL_WORD_COUNT or
            self.logical_rows[rowIndex(.vm_public_logup_input)] !=
                CHALLENGE_WORD_COUNT or
            self.logical_rows[rowIndex(.vm_public_logup_control)] !=
                CONTROL_LOGICAL_ROW_COUNT or
            self.log_sizes[rowIndex(.vm_public_logup_control)] !=
                control_witness_v2.TRACE_LOG_SIZE or
            allZeroBytes(&self.control_source_id) or
            self.logical_rows[rowIndex(.vm_public_claim_semantics_input)] !=
                self.wire_word_count)
        {
            return error.InvalidManifest;
        }
        for (self.logical_rows, self.log_sizes) |count, log_size| {
            if (log_size < MIN_LOG_SIZE or log_size > MAX_LOG_SIZE or
                (@as(u64, 1) << @intCast(log_size)) < count or
                (log_size > MIN_LOG_SIZE and
                    (@as(u64, 1) << @intCast(log_size - 1)) >= count))
            {
                return error.InvalidManifest;
            }
        }
        const expected_events = eventCountFromManifest(self) catch
            return error.InvalidManifest;
        if (self.relation_event_count != expected_events or
            !std.meta.eql(self.identity, manifestId(self)))
        {
            return error.InvalidManifest;
        }
    }
};

pub const LoweringObligationV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    circuit_id: u32 = NATIVE_SUM_CIRCUIT_ID,
    boundary_word_count: u32,
    native_sum_and_total_word_count: u16 = ARITHMETIC_PUBLICATION_WORD_COUNT,
    challenge_word_count: u16 = CHALLENGE_WORD_COUNT,
    input_count: u32,
    zero_output_count: u8 = 5,
    requires_qm31_composition: bool = true,
    requires_alpha_power_horner: bool = true,
    requires_checked_inverse: bool = true,
    requires_signed_accumulation: bool = true,
    graph_bound: bool = false,
    use_counts_bound: bool = false,
    identity: Digest,

    pub fn validate(self: *const LoweringObligationV2) Error!void {
        const expected_inputs = try checkedAddU32(
            self.boundary_word_count,
            ARITHMETIC_PUBLICATION_WORD_COUNT + CHALLENGE_WORD_COUNT,
        );
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.circuit_id != NATIVE_SUM_CIRCUIT_ID or
            self.native_sum_and_total_word_count !=
                ARITHMETIC_PUBLICATION_WORD_COUNT or
            self.challenge_word_count != CHALLENGE_WORD_COUNT or
            self.input_count != expected_inputs or self.zero_output_count != 5 or
            !self.requires_qm31_composition or
            !self.requires_alpha_power_horner or
            !self.requires_checked_inverse or
            !self.requires_signed_accumulation or self.graph_bound or
            self.use_counts_bound or
            !std.meta.eql(self.identity, loweringObligationId(self)))
        {
            return error.InvalidCapabilityLedger;
        }
    }
};

pub fn deriveCounts(
    wire_words: usize,
    authority_call_count: usize,
) Error!CountsV2 {
    var relay_relation_events = try checkedMul(PUBLICATION_WORD_COUNT, 3);
    relay_relation_events = try checkedAdd(
        relay_relation_events,
        try checkedMul(wire_words, 3),
    );
    relay_relation_events = try checkedAdd(
        relay_relation_events,
        try checkedMul(CHALLENGE_WORD_COUNT, 3),
    );
    const authority_relation_events = try checkedAdd(
        authority_call_count,
        AUTHORITY_BIND_EVENT_COUNT,
    );
    const relation_events = try checkedAdd(
        try checkedAdd(relay_relation_events, authority_relation_events),
        CONTROL_RELATION_EVENT_COUNT,
    );
    return .{
        .publication_header = PUBLICATION_HEADER_WORD_COUNT,
        .native_public_sums = NATIVE_PUBLIC_SUM_WORD_COUNT,
        .publication_seal = PUBLICATION_SEAL_WORD_COUNT,
        .boundary_bridge = wire_words,
        .native_challenges = CHALLENGE_WORD_COUNT,
        .control_relay = CONTROL_LOGICAL_ROW_COUNT,
        .relay_relation_events = relay_relation_events,
        .authority_relation_events = authority_relation_events,
        .control_relation_events = CONTROL_RELATION_EVENT_COUNT,
        .relation_events = relation_events,
    };
}

pub fn countsFromManifest(manifest: ManifestV2) CountsV2 {
    return .{
        .publication_header = manifest.logical_rows[rowIndex(.vm_public_claim_input)],
        .native_public_sums = NATIVE_PUBLIC_SUM_WORD_COUNT,
        .publication_seal = manifest.logical_rows[rowIndex(.vm_public_io_hash)],
        .boundary_bridge = manifest.logical_rows[rowIndex(.vm_public_claim_semantics_input)],
        .native_challenges = manifest.logical_rows[rowIndex(.vm_public_logup_input)],
        .control_relay = manifest.logical_rows[rowIndex(.vm_public_logup_control)],
        .relay_relation_events = manifest.relation_event_count -
            CONTROL_RELATION_EVENT_COUNT -
            manifest.authority_poseidon_call_count -
            AUTHORITY_BIND_EVENT_COUNT,
        .authority_relation_events = manifest.authority_poseidon_call_count +
            AUTHORITY_BIND_EVENT_COUNT,
        .control_relation_events = CONTROL_RELATION_EVENT_COUNT,
        .relation_events = manifest.relation_event_count,
    };
}

pub fn eventCountFromManifest(manifest: *const ManifestV2) Error!u32 {
    var relay_rows = try checkedAddU32(PUBLICATION_WORD_COUNT, manifest.wire_word_count);
    relay_rows = try checkedAddU32(relay_rows, CHALLENGE_WORD_COUNT);
    var result = try checkedMulU32(relay_rows, 3);
    result = try checkedAddU32(result, manifest.authority_poseidon_call_count);
    result = try checkedAddU32(result, AUTHORITY_BIND_EVENT_COUNT);
    return checkedAddU32(result, CONTROL_RELATION_EVENT_COUNT);
}

pub fn publicationEvents(
    publication: *const source_v2.VerifiedNativePublicLogUpPublicationV2,
) Error![PUBLICATION_WORD_COUNT]source_v2.VerifierInputEventV2 {
    var result: [PUBLICATION_WORD_COUNT]source_v2.VerifierInputEventV2 = undefined;
    try source_v2.writeVerifiedNativeVerifierInputEventsInto(publication, &result);
    return result;
}

pub fn manifestId(manifest: *const ManifestV2) Digest {
    var hash = IdentityHasher.init(MANIFEST_ID_DOMAIN);
    hash.scalar(manifest.format_version);
    hash.scalar(manifest.schema_version);
    hash.scalar(@intFromBool(manifest.frozen_v1_compatible));
    hash.scalar(manifest.first_roster_row);
    hash.scalar(manifest.row_count);
    for (manifest.logical_rows) |value| hash.scalar(value);
    for (manifest.log_sizes) |value| hash.scalar(value);
    hash.scalar(manifest.relation_event_count);
    hash.scalar(manifest.publication_word_count);
    hash.scalar(manifest.challenge_word_count);
    hash.scalar(manifest.wire_word_count);
    hash.digest(manifest.statement_source_id);
    hash.digest(manifest.publication_id);
    hash.digest(manifest.native_public_sums_id);
    hash.digest(manifest.relation_context_id);
    hash.digest(manifest.lowering_obligation_id);
    hash.digest(manifest.authority_hash_plan_id);
    hash.scalar(manifest.authority_poseidon_call_count);
    hash.shaDigest(manifest.control_source_id);
    hash.scalar(manifest.native_sum_circuit_id);
    hash.scalar(manifest.control_relay_circuit_id);
    hash.scalar(manifest.publication_bridge_circuit_id);
    hash.scalar(manifest.boundary_bridge_circuit_id);
    return hash.finalize();
}

pub fn loweringObligationId(obligation: *const LoweringObligationV2) Digest {
    var hash = IdentityHasher.init(LOWERING_OBLIGATION_ID_DOMAIN);
    hash.scalar(obligation.format_version);
    hash.scalar(obligation.schema_version);
    hash.scalar(obligation.circuit_id);
    hash.scalar(obligation.boundary_word_count);
    hash.scalar(obligation.native_sum_and_total_word_count);
    hash.scalar(obligation.challenge_word_count);
    hash.scalar(obligation.input_count);
    hash.scalar(obligation.zero_output_count);
    hash.scalar(@intFromBool(obligation.requires_qm31_composition));
    hash.scalar(@intFromBool(obligation.requires_alpha_power_horner));
    hash.scalar(@intFromBool(obligation.requires_checked_inverse));
    hash.scalar(@intFromBool(obligation.requires_signed_accumulation));
    hash.scalar(@intFromBool(obligation.graph_bound));
    hash.scalar(@intFromBool(obligation.use_counts_bound));
    return hash.finalize();
}

pub fn allZeroBytes(value: []const u8) bool {
    return std.mem.allEqual(u8, value, 0);
}

pub const IdentityHasher = struct {
    inner: channel.CanonicalWordHasher,

    pub fn init(domain: u32) IdentityHasher {
        return .{ .inner = channel.CanonicalWordHasher.init(domain) };
    }

    pub fn scalar(self: *IdentityHasher, value: anytype) void {
        const canonical: u32 = @intCast(value);
        std.debug.assert(canonical < m31.Modulus);
        self.inner.update(&.{M31.fromCanonical(canonical)});
    }

    pub fn u32Value(self: *IdentityHasher, value: u32) void {
        self.scalar(value & 0xffff);
        self.scalar(value >> 16);
    }

    pub fn digest(self: *IdentityHasher, value: Digest) void {
        for (value) |word| self.scalar(word);
    }

    pub fn shaDigest(self: *IdentityHasher, value: Sha256Digest) void {
        for (value) |byte| self.scalar(byte);
    }

    pub fn qm31(self: *IdentityHasher, value: QM31) void {
        const words = value.toM31Array();
        self.inner.update(&words);
    }

    pub fn finalize(self: *IdentityHasher) Digest {
        return self.inner.finalize();
    }
};

pub fn sumsEql(
    left: public_logup_v2.Sums,
    right: public_logup_v2.Sums,
) bool {
    return left.registers_state.eql(right.registers_state) and
        left.memory_access.eql(right.memory_access) and
        left.program_access.eql(right.program_access) and
        left.merkle.eql(right.merkle);
}

pub fn traceLogSize(row_count: usize) Error!u8 {
    const padded = std.math.ceilPowerOfTwo(usize, @max(row_count, 1)) catch
        return error.ArithmeticOverflow;
    const result: u8 = @max(MIN_LOG_SIZE, std.math.log2_int(usize, padded));
    if (result > MAX_LOG_SIZE) return error.InvalidTraceShape;
    return result;
}

pub fn rowIndex(component: roster.Component) usize {
    const raw = @intFromEnum(component);
    std.debug.assert(raw >= FIRST_ROW and raw <= LAST_ROW);
    return raw - FIRST_ROW;
}

pub fn checkedAdd(left: usize, right: usize) Error!usize {
    return std.math.add(usize, left, right) catch error.ArithmeticOverflow;
}

pub fn checkedMul(left: usize, right: usize) Error!usize {
    return std.math.mul(usize, left, right) catch error.ArithmeticOverflow;
}

pub fn checkedAddU32(left: u32, right: u32) Error!u32 {
    return std.math.add(u32, left, right) catch error.ArithmeticOverflow;
}

pub fn checkedMulU32(left: u32, right: u32) Error!u32 {
    return std.math.mul(u32, left, right) catch error.ArithmeticOverflow;
}
