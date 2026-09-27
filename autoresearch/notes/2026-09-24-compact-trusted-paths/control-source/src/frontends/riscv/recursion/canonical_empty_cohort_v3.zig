//! Canonical proofless-empty cohort for the V3.1 heterogeneous circuit.
//!
//! Empty owns no child STARK and therefore has no verifier-authenticated OODS
//! capture.  Its universal 36-row program is an explicitly inactive shell;
//! a dedicated statement provider binds the exact verified empty publication
//! and places its deterministic public LogUp contribution in V3 slot 36.
//! This avoids treating caller-supplied Binary zeros as proof evidence while
//! retaining one fixed 41-claim graph ABI.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const Sha256 = std.crypto.hash.sha2.Sha256;

const circuit = @import("recursion_air_composition_circuit_v3.zig");
const capture_layout = @import("recursion_air_composition_capture_layout_v3.zig");
const segment_recorder = @import("recursion_air_composition_segment_recorder_v3.zig");
const temporal_pair_node = @import("temporal_pair_node.zig");
const span_statement = @import("span_statement.zig");

const adapter = @import("air/universal_typed_component.zig");
const binding = @import("air/universal_relation_binding.zig");
const catalog = @import("air/universal_catalog.zig");
const manifest_mod = @import("air/universal_adapter_manifest.zig");
const provider = @import("air/universal_shared_provider.zig");
const range_bridge = @import("air/range_check_8_8_bridge.zig");
const relation = @import("../air/lang/relation.zig");
const universal = @import("air/universal_challenges.zig");

const relation_challenge_witness = @import("air/relation_challenge_witness.zig");
const statement_input = @import("air/statement_input.zig");
const vm_claim_input = @import("air/vm_public_claim_input.zig");
const vm_claim_hash = @import("air/vm_public_claim_hash.zig");
const transcript_payload = @import("air/transcript_payload.zig");
const composition_witness = @import("air/vm_air_composition_input_witness.zig");
const query_bits_witness = @import("air/query_bits_witness.zig");
const trace_merkle_witness = @import("air/trace_merkle_witness.zig");
const pcs_witness = @import("air/pcs_deep_input_witness.zig");
const fri_leaf_witness = @import("air/fri_merkle_leaf_witness.zig");
const fri_anchor_witness = @import("air/fri_merkle_anchor_witness.zig");
const fri_control_witness = @import("air/fri_verifier_control_witness.zig");
const fri_input_witness = @import("air/fri_verifier_input_witness.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const PARAMETER_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/canonical-empty-parameters/v3.1\x00";
pub const CLAIM_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/canonical-empty-claim/v3.1\x00";
pub const SAMPLE_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/canonical-empty-samples/v3.1\x00";

pub const LOGICAL_ROW_COUNT: usize = catalog.LOGICAL_COUNT;
pub const PHYSICAL_ROW_COUNT: usize = 36;
pub const HOT_SAMPLE_WRITES_HEAP_ALLOCATIONS: usize = 0;
pub const HOT_CLAIM_WRITES_HEAP_ALLOCATIONS: usize = 0;
pub const HOT_RECORD_HEAP_ALLOCATIONS: usize = 0;

pub const Error = circuit.Error || capture_layout.Error || segment_recorder.Error ||
    provider.Error ||
    range_bridge.Error || range_bridge.DefinitionError || universal.Error ||
    QM31.Error || std.mem.Allocator.Error || error{
    ClaimAuthorityMismatch,
    CohortAuthorityMismatch,
    InvalidCanonicalEmptyParameter,
    SampleAuthorityMismatch,
};

/// Runtime claim custody for one exact statement/challenge pair.  All 47
/// challenge draws are hashed so mutating an otherwise-unused relation cannot
/// create a second encoding of the same admitted empty witness.
pub const CanonicalEmptyClaimAuthorityV3 = struct {
    format_version: u16 = FORMAT_VERSION,
    program_identity: [32]u8,
    relations_identity: [32]u8,
    public_statement_claim: QM31,
    identity: [32]u8,

    pub fn seal(
        program: circuit.CanonicalEmptyProgramV3,
        relations: *const universal.UniversalRelations,
    ) Error!CanonicalEmptyClaimAuthorityV3 {
        try relations.validate();
        var result = CanonicalEmptyClaimAuthorityV3{
            .program_identity = program.identity,
            .relations_identity = relationsIdentity(relations),
            .public_statement_claim = try publicStatementClaim(
                &program.statement_words,
                relations,
            ),
            .identity = undefined,
        };
        result.identity = claimAuthorityIdentity(&result);
        try result.validateAgainst(program, relations);
        return result;
    }

    pub fn validateAgainst(
        self: CanonicalEmptyClaimAuthorityV3,
        program: circuit.CanonicalEmptyProgramV3,
        relations: *const universal.UniversalRelations,
    ) Error!void {
        try relations.validate();
        const expected_claim = try publicStatementClaim(
            &program.statement_words,
            relations,
        );
        if (self.format_version != FORMAT_VERSION or
            !std.mem.eql(u8, &self.program_identity, &program.identity) or
            !std.mem.eql(
                u8,
                &self.relations_identity,
                &relationsIdentity(relations),
            ) or
            !self.public_statement_claim.eql(expected_claim) or
            !std.mem.eql(u8, &self.identity, &claimAuthorityIdentity(&self)))
        {
            return error.ClaimAuthorityMismatch;
        }
    }

    pub fn writeClaimInputs(
        self: CanonicalEmptyClaimAuthorityV3,
        destination: *[circuit.COMPOSITION_CLAIM_INPUT_COUNT]QM31,
    ) Error!void {
        if (!std.mem.eql(u8, &self.identity, &claimAuthorityIdentity(&self)))
            return error.ClaimAuthorityMismatch;
        destination.* = [_]QM31{QM31.zero()} **
            circuit.COMPOSITION_CLAIM_INPUT_COUNT;
        destination[circuit.CANONICAL_EMPTY_PUBLIC_CLAIM_INDEX] =
            self.public_statement_claim;
        try circuit.validateClaimInputsForPolicy(
            .empty_leaf,
            .canonical_empty_provider,
            destination,
        );
    }
};

/// Empty has no capture samples.  The shared max-sized graph slice is required
/// to be canonical zero and is consumed only as the inactive shell workspace.
pub const CanonicalEmptySampleAuthorityV3 = struct {
    format_version: u16 = FORMAT_VERSION,
    layout_identity: [32]u8,
    shared_sample_count: u32,
    identity: [32]u8,

    pub fn seal(
        layout: *const capture_layout.CanonicalEmptyCaptureLayoutV3,
        shared_sample_count: u32,
    ) Error!CanonicalEmptySampleAuthorityV3 {
        if (shared_sample_count < layout.internal_sample_count)
            return error.SampleAuthorityMismatch;
        var result = CanonicalEmptySampleAuthorityV3{
            .layout_identity = layout.identity,
            .shared_sample_count = shared_sample_count,
            .identity = undefined,
        };
        result.identity = sampleAuthorityIdentity(result);
        try result.validateAgainst(layout, shared_sample_count);
        return result;
    }

    pub fn validateAgainst(
        self: CanonicalEmptySampleAuthorityV3,
        layout: *const capture_layout.CanonicalEmptyCaptureLayoutV3,
        shared_sample_count: u32,
    ) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.shared_sample_count != shared_sample_count or
            self.shared_sample_count < layout.internal_sample_count or
            !std.mem.eql(u8, &self.layout_identity, &layout.identity) or
            !std.mem.eql(u8, &self.identity, &sampleAuthorityIdentity(self)))
        {
            return error.SampleAuthorityMismatch;
        }
    }

    pub fn writeSharedSamples(
        self: CanonicalEmptySampleAuthorityV3,
        destination: []QM31,
    ) Error!void {
        if (destination.len != self.shared_sample_count or
            !std.mem.eql(u8, &self.identity, &sampleAuthorityIdentity(self)))
        {
            return error.SampleAuthorityMismatch;
        }
        @memset(destination, QM31.zero());
    }

    pub fn validateSharedSamples(
        self: CanonicalEmptySampleAuthorityV3,
        values: []const QM31,
    ) Error!void {
        if (values.len != self.shared_sample_count or
            !std.mem.eql(u8, &self.identity, &sampleAuthorityIdentity(self)))
        {
            return error.SampleAuthorityMismatch;
        }
        for (values) |value| if (!value.eql(QM31.zero()))
            return error.SampleAuthorityMismatch;
    }
};

fn LogicalOwner(comptime entry: catalog.Entry) type {
    const Air = entry.Air;
    const Relation = binding.Binding(Air);
    const TypedAdapter = adapter.Component(Air, Relation);
    return struct {
        definition: Air.Definition,
        component: TypedAdapter,

        fn init(
            allocator: std.mem.Allocator,
            manifest: *const manifest_mod.Manifest,
            relations: *const universal.UniversalRelations,
        ) !@This() {
            var definition = if (entry.requires_location)
                try Air.build(allocator, .generated)
            else
                try Air.build(allocator);
            errdefer definition.deinit();
            const relation_plan = try Relation.authenticate(&definition);
            return .{
                .definition = definition,
                .component = try TypedAdapter.init(
                    &definition,
                    relation_plan,
                    manifest,
                    entry.row,
                    (try manifest.placement(entry.row)).geometry.log_size,
                    canonicalParameters(Air),
                    relations,
                    QM31.zero(),
                ),
            };
        }

        fn deinit(self: *@This()) void {
            self.definition.deinit();
            self.* = undefined;
        }
    };
}

fn LogicalOwnersType() type {
    var types: [catalog.LOGICAL_COUNT]type = undefined;
    inline for (catalog.LOGICAL_ROWS, 0..) |entry, index|
        types[index] = LogicalOwner(entry);
    return std.meta.Tuple(&types);
}

pub const LogicalOwners = LogicalOwnersType();

/// Stable-address owner for every typed adapter and both shared providers.
/// `create` performs all allocations and authentication before publication;
/// row replay itself allocates nothing.
pub const CohortV3 = struct {
    allocator: std.mem.Allocator,
    manifest: manifest_mod.Manifest,
    relations: universal.UniversalRelations,
    provider_relations: provider.SharedProviderRelations,
    range_definition: range_bridge.Definition,
    range_executor: range_bridge.Executor,
    owners: LogicalOwners,
    initialized_owners: usize,
    poseidon: segment_recorder.EmptyProgramRecorderV3.PoseidonAdapter,
    range: segment_recorder.EmptyProgramRecorderV3.RangeCheck8x8Adapter,
    program_identity: [32]u8,
    layout_identity: [32]u8,

    pub fn create(
        allocator: std.mem.Allocator,
        manifest: *const manifest_mod.Manifest,
        binary_layout: *const capture_layout.CaptureLayoutV3,
        empty_layout: *const capture_layout.CanonicalEmptyCaptureLayoutV3,
        program: circuit.CanonicalEmptyProgramV3,
        relations: *const universal.UniversalRelations,
    ) !*CohortV3 {
        try program.validateAgainst(manifest, binary_layout, empty_layout);
        try relations.validate();
        const self = try allocator.create(CohortV3);
        errdefer allocator.destroy(self);
        self.* = undefined;
        self.allocator = allocator;
        self.manifest = manifest.*;
        self.relations = relations.*;
        self.initialized_owners = 0;
        self.program_identity = program.identity;
        self.layout_identity = empty_layout.identity;
        self.provider_relations = try provider.SharedProviderRelations.init(
            &self.relations,
        );
        self.range_definition = try range_bridge.build(allocator);
        errdefer self.range_definition.deinit();
        const range_binding = try range_bridge.Binding.canonical(
            &self.range_definition,
        );
        self.range_executor = try range_bridge.Executor.init(
            &self.range_definition,
            &range_binding,
        );
        errdefer deinitOwners(&self.owners, self.initialized_owners);
        inline for (catalog.LOGICAL_ROWS, 0..) |entry, index| {
            self.owners[index] = try LogicalOwner(entry).init(
                allocator,
                &self.manifest,
                &self.relations,
            );
            self.initialized_owners += 1;
        }
        const poseidon_log = (try self.manifest.placement(.poseidon2))
            .geometry.log_size;
        self.poseidon = try segment_recorder.EmptyProgramRecorderV3.PoseidonAdapter.init(
            &self.manifest,
            poseidon_log,
            0,
            &self.provider_relations,
            &self.relations,
            .{QM31.zero()} ** provider.POSEIDON_INTERACTION_BATCH_COUNT,
        );
        self.range = try segment_recorder.EmptyProgramRecorderV3.RangeCheck8x8Adapter.init(
            &self.range_definition,
            &self.range_executor,
            &self.manifest,
            &self.provider_relations,
            &self.relations,
            QM31.zero(),
        );
        try self.validate(program, empty_layout);
        return self;
    }

    pub fn deinit(self: *CohortV3) void {
        deinitOwners(&self.owners, self.initialized_owners);
        self.range_definition.deinit();
        const allocator = self.allocator;
        self.* = undefined;
        allocator.destroy(self);
    }

    pub fn validate(
        self: *const CohortV3,
        program: circuit.CanonicalEmptyProgramV3,
        empty_layout: *const capture_layout.CanonicalEmptyCaptureLayoutV3,
    ) !void {
        try self.manifest.validate();
        try self.relations.validate();
        try self.provider_relations.validateAgainst(&self.relations);
        const expected_parameter_authority = parameterAuthorityIdentity();
        if (self.initialized_owners != LOGICAL_ROW_COUNT or
            !std.mem.eql(u8, &self.program_identity, &program.identity) or
            !std.mem.eql(u8, &self.layout_identity, &empty_layout.identity) or
            !std.mem.eql(
                u8,
                &program.parameter_authority_identity,
                &expected_parameter_authority,
            ))
        {
            return error.CohortAuthorityMismatch;
        }
        inline for (catalog.LOGICAL_ROWS, 0..) |entry, index| {
            if (!std.meta.eql(
                self.owners[index].component.parameters,
                canonicalParameters(entry.Air),
            )) return error.CohortAuthorityMismatch;
            _ = try self.owners[index].component.binding(&self.manifest);
        }
        _ = try self.poseidon.binding(&self.manifest);
        _ = try self.range.binding(&self.manifest);
    }

    /// Allocation-free hot replay of the complete 34 logical + two provider
    /// roster.  The recorder itself enforces manifest order and exact row
    /// geometry; this owner only supplies the already-authenticated adapters.
    pub fn record(
        self: *const CohortV3,
        program_recorder: *segment_recorder.EmptyProgramRecorderV3,
    ) !segment_recorder.ProgramResultV3 {
        const recorder_layout = program_recorder.canonical_empty_layout_identity orelse
            return error.CohortAuthorityMismatch;
        if (!std.mem.eql(u8, &self.layout_identity, &recorder_layout))
            return error.CohortAuthorityMismatch;
        return program_recorder.recordCompleteCanonicalEmptyCatalog(
            &self.owners,
            &self.poseidon,
            &self.range,
        );
    }
};

pub fn sealProgram(
    manifest: *const manifest_mod.Manifest,
    binary_layout: *const capture_layout.CaptureLayoutV3,
    empty_layout: *const capture_layout.CanonicalEmptyCaptureLayoutV3,
    publication: *const temporal_pair_node.VerifiedChildV2,
) Error!circuit.CanonicalEmptyProgramV3 {
    return circuit.CanonicalEmptyProgramV3.seal(
        manifest,
        binary_layout,
        empty_layout,
        publication,
        parameterAuthorityIdentity(),
    );
}

pub fn parameterAuthorityIdentity() [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(PARAMETER_AUTHORITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    inline for (catalog.LOGICAL_ROWS) |entry| {
        hashInt(&hash, u8, @intFromEnum(entry.row));
        hash.update(&entry.Air.SEMANTIC_DIGEST);
        const parameters = canonicalParameters(entry.Air);
        hashInt(&hash, u16, parameters.len);
        for (parameters) |value| hashInt(&hash, u32, value.toU32());
    }
    return hash.finalResult();
}

fn canonicalParameters(comptime Air: type) [parameterCount(Air)]M31 {
    if (comptime @hasDecl(Air, "PARAMETER_NAMES")) {
        var result: [Air.PARAMETER_NAMES.len]M31 = undefined;
        inline for (Air.PARAMETER_NAMES, 0..) |name, index|
            result[index] = canonicalParameter(name);
        return result;
    } else {
        return .{};
    }
}

fn parameterCount(comptime Air: type) comptime_int {
    return if (@hasDecl(Air, "PARAMETER_NAMES"))
        Air.PARAMETER_NAMES.len
    else
        0;
}

fn canonicalParameter(comptime name: []const u8) M31 {
    if (comptime (std.mem.endsWith(u8, name, ".segment_active") or
        std.mem.endsWith(u8, name, ".binary_active") or
        std.mem.endsWith(u8, name, ".empty_active") or
        std.mem.endsWith(u8, name, ".zero") or
        std.mem.indexOf(u8, name, ".position_bit_mask_") != null))
    {
        return M31.zero();
    }
    const value: u32 = if (comptime std.mem.endsWith(u8, name, ".air_scope"))
        relation_challenge_witness.AIR_EVALUATION_CHALLENGE_SCOPE
    else if (comptime std.mem.endsWith(u8, name, ".public_scope"))
        relation_challenge_witness.VM_PUBLIC_LOGUP_CHALLENGE_SCOPE
    else if (comptime std.mem.endsWith(u8, name, ".input_item"))
        statement_input.STATEMENT_INPUT_ITEM
    else if (comptime std.mem.endsWith(u8, name, ".vm_claim_scope"))
        statement_input.VM_CLAIM_STATEMENT_SCOPE
    else if (comptime std.mem.endsWith(u8, name, ".semantics_scope"))
        vm_claim_input.VM_CLAIM_SEMANTICS_SCOPE
    else if (comptime std.mem.endsWith(u8, name, ".hash_domain"))
        vm_claim_hash.VM_PUBLIC_CLAIM_HASH_DOMAIN
    else if (comptime std.mem.endsWith(u8, name, ".hash_scope"))
        vm_claim_input.VM_CLAIM_HASH_SCOPE
    else if (comptime std.mem.endsWith(u8, name, ".public_logup_scope"))
        vm_claim_input.VM_PUBLIC_LOGUP_SCOPE
    else if (comptime std.mem.endsWith(u8, name, ".input_kind"))
        if (comptime std.mem.indexOf(u8, name, "statement_input") != null)
            statement_input.STATEMENT_INPUT_KIND
        else
            vm_claim_input.VM_PUBLIC_INPUT_KIND
    else if (comptime std.mem.endsWith(u8, name, ".output_kind"))
        vm_claim_input.VM_PUBLIC_OUTPUT_KIND
    else if (comptime std.mem.endsWith(u8, name, ".low_byte_index"))
        vm_claim_input.LOW_BYTE_INDEX
    else if (comptime std.mem.endsWith(u8, name, ".high_byte_index"))
        vm_claim_input.HIGH_BYTE_INDEX
    else if (comptime std.mem.endsWith(u8, name, ".verifier_id"))
        0
    else if (comptime std.mem.endsWith(u8, name, ".verifier_input_kind"))
        vm_claim_hash.VM_PUBLIC_CLAIM_DIGEST_INPUT_KIND
    else if (comptime std.mem.endsWith(u8, name, ".claim_scope"))
        if (comptime std.mem.indexOf(u8, name, "logup") != null)
            vm_claim_input.VM_PUBLIC_LOGUP_SCOPE
        else
            vm_claim_input.VM_CLAIM_SEMANTICS_SCOPE
    else if (comptime std.mem.endsWith(u8, name, ".statement_scope"))
        statement_input.VM_CLAIM_STATEMENT_SCOPE
    else if (comptime std.mem.endsWith(u8, name, ".challenge_scope"))
        if (comptime std.mem.indexOf(u8, name, "vm_air_composition") != null)
            composition_witness.CHALLENGE_SCOPE
        else
            relation_challenge_witness.VM_PUBLIC_LOGUP_CHALLENGE_SCOPE
    else if (comptime std.mem.endsWith(u8, name, ".claimed_sum_kind"))
        @intFromEnum(transcript_payload.VerifierInputKind.claimed_sum)
    else if (comptime std.mem.endsWith(u8, name, ".sampled_value_kind"))
        composition_witness.SAMPLED_VALUE_KIND
    else if (comptime std.mem.endsWith(u8, name, ".vm_claimed_sum_kind"))
        composition_witness.VM_CLAIMED_SUM_KIND
    else if (comptime std.mem.endsWith(u8, name, ".recursion_claimed_sum_kind"))
        composition_witness.RECURSION_CLAIMED_SUM_KIND
    else if (comptime std.mem.endsWith(u8, name, ".composition_randomness_kind"))
        composition_witness.COMPOSITION_RANDOMNESS_KIND
    else if (comptime std.mem.endsWith(u8, name, ".oods_point_kind"))
        composition_witness.OODS_POINT_KIND
    else if (comptime std.mem.endsWith(u8, name, ".transcript_claimed_sum_kind"))
        composition_witness.TRANSCRIPT_CLAIMED_SUM_KIND
    else if (comptime std.mem.endsWith(u8, name, ".raw_query_kind"))
        query_bits_witness.RAW_QUERY_KIND
    else if (comptime std.mem.endsWith(u8, name, ".leaf_tag"))
        trace_merkle_witness.LEAF_TAG
    else if (comptime std.mem.endsWith(u8, name, ".trace_position_kind"))
        trace_merkle_witness.TRACE_POSITION_KIND
    else if (comptime std.mem.endsWith(u8, name, ".deep_randomness_kind"))
        pcs_witness.DEEP_RANDOMNESS_KIND
    else if (comptime std.mem.endsWith(u8, name, ".deep_position_kind"))
        pcs_witness.DEEP_POSITION_KIND
    else if (comptime std.mem.endsWith(u8, name, ".fri_merkle_kind"))
        fri_anchor_witness.FRI_MERKLE_KIND
    else if (comptime std.mem.endsWith(u8, name, ".position_field"))
        fri_control_witness.POSITION_FIELD
    else if (comptime std.mem.endsWith(u8, name, ".offset_field"))
        fri_control_witness.OFFSET_FIELD
    else if (comptime std.mem.endsWith(u8, name, ".fri_alpha_kind"))
        fri_input_witness.FRI_ALPHA_KIND
    else if (comptime std.mem.endsWith(u8, name, ".fri_fold_kind"))
        fri_input_witness.FRI_FOLD_KIND
    else if (comptime std.mem.endsWith(u8, name, ".last_layer_kind"))
        fri_input_witness.LAST_LAYER_KIND
    else if (comptime std.mem.endsWith(u8, name, ".coefficient_kind"))
        fri_input_witness.COEFFICIENT_KIND
    else
        @compileError("unmapped canonical-empty AIR parameter: " ++ name);
    return M31.fromCanonical(value);
}

fn deinitOwners(owners: *LogicalOwners, initialized: usize) void {
    inline for (catalog.LOGICAL_ROWS, 0..) |entry, index| {
        _ = entry;
        if (index < initialized) owners[index].deinit();
    }
}

fn publicStatementClaim(
    words: *const span_statement.StatementWords,
    relations: *const universal.UniversalRelations,
) Error!QM31 {
    const challenge = relations.get(.recursion_statement_word);
    var sum = QM31.zero();
    for (words, 0..) |word, index| {
        const tuple = [_]M31{
            M31.fromCanonical(statement_input.PARENT_STATEMENT_SCOPE),
            M31.fromU64(index),
            word,
        };
        sum = sum.add(try (try challenge.combineBase(&tuple)).inv());
    }
    return sum.neg();
}

fn relationsIdentity(relations: *const universal.UniversalRelations) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(CLAIM_AUTHORITY_DOMAIN);
    hashInt(&hash, u16, relations.format_version);
    hash.update(&relations.registry_order_digest);
    for (relations.elements) |element| {
        hashInt(&hash, u8, element.arity);
        hashQm31(&hash, element.z);
        hashQm31(&hash, element.alpha);
    }
    return hash.finalResult();
}

fn claimAuthorityIdentity(value: *const CanonicalEmptyClaimAuthorityV3) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(CLAIM_AUTHORITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hash.update(&value.program_identity);
    hash.update(&value.relations_identity);
    hashQm31(&hash, value.public_statement_claim);
    return hash.finalResult();
}

fn sampleAuthorityIdentity(value: CanonicalEmptySampleAuthorityV3) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(SAMPLE_AUTHORITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hash.update(&value.layout_identity);
    hashInt(&hash, u32, value.shared_sample_count);
    return hash.finalResult();
}

fn hashQm31(hash: *Sha256, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (LOGICAL_ROW_COUNT != 34 or PHYSICAL_ROW_COUNT != 36 or
        circuit.CANONICAL_EMPTY_PUBLIC_CLAIM_INDEX != 36)
    {
        @compileError("canonical empty cohort roster/claim ABI drifted");
    }
}
