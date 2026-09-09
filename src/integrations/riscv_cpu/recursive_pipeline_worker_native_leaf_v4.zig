//! Persistent-worker stage-101 adapter for one full incremental Ethereum leaf.
//!
//! Seven ordered external inputs select one campaign leaf.  The source recipe
//! additionally names the raw input/output and both seal-last manifests; the
//! public-wire reference names the actual STWIPW04 bytes.  Both build and cold
//! open therefore reopen every byte from a typed Zig CAS reference and replay
//! the complete manifest/source/transition/wire custody chain.
//!
//! The producer result is STWIEF04 schema 2 carried by CAS proof kind 8,
//! schema 1.  Producer state never becomes a lease.  Only `coldOpenLease`,
//! after a second CAS replay and a complete q193 verifier transaction, returns
//! an owned process-local `FreshInputV4`.  No fresh capability has a codec.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const campaign_namespace =
    @import("recursive_pipeline_campaign_namespace_v1.zig");
const recipe_mod = @import("recursive_pipeline_incremental_leaf_recipe_v4.zig");
const support = @import("ethereum_block_leaf_support.zig");
const publication = @import("ethereum_incremental_capture_publication_v4.zig");
const wire_publication =
    @import("ethereum_incremental_public_wire_publication_v4.zig");
const boundary_artifact = @import("ethereum_incremental_boundary_artifact_v4.zig");
const postprocess_authority =
    @import("ethereum_incremental_capture_postprocess_authority_v4.zig");
const producer = @import("ethereum_incremental_full_leaf_replay_producer_v4.zig");
const proof_artifact =
    @import("ethereum_incremental_full_leaf_proof_artifact_v4.zig");
const fresh_input =
    @import("recursive_common_ethereum_incremental_leaf_input_v4.zig");
const base_profile = @import("ethereum_incremental_native_leaf_profile_v3.zig");
const node_coordinate = @import("recursive_node_artifact_v1.zig");

const Engine = frontend.recursion.engine.ProverEngineForBackend(CpuBackend);
const minimal = frontend.runner.minimal_trace;
const public_data = frontend.air.public_data;
const source_wire = support.source_wire;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const adapter_name = "ethereum_incremental_native_leaf_v4";
pub const profile_schema =
    "stwo.recursive-pipeline-native-leaf-profile.v4";
pub const validation_schema =
    "stwo.recursive-pipeline-native-leaf-validation.v4";

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const STAGE_SCHEMA_VERSION: u16 = 101;
pub const OUTPUT_SCHEMA_VERSION: u16 = 1;
pub const OUTPUT_ARTIFACT_SCHEMA_VERSION: u16 = proof_artifact.SCHEMA_VERSION;
pub const PRODUCTION_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const EXTERNAL_INPUT_COUNT: usize = 7;
pub const MAXIMUM_OUTPUT_BYTES: usize =
    (proof_artifact.Limits{}).max_artifact_bytes;
pub const maximum_output_bytes = MAXIMUM_OUTPUT_BYTES;
pub const ProverExecutionOptionsV4 = frontend.testing
    .incremental_ethereum_orchestration_v4_internal.ExecutionOptions;

const maximum_program_bytes: u64 = 64 * 1024 * 1024;
const maximum_raw_input_bytes: u64 = 64 * 1024 * 1024;
const maximum_raw_output_bytes: u64 = 16 * 1024 * 1024;
const maximum_journal_record_bytes: u64 = 1024 * 1024;
const local_task_domain =
    "stwo-zig/recursive-pipeline-native-leaf-task/v4\x00";
const layout_authority_domain =
    "stwo-zig/recursive-pipeline-native-leaf-layout-input/v4\x00";
const lease_binding_domain =
    "stwo-zig/recursive-pipeline-native-leaf-lease/v4\x00";

pub const Error = error{
    NativeLeafStage101ArtifactMismatch,
    NativeLeafStage101InputMismatch,
    NativeLeafStage101OutputMismatch,
    NativeLeafStage101ProjectionMismatch,
    NativeLeafStage101RequiresArtifactStore,
};

pub const ExternalInputCoordinateV4 = struct {
    role: artifact_store.InputRoleV1,
    ordinal: u32,
    kind: artifact_store.ArtifactKindV1,
    schema_version: u16,
    exact_byte_count: ?u64 = null,
};

/// Frozen controller order.  These are semantic coordinates, not a bag of
/// inputs: swapping the two capture refs or changing any role is rejected.
pub const external_input_coordinates = [EXTERNAL_INPUT_COUNT]ExternalInputCoordinateV4{
    .{ .role = .statement, .ordinal = 0, .kind = .statement, .schema_version = 1, .exact_byte_count = source_wire.encoded_size },
    .{ .role = .program, .ordinal = 0, .kind = .program, .schema_version = 1 },
    .{ .role = .profile, .ordinal = 0, .kind = .capture_transport, .schema_version = recipe_mod.SCHEMA_VERSION, .exact_byte_count = recipe_mod.ENCODED_BYTE_COUNT },
    .{ .role = .witness, .ordinal = 0, .kind = .capture_transport, .schema_version = 1 },
    .{ .role = .capture, .ordinal = 0, .kind = .capture_transport, .schema_version = boundary_artifact.SCHEMA_VERSION },
    .{ .role = .capture, .ordinal = 1, .kind = .capture_transport, .schema_version = wire_publication.CAS_REFERENCE_SCHEMA_VERSION, .exact_byte_count = wire_publication.reference_byte_count },
    .{ .role = .journal, .ordinal = 0, .kind = .journal, .schema_version = 1 },
};

pub fn validateExternalInputs(
    inputs: []const artifact_store.InputRefV1,
) !void {
    if (inputs.len != EXTERNAL_INPUT_COUNT)
        return error.NativeLeafStage101InputMismatch;
    for (inputs, external_input_coordinates) |input, expected| {
        try input.validate();
        const byte_count_mismatch = if (expected.exact_byte_count) |count|
            input.blob.byte_count != count
        else
            false;
        if (input.role != expected.role or input.ordinal != expected.ordinal or
            input.blob.kind != expected.kind or
            input.blob.format_version != artifact_store.types.format_version_v1 or
            input.blob.schema_version != expected.schema_version or
            input.blob.byte_count == 0 or byte_count_mismatch)
        {
            return error.NativeLeafStage101InputMismatch;
        }
    }
}

pub const SemanticProjectionV4 = struct {
    campaign_namespace_sha256: artifact_store.Digest,
    local_task_identity_sha256: artifact_store.Digest,
    authorities: protocol.SemanticAuthorities,
};

/// Zig-owned semantic projection.  Every value is derived from typed input
/// references or the frozen q193 protocol; Python never hashes proof bytes.
pub fn semanticProjection(
    segment_index: u32,
    segment_count: u32,
    inputs: []const artifact_store.InputRefV1,
    campaign_namespace_sha256: artifact_store.Digest,
) !SemanticProjectionV4 {
    try validateExternalInputs(inputs);
    if (segment_count < recipe_mod.MIN_SEGMENT_COUNT or
        segment_count > recipe_mod.MAX_SEGMENT_COUNT or
        segment_index >= segment_count or
        std.mem.allEqual(u8, &campaign_namespace_sha256, 0))
    {
        return error.NativeLeafStage101InputMismatch;
    }
    const canonical = base_profile.ProtocolAuthorityV3.canonical();
    try canonical.validate();
    return .{
        .campaign_namespace_sha256 = campaign_namespace_sha256,
        .local_task_identity_sha256 = taskIdentity(
            segment_index,
            segment_count,
            inputs,
        ),
        .authorities = .{
            .protocol_identity_sha256 = canonical.identity_sha256,
            .program_identity_sha256 = inputs[1].blob.sha256,
            .profile_identity_sha256 = inputs[2].blob.sha256,
            .pcs_identity_sha256 = canonical.pcs.identity_sha256,
            .security_identity_sha256 = canonical.proof_security_identity_sha256,
            .statement_identity_sha256 = inputs[0].blob.sha256,
            .provider_identity_sha256 = [_]u8{0} ** 32,
            .layout_identity_sha256 = layoutInputIdentity(inputs),
            .registry_identity_sha256 = [_]u8{0} ** 32,
        },
    };
}

pub fn LeasePayloadV4(comptime SelectedEngine: type) type {
    return struct {
        fresh: fresh_input.FreshInputV4(SelectedEngine),
        semantic_key_identity: artifact_store.Digest,
        ordered_input_identity_sha256: artifact_store.Digest,
        binding_identity_sha256: artifact_store.Digest,

        const Self = @This();

        pub fn initOwned(
            fresh_value: fresh_input.FreshInputV4(SelectedEngine),
            semantic_key_identity: artifact_store.Digest,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !Self {
            var fresh_owned = fresh_value;
            errdefer fresh_owned.deinit();
            const input_identity = orderedInputIdentity(ordered_inputs);
            var result = Self{
                .fresh = fresh_owned,
                .semantic_key_identity = semantic_key_identity,
                .ordered_input_identity_sha256 = input_identity,
                .binding_identity_sha256 = undefined,
            };
            result.binding_identity_sha256 = leaseBindingIdentity(
                SelectedEngine,
                &result,
            );
            try result.validate();
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.fresh.deinit();
            self.* = undefined;
        }

        pub fn validate(self: *const Self) !void {
            try self.fresh.validate();
            if (std.mem.allEqual(u8, &self.semantic_key_identity, 0) or
                std.mem.allEqual(
                    u8,
                    &self.ordered_input_identity_sha256,
                    0,
                ) or !std.mem.eql(
                u8,
                &self.binding_identity_sha256,
                &leaseBindingIdentity(SelectedEngine, self),
            )) return error.NativeLeafStage101ArtifactMismatch;
        }

        pub fn freshView(
            self: *const Self,
        ) fresh_input.FreshViewV4(SelectedEngine) {
            return self.fresh.freshView();
        }
    };
}

pub fn AdapterForEngine(comptime SelectedEngine: type) type {
    return struct {
        pub const name = adapter_name;
        pub const production = PRODUCTION_ACTIVATION;
        pub const available = true;
        pub const LeasePayload = LeasePayloadV4(SelectedEngine);
        pub const maximum_output_bytes = MAXIMUM_OUTPUT_BYTES;

        pub fn acceptsNodeAdapter(value: []const u8) bool {
            return std.mem.eql(u8, value, adapter_name) or
                std.mem.eql(u8, value, "zig-worker-v1");
        }

        pub fn describe(
            stage_kind: artifact_store.StageKindV1,
            stage_schema_version: u16,
        ) !protocol.StageDescription {
            if (stage_kind != .prove or
                stage_schema_version != STAGE_SCHEMA_VERSION)
            {
                return error.UnsupportedRecursivePipelineStage;
            }
            return .{
                .stage_kind = .prove,
                .stage_schema_version = STAGE_SCHEMA_VERSION,
                .output_kind = .proof_artifact,
                .output_schema_version = OUTPUT_SCHEMA_VERSION,
                .minimum_cpu_tokens = 1,
                .minimum_rss_tokens = 1,
                .root_cold_open_transitive = true,
            };
        }

        pub fn buildOutput(
            _: std.mem.Allocator,
            _: protocol.Node,
            _: artifact_store.SemanticKeyV1,
            _: []const artifact_store.InputRefV1,
            _: u64,
        ) ![]u8 {
            return error.NativeLeafStage101RequiresArtifactStore;
        }

        pub fn buildOutputWithLeases(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            _: u64,
            dependency_leases: []const *const LeasePayload,
        ) ![]u8 {
            if (dependency_leases.len != 0)
                return error.NativeLeafStage101InputMismatch;
            return buildOutputWithExecutionForEngine(
                SelectedEngine,
                allocator,
                store,
                node,
                semantic,
                ordered_inputs,
                .{},
            );
        }

        pub fn profileValue(
            allocator: std.mem.Allocator,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            _: artifact_store.ExecutionKeyV1,
            candidate_ordinal: u64,
        ) !protocol.Json {
            var value = protocol.jsonObject(allocator);
            try protocol.put(&value, "schema", protocol.string(profile_schema));
            try protocol.put(&value, "node_id", protocol.string(node.node_id));
            try protocol.putDigest(
                allocator,
                &value,
                "semantic_key_sha256",
                semantic.identity,
            );
            try protocol.put(
                &value,
                "candidate_ordinal",
                try protocol.integerU64(allocator, candidate_ordinal),
            );
            try protocol.put(&value, "vm_reexecution", .{ .bool = false });
            try protocol.put(&value, "production", .{ .bool = false });
            try protocol.sealObject(allocator, &value);
            return value;
        }

        /// STWIEF04 does not serialize its source BlobRefs.  Store-less output
        /// validation therefore cannot prove the seven-input binding and must
        /// not mint or imply admission.  `coldOpenLease` is the only verifier
        /// path and repeats the CAS custody chain.
        pub fn validateOutput(
            _: std.mem.Allocator,
            _: []const u8,
            _: protocol.Node,
            _: artifact_store.SemanticKeyV1,
            _: []const artifact_store.InputRefV1,
        ) !void {
            return error.NativeLeafStage101RequiresArtifactStore;
        }

        pub fn coldOpenLease(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !LeasePayload {
            var opened = try OwnedStageInputsV4.open(
                allocator,
                store,
                node,
                semantic,
                ordered_inputs,
            );
            defer opened.deinit();
            const coordinate = try node_coordinate.TaskCoordinateV1.init(
                0,
                opened.segment_index,
            );
            const retained = opened.mint.wire.data.retained_snapshots orelse
                return error.NativeLeafStage101ValidationAuthorityMissing;
            var validation_counters = frontend.air.public_data_v2.PublicDataV2
                .ValidationCountersV2{};
            var fresh = try fresh_input.FreshInputV4(SelectedEngine)
                .coldOpenWithRetainedSnapshots(
                allocator,
                bytes,
                coordinate,
                .{},
                retained,
                &validation_counters,
            );
            var fresh_owned = true;
            defer if (fresh_owned) fresh.deinit();
            const validation = validation_counters.snapshot();
            if (validation.retained_root_authentications != 1 or
                validation.legacy_full_authentications != 0)
            {
                return error.NativeLeafStage101ValidationBudgetMismatch;
            }
            try validateFreshAgainstInputs(
                SelectedEngine,
                allocator,
                &fresh,
                &opened,
                bytes,
            );
            const moved = fresh;
            fresh = undefined;
            fresh_owned = false;
            return LeasePayload.initOwned(
                moved,
                semantic.identity,
                ordered_inputs,
            );
        }

        pub fn deinitLeasePayload(
            payload: *LeasePayload,
            _: std.mem.Allocator,
        ) void {
            payload.deinit();
        }

        pub fn validationValue(
            allocator: std.mem.Allocator,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            output_ref: artifact_store.BlobRefV1,
            validator_version: u32,
            mode: []const u8,
        ) !protocol.Json {
            var value = protocol.jsonObject(allocator);
            try protocol.put(
                &value,
                "schema",
                protocol.string(validation_schema),
            );
            try protocol.put(&value, "node_id", protocol.string(node.node_id));
            try protocol.putDigest(
                allocator,
                &value,
                "semantic_key_sha256",
                semantic.identity,
            );
            try protocol.putDigest(
                allocator,
                &value,
                "output_sha256",
                output_ref.sha256,
            );
            try protocol.put(
                &value,
                "validator_version",
                protocol.integer(validator_version),
            );
            try protocol.put(&value, "mode", protocol.string(mode));
            try protocol.put(&value, "cold_verified", .{ .bool = true });
            try protocol.put(&value, "production", .{ .bool = false });
            try protocol.sealObject(allocator, &value);
            return value;
        }
    };
}

/// Shared Stage-101 build transaction with an explicit proof execution
/// request. The legacy adapter delegates with default options; execution-key
/// aware wrappers must validate their policy before crossing this boundary.
pub fn buildOutputWithExecutionForEngine(
    comptime SelectedEngine: type,
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    node: protocol.Node,
    semantic: artifact_store.SemanticKeyV1,
    ordered_inputs: []const artifact_store.InputRefV1,
    execution: ProverExecutionOptionsV4,
) ![]u8 {
    var opened = try OwnedStageInputsV4.open(
        allocator,
        store,
        node,
        semantic,
        ordered_inputs,
    );
    defer opened.deinit();
    const role = frontend.runner.memory_state.SegmentRole{
        .is_first = opened.segment_index == 0,
        .is_last = opened.segment_index + 1 == opened.segment_count,
    };
    var proof_public = opened.mint.role_public.value;
    const retained_completion = proof_public.completion orelse
        return error.NativeLeafStage101InputMismatch;
    proof_public.completion = try opened.program.completionForProof(
        role,
        retained_completion,
    );
    try proof_public.validate();
    var public_authority = opened.mint.publicAuthority();
    public_authority.public_data = &proof_public;
    try public_authority.validate();
    var validation_counters = frontend.air.public_data_v2.PublicDataV2
        .ValidationCountersV2{};
    const encoded = try producer.produceAlloc(
        SelectedEngine,
        allocator,
        .{
            .compact = &opened.mint.compact,
            .public_wire = &opened.mint.wire.data,
            .role_aware_public = &proof_public,
            .public_authority = public_authority,
            .boundary = &opened.boundary,
            .program = &opened.program,
            .replay_authority = try opened.producerReplayAuthority(),
            .validation_counters = &validation_counters,
        },
        .{},
        execution,
    );
    const validation = validation_counters.snapshot();
    if (validation.retained_root_authentications != 1 or
        validation.legacy_full_authentications != 0)
    {
        allocator.free(encoded);
        return error.NativeLeafStage101ValidationBudgetMismatch;
    }
    return encoded;
}

pub const Adapter = AdapterForEngine(Engine);

const OwnedStageInputsV4 = struct {
    mint: postprocess_authority.OwnedMintInputV4,
    boundary: boundary_artifact.OwnedArtifactV4,
    program: producer.ProgramV4,
    execution: publication.ExecutionAuthorityV4,
    segment_index: u32,
    segment_count: u32,
    global_cycle_start: u32,

    fn open(
        allocator: std.mem.Allocator,
        store: *artifact_store.Store,
        node: protocol.Node,
        semantic: artifact_store.SemanticKeyV1,
        inputs: []const artifact_store.InputRefV1,
    ) !OwnedStageInputsV4 {
        try validateStageNode(node, inputs);
        var recipe_blob = try openBlob(
            store,
            inputs[2].blob,
            recipe_mod.ENCODED_BYTE_COUNT,
        );
        defer recipe_blob.deinit(store.allocator);
        const recipe = try recipe_mod.decode(recipe_blob.bytes);
        try recipe.validateStageInputs(inputs, inputs[2].blob);
        const expected_campaign_namespace =
            try campaign_namespace.fromValidatedRecipe(&recipe);
        try validateSemantic(
            allocator,
            node,
            semantic,
            inputs,
            recipe.segment_index,
            recipe.segment_count,
            expected_campaign_namespace,
        );

        var source_blob = try openBlob(store, inputs[0].blob, source_wire.encoded_size);
        defer source_blob.deinit(store.allocator);
        const source = try source_wire.decode(source_blob.bytes);
        var program_blob = try openBlob(store, inputs[1].blob, maximum_program_bytes);
        defer program_blob.deinit(store.allocator);
        var compact_blob = try openBlob(
            store,
            inputs[3].blob,
            minimal.ethereum_wire.MAX_ENCODED_BYTES,
        );
        defer compact_blob.deinit(store.allocator);
        var boundary_blob = try openBlob(
            store,
            inputs[4].blob,
            boundary_artifact.default_limits.max_bytes,
        );
        defer boundary_blob.deinit(store.allocator);
        var public_ref_blob = try openBlob(
            store,
            inputs[5].blob,
            wire_publication.reference_byte_count,
        );
        defer public_ref_blob.deinit(store.allocator);
        const public_ref = try wire_publication.decodeSegmentRef(
            public_ref_blob.bytes,
        );
        var journal_blob = try openBlob(
            store,
            inputs[6].blob,
            maximum_journal_record_bytes,
        );
        defer journal_blob.deinit(store.allocator);

        var input_blob = try openBlob(
            store,
            recipe.raw_input,
            maximum_raw_input_bytes,
        );
        defer input_blob.deinit(store.allocator);
        var output_blob = try openBlob(
            store,
            recipe.expected_output,
            maximum_raw_output_bytes,
        );
        defer output_blob.deinit(store.allocator);
        var capture_manifest_blob = try openBlob(
            store,
            recipe.boundary_manifest_v4,
            publication.manifest_max_byte_count,
        );
        defer capture_manifest_blob.deinit(store.allocator);
        var capture_manifest = try publication.decodeManifestAlloc(
            allocator,
            capture_manifest_blob.bytes,
        );
        defer capture_manifest.deinit();
        var wire_manifest_blob = try openBlob(
            store,
            recipe.public_wire_manifest_v4,
            wire_publication.manifest_max_byte_count,
        );
        defer wire_manifest_blob.deinit(store.allocator);
        var wire_manifest = try wire_publication.decodeManifestAlloc(
            allocator,
            wire_manifest_blob.bytes,
        );
        defer wire_manifest.deinit();

        const ordinal: usize = @intCast(recipe.segment_index);
        if (capture_manifest.value.segment_count != recipe.segment_count or
            wire_manifest.value.segment_count != recipe.segment_count or
            !lengthMatches(
                capture_manifest.value.segments.len,
                recipe.segment_count,
            ) or
            !lengthMatches(
                wire_manifest.value.segments.len,
                recipe.segment_count,
            ) or
            ordinal >= capture_manifest.value.segments.len or
            ordinal >= wire_manifest.value.segments.len or
            !identityMatchesRef(capture_manifest.file, recipe.boundary_manifest_v4) or
            !identityMatchesRef(wire_manifest.file, recipe.public_wire_manifest_v4))
        {
            return error.NativeLeafStage101ArtifactMismatch;
        }
        try wire_manifest.value.validateAgainst(
            capture_manifest.value.execution,
            capture_manifest.value.final_bindings,
            capture_manifest.file,
        );
        const capture_segment = capture_manifest.value.segments[ordinal];
        const wire_segment = wire_manifest.value.segments[ordinal];
        try validateCampaignBindings(
            recipe,
            capture_segment,
            wire_segment,
            public_ref,
            source,
            journal_blob.ref,
        );

        const wire_ref = try blobRefFromIdentity(
            .capture_transport,
            wire_publication.CAS_WIRE_SCHEMA_VERSION,
            public_ref.wire_artifact,
        );
        var wire_blob = try openBlob(
            store,
            wire_ref,
            wire_publication.max_wire_bytes,
        );
        defer wire_blob.deinit(store.allocator);
        var mint = try postprocess_authority.OwnedMintInputV4.openCanonicalBytes(
            allocator,
            capture_manifest.value.execution,
            program_blob.bytes,
            input_blob.bytes,
            output_blob.bytes,
            &source,
            compact_blob.bytes,
            wire_blob.bytes,
        );
        errdefer mint.deinit();
        var boundary = try boundary_artifact.decodeAlloc(
            allocator,
            boundary_blob.bytes,
            boundary_artifact.default_limits,
        );
        errdefer boundary.deinit();
        var program = try producer.ProgramV4.init(allocator, program_blob.bytes);
        errdefer program.deinit();
        try mint.validate(capture_manifest.value.execution);
        try validateOpenedBindings(
            &mint,
            &boundary,
            &program,
            capture_segment,
            wire_segment,
            public_ref,
        );
        const metadata = try mint.wire.data.metadata();
        return .{
            .mint = mint,
            .boundary = boundary,
            .program = program,
            .execution = capture_manifest.value.execution,
            .segment_index = recipe.segment_index,
            .segment_count = recipe.segment_count,
            .global_cycle_start = metadata.global_cycle_start,
        };
    }

    fn deinit(self: *OwnedStageInputsV4) void {
        self.program.deinit();
        self.boundary.deinit();
        self.mint.deinit();
        self.* = undefined;
    }

    fn producerReplayAuthority(
        self: *const OwnedStageInputsV4,
    ) !producer.ReplayAuthorityV4 {
        return .{
            .source = self.mint.replay_authority.source,
            .global_first_cycle = std.math.add(
                u64,
                self.global_cycle_start,
                1,
            ) catch return error.NativeLeafStage101ArtifactMismatch,
            .entry_cpu_sha256 = self.mint.replay_authority.entry_cpu_sha256,
            .exit_cpu_sha256 = self.mint.replay_authority.exit_cpu_sha256,
            .completion = self.mint.replay_authority.completion,
        };
    }
};

fn validateStageNode(
    node: protocol.Node,
    inputs: []const artifact_store.InputRefV1,
) !void {
    if (node.stage_kind != .prove or
        node.stage_schema_version != STAGE_SCHEMA_VERSION or
        node.dependencies.len != 0 or
        node.external_inputs.len != EXTERNAL_INPUT_COUNT or
        node.output_kind != .proof_artifact or
        node.output_schema_version != OUTPUT_SCHEMA_VERSION or
        !Adapter.acceptsNodeAdapter(node.adapter) or
        inputs.len != node.external_inputs.len)
    {
        return error.NativeLeafStage101InputMismatch;
    }
    try validateExternalInputs(inputs);
    for (inputs, node.external_inputs) |input, external| {
        if (!std.meta.eql(input, external))
            return error.NativeLeafStage101InputMismatch;
    }
    const options = try protocol.objectValue(node.semantic_options);
    try protocol.exactKeys(options, &.{});
}

fn validateSemantic(
    allocator: std.mem.Allocator,
    node: protocol.Node,
    semantic: artifact_store.SemanticKeyV1,
    inputs: []const artifact_store.InputRefV1,
    segment_index: u32,
    segment_count: u32,
    campaign_namespace_sha256: artifact_store.Digest,
) !void {
    try semantic.validate(allocator);
    const expected = try semanticProjection(
        segment_index,
        segment_count,
        inputs,
        campaign_namespace_sha256,
    );
    const fields = semantic.fields;
    if (fields.stage_kind != .prove or
        fields.stage_schema_version != STAGE_SCHEMA_VERSION or
        !std.mem.eql(
            u8,
            &fields.campaign_namespace,
            &expected.campaign_namespace_sha256,
        ) or
        !std.mem.eql(u8, &fields.local_task_identity, &expected.local_task_identity_sha256) or
        !std.mem.eql(u8, &node.local_task_identity_sha256, &expected.local_task_identity_sha256) or
        !semanticAuthoritiesEqual(fields, expected.authorities) or
        fields.ordered_inputs.len != inputs.len)
    {
        return error.NativeLeafStage101ProjectionMismatch;
    }
    for (fields.ordered_inputs, inputs) |actual, expected_input| {
        if (!std.meta.eql(actual, expected_input))
            return error.NativeLeafStage101ProjectionMismatch;
    }
}

fn validateCampaignBindings(
    recipe: recipe_mod.RecipeV4,
    capture: publication.CommittedSegmentV4,
    wire: wire_publication.CommittedSegmentV4,
    public_ref: wire_publication.SegmentRefV4,
    source: source_wire.Source,
    journal_ref: artifact_store.BlobRefV1,
) !void {
    try capture.validate();
    try wire.validate();
    try public_ref.validate();
    try source.validate();
    if (capture.segment.segment_index != recipe.segment_index or
        capture.segment.segment_count != recipe.segment_count or
        !identityMatchesRef(capture.segment.source, recipe.statement) or
        !identityMatchesRef(capture.segment.compact_tape, recipe.compact_witness) or
        !identityMatchesRef(capture.segment.artifact, recipe.boundary_v4) or
        !identityMatchesRef(wire.reference, recipe.public_wire_reference_v4) or
        !std.meta.eql(wire.segment, public_ref) or
        !std.meta.eql(public_ref.v4_segment_reference, capture.reference) or
        !std.meta.eql(public_ref.source, capture.segment.source) or
        !std.meta.eql(public_ref.coordinate.segment_index, recipe.segment_index) or
        !std.meta.eql(public_ref.coordinate.segment_count, recipe.segment_count) or
        !std.mem.eql(u8, &public_ref.journal_record_sha256, &capture.segment.journal_record_sha256) or
        !std.mem.eql(u8, &journal_ref.sha256, &capture.segment.journal_record_sha256) or
        source.metadata.segment_index != recipe.segment_index or
        source.metadata.segment_count != recipe.segment_count or
        !std.mem.eql(u8, &source.journal_record_sha256, &journal_ref.sha256))
    {
        return error.NativeLeafStage101ArtifactMismatch;
    }
}

fn lengthMatches(length: usize, expected: u32) bool {
    const actual = std.math.cast(u32, length) orelse return false;
    return actual == expected;
}

fn validateOpenedBindings(
    mint: *const postprocess_authority.OwnedMintInputV4,
    boundary: *const boundary_artifact.OwnedArtifactV4,
    program: *const producer.ProgramV4,
    capture: publication.CommittedSegmentV4,
    wire: wire_publication.CommittedSegmentV4,
    public_ref: wire_publication.SegmentRefV4,
) !void {
    try boundary.validateCanonical(boundary_artifact.default_limits);
    if (!std.meta.eql(mint.compact_identity, capture.segment.compact_tape) or
        !std.meta.eql(mint.wire_identity, wire.segment.wire_artifact) or
        !std.meta.eql(mint.source_identity, capture.segment.source) or
        !std.mem.eql(u8, &mint.journal_record_sha256, &capture.segment.journal_record_sha256) or
        !std.mem.eql(u8, &mint.program_source.identity, &program.program.identity) or
        !std.meta.eql(boundary.coordinate.segment_index, capture.segment.segment_index) or
        !std.meta.eql(boundary.coordinate.segment_count, capture.segment.segment_count) or
        boundary.continuation_roots.entry != capture.segment.entry_root or
        boundary.continuation_roots.exit != capture.segment.exit_root or
        !std.mem.eql(u8, &boundary.content_sha256, &capture.segment.artifact_content_sha256) or
        !std.mem.eql(u8, &boundary.transition_v2.content_sha256, &capture.segment.transition_v2_content_sha256) or
        !std.meta.eql(boundary.segment_public_wire_id, public_ref.wire_id) or
        !std.meta.eql(mint.wire.data.wireId(), public_ref.wire_id))
    {
        return error.NativeLeafStage101ArtifactMismatch;
    }
}

fn validateFreshAgainstInputs(
    comptime SelectedEngine: type,
    allocator: std.mem.Allocator,
    fresh: *const fresh_input.FreshInputV4(SelectedEngine),
    opened: *const OwnedStageInputsV4,
    artifact_bytes: []const u8,
) !void {
    try fresh.validateAgainstArtifact(artifact_bytes);
    var expected_public = opened.mint.role_public.value;
    const retained_completion = expected_public.completion orelse
        return error.NativeLeafStage101OutputMismatch;
    expected_public.completion = try opened.program.completionForProof(
        .{
            .is_first = opened.segment_index == 0,
            .is_last = opened.segment_index + 1 == opened.segment_count,
        },
        retained_completion,
    );
    try expected_public.validate();
    var expected_authority = opened.mint.publicAuthority();
    expected_authority.public_data = &expected_public;
    try fresh.stage101.profile.validateAgainstInputs(
        allocator,
        &opened.boundary,
        &opened.mint.wire.data,
        expected_authority,
        &fresh.stage101.statement,
        &fresh.stage101.extension,
        boundary_artifact.default_limits,
    );
    const public_equal = try rolePublicEqual(
        allocator,
        &fresh.stage101.role_aware_public.value,
        &expected_public,
    );
    if (fresh.stage101.profile.coordinate.segment_index != opened.segment_index or
        fresh.stage101.profile.coordinate.segment_count != opened.segment_count or
        !std.meta.eql(fresh.stage101.receipt.wire_id, opened.mint.wire.data.wireId()) or
        !std.mem.eql(
            u8,
            &fresh.stage101.profile.protocol.identity_sha256,
            &base_profile.ProtocolAuthorityV3.canonical().identity_sha256,
        ) or !public_equal) return error.NativeLeafStage101OutputMismatch;
}

fn rolePublicEqual(
    allocator: std.mem.Allocator,
    left: *const public_data.PublicData,
    right: *const public_data.PublicData,
) !bool {
    const wire_support = @import("ethereum_incremental_full_leaf_profile_v4_wire.zig");
    var left_bytes: std.ArrayList(u8) = .empty;
    defer left_bytes.deinit(allocator);
    try wire_support.encodeRolePublic(left_bytes.writer(allocator), left);
    var right_bytes: std.ArrayList(u8) = .empty;
    defer right_bytes.deinit(allocator);
    try wire_support.encodeRolePublic(right_bytes.writer(allocator), right);
    return std.mem.eql(u8, left_bytes.items, right_bytes.items);
}

fn openBlob(
    store: *artifact_store.Store,
    reference: artifact_store.BlobRefV1,
    maximum_bytes: u64,
) !artifact_store.OwnedBlobV1 {
    return store.openBlob(
        reference,
        reference.kind,
        reference.schema_version,
        maximum_bytes,
    );
}

fn blobRefFromIdentity(
    kind: artifact_store.ArtifactKindV1,
    schema_version: u16,
    identity: publication.ArtifactIdentityV4,
) !artifact_store.BlobRefV1 {
    return artifact_store.BlobRefV1.create(
        kind,
        schema_version,
        identity.byte_count,
        identity.sha256,
    );
}

fn identityMatchesRef(
    identity: publication.ArtifactIdentityV4,
    reference: artifact_store.BlobRefV1,
) bool {
    return identity.byte_count == reference.byte_count and
        std.mem.eql(u8, &identity.sha256, &reference.sha256);
}

fn semanticAuthoritiesEqual(
    fields: artifact_store.SemanticKeyFieldsV1,
    expected: protocol.SemanticAuthorities,
) bool {
    return std.mem.eql(u8, &fields.protocol_identity, &expected.protocol_identity_sha256) and
        std.mem.eql(u8, &fields.program_identity, &expected.program_identity_sha256) and
        std.mem.eql(u8, &fields.profile_identity, &expected.profile_identity_sha256) and
        std.mem.eql(u8, &fields.pcs_identity, &expected.pcs_identity_sha256) and
        std.mem.eql(u8, &fields.security_identity, &expected.security_identity_sha256) and
        std.mem.eql(u8, &fields.statement_identity, &expected.statement_identity_sha256) and
        std.mem.eql(u8, &fields.provider_identity, &expected.provider_identity_sha256) and
        std.mem.eql(u8, &fields.layout_identity, &expected.layout_identity_sha256) and
        std.mem.eql(u8, &fields.registry_identity, &expected.registry_identity_sha256);
}

fn taskIdentity(
    segment_index: u32,
    segment_count: u32,
    inputs: []const artifact_store.InputRefV1,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(local_task_domain);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, STAGE_SCHEMA_VERSION);
    hashInt(&hash, u32, segment_index);
    hashInt(&hash, u32, segment_count);
    for (inputs) |input| hashInput(&hash, input);
    return hash.finalResult();
}

fn layoutInputIdentity(
    inputs: []const artifact_store.InputRefV1,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(layout_authority_domain);
    hashInput(&hash, inputs[0]);
    hashInput(&hash, inputs[3]);
    hashInput(&hash, inputs[4]);
    hashInput(&hash, inputs[5]);
    return hash.finalResult();
}

fn orderedInputIdentity(
    inputs: []const artifact_store.InputRefV1,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update("stwo-zig/recursive-pipeline-native-leaf-inputs/v4\x00");
    hashInt(&hash, u32, @as(u32, @intCast(inputs.len)));
    for (inputs) |input| hashInput(&hash, input);
    return hash.finalResult();
}

fn leaseBindingIdentity(
    comptime SelectedEngine: type,
    value: *const LeasePayloadV4(SelectedEngine),
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(lease_binding_domain);
    hash.update(&value.semantic_key_identity);
    hash.update(&value.ordered_input_identity_sha256);
    hash.update(&value.fresh.capability_identity_sha256);
    hash.update(&value.fresh.stage101.identity_sha256);
    return hash.finalResult();
}

fn hashInput(hash: *Sha256, input: artifact_store.InputRefV1) void {
    hashInt(hash, u32, @intFromEnum(input.role));
    hashInt(hash, u32, input.ordinal);
    hashInt(hash, u32, @intFromEnum(input.blob.kind));
    hashInt(hash, u16, input.blob.format_version);
    hashInt(hash, u16, input.blob.schema_version);
    hashInt(hash, u64, input.blob.byte_count);
    hash.update(&input.blob.sha256);
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 1 or
        STAGE_SCHEMA_VERSION != 101 or OUTPUT_SCHEMA_VERSION != 1 or
        OUTPUT_ARTIFACT_SCHEMA_VERSION != 2 or EXTERNAL_INPUT_COUNT != 7 or
        @intFromEnum(artifact_store.ArtifactKindV1.proof_artifact) != 8 or
        PRODUCTION_ACTIVATION or SERIALIZABLE_FRESH_CAPABILITY or
        !Adapter.available)
    {
        @compileError("incremental native-leaf stage101 adapter drifted");
    }
}
