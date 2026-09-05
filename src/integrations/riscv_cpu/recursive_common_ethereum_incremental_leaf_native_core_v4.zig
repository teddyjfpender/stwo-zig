//! Genuine rows-18--34 owner for the schema-3 Ethereum incremental wrapper.
//!
//! This owner reuses the authenticated native verifier core.  Its shared
//! Poseidon prefix is ordered exactly as the wrapper transcript requires:
//! first every call recorded while cold-verifying the stage-101 proof, then
//! every call which commits NodePublic and the padded role-aware IO stream.
//! The verifier core appends its own calls and is the sole row-34 provider.
//!
//! The runtime campaign authority is borrowed and never flattened into a
//! compile-time leaf count.  This module owns no rows 0--17 and cannot mint a
//! wrapper proof or a fold-child capability by itself.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const campaign_materializer =
    @import("recursive_common_ethereum_incremental_leaf_campaign_materializer_v4.zig");
const child_public =
    @import("recursive_common_ethereum_incremental_leaf_child_public_v4.zig");
const complete_provider =
    @import("recursive_common_ethereum_incremental_leaf_complete_provider_geometry_v4.zig");
const manifest_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const public_sums =
    @import("recursive_common_ethereum_incremental_leaf_public_sums_v4.zig");
const recursive_core = @import("recursive_fri_outer.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const schedule = recursion.air.verifier_schedule;
const transcript_shape = recursion.transcript_shape;
const shared_schedule = recursion.segment_shared_poseidon_schedule_v2;
const PoseidonCall = shared_schedule.Call;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const FIRST_ROW: usize = 18;
pub const LAST_ROW: usize = 34;
pub const ROW_COUNT: usize = LAST_ROW - FIRST_ROW + 1;
pub const NATIVE_RELATION_COUNT: u32 = 25;
pub const FIXED_PUBLIC_LOGUP_TERM_COUNT: u32 = 69;
pub const VM_AIR_INSTRUCTION_COUNT: u32 =
    schedule.VM_PROGRAM_SPEC_V1.air_instruction_count;
pub const ROWS_18_THROUGH_34_AVAILABLE = true;
pub const RUNTIME_CAMPAIGN_GEOMETRY_REQUIRED = true;
pub const SHARED_PROVIDER_FINALIZED_BY_COMPLETE_COHORT = true;
pub const PRODUCTION_ACTIVATION = false;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-native-core/v4-schema3\x00";

pub const Error = error{
    ArithmeticOverflow,
    EthereumIncrementalNativeCoreMismatchV4,
};
pub const CompleteProviderGeometryV4 =
    complete_provider.CompleteProviderGeometryV4;
pub const NativeCoreComponentsV4 =
    recursive_core.NativeSegmentCoreComponentsForManifest(manifest_mod);

/// Borrowed, verifier-owned input boundary for universal row 16.  The fixed
/// public-sum circuit is built with one base-field value per input; exposing
/// the complete QM31 cells here lets the row owner recheck that invariant
/// before narrowing.  Bindings and use counts come from the same authenticated
/// circuit and are never reconstructed from a producer-supplied index list.
pub const PublicInputViewV4 = struct {
    circuit_id: u32,
    bindings: []const public_sums.InputSourceV4,
    values: []const QM31,
    use_counts: []const u32,
    program_identity_sha256: [32]u8,
    evaluation_identity_sha256: [32]u8,

    pub fn validate(self: PublicInputViewV4) Error!void {
        if (self.circuit_id != public_sums.CIRCUIT_ID or
            self.bindings.len == 0 or
            self.values.len != self.bindings.len or
            self.use_counts.len != self.bindings.len or
            std.mem.allEqual(u8, &self.program_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.evaluation_identity_sha256, 0))
        {
            return error.EthereumIncrementalNativeCoreMismatchV4;
        }
        for (self.values) |value| {
            const words = value.toM31Array();
            if (!words[1].isZero() or !words[2].isZero() or
                !words[3].isZero())
            {
                return error.EthereumIncrementalNativeCoreMismatchV4;
            }
        }
    }
};

/// Borrowed plan pair used by universal row 17. The plans are the exact pair
/// already authenticated by `NativeSegmentCoreV2`; row 17 must not derive a
/// second schedule from caller-provided proof dimensions.
pub const ScheduleViewV4 = struct {
    vm: *const schedule.Plan,
    recursion: *const schedule.Plan,
    vm_public_term_count: u32,
    recursion_public_term_count: u32,

    pub fn validate(self: ScheduleViewV4) !void {
        try self.vm.validate();
        try self.recursion.validate();
        if (self.vm.schema != .vm or self.recursion.schema != .recursion or
            self.vm.spec.public_logup_term_count !=
                self.vm_public_term_count or
            self.recursion.spec.public_logup_term_count !=
                self.recursion_public_term_count)
        {
            return error.EthereumIncrementalNativeCoreMismatchV4;
        }
    }
};

/// Stable heap owner. `NativeSegmentCoreV2` retains pointers into the program,
/// evaluation, plans, boundary layout, and campaign materializer, so this
/// boundary deliberately returns an opaque pointer rather than a movable
/// aggregate.
pub fn OwnerV4(comptime Engine: type) type {
    const Materialized =
        campaign_materializer.PreparedOwnedCampaignCaptureV4(Engine);
    const ChildPublic = child_public.OwnerV4(Engine);
    const Evaluation = public_sums.OwnedRuntimeEvaluationV4(Engine);
    const Core = recursive_core.NativeSegmentCoreV2;

    return opaque {
        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            child: *const ChildPublic,
        ) !*Self {
            return initWithLogSizes(
                allocator,
                materialized,
                child,
                null,
            );
        }

        /// Rebuilds rows 18--34 at the authenticated padding target. This is
        /// a genuine trace-generation path: the requested vector is passed
        /// into the native core before Tree0/1/2 allocation.
        pub fn initForLogSizes(
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            child: *const ChildPublic,
            requested_log_sizes: recursive_core.NativeSegmentCoreLogSizesV2,
        ) !*Self {
            return initWithLogSizes(
                allocator,
                materialized,
                child,
                requested_log_sizes,
            );
        }

        fn initWithLogSizes(
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            child: *const ChildPublic,
            requested_log_sizes: ?recursive_core.NativeSegmentCoreLogSizesV2,
        ) !*Self {
            try materialized.validate();
            try child.validate();
            const child_binding = try child.binding();
            if (!std.mem.eql(
                u8,
                &child_binding.stage101_capability_identity_sha256,
                &materialized.base.input.capability_identity_sha256,
            ) or !std.mem.eql(
                u8,
                &child_binding.role_io_identity_sha256,
                &materialized.role_aware_io.identity_sha256,
            )) return error.EthereumIncrementalNativeCoreMismatchV4;
            const backing = try allocator.create(Storage);
            errdefer allocator.destroy(backing);

            var program = try public_sums.OwnedFixedProgramV4.init(
                allocator,
                materialized.campaign_authority,
            );
            var program_owned = true;
            errdefer if (program_owned) program.deinit();
            var evaluation = try Evaluation.init(
                allocator,
                &program,
                materialized,
            );
            var evaluation_owned = true;
            errdefer if (evaluation_owned) evaluation.deinit();

            const shape = try scheduleShape(&materialized.base.captured_fri);
            const public_term_count = std.math.add(
                u32,
                FIXED_PUBLIC_LOGUP_TERM_COUNT,
                materialized.campaign_authority.provider_geometry
                    .role_io_tuple_capacity,
            ) catch return error.ArithmeticOverflow;
            const vm_spec = try schedule.ProgramSpec.init(
                .vm,
                NATIVE_RELATION_COUNT,
                public_term_count,
                VM_AIR_INSTRUCTION_COUNT,
                NATIVE_RELATION_COUNT,
            );
            var vm_plan = try schedule.Plan.initShape(
                allocator,
                vm_spec,
                shape,
            );
            var vm_plan_owned = true;
            errdefer if (vm_plan_owned) vm_plan.deinit();
            var recursion_plan = try schedule.Plan.initShape(
                allocator,
                schedule.RECURSION_PROGRAM_SPEC_V1,
                shape,
            );
            var recursion_plan_owned = true;
            errdefer if (recursion_plan_owned) recursion_plan.deinit();

            const transcript_calls =
                materialized.base.transcript.execution.poseidon_calls;
            const child_claim_hash_calls = try child.claimHashCalls();
            const child_io_hash_calls = try child.ioHashCalls();
            const publication_calls = materialized.schedule.callsSlice();
            const authority_count = std.math.add(
                usize,
                std.math.add(
                    usize,
                    child_claim_hash_calls.len,
                    child_io_hash_calls.len,
                ) catch return error.ArithmeticOverflow,
                publication_calls.len,
            ) catch return error.ArithmeticOverflow;
            const boundary_count = std.math.add(
                usize,
                transcript_calls.len,
                authority_count,
            ) catch return error.ArithmeticOverflow;
            const boundary_calls = try allocator.alloc(
                PoseidonCall,
                boundary_count,
            );
            errdefer allocator.free(boundary_calls);
            writeTranscriptCalls(
                boundary_calls[0..transcript_calls.len],
                transcript_calls,
            );
            var boundary_cursor = transcript_calls.len;
            @memcpy(
                boundary_calls[boundary_cursor..][0..child_claim_hash_calls.len],
                child_claim_hash_calls,
            );
            boundary_cursor += child_claim_hash_calls.len;
            @memcpy(
                boundary_calls[boundary_cursor..][0..child_io_hash_calls.len],
                child_io_hash_calls,
            );
            boundary_cursor += child_io_hash_calls.len;
            @memcpy(
                boundary_calls[boundary_cursor..][0..publication_calls.len],
                publication_calls,
            );
            boundary_cursor += publication_calls.len;
            if (boundary_cursor != boundary_calls.len)
                return error.EthereumIncrementalNativeCoreMismatchV4;
            const boundary_layout =
                try shared_schedule.SharedPoseidonCallLayoutV2
                    .initBoundaryPrefix(
                    transcript_calls.len,
                    authority_count,
                    boundary_calls,
                );

            backing.* = .{
                .allocator = allocator,
                .materialized = materialized,
                .child = child,
                .child_binding = child_binding,
                .program = program,
                .evaluation = evaluation,
                .vm_plan = vm_plan,
                .recursion_plan = recursion_plan,
                .boundary_calls = boundary_calls,
                .boundary_layout = boundary_layout,
                .core = undefined,
                .core_initialized = false,
                .identity_sha256 = undefined,
            };
            program_owned = false;
            evaluation_owned = false;
            vm_plan_owned = false;
            recursion_plan_owned = false;
            errdefer backing.destroyInitialized();

            const core_inputs = recursive_core.NativeSegmentCoreAuthorityInputsV4{
                .captured = &materialized.base.captured_fri,
                .vm_air = &materialized.base.composition_prepared,
                .verifier_plans = .{
                    .vm = &backing.vm_plan,
                    .recursion = &backing.recursion_plan,
                },
                .public_native_sum_lane = backing.program.loweringLane(),
                .public_native_sum_evaluation = try backing.evaluation.loweringEvaluation(
                    &backing.program,
                ),
                .public_native_sum_evaluation_id = backing.evaluation.evaluation_identity_sha256,
                .full_query_words = &materialized.base.transcript.query_words,
                .boundary_layout = &backing.boundary_layout,
                .boundary_calls = backing.boundary_calls,
            };
            backing.core = if (requested_log_sizes) |logs|
                try Core.initVersionedV4ForLogSizes(
                    allocator,
                    core_inputs,
                    logs,
                )
            else
                try Core.initVersionedV4(allocator, core_inputs);
            backing.core_initialized = true;
            backing.identity_sha256 = try ownerIdentity(backing);
            try backing.validate();
            return handle(backing);
        }

        pub fn deinit(self: *Self) void {
            storage(self).destroyInitialized();
        }

        pub fn validate(self: *const Self) !void {
            try storageConst(self).validate();
        }

        pub fn componentLogSizes(self: *const Self) ![ROW_COUNT]u32 {
            try self.validate();
            return storageConst(self).core.componentLogSizes();
        }

        pub fn validateAgainstManifest(
            self: *const Self,
            manifest: *const manifest_mod.Manifest,
        ) !void {
            try self.validate();
            try validateCoreManifest(&storageConst(self).core, manifest);
        }

        /// Must be called exactly once after the complete 36-row manifest has
        /// validated this owner. No partial owner may finalize row 34.
        pub fn finalizeSharedProviderMain(
            self: *Self,
            manifest: *const manifest_mod.Manifest,
        ) !void {
            try self.validateAgainstManifest(manifest);
            try storage(self).core.finalizeSharedProviderMain();
            try storage(self).core.validateComplete();
        }

        pub fn nativeCore(self: *Self) *Core {
            return &storage(self).core;
        }

        pub fn nativeCoreConst(self: *const Self) *const Core {
            return &storageConst(self).core;
        }

        /// Rebinds the exact authenticated rows 18--34 AIR definitions to the
        /// role-0 universal manifest. The legacy SegmentV2 component family is
        /// left nominally unchanged; equality of every projected placement is
        /// checked before any adapter is constructed.
        pub fn initComponents(
            self: *Self,
            manifest: *const manifest_mod.Manifest,
            relations: *const recursion.air.universal_challenges.UniversalRelations,
            provider_relations: *const recursion.air.universal_shared_provider.SharedProviderRelations,
            generated: *const Core.GeneratedInteractionsV2,
        ) !NativeCoreComponentsV4 {
            try self.validateAgainstManifest(manifest);
            return recursive_core.initNativeSegmentCoreComponentsForManifest(
                manifest_mod,
                &storage(self).core,
                manifest,
                relations,
                provider_relations,
                generated,
            );
        }

        pub fn fillPreprocessedInto(
            self: *const Self,
            manifest: *const manifest_mod.Manifest,
            destination: []const []M31,
        ) !void {
            try self.validateAgainstManifest(manifest);
            const core = &storageConst(self).core;
            try publishCoreTree(
                core,
                &core.preprocessed_tree,
                manifest,
                manifest_mod.PREPROCESSED_TREE_INDEX,
                destination,
            );
        }

        pub fn fillMainInto(
            self: *const Self,
            manifest: *const manifest_mod.Manifest,
            destination: []const []M31,
        ) !void {
            try self.validateAgainstManifest(manifest);
            const core = &storageConst(self).core;
            try core.validateComplete();
            try publishCoreTree(
                core,
                &core.main_tree,
                manifest,
                manifest_mod.MAIN_TREE_INDEX,
                destination,
            );
        }

        pub fn prepareInteractions(
            self: *Self,
            allocator: std.mem.Allocator,
            relations: *const recursion.air.universal_challenges.UniversalRelations,
            provider_relations: *const recursion.air.universal_shared_provider.SharedProviderRelations,
        ) !Core.GeneratedInteractionsV2 {
            try self.validate();
            return storage(self).core.prepareInteractions(
                allocator,
                relations,
                provider_relations,
            );
        }

        pub fn fillInteractionInto(
            self: *const Self,
            manifest: *const manifest_mod.Manifest,
            generated: *const Core.GeneratedInteractionsV2,
            relations: *const recursion.air.universal_challenges.UniversalRelations,
            provider_relations: *const recursion.air.universal_shared_provider.SharedProviderRelations,
            destination: []const []M31,
        ) !void {
            try self.validateAgainstManifest(manifest);
            const core = &storageConst(self).core;
            try generated.validateAgainst(core, relations, provider_relations);
            try publishCoreTree(
                core,
                &core.interaction_tree,
                manifest,
                manifest_mod.INTERACTION_TREE_INDEX,
                destination,
            );
        }

        pub fn appendTupleContributions(
            self: *const Self,
            allocator: std.mem.Allocator,
            ledger: *recursion.air.relation_interaction.TupleLedger,
        ) !void {
            try self.validate();
            return storageConst(self).core.appendTupleContributions(
                allocator,
                ledger,
                recursion.air.relation_interaction.allDomainMask(),
            );
        }

        pub fn publicWireBoundaryClaim(
            self: *const Self,
            relations: *const recursion.air.universal_challenges.UniversalRelations,
        ) !QM31 {
            try self.validate();
            return storageConst(self).core.publicWireBoundaryClaim(relations);
        }

        pub fn publicWireBoundaryTermCount(self: *const Self) !u32 {
            try self.validate();
            return storageConst(self).core.publicWireBoundaryTermCount();
        }

        pub fn authorityIdentity(self: *const Self) ![32]u8 {
            try self.validate();
            return storageConst(self).identity_sha256;
        }

        /// Stable borrowed view consumed by the role-0 public-spine owner.
        /// `Self` is an opaque heap handle, so all three slices remain at fixed
        /// addresses until `deinit` and cannot be invalidated by a move.
        pub fn publicInputView(self: *const Self) !PublicInputViewV4 {
            try self.validate();
            const backing = storageConst(self);
            const count = backing.program.bindings.len;
            if (backing.evaluation.evaluation.values.len < count or
                backing.program.circuit.useCounts().len < count)
            {
                return error.EthereumIncrementalNativeCoreMismatchV4;
            }
            const result = PublicInputViewV4{
                .circuit_id = public_sums.CIRCUIT_ID,
                .bindings = backing.program.bindings,
                .values = backing.evaluation.evaluation.values[0..count],
                .use_counts = backing.program.circuit.useCounts()[0..count],
                .program_identity_sha256 = backing.program.program_identity_sha256,
                .evaluation_identity_sha256 = backing.evaluation.evaluation_identity_sha256,
            };
            try result.validate();
            return result;
        }

        /// Stable borrowed view consumed by the role-0 control-slice owner.
        pub fn scheduleView(self: *const Self) !ScheduleViewV4 {
            try self.validate();
            const backing = storageConst(self);
            const result = ScheduleViewV4{
                .vm = &backing.vm_plan,
                .recursion = &backing.recursion_plan,
                .vm_public_term_count = backing.vm_plan.spec.public_logup_term_count,
                .recursion_public_term_count = backing.recursion_plan.spec.public_logup_term_count,
            };
            try result.validate();
            return result;
        }

        /// Exact live geometry for the shared row-34 provider.  Campaign
        /// publication geometry alone is intentionally insufficient here.
        pub fn completeProviderGeometry(
            self: *const Self,
        ) !CompleteProviderGeometryV4 {
            try self.validate();
            return completeProviderGeometryFromStorage(storageConst(self));
        }

        const Storage = struct {
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            child: *const ChildPublic,
            child_binding: child_public.ChildPublicBindingV4,
            program: public_sums.OwnedFixedProgramV4,
            evaluation: Evaluation,
            vm_plan: schedule.Plan,
            recursion_plan: schedule.Plan,
            boundary_calls: []PoseidonCall,
            boundary_layout: shared_schedule.SharedPoseidonCallLayoutV2,
            core: Core,
            core_initialized: bool,
            identity_sha256: [32]u8,

            fn validate(self: *const Storage) !void {
                try self.materialized.validate();
                try self.child.validate();
                const expected_child_binding = try self.child.binding();
                try self.program.validateAgainstCampaign(
                    self.materialized.campaign_authority,
                );
                try self.evaluation.validateAgainst(
                    &self.program,
                    self.materialized,
                );
                try self.vm_plan.validate();
                try self.recursion_plan.validate();
                try self.boundary_layout.validate(self.boundary_calls);
                if (!self.core_initialized or
                    self.vm_plan.schema != .vm or
                    self.recursion_plan.schema != .recursion or
                    self.boundary_layout.transcript.count() catch 0 !=
                        self.materialized.base.transcript.execution
                            .poseidon_calls.len or
                    self.boundary_layout.statement_authority.count() catch 0 !=
                        @as(usize, self.child_binding.child_claim_hash_call_count) +
                            @as(usize, self.child_binding.child_io_hash_call_count) +
                            self.materialized.schedule.calls.len or
                    !std.meta.eql(self.child_binding, expected_child_binding) or
                    !std.mem.eql(
                        u8,
                        &self.identity_sha256,
                        &(try ownerIdentity(self)),
                    ))
                {
                    return error.EthereumIncrementalNativeCoreMismatchV4;
                }
                try self.core.validateCoreReady();
                _ = try completeProviderGeometryFromStorage(self);
            }

            fn destroyInitialized(self: *Storage) void {
                const allocator = self.allocator;
                if (self.core_initialized) self.core.deinit();
                allocator.free(self.boundary_calls);
                self.recursion_plan.deinit();
                self.vm_plan.deinit();
                self.evaluation.deinit();
                self.program.deinit();
                self.* = undefined;
                allocator.destroy(self);
            }
        };

        fn handle(value: *Storage) *Self {
            return @ptrCast(value);
        }

        fn storage(value: *Self) *Storage {
            return @ptrCast(@alignCast(value));
        }

        fn storageConst(value: *const Self) *const Storage {
            return @ptrCast(@alignCast(value));
        }

        fn ownerIdentity(value: *const Storage) ![32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(IDENTITY_DOMAIN);
            hashInt(&hash, u16, FORMAT_VERSION);
            hashInt(&hash, u16, SCHEMA_VERSION);
            hash.update(&value.materialized.identity_sha256);
            hash.update(&value.materialized.campaign_authority
                .authority_identity_sha256);
            hash.update(&value.child_binding.identity_sha256);
            hash.update(&value.program.program_identity_sha256);
            hash.update(&value.evaluation.evaluation_identity_sha256);
            for (value.vm_plan.authority_digest) |word|
                hashInt(&hash, u32, word);
            for (value.recursion_plan.authority_digest) |word|
                hashInt(&hash, u32, word);
            hash.update(&value.boundary_layout.identity);
            hash.update(&(try value.core.authorityIdentity()));
            hash.update(&(try completeProviderGeometryFromStorage(value))
                .identity_sha256);
            return hash.finalResult();
        }
    };
}

fn writeTranscriptCalls(
    destination: []PoseidonCall,
    source: []const recursion.recording_poseidon_channel_v4.PoseidonCall,
) void {
    std.debug.assert(destination.len == source.len);
    for (destination, source) |*output, input| {
        var words: [frontend.air.memory_commitment.poseidon2_air.WIDTH]u32 =
            undefined;
        for (&words, input.input) |*word, value| word.* = value.toU32();
        output.* = .{
            .input = words,
            .wide = false,
            .io = true,
            .narrow_output = null,
        };
    }
}

fn completeProviderGeometryFromStorage(value: anytype) !CompleteProviderGeometryV4 {
    const calls = try value.core.completePoseidonCalls();
    const layout = try value.core.completeScheduleReceipt();
    const logs = try value.core.componentLogSizes();
    const sealed = try CompleteProviderGeometryV4.mint(
        &layout,
        calls,
        .{
            .child_claim_hash = value.child_binding
                .child_claim_hash_call_count,
            .child_io_hash = value.child_binding.child_io_hash_call_count,
            .field_publication = @intCast(value.materialized.schedule.calls.len),
        },
        logs[ROW_COUNT - 1],
    );
    if (@as(usize, sealed.stage101_transcript_call_count) !=
        value.materialized.base.transcript.execution.poseidon_calls.len or
        @as(usize, sealed.child_claim_hash_call_count) !=
            value.child_binding.child_claim_hash_call_count or
        @as(usize, sealed.child_io_hash_call_count) !=
            value.child_binding.child_io_hash_call_count or
        @as(usize, sealed.field_publication_call_count) !=
            value.materialized.schedule.calls.len or
        @as(usize, sealed.total_call_count) != calls.len)
    {
        return error.EthereumIncrementalNativeCoreMismatchV4;
    }
    return sealed;
}

fn scheduleShape(value: *const recursion.captured_fri.Owned) !schedule.ScheduleShape {
    var tree_heights: [recursion.fixed_profile.TREE_COUNT]u32 = undefined;
    if (value.trace_tree_heights.len != tree_heights.len)
        return error.EthereumIncrementalNativeCoreMismatchV4;
    @memcpy(&tree_heights, value.trace_tree_heights);
    return transcript_shape.derive(
        value.circuit.profile(),
        tree_heights,
        .{
            .sampled_value_count = value.sampled_value_count,
            .queried_values_per_query = value.queried_values_per_query,
            .claimed_sum_count = value.claimed_sum_count,
            .interaction_pow_bits = value.interaction_pow_bits,
            .pcs_pow_bits = value.pcs_pow_bits,
        },
    );
}

/// The retained verifier core was originally parameterized by the appended
/// SegmentV2 manifest.  Role-0 uses the same canonical rows 18--34 through the
/// 36-row universal manifest, so admission compares every owned placement
/// field and copies by the two explicit offsets instead of casting nominal
/// manifest types.
fn validateCoreManifest(core: anytype, manifest: *const manifest_mod.Manifest) !void {
    try core.validateCoreReady();
    try core.authority.manifest.validate();
    try manifest.validate();
    inline for (FIRST_ROW..LAST_ROW + 1) |row| {
        const source = core.authority.manifest.placements[row] orelse
            return error.EthereumIncrementalNativeCoreMismatchV4;
        const target = manifest.placements[row] orelse
            return error.EthereumIncrementalNativeCoreMismatchV4;
        if (!std.meta.eql(source.geometry, target.geometry))
            return error.EthereumIncrementalNativeCoreMismatchV4;
    }
}

fn publishCoreTree(
    core: anytype,
    source_tree: anytype,
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    destination: []const []M31,
) !void {
    try validateCoreManifest(core, manifest);
    const expected_columns: usize = switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => @intCast(manifest.total_preprocessed_columns),
        manifest_mod.MAIN_TREE_INDEX => @intCast(manifest.total_main_columns),
        manifest_mod.INTERACTION_TREE_INDEX => @intCast(manifest.total_interaction_columns),
        else => return error.EthereumIncrementalNativeCoreMismatchV4,
    };
    if (destination.len != expected_columns)
        return error.EthereumIncrementalNativeCoreMismatchV4;

    inline for (FIRST_ROW..LAST_ROW + 1) |row| {
        const source = core.authority.manifest.placements[row].?;
        const target = manifest.placements[row].?;
        const count: usize = switch (tree) {
            manifest_mod.PREPROCESSED_TREE_INDEX => @intCast(target.geometry.preprocessed_columns),
            manifest_mod.MAIN_TREE_INDEX => @intCast(target.geometry.main_columns),
            manifest_mod.INTERACTION_TREE_INDEX => @intCast(target.geometry.interaction_columns),
            else => unreachable,
        };
        const source_offset: usize = switch (tree) {
            manifest_mod.PREPROCESSED_TREE_INDEX => @intCast(source.preprocessed_offset),
            manifest_mod.MAIN_TREE_INDEX => @intCast(source.main_offset),
            manifest_mod.INTERACTION_TREE_INDEX => @intCast(source.interaction_offset),
            else => unreachable,
        };
        const target_offset: usize = switch (tree) {
            manifest_mod.PREPROCESSED_TREE_INDEX => @intCast(target.preprocessed_offset),
            manifest_mod.MAIN_TREE_INDEX => @intCast(target.main_offset),
            manifest_mod.INTERACTION_TREE_INDEX => @intCast(target.interaction_offset),
            else => unreachable,
        };
        if (source_offset + count > source_tree.columns.len or
            target_offset + count > destination.len)
        {
            return error.EthereumIncrementalNativeCoreMismatchV4;
        }
        for (0..count) |local| {
            const source_column = source_tree.columns[source_offset + local];
            const target_column = destination[target_offset + local];
            if (target_column.len != source_column.len)
                return error.EthereumIncrementalNativeCoreMismatchV4;
            for (target_column) |value| if (!value.isZero())
                return error.EthereumIncrementalNativeCoreMismatchV4;
            const source_start = @intFromPtr(source_column.ptr);
            const source_end = std.math.add(
                usize,
                source_start,
                std.math.mul(usize, source_column.len, @sizeOf(M31)) catch
                    return error.ArithmeticOverflow,
            ) catch return error.ArithmeticOverflow;
            const target_start = @intFromPtr(target_column.ptr);
            const target_end = std.math.add(
                usize,
                target_start,
                std.math.mul(usize, target_column.len, @sizeOf(M31)) catch
                    return error.ArithmeticOverflow,
            ) catch return error.ArithmeticOverflow;
            if (source_start < target_end and target_start < source_end)
                return error.EthereumIncrementalNativeCoreMismatchV4;
        }
    }

    inline for (FIRST_ROW..LAST_ROW + 1) |row| {
        const source = core.authority.manifest.placements[row].?;
        const target = manifest.placements[row].?;
        const count: usize = switch (tree) {
            manifest_mod.PREPROCESSED_TREE_INDEX => @intCast(target.geometry.preprocessed_columns),
            manifest_mod.MAIN_TREE_INDEX => @intCast(target.geometry.main_columns),
            manifest_mod.INTERACTION_TREE_INDEX => @intCast(target.geometry.interaction_columns),
            else => unreachable,
        };
        const source_offset: usize = switch (tree) {
            manifest_mod.PREPROCESSED_TREE_INDEX => @intCast(source.preprocessed_offset),
            manifest_mod.MAIN_TREE_INDEX => @intCast(source.main_offset),
            manifest_mod.INTERACTION_TREE_INDEX => @intCast(source.interaction_offset),
            else => unreachable,
        };
        const target_offset: usize = switch (tree) {
            manifest_mod.PREPROCESSED_TREE_INDEX => @intCast(target.preprocessed_offset),
            manifest_mod.MAIN_TREE_INDEX => @intCast(target.main_offset),
            manifest_mod.INTERACTION_TREE_INDEX => @intCast(target.interaction_offset),
            else => unreachable,
        };
        for (0..count) |local| @memcpy(
            destination[target_offset + local],
            source_tree.columns[source_offset + local],
        );
    }
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or FIRST_ROW != 18 or
        LAST_ROW != 34 or ROW_COUNT != 17 or NATIVE_RELATION_COUNT != 25 or
        FIXED_PUBLIC_LOGUP_TERM_COUNT != 69 or
        VM_AIR_INSTRUCTION_COUNT != 101 or
        !ROWS_18_THROUGH_34_AVAILABLE or
        !RUNTIME_CAMPAIGN_GEOMETRY_REQUIRED or
        !SHARED_PROVIDER_FINALIZED_BY_COMPLETE_COHORT or
        PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum incremental native core V4 drifted");
    }
    _ = M31;
}
