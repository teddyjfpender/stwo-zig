const std = @import("std");
pub const stwo = @import("stwo");
const arena = stwo.backends.metal.arena_plan;
const metal_runtime = stwo.backends.metal.runtime;
const protocol_recipes = stwo.backends.metal.protocol_recipes;
const blake2_hash = stwo.core.vcs.blake2_hash;
const blake2_merkle = stwo.core.vcs_lifted.blake2_merkle;
const adapted_input = stwo.frontends.cairo.adapter.adapted_input;
const cairo_adapter = stwo.frontends.cairo.adapter;
const arena_lifetime = stwo.frontends.cairo.arena_lifetime;
const cairo_proof_plan = stwo.frontends.cairo.proof_plan;
const cairo_statement_bootstrap = stwo.frontends.cairo.statement_bootstrap;
const staged_arena_planner = stwo.frontends.cairo.staged_arena_planner;
const witness_bundle_mod = stwo.frontends.cairo.witness.bundle;
const feed_bundle_mod = stwo.frontends.cairo.witness.feed_bundle;
const relation_bundle_mod = stwo.frontends.cairo.witness.relation_bundle;
const fixed_table_bundle_mod = stwo.frontends.cairo.witness.fixed_table_bundle;
const composition_bundle_mod = stwo.frontends.cairo.witness.composition_bundle;
const proof_bundle = stwo.frontends.cairo.witness.proof_bundle;
const resident_verifier = stwo.frontends.cairo.witness.resident_verifier;
const arena_binding_mod = stwo.integrations.cairo_metal.arena_binding;
const cairo_memory_trace = stwo.integrations.cairo_metal.memory_trace;
const cairo_oods = stwo.integrations.cairo_metal.oods;
const cairo_quotient_inputs = stwo.integrations.cairo_metal.quotient_inputs;
const cairo_quotient_reference = stwo.integrations.cairo_metal.quotient_reference;
const runtime_decommit_geometry = stwo.integrations.cairo_metal.runtime_decommit_geometry;
const schedule_addressing = @import("schedule_addressing.zig");
const schedule_coverage = @import("schedule_coverage.zig");
const arena_diagnostics = @import("diagnostics.zig");
const proof_layout_support = @import("proof_layout.zig");
const transcript_fixture = @import("transcript_fixture.zig");
const canonical_protocol_support = @import("canonical_protocol.zig");

const aotNarrowAddressPurpose = schedule_addressing.aotNarrowAddressPurpose;
const buildMerkleCommitCoverage = schedule_coverage.buildMerkleCommitCoverage;
const buildMerkleParentSources = schedule_coverage.buildMerkleParentSources;
const buildPreprocessedSources = schedule_coverage.buildPreprocessedSources;
const buildRetainedSources = schedule_coverage.buildRetainedSources;
const bindingDegreeLogs = proof_layout_support.bindingDegreeLogs;
const compactComponent = schedule_addressing.compactComponent;
const epochIndex = schedule_addressing.epochIndex;
const globalTick = schedule_addressing.globalTick;
const localTick = schedule_addressing.localTick;
const logicalIdOf = schedule_addressing.logicalIdOf;
const logAddOpcodeCoefficientDigests = arena_diagnostics.logAddOpcodeCoefficientDigests;
const logComponentPurposeLayout = arena_diagnostics.logComponentPurposeLayout;
const logPurposeDigests = arena_diagnostics.logPurposeDigests;
const logPurposeLayout = arena_diagnostics.logPurposeLayout;
const purposeOf = schedule_addressing.purposeOf;
const CompositionCoverage = schedule_coverage.CompositionCoverage;
const FixedTableCoverage = schedule_coverage.FixedTableCoverage;
const RelationCoverage = schedule_coverage.RelationCoverage;
const stagedRole = schedule_addressing.stagedRole;
const TranscriptReferenceFixture = transcript_fixture.TranscriptReferenceFixture;
const transcriptInputBinding = proof_layout_support.transcriptInputBinding;
const validateCompositionCoverage = schedule_coverage.validateCompositionCoverage;
const validateEcOpCoverage = schedule_coverage.validateEcOpCoverage;
const validateFixedTableCoverage = schedule_coverage.validateFixedTableCoverage;
const validateNarrowAddressedBindings = schedule_addressing.validateNarrowAddressedBindings;
const validateRelationCoverage = schedule_coverage.validateRelationCoverage;
const zeroMultiplicityComponent = schedule_addressing.zeroMultiplicityComponent;
const dumpAddOpcodeCoefficients = arena_diagnostics.dumpAddOpcodeCoefficients;

const prove_timing_scope_name = "recorded_witness_start_to_verified_proof";
const pow_timing_scope_name = "cpu_nonce_search_or_fixture_validation_only";

pub const CanonicalProtocol = canonical_protocol_support.CanonicalProtocol;
pub const canonical_protocol = canonical_protocol_support.canonical_protocol;

fn runtimeVerifierGeometry(
    config_words: []const u32,
    composition: composition_bundle_mod.Bundle,
) !resident_verifier.ProtocolGeometry {
    const max_log_degree_bound = composition.verifierMaxLogDegreeBound() catch
        return error.InvalidProtocolGeometry;
    return resident_verifier.ProtocolGeometry.fromConfigWords(
        config_words,
        canonical_protocol.interaction_pow_bits,
        4,
        max_log_degree_bound,
    );
}

pub const protocolObjectIsCanonical = canonical_protocol_support.objectIsCanonical;

const Prepared = struct {
    ranges: [12]arena.LiveRange = [_]arena.LiveRange{.{ .first = 0, .last = 0 }} ** 12,
    range_count: usize = 0,
};

const PurposeStat = struct {
    purpose: []const u8,
    buffers: usize = 0,
    bytes: u64 = 0,
};

const ProofLayoutEvidence = struct {
    interaction_claim_words: usize,
    sampled_value_words: usize,
    decommitment_capacity_words: usize,
};

pub const PreparedStateKey = [32]u8;

const HostGeometryPreparationTiming = struct {
    schedule_read_and_hash_wall_s: f64 = 0,
    schedule_json_parse_wall_s: f64 = 0,
    bundle_read_wall_s: f64 = 0,
};

/// Heap-stable owner for immutable host inputs shared by repeated proofs of the
/// same admitted geometry. Proof plans and bindings are deliberately excluded:
/// they still contain per-input geometry and schedule-borrowed names.
pub const PreparedHostGeometry = struct {
    allocator: std.mem.Allocator,
    schedule_bytes: []u8,
    parsed_schedule: std.json.Parsed(std.json.Value),
    schedule_sha256: [64]u8,
    witness_bundle: ?witness_bundle_mod.Bundle,
    feed_bundle: ?feed_bundle_mod.Bundle,
    relation_bundle: ?relation_bundle_mod.Bundle,
    fixed_table_bundle: ?fixed_table_bundle_mod.Bundle,
    composition_bundle: ?composition_bundle_mod.Bundle,
    preparation_timing: HostGeometryPreparationTiming,

    pub fn init(
        allocator: std.mem.Allocator,
        args: []const []const u8,
    ) !*PreparedHostGeometry {
        if (args.len < 3 or args.len > 8) return error.InvalidArguments;
        var timer = try std.time.Timer.start();
        var timing = HostGeometryPreparationTiming{};
        var started_ns = timer.read();
        const schedule_bytes = try std.fs.cwd().readFileAlloc(allocator, args[1], 64 * 1024 * 1024);
        errdefer allocator.free(schedule_bytes);
        var input_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(schedule_bytes, &input_digest, .{});
        const schedule_sha256 = std.fmt.bytesToHex(input_digest, .lower);
        timing.schedule_read_and_hash_wall_s = nanosecondsToSeconds(timer.read() - started_ns);

        started_ns = timer.read();
        var parsed_schedule = try std.json.parseFromSlice(std.json.Value, allocator, schedule_bytes, .{});
        errdefer parsed_schedule.deinit();
        const root = switch (parsed_schedule.value) {
            .object => |object| object,
            else => return error.InvalidSchedule,
        };
        const arena_object = switch (root.get("arena") orelse return error.InvalidSchedule) {
            .object => |object| object,
            else => return error.InvalidSchedule,
        };
        const logical_schedule = arena_object.get("logical_buffer_schedule") orelse
            return error.InvalidSchedule;
        if (logical_schedule != .array) return error.InvalidSchedule;
        if (root.get("compacted_consumer_rows")) |rows| {
            if (rows != .array) return error.InvalidSchedule;
        }
        timing.schedule_json_parse_wall_s = nanosecondsToSeconds(timer.read() - started_ns);

        started_ns = timer.read();
        var witness_bundle: ?witness_bundle_mod.Bundle = if (args.len >= 4)
            try witness_bundle_mod.Bundle.readFile(allocator, args[3])
        else
            null;
        errdefer if (witness_bundle) |*bundle| bundle.deinit();
        var feed_bundle: ?feed_bundle_mod.Bundle = if (args.len >= 5)
            try feed_bundle_mod.Bundle.readFile(allocator, args[4])
        else
            null;
        errdefer if (feed_bundle) |*bundle| bundle.deinit();
        var relation_bundle: ?relation_bundle_mod.Bundle = if (args.len >= 6)
            try relation_bundle_mod.Bundle.readFile(allocator, args[5])
        else
            null;
        errdefer if (relation_bundle) |*bundle| bundle.deinit();
        var fixed_table_bundle: ?fixed_table_bundle_mod.Bundle = if (args.len >= 7)
            try fixed_table_bundle_mod.Bundle.readFile(allocator, args[6])
        else
            null;
        errdefer if (fixed_table_bundle) |*bundle| bundle.deinit();
        var composition_bundle: ?composition_bundle_mod.Bundle = if (args.len == 8)
            try composition_bundle_mod.Bundle.readFile(allocator, args[7])
        else
            null;
        errdefer if (composition_bundle) |*bundle| bundle.deinit();
        timing.bundle_read_wall_s = nanosecondsToSeconds(timer.read() - started_ns);

        const result = try allocator.create(PreparedHostGeometry);
        result.* = .{
            .allocator = allocator,
            .schedule_bytes = schedule_bytes,
            .parsed_schedule = parsed_schedule,
            .schedule_sha256 = schedule_sha256,
            .witness_bundle = witness_bundle,
            .feed_bundle = feed_bundle,
            .relation_bundle = relation_bundle,
            .fixed_table_bundle = fixed_table_bundle,
            .composition_bundle = composition_bundle,
            .preparation_timing = timing,
        };
        return result;
    }

    pub fn deinit(self: *PreparedHostGeometry) void {
        const allocator = self.allocator;
        if (self.composition_bundle) |*bundle| bundle.deinit();
        if (self.fixed_table_bundle) |*bundle| bundle.deinit();
        if (self.relation_bundle) |*bundle| bundle.deinit();
        if (self.feed_bundle) |*bundle| bundle.deinit();
        if (self.witness_bundle) |*bundle| bundle.deinit();
        self.parsed_schedule.deinit();
        allocator.free(self.schedule_bytes);
        allocator.destroy(self);
    }

    fn schedule(self: *const PreparedHostGeometry) []const std.json.Value {
        return self.parsed_schedule.value.object.get("arena").?.object
            .get("logical_buffer_schedule").?.array.items;
    }

    fn compactedConsumerRows(self: *const PreparedHostGeometry) []const std.json.Value {
        return if (self.parsed_schedule.value.object.get("compacted_consumer_rows")) |value|
            value.array.items
        else
            &.{};
    }
};

const PreparedStateIdentity = struct {
    key: PreparedStateKey,
    logical_plan_hash: u64,
    plan_hash: u64,
    arena_bytes: u64,

    fn eql(lhs: PreparedStateIdentity, rhs: PreparedStateIdentity) bool {
        return std.mem.eql(u8, &lhs.key, &rhs.key) and
            lhs.logical_plan_hash == rhs.logical_plan_hash and
            lhs.plan_hash == rhs.plan_hash and lhs.arena_bytes == rhs.arena_bytes;
    }
};

fn logicalPlanHash(logical: []const arena.LogicalBuffer) u64 {
    var hash = std.hash.Fnv1a_64.init();
    const count: u64 = @intCast(logical.len);
    hash.update(std.mem.asBytes(&count));
    for (logical) |buffer| {
        hash.update(std.mem.asBytes(&buffer.id));
        hash.update(std.mem.asBytes(&buffer.size_bytes));
        hash.update(std.mem.asBytes(&buffer.alignment));
        hash.update(std.mem.asBytes(&buffer.placement_priority));
        const range_count: u64 = @intCast(buffer.live_ranges.len);
        hash.update(std.mem.asBytes(&range_count));
        for (buffer.live_ranges) |range| {
            hash.update(std.mem.asBytes(&range.first));
            hash.update(std.mem.asBytes(&range.last));
        }
        const has_spill: u8 = @intFromBool(buffer.spill_cost_ns != null);
        hash.update(std.mem.asBytes(&has_spill));
        if (buffer.spill_cost_ns) |value| hash.update(std.mem.asBytes(&value));
        const has_recompute: u8 = @intFromBool(buffer.recompute_cost_ns != null);
        hash.update(std.mem.asBytes(&has_recompute));
        if (buffer.recompute_cost_ns) |value| hash.update(std.mem.asBytes(&value));
    }
    return hash.final();
}

const PreparedStateAdmission = struct {
    const Status = enum { empty, pending, ready, borrowed, poisoned };
    const Decision = enum { miss, hit };

    status: Status = .empty,
    identity: ?PreparedStateIdentity = null,

    fn begin(
        self: *PreparedStateAdmission,
        identity: PreparedStateIdentity,
        allow_reuse: bool,
    ) !Decision {
        switch (self.status) {
            .pending, .borrowed => return error.PreparedStateAlreadyBorrowed,
            .ready => if (allow_reuse and self.identity.?.eql(identity)) {
                self.status = .borrowed;
                return .hit;
            },
            .empty, .poisoned => {},
        }
        self.identity = identity;
        self.status = .pending;
        return .miss;
    }

    fn validateCommit(self: *const PreparedStateAdmission) !void {
        if (self.status != .pending and self.status != .borrowed)
            return error.PreparedStateNotBorrowed;
    }

    fn commitAssumeValid(self: *PreparedStateAdmission) void {
        self.status = .ready;
    }

    fn commit(self: *PreparedStateAdmission) !void {
        try self.validateCommit();
        self.commitAssumeValid();
    }

    fn poison(self: *PreparedStateAdmission) void {
        self.status = .poisoned;
        self.identity = null;
    }
};

const prepared_geometry_capacity = 4;

const PreparedGeometryEntry = struct {
    identity: PreparedStateIdentity,
    plan: arena.Plan,
    last_used: u64,

    fn deinit(self: *PreparedGeometryEntry) void {
        self.plan.deinit();
        self.* = undefined;
    }
};

const PendingPreparedGeometry = struct {
    identity: PreparedStateIdentity,
    plan: arena.Plan,
};

const PreparedGeometryPlanTransfer = struct {
    owner: *?arena.Plan,
    transferred: *bool,
};

const PreparedGeometryHandle = struct {
    index: u8,
    plan: *const arena.Plan,
};

const PreparedGeometryTransaction = union(enum) {
    none,
    hit: u8,
    pending: PendingPreparedGeometry,
};

const PreparedGeometryCache = struct {
    allocator: std.mem.Allocator,
    entries: [prepared_geometry_capacity]?PreparedGeometryEntry =
        [_]?PreparedGeometryEntry{null} ** prepared_geometry_capacity,
    active: PreparedGeometryTransaction = .none,
    clock: u64 = 0,

    fn init(allocator: std.mem.Allocator) PreparedGeometryCache {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *PreparedGeometryCache) void {
        self.poisonActive();
        for (&self.entries) |*entry| {
            if (entry.*) |*value| value.deinit();
            entry.* = null;
        }
        self.* = undefined;
    }

    fn validateEntry(entry: *const PreparedGeometryEntry) !void {
        if (entry.plan.plan_hash != entry.identity.plan_hash or
            entry.plan.total_bytes != entry.identity.arena_bytes)
        {
            return error.PreparedStatePlanIdentityMismatch;
        }
    }

    fn findCommitted(
        self: *PreparedGeometryCache,
        key: PreparedStateKey,
        logical_plan_hash: u64,
    ) !?PreparedGeometryHandle {
        if (self.active != .none) return error.PreparedGeometryAlreadyBorrowed;
        for (&self.entries, 0..) |*entry, index| {
            const value = if (entry.*) |*candidate| candidate else continue;
            if (!std.mem.eql(u8, &value.identity.key, &key) or
                value.identity.logical_plan_hash != logical_plan_hash)
            {
                continue;
            }
            validateEntry(value) catch |err| {
                self.evictIndex(index);
                return err;
            };
            const slot: u8 = @intCast(index);
            self.active = .{ .hit = slot };
            return .{ .index = slot, .plan = &value.plan };
        }
        return null;
    }

    fn validateActiveHit(
        self: *const PreparedGeometryCache,
        handle: PreparedGeometryHandle,
        identity: PreparedStateIdentity,
    ) !void {
        const active_index = switch (self.active) {
            .hit => |index| index,
            else => return error.PreparedGeometryHitNotActive,
        };
        if (active_index != handle.index) return error.PreparedGeometryHitNotActive;
        const index: usize = active_index;
        const entry = if (self.entries[index]) |*value| value else return error.PreparedGeometryHitNotActive;
        try validateEntry(entry);
        if (!entry.identity.eql(identity) or handle.plan != &entry.plan)
            return error.PreparedStatePlanIdentityMismatch;
    }

    fn stageMiss(
        self: *PreparedGeometryCache,
        identity: PreparedStateIdentity,
        transfer: PreparedGeometryPlanTransfer,
    ) !void {
        if (self.active != .none) return error.PreparedGeometryAlreadyBorrowed;
        if (transfer.transferred.*) return error.PreparedStatePlanAlreadyTransferred;
        const plan = transfer.owner.* orelse return error.MissingPreparedStatePlanOwner;
        if (plan.plan_hash != identity.plan_hash or plan.total_bytes != identity.arena_bytes)
            return error.PreparedStatePlanIdentityMismatch;
        self.active = .{ .pending = .{ .identity = identity, .plan = plan } };
        transfer.transferred.* = true;
    }

    fn validateCommit(self: *const PreparedGeometryCache) !void {
        switch (self.active) {
            .none => {},
            .hit => |raw_index| {
                const index: usize = raw_index;
                const entry = if (self.entries[index]) |*value| value else return error.PreparedGeometryHitNotActive;
                try validateEntry(entry);
            },
            .pending => |pending| {
                if (pending.plan.plan_hash != pending.identity.plan_hash or
                    pending.plan.total_bytes != pending.identity.arena_bytes)
                {
                    return error.PreparedStatePlanIdentityMismatch;
                }
            },
        }
    }

    fn commitAssumeValid(self: *PreparedGeometryCache) void {
        switch (self.active) {
            .none => {},
            .hit => |raw_index| self.touch(raw_index),
            .pending => |pending| {
                const index = self.chooseVictim();
                self.evictIndex(index);
                self.clock = self.clock +| 1;
                self.entries[index] = .{
                    .identity = pending.identity,
                    .plan = pending.plan,
                    .last_used = self.clock,
                };
            },
        }
        self.active = .none;
    }

    fn poisonActive(self: *PreparedGeometryCache) void {
        switch (self.active) {
            .none => {},
            .hit => |raw_index| self.evictIndex(raw_index),
            .pending => |pending| {
                var owned = pending.plan;
                owned.deinit();
            },
        }
        self.active = .none;
    }

    fn touch(self: *PreparedGeometryCache, raw_index: u8) void {
        const index: usize = raw_index;
        self.clock = self.clock +| 1;
        self.entries[index].?.last_used = self.clock;
    }

    fn chooseVictim(self: *const PreparedGeometryCache) usize {
        for (self.entries, 0..) |entry, index| {
            if (entry == null) return index;
        }
        var victim: usize = 0;
        for (self.entries[1..], 1..) |entry, index| {
            if (entry.?.last_used < self.entries[victim].?.last_used) victim = index;
        }
        return victim;
    }

    fn evictIndex(self: *PreparedGeometryCache, index: usize) void {
        if (self.entries[index]) |*entry| entry.deinit();
        self.entries[index] = null;
    }
};

pub const PreparedStateTelemetry = struct {
    cache_hit: bool = false,
    arena_bytes: u64 = 0,
    snapshot_bytes: u64 = 0,
    clear_bytes: u64 = 0,
    capture_gpu_ms: f64 = 0,
    restore_gpu_ms: f64 = 0,
};

const RunnerPhaseTiming = struct {
    schedule_read_and_hash_wall_s: f64 = 0,
    schedule_json_parse_wall_s: f64 = 0,
    bundle_read_and_validate_wall_s: f64 = 0,
    statement_and_proof_plan_wall_s: f64 = 0,
    schedule_liveness_analysis_wall_s: f64 = 0,
    arena_plan_and_bindings_wall_s: f64 = 0,
    resident_acquire_reset_restore_wall_s: f64 = 0,
    input_materialization_wall_s: f64 = 0,
    immutable_host_restore_wall_s: f64 = 0,
    recipe_preparation_wall_s: f64 = 0,

    fn addInterval(destination: *f64, timer: *std.time.Timer, started_ns: u64) void {
        destination.* += nanosecondsToSeconds(timer.read() - started_ns);
    }

    fn instrumentedPreProveWallSeconds(self: RunnerPhaseTiming) f64 {
        return self.schedule_read_and_hash_wall_s +
            self.schedule_json_parse_wall_s +
            self.bundle_read_and_validate_wall_s +
            self.statement_and_proof_plan_wall_s +
            self.schedule_liveness_analysis_wall_s +
            self.arena_plan_and_bindings_wall_s +
            self.resident_acquire_reset_restore_wall_s +
            self.input_materialization_wall_s +
            self.immutable_host_restore_wall_s +
            self.recipe_preparation_wall_s;
    }

    fn report(
        self: RunnerPhaseTiming,
        runner_before_report_wall_s: f64,
        prove_started_wall_s: ?f64,
        proof_verified_wall_s: ?f64,
        prove_wall_s: ?f64,
    ) RunnerPhaseTimingReport {
        const instrumented = self.instrumentedPreProveWallSeconds();
        const observed = prove_started_wall_s;
        return .{
            .schedule_read_and_hash_wall_s = self.schedule_read_and_hash_wall_s,
            .schedule_json_parse_wall_s = self.schedule_json_parse_wall_s,
            .bundle_read_and_validate_wall_s = self.bundle_read_and_validate_wall_s,
            .statement_and_proof_plan_wall_s = self.statement_and_proof_plan_wall_s,
            .schedule_liveness_analysis_wall_s = self.schedule_liveness_analysis_wall_s,
            .arena_plan_and_bindings_wall_s = self.arena_plan_and_bindings_wall_s,
            .resident_acquire_reset_restore_wall_s = self.resident_acquire_reset_restore_wall_s,
            .input_materialization_wall_s = self.input_materialization_wall_s,
            .immutable_host_restore_wall_s = self.immutable_host_restore_wall_s,
            .recipe_preparation_wall_s = self.recipe_preparation_wall_s,
            .pre_prove_observed_wall_s = observed,
            .pre_prove_instrumented_wall_s = instrumented,
            .pre_prove_unattributed_wall_s = if (observed) |value| @max(0, value - instrumented) else null,
            .post_prove_pre_report_wall_s = if (proof_verified_wall_s) |verified|
                @max(0, runner_before_report_wall_s - verified)
            else
                null,
            .runner_minus_prove_before_report_wall_s = if (prove_wall_s) |proved|
                @max(0, runner_before_report_wall_s - proved)
            else
                null,
            .runner_before_report_wall_s = runner_before_report_wall_s,
        };
    }
};

const RunnerPhaseTimingReport = struct {
    schema_version: u32 = 1,
    scope: []const u8 = "run_one_entry_to_report_serialization_start",
    schedule_read_and_hash_wall_s: f64,
    schedule_json_parse_wall_s: f64,
    bundle_read_and_validate_wall_s: f64,
    statement_and_proof_plan_wall_s: f64,
    schedule_liveness_analysis_wall_s: f64,
    arena_plan_and_bindings_wall_s: f64,
    resident_acquire_reset_restore_wall_s: f64,
    input_materialization_wall_s: f64,
    immutable_host_restore_wall_s: f64,
    recipe_preparation_wall_s: f64,
    pre_prove_observed_wall_s: ?f64,
    pre_prove_instrumented_wall_s: f64,
    pre_prove_unattributed_wall_s: ?f64,
    post_prove_pre_report_wall_s: ?f64,
    runner_minus_prove_before_report_wall_s: ?f64,
    runner_before_report_wall_s: f64,
};

const RecipePreparationTiming = struct {
    fixed_tables_wall_s: f64 = 0,
    multiplicity_feeds_wall_s: f64 = 0,
    base_aot_witness_acquire_wall_s: f64 = 0,
    compact_verify_wall_s: f64 = 0,
    compact_pedersen_wall_s: f64 = 0,
    compact_poseidon_wall_s: f64 = 0,
    ec_op_base_wall_s: f64 = 0,
    recorded_base_interpolation_wall_s: f64 = 0,
    native_base_interpolation_wall_s: f64 = 0,
    transcript_wall_s: f64 = 0,
    interaction_aot_witness_wall_s: f64 = 0,
    ec_op_interaction_wall_s: f64 = 0,
    relation_components_wall_s: f64 = 0,
    interaction_native_interpolation_wall_s: f64 = 0,
    composition_wall_s: f64 = 0,
    quotient_wall_s: f64 = 0,
    fri_wall_s: f64 = 0,
    decommit_queries_wall_s: f64 = 0,
    proof_assembly_wall_s: f64 = 0,

    fn preProveWallSeconds(self: RecipePreparationTiming) f64 {
        return self.fixed_tables_wall_s +
            self.multiplicity_feeds_wall_s +
            self.base_aot_witness_acquire_wall_s +
            self.compact_verify_wall_s +
            self.compact_pedersen_wall_s +
            self.compact_poseidon_wall_s +
            self.ec_op_base_wall_s +
            self.recorded_base_interpolation_wall_s +
            self.native_base_interpolation_wall_s;
    }

    fn recordedProveWallSeconds(self: RecipePreparationTiming) f64 {
        return self.transcript_wall_s +
            self.interaction_aot_witness_wall_s +
            self.ec_op_interaction_wall_s +
            self.relation_components_wall_s +
            self.interaction_native_interpolation_wall_s +
            self.composition_wall_s +
            self.quotient_wall_s +
            self.fri_wall_s +
            self.decommit_queries_wall_s +
            self.proof_assembly_wall_s;
    }

    fn report(
        self: RecipePreparationTiming,
        prove_wall_s: ?f64,
    ) RecipePreparationTimingReport {
        const pre_prove_wall_s = self.preProveWallSeconds();
        const recorded_prove_wall_s = self.recordedProveWallSeconds();
        return .{
            .pre_prove = .{
                .fixed_tables_wall_s = self.fixed_tables_wall_s,
                .multiplicity_feeds_wall_s = self.multiplicity_feeds_wall_s,
                .base_aot_witness_acquire_wall_s = self.base_aot_witness_acquire_wall_s,
                .compact_verify_wall_s = self.compact_verify_wall_s,
                .compact_pedersen_wall_s = self.compact_pedersen_wall_s,
                .compact_poseidon_wall_s = self.compact_poseidon_wall_s,
                .ec_op_base_wall_s = self.ec_op_base_wall_s,
                .recorded_base_interpolation_wall_s = self.recorded_base_interpolation_wall_s,
                .native_base_interpolation_wall_s = self.native_base_interpolation_wall_s,
                .total_wall_s = pre_prove_wall_s,
            },
            .recorded_prove = .{
                .transcript_wall_s = self.transcript_wall_s,
                .interaction_aot_witness_wall_s = self.interaction_aot_witness_wall_s,
                .ec_op_interaction_wall_s = self.ec_op_interaction_wall_s,
                .relation_components_wall_s = self.relation_components_wall_s,
                .interaction_native_interpolation_wall_s = self.interaction_native_interpolation_wall_s,
                .composition_wall_s = self.composition_wall_s,
                .quotient_wall_s = self.quotient_wall_s,
                .fri_wall_s = self.fri_wall_s,
                .decommit_queries_wall_s = self.decommit_queries_wall_s,
                .proof_assembly_wall_s = self.proof_assembly_wall_s,
                .total_wall_s = recorded_prove_wall_s,
            },
            .total_wall_s = pre_prove_wall_s + recorded_prove_wall_s,
            .recorded_prove_non_recipe_wall_s = if (prove_wall_s) |proved|
                @max(0, proved - recorded_prove_wall_s)
            else
                null,
        };
    }
};

const PreProveRecipePreparationTimingReport = struct {
    fixed_tables_wall_s: f64,
    multiplicity_feeds_wall_s: f64,
    base_aot_witness_acquire_wall_s: f64,
    compact_verify_wall_s: f64,
    compact_pedersen_wall_s: f64,
    compact_poseidon_wall_s: f64,
    ec_op_base_wall_s: f64,
    recorded_base_interpolation_wall_s: f64,
    native_base_interpolation_wall_s: f64,
    total_wall_s: f64,
};

const RecordedProveRecipePreparationTimingReport = struct {
    transcript_wall_s: f64,
    interaction_aot_witness_wall_s: f64,
    ec_op_interaction_wall_s: f64,
    relation_components_wall_s: f64,
    interaction_native_interpolation_wall_s: f64,
    composition_wall_s: f64,
    quotient_wall_s: f64,
    fri_wall_s: f64,
    decommit_queries_wall_s: f64,
    proof_assembly_wall_s: f64,
    total_wall_s: f64,
};

const RecipePreparationTimingReport = struct {
    schema_version: u32 = 1,
    scope: []const u8 = "run_one_recipe_acquisition_wall_time",
    pre_prove: PreProveRecipePreparationTimingReport,
    recorded_prove: RecordedProveRecipePreparationTimingReport,
    total_wall_s: f64,
    recorded_prove_non_recipe_wall_s: ?f64,
};

fn nanosecondsToSeconds(value: u64) f64 {
    return @as(f64, @floatFromInt(value)) / @as(f64, @floatFromInt(std.time.ns_per_s));
}

const CanonicalFullProofPlanMode = struct {
    execute_proof: bool,
    no_projection: bool,
    prepare_metal: bool,
    execute_preprocessed: bool,
    execute_witness: bool,
    execute_base_interpolation: bool,
    execute_commitments: bool,
    execute_relations: bool,
    execute_oods: bool,
    verify_proof: bool,

    fn eligible(self: CanonicalFullProofPlanMode) bool {
        return self.execute_proof and self.no_projection and self.prepare_metal and
            self.execute_preprocessed and self.execute_witness and
            self.execute_base_interpolation and self.execute_commitments and
            self.execute_relations and self.execute_oods and self.verify_proof;
    }
};

const PreparedStateAcquire = struct {
    resident_arena: *arena.ResidentArena,
    cache_hit: bool,
};

const PreparedCompactSlot = enum {
    verify_instruction,
    pedersen,
    poseidon,
};

/// The resident GPU state has capacity one while immutable host geometry has
/// capacity four. Both are transactional: the session commits only after
/// validating the verified proof report, or poisons the active state on error.
pub const PreparedStateCache = struct {
    allocator: std.mem.Allocator,
    admission: PreparedStateAdmission = .{},
    resident_arena: ?arena.ResidentArena = null,
    snapshot: ?metal_runtime.ResidentBuffer = null,
    ranges: []metal_runtime.PreparedStateRange = &.{},
    geometry: PreparedGeometryCache,
    fixed_tables: ?protocol_recipes.FixedTableBatchRecipe = null,
    multiplicity_feeds: ?arena_binding_mod.MultiplicityFeedBatch = null,
    base_aot_witness: ?protocol_recipes.AotWitnessBatchRecipe = null,
    recorded_base_interpolation: ?arena_binding_mod.RecordedBaseInterpolationBatch = null,
    native_base_interpolation: ?arena_binding_mod.NativeBaseInterpolationBatch = null,
    interaction_aot_witness: ?protocol_recipes.AotWitnessBatchRecipe = null,
    compact_verify: ?protocol_recipes.CompactRecipe = null,
    compact_pedersen: ?protocol_recipes.CompactRecipe = null,
    compact_poseidon: ?protocol_recipes.CompactRecipe = null,
    telemetry: PreparedStateTelemetry = .{},

    pub fn init(allocator: std.mem.Allocator) PreparedStateCache {
        return .{
            .allocator = allocator,
            .geometry = PreparedGeometryCache.init(allocator),
        };
    }

    pub fn deinit(self: *PreparedStateCache) void {
        self.clearResidentResources();
        self.geometry.deinit();
        self.* = undefined;
    }

    pub fn commit(self: *PreparedStateCache) !void {
        try self.admission.validateCommit();
        try self.geometry.validateCommit();
        self.admission.commitAssumeValid();
        self.geometry.commitAssumeValid();
    }

    pub fn poison(self: *PreparedStateCache) void {
        self.admission.poison();
        self.clearResidentResources();
        self.geometry.poisonActive();
    }

    pub fn requestTelemetry(self: *const PreparedStateCache) PreparedStateTelemetry {
        return self.telemetry;
    }

    fn clearResidentResources(self: *PreparedStateCache) void {
        if (self.interaction_aot_witness) |*recipe| recipe.deinit();
        if (self.native_base_interpolation) |*recipe| recipe.deinit();
        if (self.recorded_base_interpolation) |*recipe| recipe.deinit();
        if (self.compact_poseidon) |*recipe| recipe.deinit();
        if (self.compact_pedersen) |*recipe| recipe.deinit();
        if (self.compact_verify) |*recipe| recipe.deinit();
        if (self.multiplicity_feeds) |*recipe| recipe.deinit();
        if (self.fixed_tables) |*recipe| recipe.deinit();
        if (self.base_aot_witness) |*recipe| recipe.deinit();
        if (self.snapshot) |*snapshot| snapshot.deinit();
        if (self.resident_arena) |*resident| resident.deinit();
        if (self.ranges.len != 0) self.allocator.free(self.ranges);
        self.interaction_aot_witness = null;
        self.native_base_interpolation = null;
        self.recorded_base_interpolation = null;
        self.compact_poseidon = null;
        self.compact_pedersen = null;
        self.compact_verify = null;
        self.multiplicity_feeds = null;
        self.fixed_tables = null;
        self.base_aot_witness = null;
        self.snapshot = null;
        self.resident_arena = null;
        self.ranges = &.{};
    }

    fn compactSlot(self: *PreparedStateCache, slot: PreparedCompactSlot) *?protocol_recipes.CompactRecipe {
        return switch (slot) {
            .verify_instruction => &self.compact_verify,
            .pedersen => &self.compact_pedersen,
            .poseidon => &self.compact_poseidon,
        };
    }

    fn installCompact(
        self: *PreparedStateCache,
        slot: PreparedCompactSlot,
        owner: *?protocol_recipes.CompactRecipe,
    ) !*protocol_recipes.CompactRecipe {
        errdefer self.poison();
        if (self.admission.status != .pending) return error.PreparedStateNotPending;
        const target = self.compactSlot(slot);
        if (target.* != null) return error.PreparedStateCompactAlreadyInstalled;
        const resident = if (self.resident_arena) |*value| value else return error.PreparedStateMissingArena;
        const candidate = owner.* orelse return error.MissingPreparedStateCompactOwner;
        if (candidate.arena != resident) return error.PreparedStateCompactArenaMismatch;
        target.* = candidate;
        owner.* = null;
        return &target.*.?;
    }

    fn borrowCompact(
        self: *PreparedStateCache,
        slot: PreparedCompactSlot,
    ) !*protocol_recipes.CompactRecipe {
        errdefer self.poison();
        if (self.admission.status != .borrowed) return error.PreparedStateNotBorrowed;
        const recipe = if (self.compactSlot(slot).*) |*value| value else return error.PreparedStateMissingCompact;
        const resident = if (self.resident_arena) |*value| value else return error.PreparedStateMissingArena;
        if (recipe.arena != resident) return error.PreparedStateCompactArenaMismatch;
        try recipe.resetForRequest();
        return recipe;
    }

    fn installBaseAotWitness(
        self: *PreparedStateCache,
        owner: *?protocol_recipes.AotWitnessBatchRecipe,
    ) !*protocol_recipes.AotWitnessBatchRecipe {
        errdefer self.poison();
        if (self.admission.status != .pending) return error.PreparedStateNotPending;
        if (self.base_aot_witness != null) return error.PreparedStateBaseAotWitnessAlreadyInstalled;
        const resident = if (self.resident_arena) |*value| value else return error.PreparedStateMissingArena;
        const candidate = owner.* orelse return error.MissingPreparedStateBaseAotWitnessOwner;
        if (candidate.arena != resident) return error.PreparedStateBaseAotWitnessArenaMismatch;
        self.base_aot_witness = candidate;
        owner.* = null;
        return &self.base_aot_witness.?;
    }

    fn borrowBaseAotWitness(self: *PreparedStateCache) !*protocol_recipes.AotWitnessBatchRecipe {
        errdefer self.poison();
        if (self.admission.status != .borrowed) return error.PreparedStateNotBorrowed;
        const recipe = if (self.base_aot_witness) |*value| value else return error.PreparedStateMissingBaseAotWitness;
        const resident = if (self.resident_arena) |*value| value else return error.PreparedStateMissingArena;
        if (recipe.arena != resident) return error.PreparedStateBaseAotWitnessArenaMismatch;
        recipe.resetForRequest();
        return recipe;
    }

    fn installRecordedBaseInterpolation(
        self: *PreparedStateCache,
        owner: *?arena_binding_mod.RecordedBaseInterpolationBatch,
    ) !*arena_binding_mod.RecordedBaseInterpolationBatch {
        errdefer self.poison();
        if (self.admission.status != .pending) return error.PreparedStateNotPending;
        if (self.recorded_base_interpolation != null)
            return error.PreparedStateRecordedBaseInterpolationAlreadyInstalled;
        const resident = if (self.resident_arena) |*value| value else return error.PreparedStateMissingArena;
        const candidate = owner.* orelse return error.MissingPreparedStateRecordedBaseInterpolationOwner;
        if (candidate.resident_arena != resident)
            return error.PreparedStateRecordedBaseInterpolationArenaMismatch;
        self.recorded_base_interpolation = candidate;
        owner.* = null;
        return &self.recorded_base_interpolation.?;
    }

    fn borrowRecordedBaseInterpolation(
        self: *PreparedStateCache,
    ) !*arena_binding_mod.RecordedBaseInterpolationBatch {
        errdefer self.poison();
        if (self.admission.status != .borrowed) return error.PreparedStateNotBorrowed;
        const recipe = if (self.recorded_base_interpolation) |*value| value else return error.PreparedStateMissingRecordedBaseInterpolation;
        const resident = if (self.resident_arena) |*value| value else return error.PreparedStateMissingArena;
        if (recipe.resident_arena != resident)
            return error.PreparedStateRecordedBaseInterpolationArenaMismatch;
        recipe.resetForRequest();
        return recipe;
    }

    fn installNativeBaseInterpolation(
        self: *PreparedStateCache,
        owner: *?arena_binding_mod.NativeBaseInterpolationBatch,
    ) !*arena_binding_mod.NativeBaseInterpolationBatch {
        errdefer self.poison();
        if (self.admission.status != .pending) return error.PreparedStateNotPending;
        if (self.native_base_interpolation != null)
            return error.PreparedStateNativeBaseInterpolationAlreadyInstalled;
        const resident = if (self.resident_arena) |*value| value else return error.PreparedStateMissingArena;
        const candidate = owner.* orelse return error.MissingPreparedStateNativeBaseInterpolationOwner;
        if (candidate.resident_arena != resident)
            return error.PreparedStateNativeBaseInterpolationArenaMismatch;
        self.native_base_interpolation = candidate;
        owner.* = null;
        return &self.native_base_interpolation.?;
    }

    fn borrowNativeBaseInterpolation(
        self: *PreparedStateCache,
    ) !*arena_binding_mod.NativeBaseInterpolationBatch {
        errdefer self.poison();
        if (self.admission.status != .borrowed) return error.PreparedStateNotBorrowed;
        const recipe = if (self.native_base_interpolation) |*value| value else return error.PreparedStateMissingNativeBaseInterpolation;
        const resident = if (self.resident_arena) |*value| value else return error.PreparedStateMissingArena;
        if (recipe.resident_arena != resident)
            return error.PreparedStateNativeBaseInterpolationArenaMismatch;
        recipe.resetForRequest();
        return recipe;
    }

    fn installInteractionAotWitness(
        self: *PreparedStateCache,
        owner: *?protocol_recipes.AotWitnessBatchRecipe,
    ) !*protocol_recipes.AotWitnessBatchRecipe {
        errdefer self.poison();
        if (self.admission.status != .pending) return error.PreparedStateNotPending;
        if (self.interaction_aot_witness != null)
            return error.PreparedStateInteractionAotWitnessAlreadyInstalled;
        const resident = if (self.resident_arena) |*value| value else return error.PreparedStateMissingArena;
        const candidate = owner.* orelse return error.MissingPreparedStateInteractionAotWitnessOwner;
        if (candidate.arena != resident) return error.PreparedStateInteractionAotWitnessArenaMismatch;
        self.interaction_aot_witness = candidate;
        owner.* = null;
        return &self.interaction_aot_witness.?;
    }

    fn borrowInteractionAotWitness(self: *PreparedStateCache) !*protocol_recipes.AotWitnessBatchRecipe {
        errdefer self.poison();
        if (self.admission.status != .borrowed) return error.PreparedStateNotBorrowed;
        const recipe = if (self.interaction_aot_witness) |*value| value else return error.PreparedStateMissingInteractionAotWitness;
        const resident = if (self.resident_arena) |*value| value else return error.PreparedStateMissingArena;
        if (recipe.arena != resident) return error.PreparedStateInteractionAotWitnessArenaMismatch;
        recipe.resetForRequest();
        return recipe;
    }

    fn installFixedTables(
        self: *PreparedStateCache,
        owner: *?protocol_recipes.FixedTableBatchRecipe,
    ) !*protocol_recipes.FixedTableBatchRecipe {
        errdefer self.poison();
        if (self.admission.status != .pending) return error.PreparedStateNotPending;
        if (self.fixed_tables != null) return error.PreparedStateFixedTablesAlreadyInstalled;
        const resident = if (self.resident_arena) |*value| value else return error.PreparedStateMissingArena;
        const candidate = owner.* orelse return error.MissingPreparedStateFixedTablesOwner;
        if (candidate.arena != resident) return error.PreparedStateFixedTablesArenaMismatch;
        self.fixed_tables = candidate;
        owner.* = null;
        return &self.fixed_tables.?;
    }

    fn borrowFixedTables(self: *PreparedStateCache) !*protocol_recipes.FixedTableBatchRecipe {
        errdefer self.poison();
        if (self.admission.status != .borrowed) return error.PreparedStateNotBorrowed;
        const recipe = if (self.fixed_tables) |*value| value else return error.PreparedStateMissingFixedTables;
        const resident = if (self.resident_arena) |*value| value else return error.PreparedStateMissingArena;
        if (recipe.arena != resident) return error.PreparedStateFixedTablesArenaMismatch;
        recipe.resetForRequest();
        return recipe;
    }

    fn installMultiplicityFeeds(
        self: *PreparedStateCache,
        owner: *?arena_binding_mod.MultiplicityFeedBatch,
    ) !*arena_binding_mod.MultiplicityFeedBatch {
        errdefer self.poison();
        if (self.admission.status != .pending) return error.PreparedStateNotPending;
        if (self.multiplicity_feeds != null) return error.PreparedStateMultiplicityFeedsAlreadyInstalled;
        const resident = if (self.resident_arena) |*value| value else return error.PreparedStateMissingArena;
        const candidate = owner.* orelse return error.MissingPreparedStateMultiplicityFeedsOwner;
        if (candidate.batch.arena != resident) return error.PreparedStateMultiplicityFeedsArenaMismatch;
        self.multiplicity_feeds = candidate;
        owner.* = null;
        return &self.multiplicity_feeds.?;
    }

    fn borrowMultiplicityFeeds(self: *PreparedStateCache) !*arena_binding_mod.MultiplicityFeedBatch {
        errdefer self.poison();
        if (self.admission.status != .borrowed) return error.PreparedStateNotBorrowed;
        const recipe = if (self.multiplicity_feeds) |*value| value else return error.PreparedStateMissingMultiplicityFeeds;
        const resident = if (self.resident_arena) |*value| value else return error.PreparedStateMissingArena;
        if (recipe.batch.arena != resident) return error.PreparedStateMultiplicityFeedsArenaMismatch;
        recipe.resetForRequest();
        return recipe;
    }

    fn findCanonicalPlan(
        self: *PreparedStateCache,
        key: PreparedStateKey,
        logical_plan_hash: u64,
    ) !?PreparedGeometryHandle {
        return self.geometry.findCommitted(key, logical_plan_hash);
    }

    fn transition(
        self: *PreparedStateCache,
        key: PreparedStateKey,
        logical_plan_hash: u64,
        plan: arena.Plan,
        canonical_full_proof: bool,
        geometry_hit: ?PreparedGeometryHandle,
        plan_transfer: ?PreparedGeometryPlanTransfer,
    ) !PreparedStateAdmission.Decision {
        errdefer self.poison();
        const identity = PreparedStateIdentity{
            .key = key,
            .logical_plan_hash = logical_plan_hash,
            .plan_hash = plan.plan_hash,
            .arena_bytes = plan.total_bytes,
        };
        if (canonical_full_proof) {
            if (geometry_hit) |handle| {
                if (plan_transfer != null) return error.InvalidPreparedStatePlanHit;
                try self.geometry.validateActiveHit(handle, identity);
            } else if (plan_transfer == null) {
                return error.MissingPreparedStatePlanOwner;
            }
        } else {
            if (geometry_hit != null or plan_transfer != null)
                return error.UnexpectedPreparedStatePlanOwner;
            if (self.geometry.active != .none) return error.PreparedGeometryAlreadyBorrowed;
        }
        const decision = try self.admission.begin(identity, canonical_full_proof and geometry_hit != null);
        switch (decision) {
            .hit => {
                if (geometry_hit == null) return error.InvalidPreparedStatePlanHit;
            },
            .miss => {
                self.clearResidentResources();
                if (canonical_full_proof and geometry_hit == null) {
                    const transfer = plan_transfer orelse return error.MissingPreparedStatePlanOwner;
                    try self.geometry.stageMiss(identity, transfer);
                }
            },
        }
        return decision;
    }

    fn begin(
        self: *PreparedStateCache,
        metal: *metal_runtime.Runtime,
        key: PreparedStateKey,
        logical_plan_hash: u64,
        plan: arena.Plan,
        canonical_full_proof: bool,
        geometry_hit: ?PreparedGeometryHandle,
        plan_transfer: ?PreparedGeometryPlanTransfer,
    ) !PreparedStateAcquire {
        const arena_bytes = plan.total_bytes;
        self.telemetry = .{ .arena_bytes = arena_bytes };
        const decision = try self.transition(
            key,
            logical_plan_hash,
            plan,
            canonical_full_proof,
            geometry_hit,
            plan_transfer,
        );
        switch (decision) {
            .hit => {
                errdefer self.poison();
                const snapshot = self.snapshot orelse return error.PreparedStateMissingSnapshot;
                const resident = if (self.resident_arena) |*value| value else return error.PreparedStateMissingArena;
                if (self.ranges.len == 0) return error.PreparedStateMissingSnapshot;
                self.telemetry.cache_hit = true;
                self.telemetry.snapshot_bytes = snapshot.byte_length;
                self.telemetry.clear_bytes = resident.buffer.byte_length;
                self.telemetry.restore_gpu_ms = try metal.preparedStateTransfer(
                    resident.buffer,
                    snapshot,
                    self.ranges,
                    false,
                    true,
                );
                return .{ .resident_arena = resident, .cache_hit = true };
            },
            .miss => {
                errdefer self.poison();
                self.resident_arena = try arena.ResidentArena.initByteLength(metal, arena_bytes);
                return .{ .resident_arena = &self.resident_arena.?, .cache_hit = false };
            },
        }
    }

    fn capture(
        self: *PreparedStateCache,
        metal: *metal_runtime.Runtime,
        schedule: []const std.json.Value,
        plan: arena.Plan,
    ) !void {
        if (self.admission.status != .pending or self.snapshot != null or self.ranges.len != 0)
            return error.InvalidPreparedStateCapture;
        errdefer self.poison();
        self.ranges = try buildPreparedStateRanges(self.allocator, schedule, plan);
        var snapshot_bytes: u64 = 0;
        for (self.ranges) |range| snapshot_bytes = @max(
            snapshot_bytes,
            std.math.add(u64, range.snapshot_byte_offset, range.byte_count) catch
                return error.SizeOverflow,
        );
        if (snapshot_bytes == 0) return error.EmptyPreparedState;
        self.snapshot = try metal.allocateResidentBuffer(
            std.math.cast(usize, snapshot_bytes) orelse return error.SizeOverflow,
        );
        const resident = if (self.resident_arena) |*value| value else return error.PreparedStateMissingArena;
        self.telemetry.snapshot_bytes = snapshot_bytes;
        self.telemetry.capture_gpu_ms = try metal.preparedStateTransfer(
            resident.buffer,
            self.snapshot.?,
            self.ranges,
            true,
            false,
        );
    }
};

fn buildPreparedStateRanges(
    allocator: std.mem.Allocator,
    schedule: []const std.json.Value,
    plan: arena.Plan,
) ![]metal_runtime.PreparedStateRange {
    const PhysicalRange = struct { offset: u64, bytes: u64 };
    var physical = std.ArrayList(PhysicalRange).empty;
    defer physical.deinit(allocator);
    for (schedule) |entry| {
        const wanted_purpose = try purposeOf(entry);
        // ForwardTwiddles holds the base inverse bank at request start, then is
        // deliberately reused for forward/inverse banks later in the proof.
        const prepared_initial_state = std.mem.eql(u8, wanted_purpose, "ForwardTwiddles") or
            std.mem.eql(u8, wanted_purpose, "PreprocessedCoefficients") or
            std.mem.eql(u8, wanted_purpose, "PreprocessedEvaluations") or
            (std.mem.eql(u8, wanted_purpose, "RetainedMerkleLayers") and
                entry.object.get("ordinal") != null and
                entry.object.get("ordinal").? == .integer and
                entry.object.get("ordinal").?.integer >= 0 and
                (@as(u64, @intCast(entry.object.get("ordinal").?.integer)) >> 20) == 0);
        if (!prepared_initial_state) continue;
        const binding = plan.binding(try logicalIdOf(entry)) catch return error.MissingBinding;
        if (binding.size_bytes == 0) return error.InvalidPreparedStateRange;
        try physical.append(allocator, .{ .offset = binding.offset_bytes, .bytes = binding.size_bytes });
    }
    if (physical.items.len == 0) return error.EmptyPreparedState;
    std.mem.sortUnstable(PhysicalRange, physical.items, {}, struct {
        fn lessThan(_: void, lhs: PhysicalRange, rhs: PhysicalRange) bool {
            if (lhs.offset != rhs.offset) return lhs.offset < rhs.offset;
            return lhs.bytes < rhs.bytes;
        }
    }.lessThan);
    var merged = std.ArrayList(PhysicalRange).empty;
    defer merged.deinit(allocator);
    for (physical.items) |current| {
        if (merged.items.len == 0) {
            try merged.append(allocator, current);
            continue;
        }
        const previous = &merged.items[merged.items.len - 1];
        const previous_end = std.math.add(u64, previous.offset, previous.bytes) catch
            return error.SizeOverflow;
        const current_end = std.math.add(u64, current.offset, current.bytes) catch
            return error.SizeOverflow;
        if (current.offset <= previous_end) {
            previous.bytes = @max(previous_end, current_end) - previous.offset;
        } else {
            try merged.append(allocator, current);
        }
    }
    const ranges = try allocator.alloc(metal_runtime.PreparedStateRange, merged.items.len);
    errdefer allocator.free(ranges);
    var snapshot_offset: u64 = 0;
    for (merged.items, ranges) |physical_range, *range| {
        range.* = .{
            .arena_byte_offset = physical_range.offset,
            .snapshot_byte_offset = snapshot_offset,
            .byte_count = physical_range.bytes,
        };
        snapshot_offset = std.math.add(u64, snapshot_offset, physical_range.bytes) catch
            return error.SizeOverflow;
    }
    return ranges;
}

test "prepared state admission is transactional and fail closed" {
    const first = PreparedStateIdentity{
        .key = [_]u8{1} ** 32,
        .logical_plan_hash = 5,
        .plan_hash = 7,
        .arena_bytes = 4096,
    };
    var second = first;
    second.key[0] = 2;
    var admission = PreparedStateAdmission{};
    try std.testing.expectEqual(PreparedStateAdmission.Decision.miss, try admission.begin(first, true));
    try std.testing.expectError(error.PreparedStateAlreadyBorrowed, admission.begin(first, true));
    try admission.commit();
    try std.testing.expectEqual(PreparedStateAdmission.Decision.hit, try admission.begin(first, true));
    try admission.commit();
    try std.testing.expectEqual(PreparedStateAdmission.Decision.miss, try admission.begin(second, true));
    admission.poison();
    try std.testing.expectEqual(PreparedStateAdmission.Status.poisoned, admission.status);
    try std.testing.expectEqual(PreparedStateAdmission.Decision.miss, try admission.begin(first, true));
}

fn testOwnedArenaPlan(allocator: std.mem.Allocator, size_bytes: u64) !arena.Plan {
    const live_ranges = [_]arena.LiveRange{.{ .first = 0, .last = 1 }};
    const logical = [_]arena.LogicalBuffer{.{
        .id = 0,
        .size_bytes = size_bytes,
        .alignment = 16,
        .live_ranges = &live_ranges,
    }};
    return arena.build(allocator, &logical, 1 << 20);
}

test "prepared snapshot includes base inverse twiddle storage" {
    const encoded =
        \\[
        \\  {"id":0,"purpose":"ForwardTwiddles"},
        \\  {"id":1,"purpose":"PreprocessedCoefficients"},
        \\  {"id":2,"purpose":"BaseTrace"}
        \\]
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, encoded, .{});
    defer parsed.deinit();
    const live_ranges = [_]arena.LiveRange{.{ .first = 0, .last = 1 }};
    const logical = [_]arena.LogicalBuffer{
        .{ .id = 0, .size_bytes = 64, .alignment = 16, .live_ranges = &live_ranges },
        .{ .id = 1, .size_bytes = 128, .alignment = 16, .live_ranges = &live_ranges },
        .{ .id = 2, .size_bytes = 256, .alignment = 16, .live_ranges = &live_ranges },
    };
    var plan = try arena.build(std.testing.allocator, &logical, 1 << 20);
    defer plan.deinit();
    const ranges = try buildPreparedStateRanges(
        std.testing.allocator,
        parsed.value.array.items,
        plan,
    );
    defer std.testing.allocator.free(ranges);

    const forward = try plan.binding(0);
    const forward_end = forward.offset_bytes + forward.size_bytes;
    var forward_captured = false;
    var captured_bytes: u64 = 0;
    for (ranges) |range| {
        captured_bytes += range.byte_count;
        const range_end = range.arena_byte_offset + range.byte_count;
        forward_captured = forward_captured or
            (range.arena_byte_offset <= forward.offset_bytes and range_end >= forward_end);
    }
    try std.testing.expect(forward_captured);
    try std.testing.expectEqual(@as(u64, 64 + 128), captured_bytes);
}

test "prepared geometry logical hash binds layout policy" {
    const ranges = [_]arena.LiveRange{.{ .first = 1, .last = 2 }};
    const changed_ranges = [_]arena.LiveRange{.{ .first = 1, .last = 3 }};
    const baseline = [_]arena.LogicalBuffer{.{
        .id = 7,
        .size_bytes = 4096,
        .alignment = 256,
        .placement_priority = 1,
        .live_ranges = &ranges,
        .spill_cost_ns = 10,
    }};
    var changed = baseline;
    try std.testing.expectEqual(logicalPlanHash(&baseline), logicalPlanHash(&changed));
    changed[0].live_ranges = &changed_ranges;
    try std.testing.expect(logicalPlanHash(&baseline) != logicalPlanHash(&changed));
    changed = baseline;
    changed[0].placement_priority = 2;
    try std.testing.expect(logicalPlanHash(&baseline) != logicalPlanHash(&changed));
    changed = baseline;
    changed[0].spill_cost_ns = null;
    changed[0].recompute_cost_ns = 10;
    try std.testing.expect(logicalPlanHash(&baseline) != logicalPlanHash(&changed));
}

test "prepared host geometry owns parsed schedule independently of source file" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    const encoded =
        \\{"arena":{"logical_buffer_schedule":[{"id":7}]},"compacted_consumer_rows":[]}
    ;
    try directory.dir.writeFile(.{ .sub_path = "schedule.json", .data = encoded });
    const root = try directory.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "schedule.json" });
    defer std.testing.allocator.free(path);
    const args = [_][]const u8{ "metal-arena-plan", path, "1" };

    const geometry = try PreparedHostGeometry.init(std.testing.allocator, &args);
    defer geometry.deinit();
    try directory.dir.deleteFile("schedule.json");

    try std.testing.expectEqual(@as(usize, 1), geometry.schedule().len);
    try std.testing.expectEqual(@as(i64, 7), geometry.schedule()[0].object.get("id").?.integer);
    try std.testing.expectEqual(@as(usize, 0), geometry.compactedConsumerRows().len);
    var expected_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &expected_digest, .{});
    try std.testing.expectEqualSlices(
        u8,
        &std.fmt.bytesToHex(expected_digest, .lower),
        &geometry.schedule_sha256,
    );
}

fn testGeometryIdentity(
    key: PreparedStateKey,
    logical_plan_hash: u64,
    plan: arena.Plan,
) PreparedStateIdentity {
    return .{
        .key = key,
        .logical_plan_hash = logical_plan_hash,
        .plan_hash = plan.plan_hash,
        .arena_bytes = plan.total_bytes,
    };
}

fn testCommitGeometry(
    cache: *PreparedGeometryCache,
    key: PreparedStateKey,
    logical_plan_hash: u64,
    size_bytes: u64,
) !void {
    var owner: ?arena.Plan = try testOwnedArenaPlan(std.testing.allocator, size_bytes);
    var transferred = false;
    errdefer {
        if (!transferred) if (owner) |*plan| plan.deinit();
        cache.poisonActive();
    }
    try cache.stageMiss(testGeometryIdentity(key, logical_plan_hash, owner.?), .{
        .owner = &owner,
        .transferred = &transferred,
    });
    try std.testing.expect(owner != null);
    try std.testing.expect(transferred);
    try cache.validateCommit();
    cache.commitAssumeValid();
}

fn testGeometryContains(
    cache: *const PreparedGeometryCache,
    key: PreparedStateKey,
    logical_plan_hash: u64,
) bool {
    for (cache.entries) |entry| {
        const value = entry orelse continue;
        if (std.mem.eql(u8, &value.identity.key, &key) and
            value.identity.logical_plan_hash == logical_plan_hash)
        {
            return true;
        }
    }
    return false;
}

fn testGeometryCount(cache: *const PreparedGeometryCache) usize {
    var count: usize = 0;
    for (cache.entries) |entry| count += @intFromBool(entry != null);
    return count;
}

test "prepared geometry A B A retains both committed plans" {
    var cache = PreparedStateCache.init(std.testing.allocator);
    defer cache.deinit();
    const first_key = [_]u8{0x11} ** 32;
    const second_key = [_]u8{0x22} ** 32;
    const first_logical_hash: u64 = 0x1111;
    const second_logical_hash: u64 = 0x2222;

    var first_owner: ?arena.Plan = try testOwnedArenaPlan(std.testing.allocator, 64);
    var first_transferred = false;
    try std.testing.expectEqual(
        PreparedStateAdmission.Decision.miss,
        try cache.transition(first_key, first_logical_hash, first_owner.?, true, null, .{
            .owner = &first_owner,
            .transferred = &first_transferred,
        }),
    );
    try std.testing.expect(first_owner != null);
    try std.testing.expect(first_transferred);
    try cache.commit();

    try std.testing.expect((try cache.findCanonicalPlan(second_key, second_logical_hash)) == null);
    var second_owner: ?arena.Plan = try testOwnedArenaPlan(std.testing.allocator, 128);
    var second_transferred = false;
    try std.testing.expectEqual(
        PreparedStateAdmission.Decision.miss,
        try cache.transition(second_key, second_logical_hash, second_owner.?, true, null, .{
            .owner = &second_owner,
            .transferred = &second_transferred,
        }),
    );
    try std.testing.expect(second_owner != null);
    try std.testing.expect(second_transferred);
    try cache.commit();

    const first_cached = (try cache.findCanonicalPlan(first_key, first_logical_hash)).?;
    try std.testing.expectEqual(@as(u64, 64), first_cached.plan.bindings[0].size_bytes);
    try std.testing.expectEqual(
        PreparedStateAdmission.Decision.miss,
        try cache.transition(first_key, first_logical_hash, first_cached.plan.*, true, first_cached, null),
    );
    try cache.commit();

    try std.testing.expectEqual(@as(usize, 2), testGeometryCount(&cache.geometry));
    try std.testing.expect(testGeometryContains(&cache.geometry, first_key, first_logical_hash));
    try std.testing.expect(testGeometryContains(&cache.geometry, second_key, second_logical_hash));
    try std.testing.expect(cache.admission.identity.?.eql(testGeometryIdentity(
        first_key,
        first_logical_hash,
        first_cached.plan.*,
    )));
}

test "prepared geometry capacity four evicts least recently used plan" {
    var geometry = PreparedGeometryCache.init(std.testing.allocator);
    defer geometry.deinit();
    const hashes = [_]u64{ 0x10, 0x20, 0x30, 0x40, 0x50 };
    var keys: [hashes.len]PreparedStateKey = undefined;
    for (&keys, 1..) |*key, byte| key.* = [_]u8{@intCast(byte)} ** 32;
    for (0..prepared_geometry_capacity) |index| {
        try testCommitGeometry(&geometry, keys[index], hashes[index], 64 + index * 16);
    }
    try std.testing.expectEqual(@as(usize, prepared_geometry_capacity), testGeometryCount(&geometry));

    const first = (try geometry.findCommitted(keys[0], hashes[0])).?;
    try std.testing.expectEqual(@as(u64, 64), first.plan.bindings[0].size_bytes);
    try geometry.validateCommit();
    geometry.commitAssumeValid();
    try testCommitGeometry(&geometry, keys[4], hashes[4], 128);

    try std.testing.expect(testGeometryContains(&geometry, keys[0], hashes[0]));
    try std.testing.expect(!testGeometryContains(&geometry, keys[1], hashes[1]));
    try std.testing.expect(testGeometryContains(&geometry, keys[2], hashes[2]));
    try std.testing.expect(testGeometryContains(&geometry, keys[3], hashes[3]));
    try std.testing.expect(testGeometryContains(&geometry, keys[4], hashes[4]));
}

test "prepared geometry pending is invisible and poison destroys it" {
    var geometry = PreparedGeometryCache.init(std.testing.allocator);
    defer geometry.deinit();
    const key = [_]u8{0x61} ** 32;
    const logical_hash: u64 = 0x6161;
    var owner: ?arena.Plan = try testOwnedArenaPlan(std.testing.allocator, 64);
    var transferred = false;
    try geometry.stageMiss(testGeometryIdentity(key, logical_hash, owner.?), .{
        .owner = &owner,
        .transferred = &transferred,
    });
    try std.testing.expect(owner != null);
    try std.testing.expect(transferred);
    try std.testing.expectEqual(@as(u64, 64), (try owner.?.binding(0)).size_bytes);
    try std.testing.expectEqual(@as(usize, 0), testGeometryCount(&geometry));
    try std.testing.expectError(
        error.PreparedGeometryAlreadyBorrowed,
        geometry.findCommitted(key, logical_hash),
    );
    geometry.poisonActive();
    try std.testing.expectEqual(@as(usize, 0), testGeometryCount(&geometry));
    try std.testing.expect((try geometry.findCommitted(key, logical_hash)) == null);
}

test "prepared geometry poison evicts only the active key" {
    var geometry = PreparedGeometryCache.init(std.testing.allocator);
    defer geometry.deinit();
    const first_key = [_]u8{0x71} ** 32;
    const second_key = [_]u8{0x72} ** 32;
    try testCommitGeometry(&geometry, first_key, 0x7171, 64);
    try testCommitGeometry(&geometry, second_key, 0x7272, 128);

    _ = (try geometry.findCommitted(first_key, 0x7171)).?;
    geometry.poisonActive();
    try std.testing.expect(!testGeometryContains(&geometry, first_key, 0x7171));
    try std.testing.expect(testGeometryContains(&geometry, second_key, 0x7272));
    try std.testing.expectEqual(@as(usize, 1), testGeometryCount(&geometry));
}

test "prepared geometry requires exact key and logical hash" {
    var geometry = PreparedGeometryCache.init(std.testing.allocator);
    defer geometry.deinit();
    const key = [_]u8{0x81} ** 32;
    var wrong_key = key;
    wrong_key[0] = 0x82;
    const logical_hash: u64 = 0x8181;
    try testCommitGeometry(&geometry, key, logical_hash, 64);

    try std.testing.expect((try geometry.findCommitted(wrong_key, logical_hash)) == null);
    try std.testing.expect((try geometry.findCommitted(key, logical_hash + 1)) == null);
    const exact = (try geometry.findCommitted(key, logical_hash)).?;
    try std.testing.expectEqual(@as(u64, 64), exact.plan.bindings[0].size_bytes);
    try geometry.validateCommit();
    geometry.commitAssumeValid();
}

test "prepared geometry never reuses a noncanonical request" {
    var mode = CanonicalFullProofPlanMode{
        .execute_proof = true,
        .no_projection = true,
        .prepare_metal = true,
        .execute_preprocessed = true,
        .execute_witness = true,
        .execute_base_interpolation = true,
        .execute_commitments = true,
        .execute_relations = true,
        .execute_oods = true,
        .verify_proof = true,
    };
    try std.testing.expect(mode.eligible());
    mode.no_projection = false;
    try std.testing.expect(!mode.eligible());

    var cache = PreparedStateCache.init(std.testing.allocator);
    defer cache.deinit();
    const key = [_]u8{0x33} ** 32;
    const logical_hash: u64 = 0x3333;
    var canonical_owner: ?arena.Plan = try testOwnedArenaPlan(std.testing.allocator, 64);
    var canonical_transferred = false;
    _ = try cache.transition(key, logical_hash, canonical_owner.?, true, null, .{
        .owner = &canonical_owner,
        .transferred = &canonical_transferred,
    });
    try std.testing.expect(canonical_owner != null);
    try std.testing.expect(canonical_transferred);
    try cache.commit();
    try std.testing.expect(testGeometryContains(&cache.geometry, key, logical_hash));

    var noncanonical_owner: ?arena.Plan = try testOwnedArenaPlan(std.testing.allocator, 64);
    defer if (noncanonical_owner) |*owned| owned.deinit();
    try std.testing.expectEqual(
        PreparedStateAdmission.Decision.miss,
        try cache.transition(key, logical_hash, noncanonical_owner.?, false, null, null),
    );
    try std.testing.expect(noncanonical_owner != null);
    try cache.commit();
    try std.testing.expect(testGeometryContains(&cache.geometry, key, logical_hash));
}

test "prepared base AOT witness install fails closed without resident ownership" {
    var cache = PreparedStateCache.init(std.testing.allocator);
    defer cache.deinit();
    cache.admission.status = .pending;
    var owner: ?protocol_recipes.AotWitnessBatchRecipe = null;

    try std.testing.expectError(
        error.PreparedStateMissingArena,
        cache.installBaseAotWitness(&owner),
    );
    try std.testing.expectEqual(PreparedStateAdmission.Status.poisoned, cache.admission.status);
    try std.testing.expect(cache.base_aot_witness == null);
}

test "prepared base AOT witness hit fails closed without cached ownership" {
    var cache = PreparedStateCache.init(std.testing.allocator);
    defer cache.deinit();
    cache.admission.status = .borrowed;

    try std.testing.expectError(
        error.PreparedStateMissingBaseAotWitness,
        cache.borrowBaseAotWitness(),
    );
    try std.testing.expectEqual(PreparedStateAdmission.Status.poisoned, cache.admission.status);
    try std.testing.expect(cache.base_aot_witness == null);
}

test "prepared interaction AOT witness fails closed without resident or cached ownership" {
    var install_cache = PreparedStateCache.init(std.testing.allocator);
    defer install_cache.deinit();
    install_cache.admission.status = .pending;
    var owner: ?protocol_recipes.AotWitnessBatchRecipe = null;
    try std.testing.expectError(
        error.PreparedStateMissingArena,
        install_cache.installInteractionAotWitness(&owner),
    );
    try std.testing.expectEqual(PreparedStateAdmission.Status.poisoned, install_cache.admission.status);
    try std.testing.expect(install_cache.interaction_aot_witness == null);

    var borrow_cache = PreparedStateCache.init(std.testing.allocator);
    defer borrow_cache.deinit();
    borrow_cache.admission.status = .borrowed;
    try std.testing.expectError(
        error.PreparedStateMissingInteractionAotWitness,
        borrow_cache.borrowInteractionAotWitness(),
    );
    try std.testing.expectEqual(PreparedStateAdmission.Status.poisoned, borrow_cache.admission.status);
    try std.testing.expect(borrow_cache.interaction_aot_witness == null);
}

test "prepared fixed table recipe fails closed without resident or cached ownership" {
    var install_cache = PreparedStateCache.init(std.testing.allocator);
    defer install_cache.deinit();
    install_cache.admission.status = .pending;
    var owner: ?protocol_recipes.FixedTableBatchRecipe = null;
    try std.testing.expectError(error.PreparedStateMissingArena, install_cache.installFixedTables(&owner));
    try std.testing.expectEqual(PreparedStateAdmission.Status.poisoned, install_cache.admission.status);
    try std.testing.expect(install_cache.fixed_tables == null);

    var borrow_cache = PreparedStateCache.init(std.testing.allocator);
    defer borrow_cache.deinit();
    borrow_cache.admission.status = .borrowed;
    try std.testing.expectError(error.PreparedStateMissingFixedTables, borrow_cache.borrowFixedTables());
    try std.testing.expectEqual(PreparedStateAdmission.Status.poisoned, borrow_cache.admission.status);
    try std.testing.expect(borrow_cache.fixed_tables == null);
}

test "prepared multiplicity feed recipe fails closed without resident or cached ownership" {
    var install_cache = PreparedStateCache.init(std.testing.allocator);
    defer install_cache.deinit();
    install_cache.admission.status = .pending;
    var owner: ?arena_binding_mod.MultiplicityFeedBatch = null;
    try std.testing.expectError(error.PreparedStateMissingArena, install_cache.installMultiplicityFeeds(&owner));
    try std.testing.expectEqual(PreparedStateAdmission.Status.poisoned, install_cache.admission.status);
    try std.testing.expect(install_cache.multiplicity_feeds == null);

    var borrow_cache = PreparedStateCache.init(std.testing.allocator);
    defer borrow_cache.deinit();
    borrow_cache.admission.status = .borrowed;
    try std.testing.expectError(error.PreparedStateMissingMultiplicityFeeds, borrow_cache.borrowMultiplicityFeeds());
    try std.testing.expectEqual(PreparedStateAdmission.Status.poisoned, borrow_cache.admission.status);
    try std.testing.expect(borrow_cache.multiplicity_feeds == null);
}

test "prepared base interpolation batches transfer ownership and reset on hit" {
    const Helpers = struct {
        fn circle(last_tick: u16, accumulated_gpu_ms: f64) protocol_recipes.CircleIfftRecipe {
            return .{
                .allocator = std.testing.allocator,
                .metal = undefined,
                .arena = undefined,
                .sources = &.{},
                .destinations = &.{},
                .prepared = undefined,
                .log_size = 19,
                .inverse_twiddle_offset_words = 0,
                .scale_factor = 1,
                .last_tick = last_tick,
                .accumulated_gpu_ms = accumulated_gpu_ms,
            };
        }
    };

    var cache = PreparedStateCache.init(std.testing.allocator);
    cache.resident_arena = .{ .buffer = undefined };
    defer {
        cache.recorded_base_interpolation = null;
        cache.native_base_interpolation = null;
        cache.resident_arena = null;
        cache.deinit();
    }
    const resident = &cache.resident_arena.?;
    var recorded_recipes = [_]protocol_recipes.CircleIfftRecipe{Helpers.circle(11, 1.25)};
    var recorded_owner: ?arena_binding_mod.RecordedBaseInterpolationBatch = .{
        .allocator = std.testing.allocator,
        .resident_arena = resident,
        .recipes = &recorded_recipes,
        .ec_op_recipe = null,
        .ec_op_owner = null,
    };
    var native_owner: ?arena_binding_mod.NativeBaseInterpolationBatch = .{
        .allocator = std.testing.allocator,
        .metal = undefined,
        .resident_arena = resident,
        .memory_address = Helpers.circle(12, 2.5),
        .memory_values = &.{},
        .fixed = &.{},
    };

    cache.admission.status = .pending;
    const installed_recorded = try cache.installRecordedBaseInterpolation(&recorded_owner);
    const installed_native = try cache.installNativeBaseInterpolation(&native_owner);
    try std.testing.expect(recorded_owner == null);
    try std.testing.expect(native_owner == null);
    try std.testing.expectEqual(@as(?u16, 11), installed_recorded.recipes[0].last_tick);
    try std.testing.expectEqual(@as(?u16, 12), installed_native.memory_address.last_tick);

    cache.admission.status = .borrowed;
    try std.testing.expectEqual(installed_recorded, try cache.borrowRecordedBaseInterpolation());
    try std.testing.expectEqual(installed_native, try cache.borrowNativeBaseInterpolation());
    try std.testing.expectEqual(@as(?u16, null), installed_recorded.recipes[0].last_tick);
    try std.testing.expectEqual(@as(f64, 0), installed_recorded.recipes[0].accumulated_gpu_ms);
    try std.testing.expectEqual(@as(?u16, null), installed_native.memory_address.last_tick);
    try std.testing.expectEqual(@as(f64, 0), installed_native.memory_address.accumulated_gpu_ms);
}

test "prepared compact recipes transfer ownership and reset descriptors on hit" {
    const Helpers = struct {
        fn binding(logical_id: u32, offset_bytes: u64) arena.Binding {
            return .{
                .logical_id = logical_id,
                .slot = logical_id,
                .offset_bytes = offset_bytes,
                .size_bytes = 5 * @sizeOf(u32),
                .materialization = .resident,
                .occupied = [_]u64{0} ** (arena.max_ticks / 64),
            };
        }

        fn recipe(
            allocator: std.mem.Allocator,
            resident: *arena.ResidentArena,
            destination: arena.Binding,
            seed: u32,
        ) !protocol_recipes.CompactRecipe {
            const words = try allocator.alloc(u32, 5);
            errdefer allocator.free(words);
            for (words, 0..) |*word, index| word.* = seed + @as(u32, @intCast(index));
            const destinations = try allocator.alloc(arena.Binding, 1);
            errdefer allocator.free(destinations);
            destinations[0] = destination;
            return .{
                .allocator = allocator,
                .metal = undefined,
                .arena = resident,
                .destinations = destinations,
                .descriptor_image = .{
                    .allocator = allocator,
                    .destination = destination,
                    .words = words,
                },
                .prepared = .{ .handle = resident.buffer.contents },
                .last_tick = 19,
                .accumulated_gpu_ms = 23.5,
            };
        }

        fn destroy(recipe_value: *protocol_recipes.CompactRecipe) void {
            recipe_value.allocator.free(recipe_value.destinations);
            recipe_value.descriptor_image.allocator.free(recipe_value.descriptor_image.words);
            recipe_value.* = undefined;
        }

        fn destroyOptional(optional: *?protocol_recipes.CompactRecipe) void {
            if (optional.*) |*recipe_value| destroy(recipe_value);
            optional.* = null;
        }
    };

    var storage = [_]u8{0xa5} ** 96;
    var cache = PreparedStateCache.init(std.testing.allocator);
    cache.resident_arena = .{ .buffer = .{
        .handle = @ptrCast(&storage),
        .contents = @ptrCast(&storage),
        .byte_length = storage.len,
    } };
    const resident = &cache.resident_arena.?;
    var verify_owner: ?protocol_recipes.CompactRecipe = try Helpers.recipe(
        std.testing.allocator,
        resident,
        Helpers.binding(1, 0),
        100,
    );
    var pedersen_owner: ?protocol_recipes.CompactRecipe = try Helpers.recipe(
        std.testing.allocator,
        resident,
        Helpers.binding(2, 32),
        200,
    );
    var poseidon_owner: ?protocol_recipes.CompactRecipe = try Helpers.recipe(
        std.testing.allocator,
        resident,
        Helpers.binding(3, 64),
        300,
    );
    defer {
        Helpers.destroyOptional(&verify_owner);
        Helpers.destroyOptional(&pedersen_owner);
        Helpers.destroyOptional(&poseidon_owner);
        Helpers.destroyOptional(&cache.compact_verify);
        Helpers.destroyOptional(&cache.compact_pedersen);
        Helpers.destroyOptional(&cache.compact_poseidon);
        cache.resident_arena = null;
        cache.deinit();
    }

    cache.admission.status = .pending;
    const installed_verify = try cache.installCompact(.verify_instruction, &verify_owner);
    const installed_pedersen = try cache.installCompact(.pedersen, &pedersen_owner);
    const installed_poseidon = try cache.installCompact(.poseidon, &poseidon_owner);
    try std.testing.expect(verify_owner == null);
    try std.testing.expect(pedersen_owner == null);
    try std.testing.expect(poseidon_owner == null);

    @memset(&storage, 0);
    cache.admission.status = .borrowed;
    try std.testing.expectEqual(installed_verify, try cache.borrowCompact(.verify_instruction));
    try std.testing.expectEqual(installed_pedersen, try cache.borrowCompact(.pedersen));
    try std.testing.expectEqual(installed_poseidon, try cache.borrowCompact(.poseidon));

    inline for (.{
        .{ installed_verify, @as(usize, 0), @as(u32, 100) },
        .{ installed_pedersen, @as(usize, 32), @as(u32, 200) },
        .{ installed_poseidon, @as(usize, 64), @as(u32, 300) },
    }) |expected| {
        try std.testing.expectEqual(@as(?u16, null), expected[0].last_tick);
        try std.testing.expectEqual(@as(f64, 0), expected[0].accumulated_gpu_ms);
        try std.testing.expectEqualSlices(
            u8,
            std.mem.sliceAsBytes(expected[0].descriptor_image.words),
            storage[expected[1]..][0 .. 5 * @sizeOf(u32)],
        );
        try std.testing.expectEqual(expected[2], expected[0].descriptor_image.words[0]);
    }
}

test "runner phase timing schema accounts for runner minus prove wall" {
    const timing = RunnerPhaseTiming{
        .schedule_read_and_hash_wall_s = 0.1,
        .schedule_json_parse_wall_s = 0.1,
        .bundle_read_and_validate_wall_s = 0.1,
        .statement_and_proof_plan_wall_s = 0.1,
        .schedule_liveness_analysis_wall_s = 0.1,
        .arena_plan_and_bindings_wall_s = 0.1,
        .resident_acquire_reset_restore_wall_s = 0.1,
        .input_materialization_wall_s = 0.1,
        .immutable_host_restore_wall_s = 0.1,
        .recipe_preparation_wall_s = 0.1,
    };
    const report = timing.report(4.0, 2.0, 3.0, 1.5);
    try std.testing.expectApproxEqAbs(@as(f64, 1.0), report.pre_prove_instrumented_wall_s, 1e-12);
    try std.testing.expectApproxEqAbs(@as(f64, 1.0), report.pre_prove_unattributed_wall_s.?, 1e-12);
    try std.testing.expectApproxEqAbs(@as(f64, 1.0), report.post_prove_pre_report_wall_s.?, 1e-12);
    try std.testing.expectApproxEqAbs(@as(f64, 2.5), report.runner_minus_prove_before_report_wall_s.?, 1e-12);

    var encoded: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&encoded);
    try std.json.Stringify.value(report, .{}, &writer);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, writer.buffered(), .{});
    defer parsed.deinit();
    const object = parsed.value.object;
    try std.testing.expectEqual(@as(usize, 18), object.count());
    try std.testing.expectEqual(@as(i64, 1), object.get("schema_version").?.integer);
    try std.testing.expectEqualStrings(
        "run_one_entry_to_report_serialization_start",
        object.get("scope").?.string,
    );
    inline for (.{
        "schedule_read_and_hash_wall_s",
        "schedule_json_parse_wall_s",
        "bundle_read_and_validate_wall_s",
        "statement_and_proof_plan_wall_s",
        "schedule_liveness_analysis_wall_s",
        "arena_plan_and_bindings_wall_s",
        "resident_acquire_reset_restore_wall_s",
        "input_materialization_wall_s",
        "immutable_host_restore_wall_s",
        "recipe_preparation_wall_s",
        "pre_prove_observed_wall_s",
        "pre_prove_instrumented_wall_s",
        "pre_prove_unattributed_wall_s",
        "post_prove_pre_report_wall_s",
        "runner_minus_prove_before_report_wall_s",
        "runner_before_report_wall_s",
    }) |name| try std.testing.expect(object.get(name) != null);
}

test "recipe preparation timing schema separates pre-prove and recorded-prove work" {
    const timing = RecipePreparationTiming{
        .fixed_tables_wall_s = 0.01,
        .multiplicity_feeds_wall_s = 0.02,
        .base_aot_witness_acquire_wall_s = 0.03,
        .compact_verify_wall_s = 0.04,
        .compact_pedersen_wall_s = 0.05,
        .compact_poseidon_wall_s = 0.06,
        .ec_op_base_wall_s = 0.07,
        .recorded_base_interpolation_wall_s = 0.08,
        .native_base_interpolation_wall_s = 0.09,
        .transcript_wall_s = 0.10,
        .interaction_aot_witness_wall_s = 0.11,
        .ec_op_interaction_wall_s = 0.12,
        .relation_components_wall_s = 0.13,
        .interaction_native_interpolation_wall_s = 0.14,
        .composition_wall_s = 0.15,
        .quotient_wall_s = 0.16,
        .fri_wall_s = 0.17,
        .decommit_queries_wall_s = 0.18,
        .proof_assembly_wall_s = 0.19,
    };
    const report = timing.report(2.0);
    try std.testing.expectApproxEqAbs(@as(f64, 0.45), report.pre_prove.total_wall_s, 1e-12);
    try std.testing.expectApproxEqAbs(@as(f64, 1.45), report.recorded_prove.total_wall_s, 1e-12);
    try std.testing.expectApproxEqAbs(@as(f64, 1.90), report.total_wall_s, 1e-12);
    try std.testing.expectApproxEqAbs(
        @as(f64, 0.55),
        report.recorded_prove_non_recipe_wall_s.?,
        1e-12,
    );
    try std.testing.expect(timing.report(null).recorded_prove_non_recipe_wall_s == null);

    var encoded: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&encoded);
    try std.json.Stringify.value(report, .{}, &writer);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, writer.buffered(), .{});
    defer parsed.deinit();
    const object = parsed.value.object;
    try std.testing.expectEqual(@as(usize, 6), object.count());
    try std.testing.expectEqual(@as(i64, 1), object.get("schema_version").?.integer);
    try std.testing.expectEqualStrings(
        "run_one_recipe_acquisition_wall_time",
        object.get("scope").?.string,
    );
    try std.testing.expectEqual(@as(usize, 10), object.get("pre_prove").?.object.count());
    try std.testing.expectEqual(@as(usize, 11), object.get("recorded_prove").?.object.count());
    inline for (.{
        "pre_prove",
        "recorded_prove",
        "total_wall_s",
        "recorded_prove_non_recipe_wall_s",
    }) |name| try std.testing.expect(object.get(name) != null);
}

pub fn main() !void {
    var debug_allocator = std.heap.DebugAllocator(.{}).init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    var output_buffer: [4096]u8 = undefined;
    var output = std.fs.File.stdout().writer(&output_buffer);
    try runOne(allocator, args, null, null, null, &output.interface);
    try output.interface.flush();
}

/// Executes one invocation while borrowing a process-owned Metal runtime.
/// Request isolation and the report destination remain caller-owned.
pub fn proveOne(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    runtime: *metal_runtime.Runtime,
    report_writer: *std.Io.Writer,
) !void {
    try runOne(allocator, args, runtime, null, null, report_writer);
}

pub fn proveOnePrepared(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    runtime: *metal_runtime.Runtime,
    prepared_state: *PreparedStateCache,
    prepared_state_key: PreparedStateKey,
    report_writer: *std.Io.Writer,
) !void {
    try runOne(
        allocator,
        args,
        runtime,
        .{ .cache = prepared_state, .key = prepared_state_key },
        null,
        report_writer,
    );
}

pub fn proveOnePreparedGeometry(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    runtime: *metal_runtime.Runtime,
    prepared_state: *PreparedStateCache,
    prepared_state_key: PreparedStateKey,
    prepared_geometry: *const PreparedHostGeometry,
    report_writer: *std.Io.Writer,
) !void {
    try runOne(
        allocator,
        args,
        runtime,
        .{ .cache = prepared_state, .key = prepared_state_key },
        prepared_geometry,
        report_writer,
    );
}

const PreparedStateRequest = struct { cache: *PreparedStateCache, key: PreparedStateKey };

fn runOne(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    external_runtime: ?*metal_runtime.Runtime,
    prepared_state_request: ?PreparedStateRequest,
    prepared_host_geometry: ?*const PreparedHostGeometry,
    report_writer: *std.Io.Writer,
) !void {
    var runner_wall_timer = try std.time.Timer.start();
    var runner_phase_timing = RunnerPhaseTiming{};
    var recipe_preparation_timing = RecipePreparationTiming{};
    var prove_started_wall_s: ?f64 = null;
    var proof_verified_wall_s: ?f64 = null;
    if (args.len < 3 or args.len > 8) {
        std.debug.print("usage: metal-arena-plan <arena_preflight.json> <budget-gib> [witness-programs.bin] [multiplicity-feeds.bin] [relation-templates.bin] [fixed-tables.bin] [composition.bin]\n", .{});
        return error.InvalidArguments;
    }
    const budget_gib = try std.fmt.parseFloat(f64, args[2]);
    const budget_bytes: u64 = @intFromFloat(budget_gib * 1024.0 * 1024.0 * 1024.0);
    var owned_host_geometry: ?*PreparedHostGeometry = null;
    defer if (owned_host_geometry) |geometry| geometry.deinit();
    const host_geometry = prepared_host_geometry orelse blk: {
        owned_host_geometry = try PreparedHostGeometry.init(allocator, args);
        runner_phase_timing.schedule_read_and_hash_wall_s =
            owned_host_geometry.?.preparation_timing.schedule_read_and_hash_wall_s;
        runner_phase_timing.schedule_json_parse_wall_s =
            owned_host_geometry.?.preparation_timing.schedule_json_parse_wall_s;
        runner_phase_timing.bundle_read_and_validate_wall_s =
            owned_host_geometry.?.preparation_timing.bundle_read_wall_s;
        break :blk owned_host_geometry.?;
    };
    const input_sha256 = host_geometry.schedule_sha256;
    const schedule = host_geometry.schedule();
    const compacted_consumer_rows = host_geometry.compactedConsumerRows();
    const schedule_coverage_started_ns = runner_wall_timer.read();
    const retained_sources = try buildRetainedSources(allocator, schedule);
    defer allocator.free(retained_sources);
    const preprocessed_coverage = try buildPreprocessedSources(allocator, schedule);
    defer allocator.free(preprocessed_coverage.sources);
    const merkle_parent_coverage = try buildMerkleParentSources(allocator, schedule);
    defer allocator.free(merkle_parent_coverage.sources);
    const merkle_commit_coverage = try buildMerkleCommitCoverage(allocator, schedule);
    defer allocator.free(merkle_commit_coverage.bottoms);
    const ec_op_coverage = try validateEcOpCoverage(schedule);
    RunnerPhaseTiming.addInterval(
        &runner_phase_timing.schedule_liveness_analysis_wall_s,
        &runner_wall_timer,
        schedule_coverage_started_ns,
    );
    const bundle_read_started_ns = runner_wall_timer.read();
    const witness_bundle = host_geometry.witness_bundle;
    const witness_recipe_requirements = if (witness_bundle) |bundle|
        arena_binding_mod.WitnessRecipeRequirements.fromBundle(bundle)
    else
        arena_binding_mod.WitnessRecipeRequirements{};
    const feed_bundle = host_geometry.feed_bundle;
    const relation_bundle = host_geometry.relation_bundle;
    const relation_coverage: ?RelationCoverage = if (relation_bundle) |bundle|
        try validateRelationCoverage(allocator, schedule, bundle)
    else
        null;
    const fixed_table_bundle = host_geometry.fixed_table_bundle;
    var fixed_table_destinations = std.StringHashMap(void).init(allocator);
    defer fixed_table_destinations.deinit();
    const fixed_table_coverage: ?FixedTableCoverage = if (fixed_table_bundle) |bundle|
        try validateFixedTableCoverage(schedule, bundle, &fixed_table_destinations)
    else
        null;
    const composition_bundle = host_geometry.composition_bundle;
    RunnerPhaseTiming.addInterval(
        &runner_phase_timing.bundle_read_and_validate_wall_s,
        &runner_wall_timer,
        bundle_read_started_ns,
    );
    const adapted_input_started_ns = runner_wall_timer.read();
    var prover_input: ?cairo_adapter.ProverInput = if (std.process.getEnvVarOwned(allocator, "STWO_ZIG_SN2_POPULATE_INPUT")) |input_path| blk: {
        defer allocator.free(input_path);
        break :blk try adapted_input.readFile(allocator, input_path);
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (prover_input) |*adapted| adapted.deinit(allocator);
    RunnerPhaseTiming.addInterval(
        &runner_phase_timing.input_materialization_wall_s,
        &runner_wall_timer,
        adapted_input_started_ns,
    );
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_BASE_EVAL_DIGESTS")) {
        const prover_input_sha256 = try std.process.getEnvVarOwned(allocator, "STWO_ZIG_SN2_INPUT_SHA256");
        defer allocator.free(prover_input_sha256);
        if (prover_input_sha256.len != 64) return error.InvalidInputDigest;
        std.debug.print("base_eval_digest_input sha256={s}\n", .{prover_input_sha256});
    }
    const reference_read_started_ns = runner_wall_timer.read();
    const transcript_reference_path = std.process.getEnvVarOwned(
        allocator,
        "STWO_ZIG_SN2_TRANSCRIPT_REFERENCE",
    ) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (transcript_reference_path) |path| allocator.free(path);
    var transcript_reference: ?TranscriptReferenceFixture = if (transcript_reference_path) |path|
        try TranscriptReferenceFixture.read(allocator, path)
    else
        null;
    defer if (transcript_reference) |*fixture| fixture.deinit();
    RunnerPhaseTiming.addInterval(
        &runner_phase_timing.bundle_read_and_validate_wall_s,
        &runner_wall_timer,
        reference_read_started_ns,
    );
    const statement_plan_started_ns = runner_wall_timer.read();
    var statement_bootstrap: ?cairo_statement_bootstrap.OwnedStatementBootstrap = null;
    if (composition_bundle) |*composition| {
        if (prover_input) |*adapted| {
            statement_bootstrap = try cairo_statement_bootstrap.initFromCompositionSchedule(
                allocator,
                .{
                    .channel_salt = canonical_protocol.channel_salt,
                    .pcs = .{
                        .pow_bits = canonical_protocol.query_pow_bits,
                        .log_blowup_factor = canonical_protocol.log_blowup_factor,
                        .n_queries = canonical_protocol.n_queries,
                        .log_last_layer_degree_bound = canonical_protocol.fri_log_last_layer_degree_bound,
                        .fold_step = canonical_protocol.fri_fold_step,
                        .lifting_log_size = canonical_protocol.fri_lifting,
                    },
                    .composition = composition,
                    .prover_input = adapted,
                },
            );
        }
    }
    defer if (statement_bootstrap) |*statement| statement.deinit();
    if (composition_bundle) |*composition| {
        if (prover_input) |*adapted| {
            if (std.process.getEnvVarOwned(
                allocator,
                "STWO_ZIG_SN2_COMPACT_STATEMENT_OUTPUT",
            )) |statement_output_path| {
                defer allocator.free(statement_output_path);
                const compact_statement = try cairo_statement_bootstrap.encodeCompactStatementV1(
                    allocator,
                    composition,
                    adapted,
                );
                defer allocator.free(compact_statement);
                const statement_file = try std.fs.createFileAbsolute(
                    statement_output_path,
                    .{ .exclusive = true },
                );
                defer statement_file.close();
                try statement_file.writeAll(compact_statement);
                try statement_file.sync();
            } else |err| switch (err) {
                error.EnvironmentVariableNotFound => {},
                else => return err,
            }
        }
    }
    var proof_plan: ?cairo_proof_plan.CairoProofPlan = if (witness_bundle != null)
        try cairo_proof_plan.CairoProofPlan.fromWitnessSchedule(
            allocator,
            schedule,
            compacted_consumer_rows,
            witness_bundle.?,
            if (prover_input) |*adapted| adapted else null,
        )
    else
        null;
    defer if (proof_plan) |*value| value.deinit();
    var staged_planner: ?staged_arena_planner.StagedArenaPlanner = if (proof_plan) |*value|
        try staged_arena_planner.StagedArenaPlanner.init(allocator, value)
    else
        null;
    defer if (staged_planner) |*value| value.deinit();
    const composition_coverage: ?CompositionCoverage = if (composition_bundle) |bundle|
        try validateCompositionCoverage(schedule, bundle)
    else
        null;
    RunnerPhaseTiming.addInterval(
        &runner_phase_timing.statement_and_proof_plan_wall_s,
        &runner_wall_timer,
        statement_plan_started_ns,
    );
    const schedule_liveness_started_ns = runner_wall_timer.read();
    var native_destinations = std.StringHashMap(void).init(allocator);
    defer native_destinations.deinit();
    var native_producers = std.StringHashMap(void).init(allocator);
    defer native_producers.deinit();
    var missing_components = std.StringHashMap(void).init(allocator);
    defer missing_components.deinit();
    var missing_lookup_components = std.StringHashMap(void).init(allocator);
    defer missing_lookup_components.deinit();
    if (feed_bundle) |bundle| {
        for (bundle.feeds) |feed| {
            try native_producers.put(feed.producer, {});
            for (feed.destinations) |destination| try native_destinations.put(destination.name, {});
        }
    }

    const prepared = try allocator.alloc(Prepared, schedule.len);
    defer allocator.free(prepared);
    @memset(prepared, .{});
    const logical = try allocator.alloc(arena.LogicalBuffer, schedule.len);
    defer allocator.free(logical);
    var component_ids = std.StringHashMap(u16).init(allocator);
    defer component_ids.deinit();
    var native_interaction_ids = std.StringHashMap(u16).init(allocator);
    defer native_interaction_ids.deinit();
    if (proof_plan) |*value| {
        var next_native = std.math.cast(u16, value.components.len) orelse return error.TooManyComponents;
        for (schedule) |entry| {
            const component_value = entry.object.get("component") orelse continue;
            if (component_value != .string or value.componentIndex(component_value.string) != null or
                std.mem.eql(u8, component_value.string, "ec_op_builtin")) continue;
            const result = try native_interaction_ids.getOrPut(component_value.string);
            if (result.found_existing) continue;
            if (next_native >= 64) return error.TooManyComponents;
            result.value_ptr.* = next_native;
            next_native += 1;
        }
    }
    var next_component: u16 = 0;
    var witness_recipe_buffers: usize = 0;
    var witness_recipe_bytes: u64 = 0;
    var witness_missing_buffers: usize = 0;
    var native_recipe_buffers: usize = 0;
    var native_recipe_bytes: u64 = 0;
    var zero_recipe_buffers: usize = 0;
    var zero_recipe_bytes: u64 = 0;
    var bound_recipe_buffers: usize = 0;
    var bound_recipe_bytes: u64 = 0;
    var circle_recipe_buffers: usize = 0;
    var circle_recipe_bytes: u64 = 0;
    var preprocessed_recipe_buffers: usize = 0;
    var preprocessed_recipe_bytes: u64 = 0;

    for (schedule, 0..) |entry, index| {
        const object = entry.object;
        const purpose = object.get("purpose").?.string;
        const first = epochIndex(object.get("first").?.string) orelse return error.InvalidEpoch;
        const last = epochIndex(object.get("last").?.string) orelse return error.InvalidEpoch;
        var component: ?u16 = null;
        if (object.get("component")) |value| switch (value) {
            .string => |name| {
                const result = try component_ids.getOrPut(name);
                if (!result.found_existing) {
                    if (next_component >= 64) return error.TooManyComponents;
                    result.value_ptr.* = next_component;
                    next_component += 1;
                }
                component = native_interaction_ids.get(name) orelse result.value_ptr.*;
            },
            else => {},
        };
        var staged = false;
        if (staged_planner) |planner| {
            if (std.mem.eql(u8, purpose, "PreprocessedEvaluations")) {
                prepared[index].ranges[0] = .{ .first = 0, .last = globalTick(4) };
                prepared[index].range_count = 1;
                staged = true;
            } else if (std.mem.eql(u8, purpose, "CompositionCoefficients")) {
                prepared[index].ranges[0] = .{ .first = globalTick(5) + 64, .last = globalTick(10) };
                prepared[index].range_count = 1;
                staged = true;
            } else if (std.mem.eql(u8, purpose, "CompositionLdeTile")) {
                prepared[index].ranges[0] = .{ .first = globalTick(5), .last = globalTick(5) + 63 };
                prepared[index].range_count = 1;
                staged = true;
            } else if (std.mem.eql(u8, purpose, "ForwardTwiddles") or
                std.mem.eql(u8, purpose, "EcOpSegmentStart") or
                std.mem.eql(u8, purpose, "WitnessFeedLut"))
            {
                var ranges: [3]arena.LiveRange = undefined;
                const derived = try planner.rangesFor(.protocol_persistent, null, &ranges);
                @memcpy(prepared[index].ranges[0..derived.len], derived);
                prepared[index].range_count = derived.len;
                staged = true;
            } else if (std.mem.eql(u8, purpose, "EcOpPartialIota")) {
                const proof_component = proof_plan.?.componentIndex("partial_ec_mul_generic") orelse
                    return error.MissingProofComponent;
                var ranges: [3]arena.LiveRange = undefined;
                const derived = try planner.rangesFor(.component_scratch, proof_component, &ranges);
                @memcpy(prepared[index].ranges[0..derived.len], derived);
                prepared[index].range_count = derived.len;
                staged = true;
            } else if (std.mem.eql(u8, purpose, "FixedTableSourcePointers") or
                std.mem.eql(u8, purpose, "ExecutionTablePointers") or
                std.mem.eql(u8, purpose, "ExecutionTableStrides") or
                std.mem.eql(u8, purpose, "ExecutionTableRawAddressToId") or
                std.mem.eql(u8, purpose, "ExecutionTableRawF252Words") or
                std.mem.eql(u8, purpose, "ExecutionTableRawSmallWords") or
                std.mem.eql(u8, purpose, "ExecutionTableBigLimb") or
                std.mem.eql(u8, purpose, "ExecutionTableSmallLimb"))
            {
                var ranges: [3]arena.LiveRange = undefined;
                const derived = try planner.rangesFor(.witness_shared, null, &ranges);
                @memcpy(prepared[index].ranges[0..derived.len], derived);
                prepared[index].range_count = derived.len;
                staged = true;
            } else if (std.mem.eql(u8, purpose, "BaseCoefficients") or
                std.mem.eql(u8, purpose, "InteractionCoefficients"))
            {
                const proof_component = if (object.get("component")) |component_value|
                    if (component_value == .string)
                        proof_plan.?.componentIndex(component_value.string) orelse
                            if (std.mem.eql(u8, component_value.string, "ec_op_builtin"))
                                proof_plan.?.componentIndex("partial_ec_mul_generic")
                            else
                                null
                    else
                        null
                else
                    null;
                const role: staged_arena_planner.BufferRole = if (std.mem.eql(u8, purpose, "BaseCoefficients"))
                    .base_coefficients
                else
                    .interaction_coefficients;
                var ranges: [3]arena.LiveRange = undefined;
                const derived = try planner.rangesFor(role, proof_component, &ranges);
                prepared[index].ranges[0] = derived[0];
                prepared[index].ranges[1] = .{ .first = globalTick(5), .last = globalTick(10) };
                prepared[index].range_count = 2;
                staged = true;
            } else if (std.mem.eql(u8, purpose, "FixedMultiplicity") or std.mem.eql(u8, purpose, "RuntimeMultiplicity")) {
                var ranges: [3]arena.LiveRange = undefined;
                const derived = try planner.rangesFor(.multiplicity, null, &ranges);
                @memcpy(prepared[index].ranges[0..derived.len], derived);
                prepared[index].range_count = derived.len;
                staged = true;
            } else if (object.get("component")) |component_value| if (component_value == .string) {
                const proof_component = proof_plan.?.componentIndex(component_value.string) orelse
                    if (std.mem.eql(u8, component_value.string, "ec_op_builtin"))
                        proof_plan.?.componentIndex("partial_ec_mul_generic")
                    else
                        null;
                const role = if (std.mem.eql(u8, purpose, "WitnessInput") and
                    std.mem.eql(u8, component_value.string, "partial_ec_mul_generic") and
                    object.get("ordinal").?.integer < 126)
                    staged_arena_planner.BufferRole.retained_witness_input
                else if (std.mem.eql(u8, purpose, "LookupInputs") and
                    cairo_proof_plan.retainsLookupInputs(component_value.string))
                    staged_arena_planner.BufferRole.retained_lookup_inputs
                else
                    stagedRole(purpose);
                if (proof_component) |component_index| if (role) |staged_role| {
                    var ranges: [3]arena.LiveRange = undefined;
                    const derived = try planner.rangesFor(staged_role, component_index, &ranges);
                    @memcpy(prepared[index].ranges[0..derived.len], derived);
                    prepared[index].range_count = derived.len;
                    staged = true;
                };
            };
        }
        if (!staged) {
            const phases = arena_lifetime.inferredUsePhases(purpose, first, last);
            for (phases.slice()) |phase| {
                const range: arena.LiveRange = if (component) |id|
                    .{ .first = localTick(phase, id), .last = localTick(phase, id) }
                else
                    .{ .first = globalTick(phase), .last = globalTick(phase) + 64 };
                prepared[index].ranges[prepared[index].range_count] = range;
                prepared[index].range_count += 1;
            }
        }
        const words: u64 = @intCast(object.get("len_words").?.integer);
        const bytes = std.math.mul(u64, words, 4) catch return error.SizeOverflow;
        // The fused relation recipe consumes schedule metadata directly and
        // uses RelationScanEvalScratch for its block scan. These captured CUDA
        // workspaces are retained as virtual bindings for schedule validation,
        // but do not need resident Metal storage.
        const planned_bytes: u64 = if (std.mem.eql(u8, purpose, "RelationScanEvalScratch"))
            if (relation_coverage) |coverage| coverage.scan_scratch_bytes else bytes
        else if (std.mem.eql(u8, purpose, "RelationSourcePointers") or
            std.mem.eql(u8, purpose, "RelationOutputPointers") or
            std.mem.eql(u8, purpose, "RelationDenominators"))
            16
        else
            bytes;
        var has_recompute_recipe = false;
        if ((std.mem.eql(u8, purpose, "BaseTrace") or
            std.mem.eql(u8, purpose, "LookupInputs") or
            std.mem.eql(u8, purpose, "SubcomponentInputs")) and witness_bundle != null)
        {
            const component_name = object.get("component").?.string;
            const ordinal: u32 = @intCast(object.get("ordinal").?.integer);
            if (witness_bundle.?.find(component_name)) |program_entry| {
                if ((std.mem.eql(u8, purpose, "BaseTrace") and ordinal >= program_entry.program.n_cols) or
                    (std.mem.eql(u8, purpose, "LookupInputs") and program_entry.program.n_lookup_words == 0) or
                    (std.mem.eql(u8, purpose, "SubcomponentInputs") and program_entry.program.n_sub_words == 0))
                    return error.WitnessShapeMismatch;
                witness_recipe_buffers += 1;
                witness_recipe_bytes += bytes;
                has_recompute_recipe = true;
            } else if (std.mem.eql(u8, purpose, "BaseTrace")) {
                if (std.mem.eql(u8, component_name, "ec_op_builtin")) {
                    native_recipe_buffers += 1;
                    native_recipe_bytes += bytes;
                    has_recompute_recipe = true;
                } else if (native_destinations.contains(component_name)) {
                    native_recipe_buffers += 1;
                    native_recipe_bytes += bytes;
                    has_recompute_recipe = true;
                } else if (zeroMultiplicityComponent(component_name)) {
                    zero_recipe_buffers += 1;
                    zero_recipe_bytes += bytes;
                    has_recompute_recipe = true;
                } else {
                    witness_missing_buffers += 1;
                    try missing_components.put(component_name, {});
                }
            } else if (std.mem.eql(u8, purpose, "LookupInputs")) {
                if (std.mem.eql(u8, component_name, "ec_op_builtin")) {
                    native_recipe_buffers += 1;
                    native_recipe_bytes += bytes;
                    has_recompute_recipe = true;
                } else if (fixed_table_destinations.contains(component_name)) {
                    native_recipe_buffers += 1;
                    native_recipe_bytes += bytes;
                    has_recompute_recipe = true;
                } else {
                    try missing_lookup_components.put(component_name, {});
                }
            }
        }
        if (std.mem.eql(u8, purpose, "WitnessInput") and object.get("component") != null and
            object.get("component").? == .string)
        {
            const component_name = object.get("component").?.string;
            const ec_partial = std.mem.eql(u8, component_name, "partial_ec_mul_generic") and
                object.get("ordinal").?.integer < 126;
            if (ec_partial or compactComponent(component_name)) {
                native_recipe_buffers += 1;
                native_recipe_bytes += bytes;
                has_recompute_recipe = true;
            }
        }
        if (std.mem.eql(u8, purpose, "BaseCoefficients") and witness_bundle != null) {
            const component_name = object.get("component").?.string;
            const ordinal: u32 = @intCast(object.get("ordinal").?.integer);
            if (witness_bundle.?.find(component_name)) |program_entry| {
                if (ordinal >= program_entry.program.n_cols) return error.WitnessShapeMismatch;
            }
            circle_recipe_buffers += 1;
            circle_recipe_bytes += bytes;
            has_recompute_recipe = true;
        } else if (std.mem.eql(u8, purpose, "InteractionCoefficients")) {
            circle_recipe_buffers += 1;
            circle_recipe_bytes += bytes;
            has_recompute_recipe = true;
        } else if (std.mem.eql(u8, purpose, "CommitRetainedEvaluation")) {
            if (retained_sources[index] == null) return error.MissingRetainedSource;
            has_recompute_recipe = true;
        } else if (std.mem.eql(u8, purpose, "PreprocessedCoefficients") and preprocessed_coverage.sources[index] != null) {
            preprocessed_recipe_buffers += 1;
            preprocessed_recipe_bytes += bytes;
            has_recompute_recipe = true;
        } else if ((std.mem.eql(u8, purpose, "RetainedMerkleLayers") or std.mem.eql(u8, purpose, "FriMerkleLayer")) and
            (merkle_parent_coverage.sources[index] != null or merkle_commit_coverage.bottoms[index]))
        {
            has_recompute_recipe = true;
        } else if ((std.mem.eql(u8, purpose, "InteractionTrace") or std.mem.eql(u8, purpose, "RelationClaimedSum")) and relation_coverage != null) {
            has_recompute_recipe = true;
        } else if (std.mem.eql(u8, purpose, "CompositionCoefficients") and composition_coverage != null) {
            has_recompute_recipe = true;
        }
        const recoverable = prepared[index].range_count > 1;
        // These values cross protocol gaps, but the resident prover does not
        // yet execute the planner's spill/recompute actions at their final
        // consumption boundaries. Keep them resident until recovery actions
        // are wired into execution.
        const recovery_executed = !std.mem.eql(u8, purpose, "BaseCoefficients") and
            !std.mem.eql(u8, purpose, "InteractionCoefficients") and
            !std.mem.eql(u8, purpose, "PreprocessedCoefficients") and
            !std.mem.eql(u8, purpose, "RetainedMerkleLayers") and
            !std.mem.eql(u8, purpose, "FriMerkleLayer");
        const can_spill = recoverable and recovery_executed;
        const can_recompute = can_spill and has_recompute_recipe and
            !std.mem.eql(u8, purpose, "BaseCoefficients") and
            !std.mem.eql(u8, purpose, "InteractionCoefficients");
        if (can_recompute) {
            bound_recipe_buffers += 1;
            bound_recipe_bytes += bytes;
        }
        logical[index] = .{
            .id = @intCast(object.get("id").?.integer),
            .size_bytes = planned_bytes,
            // AOT witness kernels use u32 word offsets, including the bindings
            // reached through their arena-resident pointer tables.
            .placement_priority = if (std.mem.eql(u8, purpose, "CompositionLdeTile") or
                std.mem.eql(u8, purpose, "TranscriptState") or
                std.mem.eql(u8, purpose, "TranscriptInput") or
                std.mem.eql(u8, purpose, "TranscriptOutput")) 4 else if (aotNarrowAddressPurpose(purpose)) 3 else if (std.mem.eql(u8, purpose, "ForwardTwiddles") or
                std.mem.eql(u8, purpose, "QuotientInverseTwiddles") or
                std.mem.eql(u8, purpose, "QuotientTile") or
                std.mem.eql(u8, purpose, "InverseTwiddles") or
                std.mem.eql(u8, purpose, "FriRetainedEvaluation") or
                std.mem.eql(u8, purpose, "FriFoldingChallenge") or
                std.mem.eql(u8, purpose, "FriMerkleLayer") or
                std.mem.eql(u8, purpose, "FriPing") or
                std.mem.eql(u8, purpose, "FriPong") or
                std.mem.eql(u8, purpose, "FriFinalCoefficients") or
                std.mem.eql(u8, purpose, "FriFinalDegreeError") or
                std.mem.eql(u8, purpose, "PreprocessedEvaluations")) 2 else if (std.mem.eql(u8, purpose, "InteractionTrace") or
                std.mem.eql(u8, purpose, "RelationClaimedSum") or
                std.mem.eql(u8, purpose, "RelationAlphaPowers") or
                std.mem.eql(u8, purpose, "RelationZ") or
                std.mem.eql(u8, purpose, "RelationScanEvalScratch") or
                std.mem.eql(u8, purpose, "CompositionAccumulators") or
                std.mem.eql(u8, purpose, "CompositionCoefficients") or
                std.mem.eql(u8, purpose, "CompositionExtParams") or
                std.mem.eql(u8, purpose, "CompositionRandomCoefficientPowers") or
                std.mem.eql(u8, purpose, "CompositionDescriptors") or
                std.mem.eql(u8, purpose, "DecommitTraceLdeTile") or
                object.get("component") != null and object.get("component").? == .string and
                    ((std.mem.eql(u8, purpose, "LookupInputs") and
                        (fixed_table_destinations.contains(object.get("component").?.string) or
                            cairo_proof_plan.retainsLookupInputs(object.get("component").?.string))) or
                        (std.mem.eql(u8, purpose, "SubcomponentInputs") and
                            native_producers.contains(object.get("component").?.string)))) 1 else 0,
            .live_ranges = prepared[index].ranges[0..prepared[index].range_count],
            .spill_cost_ns = if (can_spill) @max(1, planned_bytes / 20) else null,
            .recompute_cost_ns = if (can_recompute) @max(1, planned_bytes / 100) else null,
        };
    }

    var peak_tick: u16 = 0;
    var diagnostic_peak_logical_bytes: u64 = 0;
    var diagnostic_base_peak_bytes: u64 = 0;
    var diagnostic_base_peak_tick: u16 = 0;
    var diagnostic_interaction_peak_bytes: u64 = 0;
    var diagnostic_interaction_peak_tick: u16 = 3 * 65;
    for (0..arena.max_ticks) |tick_usize| {
        const tick: u16 = @intCast(tick_usize);
        var live_bytes: u64 = 0;
        for (logical) |buffer| {
            var live = false;
            for (buffer.live_ranges) |range| live = live or (range.first <= tick and tick <= range.last);
            if (live) live_bytes = std.math.add(u64, live_bytes, buffer.size_bytes) catch return error.SizeOverflow;
        }
        if (live_bytes > diagnostic_peak_logical_bytes) {
            diagnostic_peak_logical_bytes = live_bytes;
            peak_tick = tick;
        }
        if (tick <= 2 * 65 and live_bytes > diagnostic_base_peak_bytes) {
            diagnostic_base_peak_bytes = live_bytes;
            diagnostic_base_peak_tick = tick;
        }
        if (tick >= 3 * 65 and tick <= 4 * 65 and live_bytes > diagnostic_interaction_peak_bytes) {
            diagnostic_interaction_peak_bytes = live_bytes;
            diagnostic_interaction_peak_tick = tick;
        }
    }
    var peak_purpose_map = std.StringHashMap(PurposeStat).init(allocator);
    defer peak_purpose_map.deinit();
    for (schedule, logical) |entry, buffer| {
        var live = false;
        for (buffer.live_ranges) |range| live = live or (range.first <= peak_tick and peak_tick <= range.last);
        if (!live) continue;
        const purpose = entry.object.get("purpose").?.string;
        const result = try peak_purpose_map.getOrPut(purpose);
        if (!result.found_existing) result.value_ptr.* = .{ .purpose = purpose };
        result.value_ptr.buffers += 1;
        result.value_ptr.bytes = std.math.add(u64, result.value_ptr.bytes, buffer.size_bytes) catch return error.SizeOverflow;
    }
    const peak_purposes = try allocator.alloc(PurposeStat, peak_purpose_map.count());
    defer allocator.free(peak_purposes);
    var peak_purpose_iterator = peak_purpose_map.valueIterator();
    var peak_purpose_index: usize = 0;
    while (peak_purpose_iterator.next()) |stat| : (peak_purpose_index += 1) peak_purposes[peak_purpose_index] = stat.*;
    std.mem.sortUnstable(PurposeStat, peak_purposes, {}, struct {
        fn lessThan(_: void, lhs: PurposeStat, rhs: PurposeStat) bool {
            if (lhs.bytes != rhs.bytes) return lhs.bytes > rhs.bytes;
            return std.mem.lessThan(u8, lhs.purpose, rhs.purpose);
        }
    }.lessThan);
    var base_peak_purpose_map = std.StringHashMap(PurposeStat).init(allocator);
    defer base_peak_purpose_map.deinit();
    for (schedule, logical) |entry, buffer| {
        var live = false;
        for (buffer.live_ranges) |range| live = live or (range.first <= diagnostic_base_peak_tick and diagnostic_base_peak_tick <= range.last);
        if (!live) continue;
        const purpose = entry.object.get("purpose").?.string;
        const result = try base_peak_purpose_map.getOrPut(purpose);
        if (!result.found_existing) result.value_ptr.* = .{ .purpose = purpose };
        result.value_ptr.buffers += 1;
        result.value_ptr.bytes = std.math.add(u64, result.value_ptr.bytes, buffer.size_bytes) catch return error.SizeOverflow;
    }
    const base_peak_purposes = try allocator.alloc(PurposeStat, base_peak_purpose_map.count());
    defer allocator.free(base_peak_purposes);
    var base_peak_iterator = base_peak_purpose_map.valueIterator();
    var base_peak_index: usize = 0;
    while (base_peak_iterator.next()) |stat| : (base_peak_index += 1) base_peak_purposes[base_peak_index] = stat.*;
    std.mem.sortUnstable(PurposeStat, base_peak_purposes, {}, struct {
        fn lessThan(_: void, lhs: PurposeStat, rhs: PurposeStat) bool {
            if (lhs.bytes != rhs.bytes) return lhs.bytes > rhs.bytes;
            return std.mem.lessThan(u8, lhs.purpose, rhs.purpose);
        }
    }.lessThan);
    var interaction_peak_purpose_map = std.StringHashMap(PurposeStat).init(allocator);
    defer interaction_peak_purpose_map.deinit();
    for (schedule, logical) |entry, buffer| {
        var live = false;
        for (buffer.live_ranges) |range| live = live or
            (range.first <= diagnostic_interaction_peak_tick and diagnostic_interaction_peak_tick <= range.last);
        if (!live) continue;
        const purpose = entry.object.get("purpose").?.string;
        const result = try interaction_peak_purpose_map.getOrPut(purpose);
        if (!result.found_existing) result.value_ptr.* = .{ .purpose = purpose };
        result.value_ptr.buffers += 1;
        result.value_ptr.bytes = std.math.add(u64, result.value_ptr.bytes, buffer.size_bytes) catch return error.SizeOverflow;
    }
    const interaction_peak_purposes = try allocator.alloc(PurposeStat, interaction_peak_purpose_map.count());
    defer allocator.free(interaction_peak_purposes);
    var interaction_peak_iterator = interaction_peak_purpose_map.valueIterator();
    var interaction_peak_index: usize = 0;
    while (interaction_peak_iterator.next()) |stat| : (interaction_peak_index += 1)
        interaction_peak_purposes[interaction_peak_index] = stat.*;
    std.mem.sortUnstable(PurposeStat, interaction_peak_purposes, {}, struct {
        fn lessThan(_: void, lhs: PurposeStat, rhs: PurposeStat) bool {
            if (lhs.bytes != rhs.bytes) return lhs.bytes > rhs.bytes;
            return std.mem.lessThan(u8, lhs.purpose, rhs.purpose);
        }
    }.lessThan);

    RunnerPhaseTiming.addInterval(
        &runner_phase_timing.schedule_liveness_analysis_wall_s,
        &runner_wall_timer,
        schedule_liveness_started_ns,
    );
    const arena_plan_started_ns = runner_wall_timer.read();
    const execute_proof = std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_PROOF");
    const execute_decommit = std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_DECOMMIT") or execute_proof;
    const execute_fri = std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_FRI") or execute_decommit;
    const execute_quotient = std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_QUOTIENT") or execute_fri;
    const execute_composition = std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_COMPOSITION") or execute_quotient;
    const projection_tick: ?u16 = if (!std.process.hasEnvVarConstant("STWO_ZIG_SN2_PREPARE_METAL") or execute_composition)
        null
    else if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_RELATIONS"))
        4 * 65
    else
        2 * 65;
    const canonical_full_proof_plan = prepared_state_request != null and (CanonicalFullProofPlanMode{
        .execute_proof = execute_proof,
        .no_projection = projection_tick == null,
        .prepare_metal = std.process.hasEnvVarConstant("STWO_ZIG_SN2_PREPARE_METAL"),
        .execute_preprocessed = std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_PREPROCESSED"),
        .execute_witness = std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_WITNESS"),
        .execute_base_interpolation = std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_BASE_INTERPOLATION"),
        .execute_commitments = std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_COMMITMENTS"),
        .execute_relations = std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_RELATIONS"),
        .execute_oods = std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_OODS"),
        .verify_proof = std.process.hasEnvVarConstant("STWO_ZIG_SN2_VERIFY_PROOF"),
    }).eligible();
    const logical_plan_hash = logicalPlanHash(logical);
    const cached_full_plan: ?PreparedGeometryHandle = if (canonical_full_proof_plan)
        try prepared_state_request.?.cache.findCanonicalPlan(
            prepared_state_request.?.key,
            logical_plan_hash,
        )
    else
        null;
    const arena_plan_cache_hit = cached_full_plan != null;
    var owned_full_plan: ?arena.Plan = null;
    var full_plan_ownership_transferred = false;
    defer if (!full_plan_ownership_transferred) {
        if (owned_full_plan) |*owned| owned.deinit();
    };
    if (cached_full_plan == null) {
        owned_full_plan = arena.build(allocator, logical, budget_bytes) catch |err| {
            try writeFailure(report_writer, err, schedule.len, component_ids.count(), budget_bytes);
            return;
        };
    }
    const full_plan = if (cached_full_plan) |cached| cached.plan.* else owned_full_plan.?;
    if (full_plan.bindings.len != logical.len) return error.PreparedStatePlanIdentityMismatch;
    var projected_plan: ?arena.Plan = if (projection_tick) |last_tick|
        try arena.projectThroughTick(allocator, logical, full_plan, last_tick, budget_bytes)
    else
        null;
    defer if (projected_plan) |*projected| projected.deinit();
    const plan = if (projected_plan) |projected| projected else full_plan;
    try validateNarrowAddressedBindings(schedule, plan);
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_PROTOCOL_LAYOUT")) {
        inline for ([_][]const u8{
            "PreprocessedCoefficients",
            "BaseCoefficients",
            "InteractionCoefficients",
            "RelationAlphaPowers",
            "RelationZ",
            "RelationClaimedSum",
            "CompositionCoefficients",
            "CompositionDescriptors",
            "CompositionLdeTile",
            "CompositionAccumulators",
            "CompositionRandomCoefficientPowers",
            "CompositionExtParams",
            "CommitLdeTile",
            "MerkleLeafState",
            "MerkleLayerScratch",
            "QuotientTile",
            "InverseTwiddles",
            "FriRetainedEvaluation",
            "FriFoldingChallenge",
            "FriMerkleLayer",
            "FriPing",
            "FriPong",
            "FriFinalCoefficients",
            "FriFinalDegreeError",
            "DecommitUniqueQueries",
            "DecommitMappedQueries",
            "DecommitWalkQueries",
            "DecommitWalkScratch",
            "DecommitExpandedPositions",
            "DecommitSparseIndices",
            "DecommitSparseHashes",
            "DecommitCounts",
            "DecommitValues",
            "DecommitAssembly",
            "DecommitTraceLdeTile",
            "DecommitTraceEvaluationPointers",
            "DecommitTraceRetainedPointers",
            "DecommitFriCoordinatePointers",
            "DecommitFriRetainedPointers",
            "ProofBytes",
            "TranscriptState",
            "TranscriptInput",
            "TranscriptOutput",
        }) |wanted_purpose| try logPurposeLayout(schedule, plan, wanted_purpose);
    }
    var decommit_geometry: ?runtime_decommit_geometry.OwnedProofDecommitGeometry = if (composition_bundle) |bundle|
        try runtime_decommit_geometry.OwnedProofDecommitGeometry.init(
            allocator,
            schedule,
            plan,
            bundle,
        )
    else
        null;
    defer if (decommit_geometry) |*geometry| geometry.deinit();
    var proof_bindings: ?arena_binding_mod.PreparedProofBindings = if (composition_bundle != null)
        try arena_binding_mod.PreparedProofBindings.init(
            allocator,
            schedule,
            plan,
            composition_bundle.?,
            relation_bundle orelse return error.MissingRelationBundle,
            decommit_geometry.?.geometry(),
        )
    else
        null;
    defer if (proof_bindings) |*bindings| bindings.deinit();
    RunnerPhaseTiming.addInterval(
        &runner_phase_timing.arena_plan_and_bindings_wall_s,
        &runner_wall_timer,
        arena_plan_started_ns,
    );
    var resident_prepare_gate: []const u8 = "not_requested";
    var populated_direct_witness_lanes: usize = 0;
    var execution_table_split_gpu_ms: f64 = 0;
    var executed_witness_programs: usize = 0;
    var witness_graph_gpu_ms: f64 = 0;
    var multiplicity_feed_gpu_ms: f64 = 0;
    var memory_public_seed_gpu_ms: f64 = 0;
    var memory_trace_gpu_ms: f64 = 0;
    var memory_rc99_gpu_ms: f64 = 0;
    var populated_preprocessed_coefficients: usize = 0;
    var resident_preprocessed_coefficients = false;
    var preprocessed_gpu_ms: f64 = 0;
    var base_interpolation_gpu_ms: f64 = 0;
    var relation_gpu_ms: f64 = 0;
    var interaction_witness_gpu_ms: f64 = 0;
    var interaction_interpolation_gpu_ms: f64 = 0;
    var composition_gpu_ms: f64 = 0;
    var quotient_gpu_ms: f64 = 0;
    var quotient_executed = false;
    var quotient_reference_parity = false;
    var fri_gpu_ms: f64 = 0;
    var fri_executed = false;
    var fri_reference_parity = false;
    var fri_final_degree_valid = false;
    var interaction_pow_nonce: ?u64 = null;
    var interaction_pow_wall_s: ?f64 = null;
    var interaction_pow_mode: ?[]const u8 = null;
    var interaction_pow_bits: ?u32 = null;
    var interaction_pow_invocations: u32 = 0;
    var query_pow_nonce: ?u64 = null;
    var query_pow_wall_s: ?f64 = null;
    var query_pow_mode: ?[]const u8 = null;
    var query_pow_bits: ?u32 = null;
    var query_pow_invocations: u32 = 0;
    var decommit_lde_gpu_ms: f64 = 0;
    var decommit_gpu_ms: f64 = 0;
    var decommit_executed = false;
    var proof_assembly_gpu_ms: f64 = 0;
    var proof_assembled = false;
    var proof_bundle_valid = false;
    var proof_verified = false;
    var proof_layout: ?ProofLayoutEvidence = null;
    var statement_self_derived = false;
    var legacy_transcript_bootstrap_used = false;
    var parity_fixture_used = transcript_reference != null;
    var proof_output_bytes: u64 = 0;
    var prove_timer: ?std.time.Timer = null;
    var prove_wall_s: ?f64 = null;
    var transcript_gpu_ms: f64 = 0;
    var commitment_gpu_ms: f64 = 0;
    var commitment_lde_gpu_ms: f64 = 0;
    var commitment_leaf_gpu_ms: f64 = 0;
    var commitment_parent_gpu_ms: f64 = 0;
    var resident_arena_bytes: u64 = 0;
    var prepared_state_cache_hit = false;
    var fixed_table_recipe_cache_hit = false;
    var multiplicity_feed_recipe_cache_hit = false;
    var base_aot_witness_cache_hit = false;
    var interaction_aot_witness_cache_hit = false;
    var compact_verify_recipe_cache_hit = false;
    var compact_pedersen_recipe_cache_hit = false;
    var compact_poseidon_recipe_cache_hit = false;
    var recorded_base_interpolation_cache_hit = false;
    var native_base_interpolation_cache_hit = false;
    var prepared_state_snapshot_bytes: u64 = 0;
    var prepared_state_clear_bytes: u64 = 0;
    var prepared_state_capture_gpu_ms: f64 = 0;
    var prepared_state_restore_gpu_ms: f64 = 0;
    var preprocessed_coefficients_loaded_bytes: u64 = 0;
    var preprocessed_coefficients_reconstructed_bytes: u64 = 0;
    var commitment_roots: [4]?[32]u8 = .{ null, null, null, null };
    const fri_root_count = if (proof_bindings) |bindings| bindings.decommit_fri_trees.len else 0;
    const fri_roots = try allocator.alloc(?[32]u8, fri_root_count);
    defer allocator.free(fri_roots);
    @memset(fri_roots, null);
    const requested_commit_tree_count = if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_COMMITMENTS")) blk: {
        const tree_count = if (std.process.getEnvVarOwned(allocator, "STWO_ZIG_SN2_COMMIT_TREE_COUNT")) |value| value_blk: {
            defer allocator.free(value);
            break :value_blk try std.fmt.parseInt(usize, value, 10);
        } else |err| switch (err) {
            error.EnvironmentVariableNotFound => 1,
            else => return err,
        };
        if (tree_count == 0 or tree_count > 4) return error.InvalidCommitmentTreeCount;
        break :blk tree_count;
    } else 0;
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_PREPARE_METAL")) {
        const bindings = if (proof_bindings) |*value| value else return error.MissingPreparedProofBindings;
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("resident_plan bytes={} peak_live_bytes={}\n", .{ plan.total_bytes, plan.peak_live_bytes });
        var owned_metal: ?metal_runtime.Runtime = if (external_runtime == null)
            try metal_runtime.Runtime.initFull()
        else
            null;
        defer if (owned_metal) |*value| value.deinit();
        const metal = external_runtime orelse &owned_metal.?;
        const restored_preprocessed_path = std.process.getEnvVarOwned(
            allocator,
            "STWO_ZIG_SN2_RESTORE_PREPROCESSED_EVALUATIONS",
        ) catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (restored_preprocessed_path) |path| allocator.free(path);
        const staged_preprocessed_path = std.process.getEnvVarOwned(
            allocator,
            "STWO_ZIG_SN2_PREPROCESSED_EVALUATIONS_OUTPUT",
        ) catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (staged_preprocessed_path) |path| allocator.free(path);
        if (restored_preprocessed_path != null and staged_preprocessed_path != null)
            return error.ConflictingPreprocessedPaths;
        const restoring_tree0 = restored_preprocessed_path != null;
        const staged_tree0 = !restoring_tree0 and requested_commit_tree_count > 0 and
            std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_PREPROCESSED") and
            std.process.hasEnvVarConstant("STWO_ZIG_SN2_PREPROCESSED_COEFFS");
        const preprocessed_spill_path = restored_preprocessed_path orelse
            staged_preprocessed_path orelse
            "/tmp/stwo-zig-sn2-preprocessed-evaluations.spill";
        const tree0_merkle_path = try std.fmt.allocPrint(allocator, "{s}.tree0-merkle", .{preprocessed_spill_path});
        defer allocator.free(tree0_merkle_path);
        if (staged_tree0) {
            for ([_][]const u8{ preprocessed_spill_path, tree0_merkle_path }) |output_path| {
                if (std.fs.accessAbsolute(output_path, .{})) |_| {
                    return error.PreprocessedOutputAlreadyExists;
                } else |err| switch (err) {
                    error.FileNotFound => {},
                    else => return err,
                }
            }
        }
        var staged_tree0_root: ?[32]u8 = null;
        if (restoring_tree0) {
            const root_hex = try std.process.getEnvVarOwned(allocator, "STWO_ZIG_SN2_TREE0_ROOT_HEX");
            defer allocator.free(root_hex);
            if (root_hex.len != 64) return error.InvalidCommitmentRoot;
            var root: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&root, root_hex) catch return error.InvalidCommitmentRoot;
            staged_tree0_root = root;
            commitment_roots[0] = root;
            populated_preprocessed_coefficients = fixed_table_bundle.?.preprocessed_identities.len;
        }
        if (staged_tree0) {
            var tree0_arena = try arena.ResidentArena.initWithExtra(metal, plan, bindings.commitmentScratchBytes(0));
            defer tree0_arena.deinit();
            const coefficients_path = try std.process.getEnvVarOwned(allocator, "STWO_ZIG_SN2_PREPROCESSED_COEFFS");
            defer allocator.free(coefficients_path);
            try arena_binding_mod.populatePreprocessedCoefficients(
                allocator,
                &tree0_arena,
                schedule,
                plan,
                fixed_table_bundle.?,
                coefficients_path,
            );
            populated_preprocessed_coefficients = fixed_table_bundle.?.preprocessed_identities.len;
            try bindings.populateCommitmentTwiddles(allocator, &tree0_arena, plan, 0);
            const committed = try bindings.executeCommitment(
                metal,
                &tree0_arena,
                schedule,
                plan,
                0,
                blake2_merkle.Blake2sPlainMerkleHasher.leafSeed(),
                blake2_merkle.Blake2sPlainMerkleHasher.nodeSeed(),
            );
            commitment_gpu_ms += committed.gpu_ms;
            commitment_lde_gpu_ms += committed.lde_gpu_ms;
            commitment_leaf_gpu_ms += committed.leaf_gpu_ms;
            commitment_parent_gpu_ms += committed.parent_gpu_ms;
            try arena_binding_mod.spillRetainedMerkleLayers(
                allocator,
                &tree0_arena,
                schedule,
                plan,
                0,
                tree0_merkle_path,
            );
            var root: [32]u8 = undefined;
            @memcpy(&root, (try tree0_arena.bytes(committed.root))[0..32]);
            staged_tree0_root = root;
            commitment_roots[0] = root;
            preprocessed_gpu_ms += try arena_binding_mod.evaluatePreprocessedCoefficients(
                allocator,
                metal,
                &tree0_arena,
                schedule,
                plan,
                bindings.commitmentTwiddleStorage(plan, 0),
            );
            try arena_binding_mod.spillPreprocessedEvaluations(
                allocator,
                &tree0_arena,
                schedule,
                plan,
                preprocessed_spill_path,
            );
        }
        const resident_bytes = plan.total_bytes;
        resident_arena_bytes = resident_bytes;
        var local_resident_arena: ?arena.ResidentArena = null;
        defer if (local_resident_arena) |*resident| resident.deinit();
        const resident_acquire_started_ns = runner_wall_timer.read();
        const resident_acquire = if (prepared_state_request) |request|
            try request.cache.begin(
                metal,
                request.key,
                logical_plan_hash,
                plan,
                canonical_full_proof_plan,
                cached_full_plan,
                if (canonical_full_proof_plan and !arena_plan_cache_hit) .{
                    .owner = &owned_full_plan,
                    .transferred = &full_plan_ownership_transferred,
                } else null,
            )
        else blk: {
            local_resident_arena = try arena.ResidentArena.initByteLength(metal, resident_bytes);
            break :blk PreparedStateAcquire{
                .resident_arena = &local_resident_arena.?,
                .cache_hit = false,
            };
        };
        RunnerPhaseTiming.addInterval(
            &runner_phase_timing.resident_acquire_reset_restore_wall_s,
            &runner_wall_timer,
            resident_acquire_started_ns,
        );
        const resident_arena = resident_acquire.resident_arena;
        prepared_state_cache_hit = resident_acquire.cache_hit;
        if (prepared_state_request) |request| {
            const telemetry = request.cache.requestTelemetry();
            prepared_state_snapshot_bytes = telemetry.snapshot_bytes;
            prepared_state_clear_bytes = telemetry.clear_bytes;
            prepared_state_restore_gpu_ms = telemetry.restore_gpu_ms;
        }
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_ARENA_LAYOUT")) {
            try logPurposeLayout(schedule, plan, "ForwardTwiddles");
            try logPurposeLayout(schedule, plan, "PreprocessedEvaluations");
            try logPurposeLayout(schedule, plan, "RuntimeMultiplicity");
            try logPurposeLayout(schedule, plan, "FixedMultiplicity");
            try logPurposeLayout(schedule, plan, "CommitLdeTile");
            try logPurposeLayout(schedule, plan, "MerkleLeafState");
            try logPurposeLayout(schedule, plan, "MerkleLayerScratch");
            try logPurposeLayout(schedule, plan, "TranscriptState");
            try logPurposeLayout(schedule, plan, "TranscriptInput");
            try logPurposeLayout(schedule, plan, "TranscriptOutput");
            try logPurposeLayout(schedule, plan, "ExecutionTablePointers");
            try logPurposeLayout(schedule, plan, "ExecutionTableStrides");
            try logPurposeLayout(schedule, plan, "FixedTableSourcePointers");
            try logComponentPurposeLayout(schedule, plan, "WitnessInput", "partial_ec_mul_generic");
            try logComponentPurposeLayout(schedule, plan, "BaseTrace", "ec_op_builtin");
            try logComponentPurposeLayout(schedule, plan, "BaseCoefficients", "blake_g");
            try logComponentPurposeLayout(schedule, plan, "InteractionTrace", "blake_g");
            try logComponentPurposeLayout(schedule, plan, "InteractionCoefficients", "blake_g");
            try logComponentPurposeLayout(schedule, plan, "BaseTrace", "add_opcode");
            try logComponentPurposeLayout(schedule, plan, "BaseCoefficients", "add_opcode");
            try logComponentPurposeLayout(schedule, plan, "BaseTrace", "add_opcode_small");
            try logComponentPurposeLayout(schedule, plan, "LookupInputs", "add_opcode_small");
            try logComponentPurposeLayout(schedule, plan, "SubcomponentInputs", "add_opcode_small");
            try logComponentPurposeLayout(schedule, plan, "WitnessInput", "add_opcode_small");
            try logComponentPurposeLayout(schedule, plan, "WitnessOutputPointers", "add_opcode_small");
            try logComponentPurposeLayout(schedule, plan, "WitnessInputPointers", "add_opcode_small");
            try logComponentPurposeLayout(schedule, plan, "WitnessMultiplicityPointers", "add_opcode_small");
        }
        const memory_trace_started_ns = runner_wall_timer.read();
        var memory_trace: ?cairo_memory_trace.CairoMemoryTrace = if (prover_input != null)
            try cairo_memory_trace.CairoMemoryTrace.init(allocator, schedule, plan, fixed_table_bundle.?)
        else
            null;
        defer if (memory_trace) |*trace| trace.deinit();
        RunnerPhaseTiming.addInterval(
            &runner_phase_timing.input_materialization_wall_s,
            &runner_wall_timer,
            memory_trace_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=memory_trace done\n", .{});
        const coefficient_restore_started_ns = runner_wall_timer.read();
        if (std.process.getEnvVarOwned(allocator, "STWO_ZIG_SN2_PREPROCESSED_COEFFS")) |coefficients_path| {
            defer allocator.free(coefficients_path);
            if (!prepared_state_cache_hit) {
                if (restoring_tree0) {
                    const loaded = try arena_binding_mod.populateUnreconstructedPreprocessedCoefficients(
                        allocator,
                        resident_arena,
                        schedule,
                        plan,
                        fixed_table_bundle.?,
                        coefficients_path,
                    );
                    preprocessed_coefficients_loaded_bytes = loaded.loaded_bytes;
                    preprocessed_coefficients_reconstructed_bytes = loaded.reconstructed_bytes;
                } else {
                    try arena_binding_mod.populatePreprocessedCoefficients(
                        allocator,
                        resident_arena,
                        schedule,
                        plan,
                        fixed_table_bundle.?,
                        coefficients_path,
                    );
                    for (bindings.preprocessed_coefficients) |binding|
                        preprocessed_coefficients_loaded_bytes += binding.size_bytes;
                }
            }
            populated_preprocessed_coefficients = fixed_table_bundle.?.preprocessed_identities.len;
            resident_preprocessed_coefficients = true;
        } else |err| switch (err) {
            error.EnvironmentVariableNotFound => {},
            else => return err,
        }
        RunnerPhaseTiming.addInterval(
            &runner_phase_timing.immutable_host_restore_wall_s,
            &runner_wall_timer,
            coefficient_restore_started_ns,
        );
        try requireResidentPreprocessedCoefficients(execute_composition, resident_preprocessed_coefficients);
        if (requested_commit_tree_count > 0 and !staged_tree0 and !restoring_tree0) {
            if (populated_preprocessed_coefficients == 0) return error.CommitmentInputsNotExecuted;
            try bindings.populateCommitmentTwiddles(allocator, resident_arena, plan, 0);
            const committed = try bindings.executeCommitment(
                metal,
                resident_arena,
                schedule,
                plan,
                0,
                blake2_merkle.Blake2sPlainMerkleHasher.leafSeed(),
                blake2_merkle.Blake2sPlainMerkleHasher.nodeSeed(),
            );
            commitment_gpu_ms += committed.gpu_ms;
            commitment_lde_gpu_ms += committed.lde_gpu_ms;
            commitment_leaf_gpu_ms += committed.leaf_gpu_ms;
            commitment_parent_gpu_ms += committed.parent_gpu_ms;
            var root: [32]u8 = undefined;
            @memcpy(&root, (try resident_arena.bytes(committed.root))[0..32]);
            commitment_roots[0] = root;
        }
        const input_population_started_ns = runner_wall_timer.read();
        if (prover_input) |*adapted| {
            execution_table_split_gpu_ms = try arena_binding_mod.populateExecutionTables(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                adapted,
            );
            populated_direct_witness_lanes = try arena_binding_mod.populateCasmWitnessInputs(
                allocator,
                resident_arena,
                schedule,
                plan,
                witness_bundle.?,
                adapted,
            );
            populated_direct_witness_lanes += try arena_binding_mod.populateBuiltinSeedWitnessInputs(
                allocator,
                resident_arena,
                schedule,
                plan,
                witness_bundle.?,
                adapted,
            );
        }
        RunnerPhaseTiming.addInterval(
            &runner_phase_timing.input_materialization_wall_s,
            &runner_wall_timer,
            input_population_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=inputs done\n", .{});
        const fixed_recipe_started_ns = runner_wall_timer.read();
        var local_fixed_tables: ?protocol_recipes.FixedTableBatchRecipe = null;
        defer if (local_fixed_tables) |*recipe| recipe.deinit();
        const fixed_tables = if (prepared_state_request) |request| fixed_blk: {
            if (canonical_full_proof_plan) {
                if (prepared_state_cache_hit) {
                    fixed_table_recipe_cache_hit = true;
                    break :fixed_blk try request.cache.borrowFixedTables();
                }
                local_fixed_tables = try arena_binding_mod.prepareFixedTableBatch(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    fixed_table_bundle.?,
                );
                break :fixed_blk try request.cache.installFixedTables(&local_fixed_tables);
            }
            local_fixed_tables = try arena_binding_mod.prepareFixedTableBatch(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                fixed_table_bundle.?,
            );
            break :fixed_blk &local_fixed_tables.?;
        } else fixed_blk: {
            local_fixed_tables = try arena_binding_mod.prepareFixedTableBatch(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                fixed_table_bundle.?,
            );
            break :fixed_blk &local_fixed_tables.?;
        };
        RunnerPhaseTiming.addInterval(
            &runner_phase_timing.recipe_preparation_wall_s,
            &runner_wall_timer,
            fixed_recipe_started_ns,
        );
        RunnerPhaseTiming.addInterval(
            &recipe_preparation_timing.fixed_tables_wall_s,
            &runner_wall_timer,
            fixed_recipe_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=fixed_tables done\n", .{});
        const feed_recipe_started_ns = runner_wall_timer.read();
        var local_multiplicity_feeds: ?arena_binding_mod.MultiplicityFeedBatch = null;
        defer if (local_multiplicity_feeds) |*recipe| recipe.deinit();
        const multiplicity_feeds = if (prepared_state_request) |request| feed_blk: {
            if (canonical_full_proof_plan) {
                if (prepared_state_cache_hit) {
                    multiplicity_feed_recipe_cache_hit = true;
                    break :feed_blk try request.cache.borrowMultiplicityFeeds();
                }
                local_multiplicity_feeds = try arena_binding_mod.prepareMultiplicityFeedBatch(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    feed_bundle.?,
                );
                break :feed_blk try request.cache.installMultiplicityFeeds(&local_multiplicity_feeds);
            }
            local_multiplicity_feeds = try arena_binding_mod.prepareMultiplicityFeedBatch(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                feed_bundle.?,
            );
            break :feed_blk &local_multiplicity_feeds.?;
        } else feed_blk: {
            local_multiplicity_feeds = try arena_binding_mod.prepareMultiplicityFeedBatch(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                feed_bundle.?,
            );
            break :feed_blk &local_multiplicity_feeds.?;
        };
        RunnerPhaseTiming.addInterval(
            &runner_phase_timing.recipe_preparation_wall_s,
            &runner_wall_timer,
            feed_recipe_started_ns,
        );
        RunnerPhaseTiming.addInterval(
            &recipe_preparation_timing.multiplicity_feeds_wall_s,
            &runner_wall_timer,
            feed_recipe_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=multiplicity_feeds done\n", .{});
        const immutable_restore_started_ns = runner_wall_timer.read();
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_PREPROCESSED")) {
            if (populated_preprocessed_coefficients == 0) return error.MissingPreprocessedCoefficients;
            if (prepared_state_cache_hit) {
                // The arena was zeroed and the validated immutable snapshot was
                // restored before any request-specific input was populated.
            } else if (staged_tree0 or restoring_tree0) {
                try arena_binding_mod.restorePreprocessedEvaluations(
                    allocator,
                    resident_arena,
                    schedule,
                    plan,
                    preprocessed_spill_path,
                );
                try arena_binding_mod.populateNamedInverseTwiddles(
                    allocator,
                    resident_arena,
                    schedule,
                    plan,
                    "PreprocessedInverseTwiddles",
                );
                preprocessed_gpu_ms += try arena_binding_mod.interpolateAvailablePreprocessedColumns(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                );
                try arena_binding_mod.restoreRetainedMerkleLayers(
                    allocator,
                    resident_arena,
                    schedule,
                    plan,
                    0,
                    tree0_merkle_path,
                );
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS")) {
                    if (memory_trace) |trace| {
                        try trace.populateRc99Lut(resident_arena);
                        std.debug.print("restored RC9_9 preprocessed table validated\n", .{});
                    }
                }
            } else {
                if (requested_commit_tree_count == 0)
                    try bindings.populateCommitmentTwiddles(allocator, resident_arena, plan, 0);
                preprocessed_gpu_ms += try arena_binding_mod.evaluatePreprocessedCoefficients(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    bindings.commitmentTwiddleStorage(plan, 0),
                );
            }
        }
        var base_inverse_twiddles_prepared = prepared_state_cache_hit and canonical_full_proof_plan;
        if (prepared_state_request) |request| {
            if (!prepared_state_cache_hit and canonical_full_proof_plan) {
                try bindings.populateCommitmentInverseTwiddles(allocator, resident_arena, plan, 1);
                base_inverse_twiddles_prepared = true;
            }
            if (!prepared_state_cache_hit) try request.cache.capture(metal, schedule, plan);
            const telemetry = request.cache.requestTelemetry();
            prepared_state_snapshot_bytes = telemetry.snapshot_bytes;
            prepared_state_capture_gpu_ms = telemetry.capture_gpu_ms;
        }
        RunnerPhaseTiming.addInterval(
            &runner_phase_timing.immutable_host_restore_wall_s,
            &runner_wall_timer,
            immutable_restore_started_ns,
        );
        const remaining_recipe_started_ns = runner_wall_timer.read();
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=aot_witness begin\n", .{});
        var local_witness: ?protocol_recipes.AotWitnessBatchRecipe = null;
        defer if (local_witness) |*recipe| recipe.deinit();
        const base_aot_witness_started_ns = runner_wall_timer.read();
        const witness = if (prepared_state_request) |request| witness_blk: {
            if (canonical_full_proof_plan) {
                if (prepared_state_cache_hit) {
                    base_aot_witness_cache_hit = true;
                    break :witness_blk try request.cache.borrowBaseAotWitness();
                }
                local_witness = try arena_binding_mod.prepareAotWitnessBatch(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    witness_bundle.?,
                    fixed_table_bundle.?,
                );
                break :witness_blk try request.cache.installBaseAotWitness(&local_witness);
            }
            local_witness = try arena_binding_mod.prepareAotWitnessBatch(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                witness_bundle.?,
                fixed_table_bundle.?,
            );
            break :witness_blk &local_witness.?;
        } else witness_blk: {
            local_witness = try arena_binding_mod.prepareAotWitnessBatch(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                witness_bundle.?,
                fixed_table_bundle.?,
            );
            break :witness_blk &local_witness.?;
        };
        RunnerPhaseTiming.addInterval(
            &recipe_preparation_timing.base_aot_witness_acquire_wall_s,
            &runner_wall_timer,
            base_aot_witness_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=aot_witness done\n", .{});
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=compact_verify begin\n", .{});
        const compact_verify_started_ns = runner_wall_timer.read();
        var local_compact_verify: ?protocol_recipes.CompactRecipe = null;
        defer if (local_compact_verify) |*recipe| recipe.deinit();
        const compact_verify: ?*protocol_recipes.CompactRecipe = if (!witness_recipe_requirements.verify_instruction)
            null
        else if (prepared_state_request) |request| compact_blk: {
            if (canonical_full_proof_plan) {
                if (prepared_state_cache_hit) {
                    compact_verify_recipe_cache_hit = true;
                    break :compact_blk try request.cache.borrowCompact(.verify_instruction);
                }
                local_compact_verify = try arena_binding_mod.prepareCompactWitnessInput(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    witness_bundle.?,
                    "verify_instruction",
                );
                break :compact_blk try request.cache.installCompact(.verify_instruction, &local_compact_verify);
            }
            local_compact_verify = try arena_binding_mod.prepareCompactWitnessInput(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                witness_bundle.?,
                "verify_instruction",
            );
            break :compact_blk &local_compact_verify.?;
        } else compact_blk: {
            local_compact_verify = try arena_binding_mod.prepareCompactWitnessInput(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                witness_bundle.?,
                "verify_instruction",
            );
            break :compact_blk &local_compact_verify.?;
        };
        RunnerPhaseTiming.addInterval(
            &recipe_preparation_timing.compact_verify_wall_s,
            &runner_wall_timer,
            compact_verify_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=compact_verify done\n", .{});
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=compact_pedersen begin\n", .{});
        const compact_pedersen_started_ns = runner_wall_timer.read();
        var local_compact_pedersen: ?protocol_recipes.CompactRecipe = null;
        defer if (local_compact_pedersen) |*recipe| recipe.deinit();
        const compact_pedersen: ?*protocol_recipes.CompactRecipe = if (!witness_recipe_requirements.pedersen)
            null
        else if (prepared_state_request) |request| compact_blk: {
            if (canonical_full_proof_plan) {
                if (prepared_state_cache_hit) {
                    compact_pedersen_recipe_cache_hit = true;
                    break :compact_blk try request.cache.borrowCompact(.pedersen);
                }
                local_compact_pedersen = try arena_binding_mod.prepareCompactWitnessInput(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    witness_bundle.?,
                    "pedersen_aggregator_window_bits_18",
                );
                break :compact_blk try request.cache.installCompact(.pedersen, &local_compact_pedersen);
            }
            local_compact_pedersen = try arena_binding_mod.prepareCompactWitnessInput(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                witness_bundle.?,
                "pedersen_aggregator_window_bits_18",
            );
            break :compact_blk &local_compact_pedersen.?;
        } else compact_blk: {
            local_compact_pedersen = try arena_binding_mod.prepareCompactWitnessInput(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                witness_bundle.?,
                "pedersen_aggregator_window_bits_18",
            );
            break :compact_blk &local_compact_pedersen.?;
        };
        RunnerPhaseTiming.addInterval(
            &recipe_preparation_timing.compact_pedersen_wall_s,
            &runner_wall_timer,
            compact_pedersen_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=compact_pedersen done\n", .{});
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=compact_poseidon begin\n", .{});
        const compact_poseidon_started_ns = runner_wall_timer.read();
        var local_compact_poseidon: ?protocol_recipes.CompactRecipe = null;
        defer if (local_compact_poseidon) |*recipe| recipe.deinit();
        const compact_poseidon: ?*protocol_recipes.CompactRecipe = if (!witness_recipe_requirements.poseidon)
            null
        else if (prepared_state_request) |request| compact_blk: {
            if (canonical_full_proof_plan) {
                if (prepared_state_cache_hit) {
                    compact_poseidon_recipe_cache_hit = true;
                    break :compact_blk try request.cache.borrowCompact(.poseidon);
                }
                local_compact_poseidon = try arena_binding_mod.prepareCompactWitnessInput(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    witness_bundle.?,
                    "poseidon_aggregator",
                );
                break :compact_blk try request.cache.installCompact(.poseidon, &local_compact_poseidon);
            }
            local_compact_poseidon = try arena_binding_mod.prepareCompactWitnessInput(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                witness_bundle.?,
                "poseidon_aggregator",
            );
            break :compact_blk &local_compact_poseidon.?;
        } else compact_blk: {
            local_compact_poseidon = try arena_binding_mod.prepareCompactWitnessInput(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                witness_bundle.?,
                "poseidon_aggregator",
            );
            break :compact_blk &local_compact_poseidon.?;
        };
        RunnerPhaseTiming.addInterval(
            &recipe_preparation_timing.compact_poseidon_wall_s,
            &runner_wall_timer,
            compact_poseidon_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=compact_poseidon done\n", .{});
        if (prover_input) |*adapted| {
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("prepare stage=ec_op_base begin\n", .{});
            const ec_op_base_started_ns = runner_wall_timer.read();
            var ec_op: ?protocol_recipes.EcOpRecipe = if (witness_recipe_requirements.ec_op)
                try arena_binding_mod.prepareEcOpWitness(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    adapted,
                    .base,
                )
            else
                null;
            defer if (ec_op) |*recipe| recipe.deinit();
            RunnerPhaseTiming.addInterval(
                &recipe_preparation_timing.ec_op_base_wall_s,
                &runner_wall_timer,
                ec_op_base_started_ns,
            );
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("prepare stage=ec_op_base done\n", .{});
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_WITNESS")) {
                if (!std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_BASE_INTERPOLATION"))
                    return error.MissingBaseInterpolation;
                if (!base_inverse_twiddles_prepared)
                    try bindings.populateCommitmentInverseTwiddles(allocator, resident_arena, plan, 1);
                const recorded_base_interpolation_started_ns = runner_wall_timer.read();
                var local_recorded_interpolation: ?arena_binding_mod.RecordedBaseInterpolationBatch = null;
                defer if (local_recorded_interpolation) |*recipe| recipe.deinit();
                const recorded_interpolation = if (prepared_state_request) |request| recorded_blk: {
                    if (canonical_full_proof_plan) {
                        if (prepared_state_cache_hit) {
                            recorded_base_interpolation_cache_hit = true;
                            break :recorded_blk try request.cache.borrowRecordedBaseInterpolation();
                        }
                        local_recorded_interpolation = try arena_binding_mod.prepareRecordedBaseInterpolation(
                            allocator,
                            metal,
                            resident_arena,
                            schedule,
                            plan,
                            &proof_plan.?,
                            bindings.commitmentTwiddleStorage(plan, 1),
                        );
                        break :recorded_blk try request.cache.installRecordedBaseInterpolation(
                            &local_recorded_interpolation,
                        );
                    }
                    local_recorded_interpolation = try arena_binding_mod.prepareRecordedBaseInterpolation(
                        allocator,
                        metal,
                        resident_arena,
                        schedule,
                        plan,
                        &proof_plan.?,
                        bindings.commitmentTwiddleStorage(plan, 1),
                    );
                    break :recorded_blk &local_recorded_interpolation.?;
                } else recorded_blk: {
                    local_recorded_interpolation = try arena_binding_mod.prepareRecordedBaseInterpolation(
                        allocator,
                        metal,
                        resident_arena,
                        schedule,
                        plan,
                        &proof_plan.?,
                        bindings.commitmentTwiddleStorage(plan, 1),
                    );
                    break :recorded_blk &local_recorded_interpolation.?;
                };
                RunnerPhaseTiming.addInterval(
                    &recipe_preparation_timing.recorded_base_interpolation_wall_s,
                    &runner_wall_timer,
                    recorded_base_interpolation_started_ns,
                );
                const native_base_interpolation_started_ns = runner_wall_timer.read();
                var local_native_interpolation: ?arena_binding_mod.NativeBaseInterpolationBatch = null;
                defer if (local_native_interpolation) |*recipe| recipe.deinit();
                const native_interpolation = if (prepared_state_request) |request| native_blk: {
                    if (canonical_full_proof_plan) {
                        if (prepared_state_cache_hit) {
                            native_base_interpolation_cache_hit = true;
                            break :native_blk try request.cache.borrowNativeBaseInterpolation();
                        }
                        local_native_interpolation = try arena_binding_mod.prepareNativeBaseInterpolation(
                            allocator,
                            metal,
                            resident_arena,
                            schedule,
                            plan,
                            fixed_table_bundle.?,
                            bindings.commitmentTwiddleStorage(plan, 1),
                        );
                        break :native_blk try request.cache.installNativeBaseInterpolation(
                            &local_native_interpolation,
                        );
                    }
                    local_native_interpolation = try arena_binding_mod.prepareNativeBaseInterpolation(
                        allocator,
                        metal,
                        resident_arena,
                        schedule,
                        plan,
                        fixed_table_bundle.?,
                        bindings.commitmentTwiddleStorage(plan, 1),
                    );
                    break :native_blk &local_native_interpolation.?;
                } else native_blk: {
                    local_native_interpolation = try arena_binding_mod.prepareNativeBaseInterpolation(
                        allocator,
                        metal,
                        resident_arena,
                        schedule,
                        plan,
                        fixed_table_bundle.?,
                        bindings.commitmentTwiddleStorage(plan, 1),
                    );
                    break :native_blk &local_native_interpolation.?;
                };
                RunnerPhaseTiming.addInterval(
                    &recipe_preparation_timing.native_base_interpolation_wall_s,
                    &runner_wall_timer,
                    native_base_interpolation_started_ns,
                );
                try arena_binding_mod.clearFixedMultiplicities(allocator, metal, resident_arena, schedule, plan);
                if (execute_proof) {
                    const prove_started_ns = runner_wall_timer.read();
                    runner_phase_timing.recipe_preparation_wall_s +=
                        nanosecondsToSeconds(prove_started_ns - remaining_recipe_started_ns);
                    prove_started_wall_s = nanosecondsToSeconds(prove_started_ns);
                    prove_timer = try std.time.Timer.start();
                }
                const recorded = try arena_binding_mod.executeScheduledWitnessGraph(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    &proof_plan.?,
                    witness_bundle.?,
                    witness,
                    .{
                        .compact_verify = compact_verify,
                        .compact_pedersen = compact_pedersen,
                        .compact_poseidon = compact_poseidon,
                        .ec_op = if (ec_op) |*recipe| recipe else null,
                    },
                    recorded_interpolation,
                    multiplicity_feeds,
                );
                executed_witness_programs = recorded.executed_programs;
                witness_graph_gpu_ms = recorded.writer_gpu_ms + recorded.input_gpu_ms;
                multiplicity_feed_gpu_ms = recorded.feed_gpu_ms;
                base_interpolation_gpu_ms = recorded.interpolation_gpu_ms;
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS")) std.debug.print(
                    "recorded_witness writer_gpu_ms={d:.6} input_gpu_ms={d:.6} feed_gpu_ms={d:.6} interpolation_gpu_ms={d:.6} programs={}\n",
                    .{
                        recorded.writer_gpu_ms,
                        recorded.input_gpu_ms,
                        recorded.feed_gpu_ms,
                        recorded.interpolation_gpu_ms,
                        recorded.executed_programs,
                    },
                );
                if (!std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_PREPROCESSED"))
                    return error.MissingPreprocessedEvaluations;
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_ADD_OPCODE_COEFF_DIGESTS"))
                    try logAddOpcodeCoefficientDigests(resident_arena, schedule, plan, "recorded_graph");
                const trace = if (memory_trace) |*value| value else return error.MissingMemoryTrace;
                try trace.populateRc99Lut(resident_arena);
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                    std.debug.print("base stage=rc99_lut done\n", .{});
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_ADD_OPCODE_COEFF_DIGESTS"))
                    try logAddOpcodeCoefficientDigests(resident_arena, schedule, plan, "rc99_lut");
                memory_public_seed_gpu_ms = try trace.seedPublicMemory(metal, resident_arena, adapted);
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                    std.debug.print("base stage=public_memory done\n", .{});
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_ADD_OPCODE_COEFF_DIGESTS"))
                    try logAddOpcodeCoefficientDigests(resident_arena, schedule, plan, "public_memory");
                memory_trace_gpu_ms = try trace.executeAddress(metal, resident_arena, adapted);
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                    std.debug.print("base stage=memory_address done\n", .{});
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_BASE_EVAL_DIGESTS"))
                    try arena_binding_mod.logComponentBaseEvalDigests(
                        resident_arena,
                        schedule,
                        plan,
                        "memory_address_to_id",
                    );
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_ADD_OPCODE_COEFF_DIGESTS"))
                    try logAddOpcodeCoefficientDigests(resident_arena, schedule, plan, "memory_address");
                base_interpolation_gpu_ms += try native_interpolation.interpolateMemoryAddress();
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                    std.debug.print("base stage=memory_address_ifft done\n", .{});
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_ADD_OPCODE_COEFF_DIGESTS"))
                    try logAddOpcodeCoefficientDigests(resident_arena, schedule, plan, "memory_address_ifft");
                const memory_values = try trace.executeValues(metal, resident_arena);
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                    std.debug.print("base stage=memory_values done\n", .{});
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_ADD_OPCODE_COEFF_DIGESTS"))
                    try logAddOpcodeCoefficientDigests(resident_arena, schedule, plan, "memory_values");
                memory_trace_gpu_ms += memory_values.trace_gpu_ms;
                memory_rc99_gpu_ms = memory_values.rc99_gpu_ms;
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_BASE_EVAL_DIGESTS"))
                    try arena_binding_mod.logComponentBaseEvalDigests(
                        resident_arena,
                        schedule,
                        plan,
                        "memory_id_to_big",
                    );
                base_interpolation_gpu_ms += try native_interpolation.interpolateMemoryValues();
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                    std.debug.print("base stage=memory_values_ifft done\n", .{});
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_ADD_OPCODE_COEFF_DIGESTS"))
                    try logAddOpcodeCoefficientDigests(resident_arena, schedule, plan, "memory_values_ifft");
                base_interpolation_gpu_ms += try native_interpolation.executeFixed(schedule, plan);
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                    std.debug.print("base stage=fixed_ifft done\n", .{});
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_ADD_OPCODE_COEFF_DIGESTS"))
                    try logAddOpcodeCoefficientDigests(resident_arena, schedule, plan, "fixed_ifft");
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_DUMP_ADD_OPCODE_COEFFICIENTS"))
                    try dumpAddOpcodeCoefficients(resident_arena, schedule, plan);
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_BASE_DIGESTS"))
                    try logPurposeDigests(resident_arena, schedule, plan, "BaseCoefficients");
            }
        }
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_BASE_INTERPOLATION")) {
            if (executed_witness_programs != witness_bundle.?.entries.len) return error.WitnessGraphNotExecuted;
            if (base_interpolation_gpu_ms == 0) return error.MissingBaseInterpolation;
        }
        if (requested_commit_tree_count > 1) {
            if (base_interpolation_gpu_ms == 0) return error.CommitmentInputsNotExecuted;
            try bindings.populateCommitmentTwiddles(allocator, resident_arena, plan, 1);
            const committed = try bindings.executeCommitment(
                metal,
                resident_arena,
                schedule,
                plan,
                1,
                blake2_merkle.Blake2sPlainMerkleHasher.leafSeed(),
                blake2_merkle.Blake2sPlainMerkleHasher.nodeSeed(),
            );
            commitment_gpu_ms += committed.gpu_ms;
            commitment_lde_gpu_ms += committed.lde_gpu_ms;
            commitment_leaf_gpu_ms += committed.leaf_gpu_ms;
            commitment_parent_gpu_ms += committed.parent_gpu_ms;
            var root: [32]u8 = undefined;
            @memcpy(&root, (try resident_arena.bytes(committed.root))[0..32]);
            commitment_roots[1] = root;
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("base tree1_root={x}\n", .{root});
        }
        if (staged_tree0_root) |root|
            try bindings.restoreCommitmentRoot(resident_arena, schedule, plan, 0, root);
        const transcript_recipe_started_ns = runner_wall_timer.read();
        var transcript = try bindings.prepareTranscript(metal, resident_arena);
        defer transcript.deinit();
        RunnerPhaseTiming.addInterval(
            &recipe_preparation_timing.transcript_wall_s,
            &runner_wall_timer,
            transcript_recipe_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_RELATIONS")) {
            if (requested_commit_tree_count < 3 or commitment_roots[0] == null or commitment_roots[1] == null)
                return error.CommitmentInputsNotExecuted;
            const adapted = if (prover_input) |*value| value else return error.MissingAdaptedInput;
            try bindings.populateCommitmentInverseTwiddles(allocator, resident_arena, plan, 2);
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("interaction_prepare stage=witness begin\n", .{});
            var local_interaction_witness: ?protocol_recipes.AotWitnessBatchRecipe = null;
            defer if (local_interaction_witness) |*recipe| recipe.deinit();
            const interaction_aot_witness_started_ns = runner_wall_timer.read();
            const interaction_witness = if (prepared_state_request) |request| interaction_blk: {
                if (canonical_full_proof_plan) {
                    if (prepared_state_cache_hit) {
                        interaction_aot_witness_cache_hit = true;
                        break :interaction_blk try request.cache.borrowInteractionAotWitness();
                    }
                    local_interaction_witness = try arena_binding_mod.prepareAotInteractionBatch(
                        allocator,
                        metal,
                        resident_arena,
                        schedule,
                        plan,
                        witness_bundle.?,
                        fixed_table_bundle.?,
                    );
                    break :interaction_blk try request.cache.installInteractionAotWitness(
                        &local_interaction_witness,
                    );
                }
                local_interaction_witness = try arena_binding_mod.prepareAotInteractionBatch(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    witness_bundle.?,
                    fixed_table_bundle.?,
                );
                break :interaction_blk &local_interaction_witness.?;
            } else interaction_blk: {
                local_interaction_witness = try arena_binding_mod.prepareAotInteractionBatch(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    witness_bundle.?,
                    fixed_table_bundle.?,
                );
                break :interaction_blk &local_interaction_witness.?;
            };
            RunnerPhaseTiming.addInterval(
                &recipe_preparation_timing.interaction_aot_witness_wall_s,
                &runner_wall_timer,
                interaction_aot_witness_started_ns,
            );
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("interaction_prepare stage=witness done\n", .{});
            const ec_op_interaction_started_ns = runner_wall_timer.read();
            var ec_lookup: ?protocol_recipes.EcOpRecipe = if (witness_recipe_requirements.ec_op)
                try arena_binding_mod.prepareEcOpWitness(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    adapted,
                    .lookup,
                )
            else
                null;
            defer if (ec_lookup) |*recipe| recipe.deinit();
            RunnerPhaseTiming.addInterval(
                &recipe_preparation_timing.ec_op_interaction_wall_s,
                &runner_wall_timer,
                ec_op_interaction_started_ns,
            );
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("interaction_prepare stage=ec_lookup done\n", .{});
            const relation_components_started_ns = runner_wall_timer.read();
            var relations = try bindings.prepareRelationComponents(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                relation_bundle.?,
                witness_bundle.?,
                bindings.commitmentTwiddleStorage(plan, 2),
            );
            defer relations.deinit();
            RunnerPhaseTiming.addInterval(
                &recipe_preparation_timing.relation_components_wall_s,
                &runner_wall_timer,
                relation_components_started_ns,
            );
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("interaction_prepare stage=relations done\n", .{});
            const interaction_native_interpolation_started_ns = runner_wall_timer.read();
            var interaction_native = try arena_binding_mod.prepareNativeBaseInterpolation(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                fixed_table_bundle.?,
                bindings.commitmentTwiddleStorage(plan, 2),
            );
            defer interaction_native.deinit();
            RunnerPhaseTiming.addInterval(
                &recipe_preparation_timing.interaction_native_interpolation_wall_s,
                &runner_wall_timer,
                interaction_native_interpolation_started_ns,
            );
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("interaction_prepare stage=native done\n", .{});
            if (statement_bootstrap) |*statement| {
                try statement.populateTranscriptRecipeInputs(&transcript);
                statement_self_derived = true;
                if (transcript_reference_path) |reference_path|
                    try arena_binding_mod.validateTranscriptBootstrap(
                        allocator,
                        resident_arena,
                        schedule,
                        plan,
                        reference_path,
                        .{ .validate_commitment_roots = true },
                    );
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                    std.debug.print(
                        "interaction_prepare stage=statement_bootstrap source=self_derived parity={s}\n",
                        .{if (transcript_reference_path != null) "exact" else "unchecked"},
                    );
            } else if (transcript_reference_path) |reference_path| {
                try arena_binding_mod.restoreTranscriptBootstrap(
                    allocator,
                    resident_arena,
                    schedule,
                    plan,
                    reference_path,
                );
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                    std.debug.print("interaction_prepare stage=transcript_reference_bootstrap fallback=true\n", .{});
            } else {
                if (std.process.getEnvVarOwned(allocator, "STWO_ZIG_SN2_TRANSCRIPT_BOOTSTRAP")) |bootstrap_path| {
                    defer allocator.free(bootstrap_path);
                    legacy_transcript_bootstrap_used = true;
                    parity_fixture_used = true;
                    try arena_binding_mod.restoreTranscriptBootstrap(
                        allocator,
                        resident_arena,
                        schedule,
                        plan,
                        bootstrap_path,
                    );
                    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                        std.debug.print("interaction_prepare stage=transcript_bootstrap done\n", .{});
                } else |err| switch (err) {
                    error.EnvironmentVariableNotFound => {},
                    else => return err,
                }
            }
            try transcript.initialize();
            try transcript.bootstrapThroughBase();
            const interaction_pow = if (transcript_reference) |fixture| blk: {
                try transcript.interactionPowAndLookupNonce(fixture.interaction_nonce);
                try transcript.expectOutputWords(1, &fixture.expected_output_1);
                break :blk fixture.interaction_nonce;
            } else try transcript.interactionPowAndLookup();
            interaction_pow_nonce = interaction_pow;
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("transcript interaction_pow={d}\n", .{interaction_pow});
            try bindings.materializeRelationChallenges(resident_arena);
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_RESTORE_REFERENCE_RELATION_CHALLENGES"))
                try bindings.restoreRelationChallenges(
                    resident_arena,
                    .{ 23353985, 545987341, 122919781, 2037762338 },
                    .{ 738082848, 31333331, 241479621, 1778656766 },
                );
            const recorded = try arena_binding_mod.executeScheduledInteractionGraph(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                &proof_plan.?,
                witness_bundle.?,
                adapted,
                interaction_witness,
                .{
                    .compact_verify = compact_verify,
                    .compact_pedersen = compact_pedersen,
                    .compact_poseidon = compact_poseidon,
                    .ec_op = if (ec_lookup) |*recipe| recipe else null,
                },
                &relations,
            );
            interaction_witness_gpu_ms += recorded.writer_gpu_ms + recorded.input_gpu_ms;
            relation_gpu_ms += recorded.relation_gpu_ms;
            interaction_interpolation_gpu_ms += recorded.interpolation_gpu_ms;
            var executed_relations = recorded.executed_relations;

            // Native relation components follow the recorded proof DAG in the
            // staged tick order. Each source is rebuilt, related, and IFFT'd
            // before the next component can reuse its trace allocation.
            for (relations.operations) |operation| {
                if (proof_plan.?.componentIndex(operation.component) != null or
                    std.mem.eql(u8, operation.component, "ec_op_builtin")) continue;
                if (std.mem.eql(u8, operation.component, "memory_address_to_id")) {
                    const trace = if (memory_trace) |*value| value else return error.MissingMemoryTrace;
                    interaction_witness_gpu_ms += try trace.executeAddress(metal, resident_arena, adapted);
                } else if (std.mem.eql(u8, operation.component, "memory_id_to_big")) {
                    const trace = if (memory_trace) |*value| value else return error.MissingMemoryTrace;
                    interaction_witness_gpu_ms += try trace.executeValueTraces(metal, resident_arena);
                } else {
                    const fixed_entry = fixed_table_bundle.?.find(operation.component) orelse return error.MissingFixedTable;
                    var needs_lookup = false;
                    var needs_base = false;
                    const relation_component = relation_bundle.?.find(operation.component) orelse return error.MissingRelation;
                    for (relation_component.traces) |trace| {
                        needs_lookup = needs_lookup or trace.layout == .lookup_words;
                        needs_base = needs_base or trace.layout != .lookup_words;
                    }
                    if (needs_lookup) {
                        const fixed_index = try arena_binding_mod.fixedLookupIndex(
                            schedule,
                            plan,
                            fixed_table_bundle.?,
                            operation.component,
                        ) orelse return error.MissingFixedTable;
                        const before = fixed_tables.accumulated_gpu_ms;
                        try fixed_tables.executeIndex(fixed_index);
                        interaction_witness_gpu_ms += fixed_tables.accumulated_gpu_ms - before;
                    }
                    if (needs_base)
                        interaction_witness_gpu_ms += try interaction_native.materializeFixed(fixed_entry.component);
                }
                const native = try relations.executeComponent(operation.component);
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_INTERACTION_EVAL_DIGESTS"))
                    try arena_binding_mod.logComponentInteractionDigests(
                        allocator,
                        resident_arena,
                        schedule,
                        plan,
                        operation.component,
                    );
                relation_gpu_ms += native.relation_gpu_ms;
                interaction_interpolation_gpu_ms += native.interpolation_gpu_ms;
                executed_relations += 1;
            }
            if (executed_relations != relations.operations.len) return error.RelationGraphNotExecuted;
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_TRACE_COLUMN_613"))
                try arena_binding_mod.logLogicalBindingDigest(
                    resident_arena,
                    plan,
                    1737,
                    "after_all_relations",
                );
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_RELATION_DIAGNOSTICS"))
                try bindings.logRelationDiagnostics(resident_arena, relations);
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_REPAIR_COLUMN_613_LDE")) {
                const file = try std.fs.createFileAbsolute("/tmp/sn2-column613-before-publish.u32le", .{});
                defer file.close();
                try file.writeAll(try resident_arena.bytes(plan.binding(1737) catch return error.MissingBinding));
            }
            try bindings.publishInteractionClaim(resident_arena, schedule, plan);
            if (transcript_reference) |fixture|
                try transcript.expectInputWords(22, fixture.input_22);
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_REPAIR_COLUMN_613_LDE")) {
                const file = try std.fs.createFileAbsolute("/tmp/sn2-column613-after-publish.u32le", .{});
                defer file.close();
                try file.writeAll(try resident_arena.bytes(plan.binding(1737) catch return error.MissingBinding));
            }
            try bindings.populateCommitmentTwiddles(allocator, resident_arena, plan, 2);
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_REPAIR_COLUMN_613_LDE")) {
                const file = try std.fs.createFileAbsolute("/tmp/sn2-column613-pre-commit-source.u32le", .{});
                defer file.close();
                try file.writeAll(try resident_arena.bytes(plan.binding(1737) catch return error.MissingBinding));
            }
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_INTERACTION_COEFF_DIGESTS"))
                try arena_binding_mod.logInteractionCoefficientDigests(
                    resident_arena,
                    schedule,
                    plan,
                    "before_commit",
                );
            const committed = try bindings.executeCommitment(
                metal,
                resident_arena,
                schedule,
                plan,
                2,
                blake2_merkle.Blake2sPlainMerkleHasher.leafSeed(),
                blake2_merkle.Blake2sPlainMerkleHasher.nodeSeed(),
            );
            commitment_gpu_ms += committed.gpu_ms;
            commitment_lde_gpu_ms += committed.lde_gpu_ms;
            commitment_leaf_gpu_ms += committed.leaf_gpu_ms;
            commitment_parent_gpu_ms += committed.parent_gpu_ms;
            var root: [32]u8 = undefined;
            @memcpy(&root, (try resident_arena.bytes(committed.root))[0..32]);
            commitment_roots[2] = root;
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("interaction tree2_root={x}\n", .{root});
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("interaction stage=tree2_commit done\n", .{});
            if (transcript_reference) |fixture|
                try transcript.expectInputWords(22, fixture.input_22);
            if (transcript_reference) |fixture|
                try transcript.expectInputWords(23, &fixture.input_23);
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_REPLAY_TRANSCRIPT_AFTER_TREE2")) {
                const fixture = transcript_reference orelse return error.MissingTranscriptReference;
                try transcript.initialize();
                try transcript.bootstrapThroughBase();
                try transcript.interactionPowAndLookupNonce(fixture.interaction_nonce);
                try transcript.expectOutputWords(1, &fixture.expected_output_1);
            }
            try transcript.interactionAndComposition();
            if (transcript_reference) |fixture|
                try transcript.expectOutputWords(2, &fixture.expected_output_2);
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("interaction stage=transcript done\n", .{});
            transcript_gpu_ms = transcript.accumulated_gpu_ms;
            interaction_pow_wall_s = transcript.interaction_pow.wallSeconds();
            interaction_pow_mode = transcript.interaction_pow.modeName();
            interaction_pow_invocations = transcript.interaction_pow.invocations;
            if (interaction_pow_invocations != 0)
                interaction_pow_bits = transcript.interaction_pow.pow_bits;
        }
        const prepare_full_protocol = !std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_WITNESS");
        if (prepare_full_protocol or execute_composition) {
            const composition_path = args[7];
            if (!std.mem.endsWith(u8, composition_path, ".bin")) return error.InvalidCompositionPath;
            try arena_binding_mod.populateNamedInverseTwiddles(
                allocator,
                resident_arena,
                schedule,
                plan,
                "InverseTwiddles",
            );
            const composition_metallib = try std.fmt.allocPrint(
                allocator,
                "{s}.metallib",
                .{composition_path[0 .. composition_path.len - ".bin".len]},
            );
            defer allocator.free(composition_metallib);
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("composition_prepare begin\n", .{});
            const composition_recipe_started_ns = runner_wall_timer.read();
            var composition = try bindings.prepareComposition(
                allocator,
                metal,
                resident_arena,
                composition_bundle.?,
                composition_metallib,
            );
            defer composition.deinit();
            RunnerPhaseTiming.addInterval(
                &recipe_preparation_timing.composition_wall_s,
                &runner_wall_timer,
                composition_recipe_started_ns,
            );
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("composition_prepare done\n", .{});
            if (execute_composition) {
                if (requested_commit_tree_count < 4 or commitment_roots[2] == null)
                    return error.CommitmentInputsNotExecuted;
                if (!composition.isComplete() and
                    (execute_quotient or std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_OODS")))
                    return error.PartialCompositionCannotContinue;
                try composition.execute();
                composition_gpu_ms = composition.accumulated_gpu_ms;
                if (composition.isComplete()) {
                    try bindings.populateCommitmentTwiddles(allocator, resident_arena, plan, 3);
                    const committed = try bindings.executeCommitment(
                        metal,
                        resident_arena,
                        schedule,
                        plan,
                        3,
                        blake2_merkle.Blake2sPlainMerkleHasher.leafSeed(),
                        blake2_merkle.Blake2sPlainMerkleHasher.nodeSeed(),
                    );
                    commitment_gpu_ms += committed.gpu_ms;
                    commitment_lde_gpu_ms += committed.lde_gpu_ms;
                    commitment_leaf_gpu_ms += committed.leaf_gpu_ms;
                    commitment_parent_gpu_ms += committed.parent_gpu_ms;
                    var root: [32]u8 = undefined;
                    @memcpy(&root, (try resident_arena.bytes(committed.root))[0..32]);
                    commitment_roots[3] = root;
                    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                        std.debug.print("composition tree3_root={x}\n", .{root});
                    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                        std.debug.print("composition stage=tree3_commit done\n", .{});
                    try transcript.compositionAndOods();
                    if (transcript_reference) |fixture|
                        try transcript.expectOutputWords(3, &fixture.expected_output_3);
                    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                        std.debug.print("composition stage=transcript done\n", .{});
                } else if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS")) {
                    std.debug.print("composition stage=partial_front done\n", .{});
                }
                if (composition.isComplete() and std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_OODS")) {
                    var oods_input: ?arena.Binding = null;
                    for (bindings.transcript_inputs) |transcript_input| if (transcript_input.ordinal == 25) {
                        oods_input = transcript_input.binding;
                        break;
                    };
                    const oods = try cairo_oods.populate(
                        allocator,
                        metal,
                        resident_arena,
                        composition_bundle.?,
                        bindings.preprocessed_coefficients,
                        bindings.canonical_base_coefficients,
                        bindings.canonical_interaction_coefficients,
                        bindings.composition_coefficients,
                        try transcript.output(3),
                        oods_input orelse return error.MissingTranscriptInput,
                    );
                    if (transcript_reference) |fixture|
                        try transcript.expectInputWords(25, fixture.input_25);
                    try transcript.oodsAndQuotient();
                    if (transcript_reference) |fixture|
                        try transcript.expectOutputWords(4, &fixture.expected_output_4);
                    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                        std.debug.print(
                            "oods stage=evaluate samples={} columns={} wall_ms={d:.3} gpu_ms={d:.3} parity={s}\n",
                            .{
                                oods.sample_count,
                                oods.column_count,
                                oods.wall_ms,
                                oods.gpu_ms,
                                if (transcript_reference != null) "exact" else "unchecked",
                            },
                        );
                } else if (composition.isComplete() and execute_quotient) {
                    const fixture = transcript_reference orelse return error.MissingTranscriptReference;
                    try transcript.loadInputWords(25, fixture.input_25);
                    try transcript.oodsAndQuotient();
                    try transcript.expectOutputWords(4, &fixture.expected_output_4);
                    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                        std.debug.print(
                            "oods stage=reference_transcript samples={} parity=exact fixture_only=true\n",
                            .{fixture.input_25.len / 4},
                        );
                }
                if (composition.isComplete()) transcript_gpu_ms = transcript.accumulated_gpu_ms;
            }
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("quotient_prepare begin\n", .{});
            const quotient_recipe_started_ns = runner_wall_timer.read();
            var quotient = try bindings.prepareQuotient(allocator, metal, resident_arena);
            defer quotient.deinit();
            RunnerPhaseTiming.addInterval(
                &recipe_preparation_timing.quotient_wall_s,
                &runner_wall_timer,
                quotient_recipe_started_ns,
            );
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("quotient_prepare done\n", .{});
            if (execute_quotient) {
                const quotient_reference_path = std.process.getEnvVarOwned(
                    allocator,
                    "STWO_ZIG_SN2_QUOTIENT_REFERENCE",
                ) catch |err| switch (err) {
                    error.EnvironmentVariableNotFound => null,
                    else => return err,
                };
                defer if (quotient_reference_path) |path| allocator.free(path);
                if (quotient_reference_path != null) parity_fixture_used = true;
                const quotient_inputs = try cairo_quotient_inputs.populate(
                    allocator,
                    metal,
                    resident_arena,
                    composition_bundle.?,
                    bindings.preprocessed_coefficients,
                    bindings.canonical_base_coefficients,
                    bindings.canonical_interaction_coefficients,
                    bindings.composition_coefficients,
                    try transcript.output(3),
                    try transcript.output(4),
                    try transcriptInputBinding(bindings, 25),
                    bindings.quotient_partials,
                    bindings.quotient_sample_points,
                    bindings.quotient_first_linear_terms,
                    bindings.forward_twiddles,
                );
                const reference: ?cairo_quotient_reference.ReferenceValidation = if (quotient_reference_path) |path|
                    try cairo_quotient_reference.validateReferenceFixture(
                        allocator,
                        resident_arena,
                        composition_bundle.?,
                        bindings.quotient_partials,
                        bindings.quotient_sample_points,
                        bindings.quotient_first_linear_terms,
                        bindings.quotient_subdomain_values,
                        bindings.quotient_tile,
                        path,
                    )
                else
                    null;
                // Quotient input materialization reuses the epoch-local arena
                // aggressively. Restore the split-domain protocol constant at
                // its final consumption boundary so no transient input kernel
                // can clobber it before the IFFT.
                try arena_binding_mod.populateQuotientInverseTwiddles(
                    allocator,
                    resident_arena,
                    schedule,
                    plan,
                );
                try quotient.execute();
                quotient_gpu_ms = quotient.accumulated_gpu_ms;
                quotient_executed = true;
                if (reference) |expected| {
                    const actual_digest = blake2_hash.Blake2sHasher.hash(
                        try resident_arena.bytes(bindings.quotient_tile),
                    );
                    if (!std.mem.eql(u8, &actual_digest, &expected.quotient_digest)) {
                        std.debug.print(
                            "quotient stage=final_digest mismatch expected={x} actual={x}\n",
                            .{ expected.quotient_digest, actual_digest },
                        );
                        return error.QuotientParityMismatch;
                    }
                    quotient_reference_parity = true;
                    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                        std.debug.print(
                            "quotient stage=inputs wall_ms={d:.3} gpu_ms={d:.3} samples={} columns={} scanned_words={} reference_bytes={} parity=exact\n" ++
                                "quotient stage=execute gpu_ms={d:.3} blake2s={x} parity=exact\n",
                            .{
                                quotient_inputs.wall_ms,
                                quotient_inputs.gpu_ms,
                                quotient_inputs.sample_count,
                                quotient_inputs.column_count,
                                quotient_inputs.source_words_scanned,
                                expected.payload_bytes,
                                quotient_gpu_ms,
                                actual_digest,
                            },
                        );
                } else if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS")) {
                    std.debug.print(
                        "quotient stage=inputs wall_ms={d:.3} gpu_ms={d:.3} samples={} columns={} scanned_words={} parity=unchecked\n" ++
                            "quotient stage=execute gpu_ms={d:.3} parity=unchecked\n",
                        .{
                            quotient_inputs.wall_ms,
                            quotient_inputs.gpu_ms,
                            quotient_inputs.sample_count,
                            quotient_inputs.column_count,
                            quotient_inputs.source_words_scanned,
                            quotient_gpu_ms,
                        },
                    );
                }
            }
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("fri_prepare begin\n", .{});
            // Composition and quotient may reuse the sparse arena range that
            // holds this protocol constant. Restore it at the FRI boundary
            // without perturbing the established arena placement.
            try arena_binding_mod.populateNamedInverseTwiddles(
                allocator,
                resident_arena,
                schedule,
                plan,
                "InverseTwiddles",
            );
            const fri_recipe_started_ns = runner_wall_timer.read();
            var fri = try bindings.prepareFri(
                metal,
                resident_arena,
                blake2_merkle.Blake2sPlainMerkleHasher.leafSeed(),
                blake2_merkle.Blake2sPlainMerkleHasher.nodeSeed(),
            );
            defer fri.deinit();
            RunnerPhaseTiming.addInterval(
                &recipe_preparation_timing.fri_wall_s,
                &runner_wall_timer,
                fri_recipe_started_ns,
            );
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("fri_prepare done\n", .{});
            if (execute_fri) {
                if (!quotient_executed) return error.QuotientRequired;
                if (transcript_reference) |fixture| {
                    if (fixture.fri_inputs.len != bindings.decommit_fri_trees.len)
                        return error.InvalidTranscriptReference;
                }
                for (0..bindings.decommit_fri_trees.len) |round| {
                    const root_binding = try fri.commitTree(round);
                    var root: [32]u8 = undefined;
                    @memcpy(&root, (try resident_arena.bytes(root_binding))[0..32]);
                    fri_roots[round] = root;
                    try transcript.friLayer(@intCast(round), root_binding, bindings.fri_challenges[round]);
                    if (transcript_reference) |fixture|
                        try transcript.expectInputWords(
                            @intCast(65536 + round * 4),
                            &fixture.fri_inputs[round],
                        );
                    try fri.foldRound(round);
                    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                        std.debug.print("fri round={} root={x}\n", .{ round, root });
                }
                try fri.finalize();
                fri_final_degree_valid = true;
                try transcript.lastLayer(bindings.fri_final_coefficients);
                if (transcript_reference) |fixture|
                    try transcript.expectInputWords(30, &fixture.input_30);
                fri_gpu_ms = fri.accumulated_gpu_ms;
                transcript_gpu_ms = transcript.accumulated_gpu_ms;
                fri_executed = true;
                fri_reference_parity = transcript_reference != null;
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                    std.debug.print(
                        "fri stage=execute gpu_ms={d:.3} roots={} final_degree=valid parity={s}\n",
                        .{ fri_gpu_ms, bindings.decommit_fri_trees.len, if (fri_reference_parity) "exact" else "unchecked" },
                    );
            }
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("decommit_prepare begin\n", .{});
            const decommit_queries_started_ns = runner_wall_timer.read();
            var decommit_queries = try bindings.prepareDecommitQueries(metal, resident_arena);
            RunnerPhaseTiming.addInterval(
                &recipe_preparation_timing.decommit_queries_wall_s,
                &runner_wall_timer,
                decommit_queries_started_ns,
            );
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("decommit_prepare done\n", .{});
            if (execute_decommit) {
                if (!fri_executed or !fri_final_degree_valid) return error.FriRequired;
                const nonce = if (transcript_reference) |fixture| blk: {
                    try transcript.queryPowAndPositionsNonce(fixture.query_nonce);
                    try transcript.expectInputWords(31, &fixture.input_31);
                    break :blk fixture.query_nonce;
                } else try transcript.queryPowAndPositions();
                query_pow_nonce = nonce;
                query_pow_wall_s = transcript.query_pow.wallSeconds();
                query_pow_mode = transcript.query_pow.modeName();
                query_pow_invocations = transcript.query_pow.invocations;
                if (query_pow_invocations != 0)
                    query_pow_bits = transcript.query_pow.pow_bits;
                decommit_lde_gpu_ms = try bindings.executeDecommit(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    &decommit_queries,
                    blake2_merkle.Blake2sPlainMerkleHasher.leafSeed(),
                    blake2_merkle.Blake2sPlainMerkleHasher.nodeSeed(),
                );
                decommit_gpu_ms = decommit_queries.accumulated_gpu_ms;
                transcript_gpu_ms = transcript.accumulated_gpu_ms;
                decommit_executed = true;
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                    std.debug.print(
                        "decommit stage=execute query_nonce={} lde_gpu_ms={d:.3} gpu_ms={d:.3} parity={s}\n",
                        .{
                            nonce,
                            decommit_lde_gpu_ms,
                            decommit_gpu_ms,
                            if (transcript_reference != null) "exact" else "unchecked",
                        },
                    );
            }
            const proof_assembly_started_ns = runner_wall_timer.read();
            var assembly = try bindings.prepareProofAssembly(allocator, metal, resident_arena);
            defer assembly.deinit();
            RunnerPhaseTiming.addInterval(
                &recipe_preparation_timing.proof_assembly_wall_s,
                &runner_wall_timer,
                proof_assembly_started_ns,
            );
            if (execute_proof) {
                if (!decommit_executed) return error.DecommitmentRequired;
                try assembly.execute();
                proof_assembly_gpu_ms = assembly.accumulated_gpu_ms;
                const proof_words = try assembly.words();
                const interaction_claim_words = std.math.cast(
                    usize,
                    (try transcriptInputBinding(bindings, 22)).size_bytes / 4,
                ) orelse return error.InvalidProofLayout;
                const sampled_value_words = std.math.cast(
                    usize,
                    (try transcriptInputBinding(bindings, 25)).size_bytes / 4,
                ) orelse return error.InvalidProofLayout;
                const decommitment_capacity_words = std.math.cast(
                    usize,
                    bindings.decommit_assembly.size_bytes / 4,
                ) orelse return error.InvalidProofLayout;
                const layout = try proof_bundle.Layout.init(
                    interaction_claim_words,
                    sampled_value_words,
                    bindings.decommit_fri_trees.len,
                    std.math.cast(usize, (try transcriptInputBinding(bindings, 30)).size_bytes / 4) orelse
                        return error.InvalidProofLayout,
                    decommitment_capacity_words,
                );
                var decoded = try proof_bundle.ProofBundle.decode(allocator, proof_words, layout);
                defer decoded.deinit(allocator);
                proof_bundle_valid = true;
                proof_layout = .{
                    .interaction_claim_words = interaction_claim_words,
                    .sampled_value_words = sampled_value_words,
                    .decommitment_capacity_words = decommitment_capacity_words,
                };
                const proof_output_path = try std.process.getEnvVarOwned(
                    allocator,
                    "STWO_ZIG_SN2_PROOF_OUTPUT",
                );
                defer allocator.free(proof_output_path);
                const proof_file = try std.fs.createFileAbsolute(proof_output_path, .{ .exclusive = true });
                defer proof_file.close();
                try proof_file.writeAll(std.mem.sliceAsBytes(proof_words));
                proof_output_bytes = proof_words.len * 4;
                proof_assembled = true;
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_VERIFY_PROOF")) {
                    const verify_ordinals = [_]u32{ 1, 2, 3, 10, 11, 12, 13, 14, 15, 16, 20 };
                    var verify_inputs: [verify_ordinals.len]resident_verifier.TranscriptInput = undefined;
                    var verifier_config_words: ?[]const u32 = null;
                    for (verify_ordinals, &verify_inputs) |ordinal, *verify_input| {
                        const binding = try transcriptInputBinding(bindings, ordinal);
                        const bytes: []align(4) u8 = @alignCast(try resident_arena.bytes(binding));
                        verify_input.* = .{ .ordinal = ordinal, .words = std.mem.bytesAsSlice(u32, bytes) };
                        if (ordinal == 2) verifier_config_words = verify_input.words;
                    }
                    const preprocessed_logs = try bindingDegreeLogs(allocator, bindings.preprocessed_coefficients);
                    defer allocator.free(preprocessed_logs);
                    const base_logs = try bindingDegreeLogs(allocator, bindings.canonical_base_coefficients);
                    defer allocator.free(base_logs);
                    const interaction_logs = try bindingDegreeLogs(allocator, bindings.canonical_interaction_coefficients);
                    defer allocator.free(interaction_logs);
                    const verifier_geometry = try runtimeVerifierGeometry(
                        verifier_config_words orelse return error.MissingTranscriptInput,
                        composition_bundle.?,
                    );
                    try resident_verifier.verifyRuntime(allocator, .{
                        .bundle = decoded,
                        .composition = composition_bundle.?,
                        .tree_logs = .{ preprocessed_logs, base_logs, interaction_logs },
                        .transcript_inputs = &verify_inputs,
                        .statement = if (prover_input) |*p| p else return error.MissingAdaptedInput,
                    }, verifier_geometry);
                    proof_verified = true;
                    const prove_elapsed_ns = if (prove_timer) |*timer|
                        timer.read()
                    else
                        return error.MissingProveTimer;
                    prove_wall_s = @as(f64, @floatFromInt(prove_elapsed_ns)) /
                        @as(f64, @floatFromInt(std.time.ns_per_s));
                    proof_verified_wall_s = nanosecondsToSeconds(runner_wall_timer.read());
                }
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                    std.debug.print(
                        "proof stage=assemble gpu_ms={d:.3} bytes={} bundle_valid=true verified={s}\n",
                        .{ proof_assembly_gpu_ms, proof_output_bytes, if (proof_verified) "true" else "false" },
                    );
            }
            resident_prepare_gate = "passed_full_arena_and_protocol_plans";
        } else {
            resident_prepare_gate = "passed_requested_protocol_prefix";
        }
    }
    const missing_names = try allocator.alloc([]const u8, missing_components.count());
    defer allocator.free(missing_names);
    var missing_iterator = missing_components.keyIterator();
    var missing_index: usize = 0;
    while (missing_iterator.next()) |name| : (missing_index += 1) missing_names[missing_index] = name.*;
    std.mem.sortUnstable([]const u8, missing_names, {}, struct {
        fn lessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
            return std.mem.order(u8, lhs, rhs) == .lt;
        }
    }.lessThan);
    const missing_lookup_names = try allocator.alloc([]const u8, missing_lookup_components.count());
    defer allocator.free(missing_lookup_names);
    var missing_lookup_iterator = missing_lookup_components.keyIterator();
    var missing_lookup_index: usize = 0;
    while (missing_lookup_iterator.next()) |name| : (missing_lookup_index += 1) missing_lookup_names[missing_lookup_index] = name.*;
    std.mem.sortUnstable([]const u8, missing_lookup_names, {}, struct {
        fn lessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
            return std.mem.order(u8, lhs, rhs) == .lt;
        }
    }.lessThan);
    var resident: usize = 0;
    var spilled: usize = 0;
    var recomputed: usize = 0;
    var spill_snapshot_bytes: u64 = 0;
    var recompute_snapshot_bytes: u64 = 0;
    var spill_by_purpose = std.ArrayList(PurposeStat).empty;
    defer spill_by_purpose.deinit(allocator);
    for (plan.bindings) |binding| switch (binding.materialization) {
        .resident => resident += 1,
        .spill => {
            spilled += 1;
            spill_snapshot_bytes += binding.size_bytes;
            const purpose = schedule[binding.logical_id].object.get("purpose").?.string;
            var stat: ?*PurposeStat = null;
            for (spill_by_purpose.items) |*candidate| {
                if (std.mem.eql(u8, candidate.purpose, purpose)) {
                    stat = candidate;
                    break;
                }
            }
            if (stat == null) {
                try spill_by_purpose.append(allocator, .{ .purpose = purpose });
                stat = &spill_by_purpose.items[spill_by_purpose.items.len - 1];
            }
            stat.?.buffers += 1;
            stat.?.bytes += binding.size_bytes;
        },
        .recompute => {
            recomputed += 1;
            recompute_snapshot_bytes += binding.size_bytes;
        },
    };
    std.mem.sortUnstable(PurposeStat, spill_by_purpose.items, {}, struct {
        fn lessThan(_: void, lhs: PurposeStat, rhs: PurposeStat) bool {
            if (lhs.bytes != rhs.bytes) return lhs.bytes > rhs.bytes;
            return std.mem.order(u8, lhs.purpose, rhs.purpose) == .lt;
        }
    }.lessThan);
    const runner_before_report_wall_s = nanosecondsToSeconds(runner_wall_timer.read());
    const runner_phase_report = runner_phase_timing.report(
        runner_before_report_wall_s,
        prove_started_wall_s,
        proof_verified_wall_s,
        prove_wall_s,
    );
    const recipe_preparation_report = recipe_preparation_timing.report(prove_wall_s);
    const result = .{
        .schema_version = 1,
        .protocol = canonical_protocol,
        .protocol_complete = true,
        .planner = "zig-metal-sparse-epochs-v1",
        .schedule_policy = "protocol-purpose-v1-global-phase-conservative",
        .source = args[1],
        .source_sha256 = input_sha256,
        .logical_buffers = plan.bindings.len,
        .component_subepochs = component_ids.count(),
        .canonical_witness_programs = if (witness_bundle) |bundle| bundle.entries.len else 0,
        .native_feed_producers = if (feed_bundle) |bundle| bundle.feeds.len else 0,
        .native_feed_destinations = native_destinations.count(),
        .relation_graph_hash = if (relation_bundle) |bundle| bundle.graph_hash else 0,
        .relation_instances = if (relation_coverage) |coverage| coverage.instances else 0,
        .relation_output_buffers = if (relation_coverage) |coverage| coverage.output_buffers else 0,
        .relation_output_bytes = if (relation_coverage) |coverage| coverage.output_bytes else 0,
        .fixed_table_graph_hash = if (fixed_table_bundle) |bundle| bundle.graph_hash else 0,
        .fixed_table_components = if (fixed_table_coverage) |coverage| coverage.components else 0,
        .fixed_table_lookup_buffers = if (fixed_table_coverage) |coverage| coverage.lookup_buffers else 0,
        .fixed_table_lookup_bytes = if (fixed_table_coverage) |coverage| coverage.lookup_bytes else 0,
        .ec_op_rows = ec_op_coverage.rows,
        .ec_op_output_buffers = ec_op_coverage.output_buffers,
        .ec_op_output_bytes = ec_op_coverage.output_bytes,
        .composition_plan_hash = if (composition_bundle) |bundle| bundle.plan_hash else 0,
        .composition_recipe_components = if (composition_coverage) |coverage| coverage.components else 0,
        .composition_recipe_parts = if (composition_coverage) |coverage| coverage.parts else 0,
        .composition_recipe_buffers = if (composition_coverage) |coverage| coverage.output_buffers else 0,
        .composition_recipe_bytes = if (composition_coverage) |coverage| coverage.output_bytes else 0,
        .composition_radix4 = (try metal_runtime.compositionLdeOptionsFromEnvironment()).radix4,
        .prepared_proof_bindings = if (proof_bindings) |bindings| bindings.assembly.len else 0,
        .prepared_proof_copy_ranges = if (proof_bindings) |bindings| bindings.proof_copies.len else 0,
        .prepared_proof_words = if (proof_bindings) |bindings| bindings.proof_bytes.size_bytes / 4 else 0,
        .cairo_proof_plan_components = if (proof_plan) |value| value.components.len else 0,
        .cairo_witness_levels = if (proof_plan) |value| value.levels.len else 0,
        .resident_prepare_gate = resident_prepare_gate,
        .populated_direct_witness_lanes = populated_direct_witness_lanes,
        .execution_table_split_gpu_ms = execution_table_split_gpu_ms,
        .executed_witness_programs = executed_witness_programs,
        .witness_graph_gpu_ms = witness_graph_gpu_ms,
        .multiplicity_feed_gpu_ms = multiplicity_feed_gpu_ms,
        .memory_public_seed_gpu_ms = memory_public_seed_gpu_ms,
        .memory_trace_gpu_ms = memory_trace_gpu_ms,
        .memory_rc99_gpu_ms = memory_rc99_gpu_ms,
        .populated_preprocessed_coefficients = populated_preprocessed_coefficients,
        .preprocessed_gpu_ms = preprocessed_gpu_ms,
        .base_interpolation_gpu_ms = base_interpolation_gpu_ms,
        .interaction_witness_gpu_ms = interaction_witness_gpu_ms,
        .relation_gpu_ms = relation_gpu_ms,
        .interaction_interpolation_gpu_ms = interaction_interpolation_gpu_ms,
        .composition_gpu_ms = composition_gpu_ms,
        .quotient_gpu_ms = quotient_gpu_ms,
        .quotient_executed = quotient_executed,
        .quotient_reference_parity = quotient_reference_parity,
        .fri_gpu_ms = fri_gpu_ms,
        .fri_executed = fri_executed,
        .fri_reference_parity = fri_reference_parity,
        .fri_final_degree_valid = fri_final_degree_valid,
        .interaction_pow_nonce = interaction_pow_nonce,
        .interaction_pow_wall_s = interaction_pow_wall_s,
        .interaction_pow_mode = interaction_pow_mode,
        .interaction_pow_bits = interaction_pow_bits,
        .interaction_pow_invocations = interaction_pow_invocations,
        .query_pow_nonce = query_pow_nonce,
        .query_pow_wall_s = query_pow_wall_s,
        .query_pow_mode = query_pow_mode,
        .query_pow_bits = query_pow_bits,
        .query_pow_invocations = query_pow_invocations,
        .pow_timing_scope = if (interaction_pow_wall_s != null or query_pow_wall_s != null)
            pow_timing_scope_name
        else
            null,
        .decommit_lde_gpu_ms = decommit_lde_gpu_ms,
        .decommit_gpu_ms = decommit_gpu_ms,
        .decommit_executed = decommit_executed,
        .proof_assembly_gpu_ms = proof_assembly_gpu_ms,
        .proof_assembled = proof_assembled,
        .proof_bundle_valid = proof_bundle_valid,
        .proof_verified = proof_verified,
        .proof_layout = proof_layout,
        .statement_self_derived = statement_self_derived,
        .legacy_transcript_bootstrap_used = legacy_transcript_bootstrap_used,
        .parity_fixture_used = parity_fixture_used,
        .proof_derived_artifact_used = true,
        .self_contained = false,
        .proof_output_bytes = proof_output_bytes,
        .prove_wall_s = prove_wall_s,
        .prove_timing_scope = if (prove_wall_s != null) prove_timing_scope_name else null,
        .runner_phase_timing = runner_phase_report,
        .recipe_preparation_timing = recipe_preparation_report,
        .proof_serialization = if (proof_assembled) "resident_sn2_bundle_v1" else null,
        .transcript_gpu_ms = transcript_gpu_ms,
        .commitment_gpu_ms = commitment_gpu_ms,
        .commitment_lde_gpu_ms = commitment_lde_gpu_ms,
        .commitment_leaf_gpu_ms = commitment_leaf_gpu_ms,
        .commitment_parent_gpu_ms = commitment_parent_gpu_ms,
        .resident_arena_bytes = resident_arena_bytes,
        .arena_plan_cache_hit = arena_plan_cache_hit,
        .prepared_state_cache_hit = prepared_state_cache_hit,
        .fixed_table_recipe_cache_hit = fixed_table_recipe_cache_hit,
        .multiplicity_feed_recipe_cache_hit = multiplicity_feed_recipe_cache_hit,
        .base_aot_witness_cache_hit = base_aot_witness_cache_hit,
        .interaction_aot_witness_cache_hit = interaction_aot_witness_cache_hit,
        .compact_verify_recipe_cache_hit = compact_verify_recipe_cache_hit,
        .compact_pedersen_recipe_cache_hit = compact_pedersen_recipe_cache_hit,
        .compact_poseidon_recipe_cache_hit = compact_poseidon_recipe_cache_hit,
        .recorded_base_interpolation_cache_hit = recorded_base_interpolation_cache_hit,
        .native_base_interpolation_cache_hit = native_base_interpolation_cache_hit,
        .prepared_state_snapshot_bytes = prepared_state_snapshot_bytes,
        .prepared_state_clear_bytes = prepared_state_clear_bytes,
        .prepared_state_capture_gpu_ms = prepared_state_capture_gpu_ms,
        .prepared_state_restore_gpu_ms = prepared_state_restore_gpu_ms,
        .preprocessed_coefficients_loaded_bytes = preprocessed_coefficients_loaded_bytes,
        .preprocessed_coefficients_reconstructed_bytes = preprocessed_coefficients_reconstructed_bytes,
        .commitment_roots = commitment_roots,
        .fri_roots = fri_roots,
        .prepared_quotient_partials = if (proof_bindings) |bindings| bindings.quotient_partials.len else 0,
        .prepared_fri_layers = if (proof_bindings) |bindings| bindings.fri_merkle_layers.len else 0,
        .native_recipe_buffers = native_recipe_buffers,
        .native_recipe_bytes = native_recipe_bytes,
        .zero_recipe_buffers = zero_recipe_buffers,
        .zero_recipe_bytes = zero_recipe_bytes,
        .witness_recipe_buffers = witness_recipe_buffers,
        .witness_recipe_bytes = witness_recipe_bytes,
        .witness_missing_buffers = witness_missing_buffers,
        .witness_missing_components = missing_names,
        .lookup_missing_components = missing_lookup_names,
        .bound_recompute_recipe_buffers = bound_recipe_buffers,
        .bound_recompute_recipe_bytes = bound_recipe_bytes,
        .metal_circle_recipe_buffers = circle_recipe_buffers,
        .metal_circle_recipe_bytes = circle_recipe_bytes,
        .preprocessed_ifft_recipe_buffers = preprocessed_recipe_buffers,
        .preprocessed_ifft_recipe_bytes = preprocessed_recipe_bytes,
        .merkle_parent_recipe_chains = merkle_parent_coverage.chains,
        .merkle_parent_recipe_buffers = merkle_parent_coverage.buffers,
        .merkle_parent_recipe_bytes = merkle_parent_coverage.bytes,
        .merkle_commit_recipe_commitments = merkle_commit_coverage.commitments,
        .merkle_commit_recipe_buffers = merkle_commit_coverage.buffers,
        .merkle_commit_recipe_bytes = merkle_commit_coverage.bytes,
        .physical_slots = plan.slots.len,
        .actions = plan.actions.len,
        .resident_buffers = resident,
        .spilled_buffers = spilled,
        .spill_snapshot_bytes = spill_snapshot_bytes,
        .spill_by_purpose = spill_by_purpose.items,
        .recomputed_buffers = recomputed,
        .recompute_snapshot_bytes = recompute_snapshot_bytes,
        .total_bytes = plan.total_bytes,
        .total_gib = @as(f64, @floatFromInt(plan.total_bytes)) / (1024.0 * 1024.0 * 1024.0),
        .base_epoch_arena_bytes = arena.bytesThroughTick(plan, 2 * 65),
        .peak_live_bytes = plan.peak_live_bytes,
        .peak_logical_bytes = arena.peakLogicalBytes(plan.bindings),
        .diagnostic_peak_tick = peak_tick,
        .diagnostic_peak_logical_bytes = diagnostic_peak_logical_bytes,
        .diagnostic_base_peak_bytes = diagnostic_base_peak_bytes,
        .diagnostic_base_peak_tick = diagnostic_base_peak_tick,
        .diagnostic_interaction_peak_bytes = diagnostic_interaction_peak_bytes,
        .diagnostic_interaction_peak_tick = diagnostic_interaction_peak_tick,
        .diagnostic_interaction_peak_purposes = interaction_peak_purposes,
        .diagnostic_base_peak_purposes = base_peak_purposes,
        .diagnostic_peak_purposes = peak_purposes,
        .budget_bytes = budget_bytes,
        .budget_gib = budget_gib,
        .fits = true,
        .alias_validation = "passed",
        .recovery_gate = "passed_no_unbound_recompute",
        .plan_hash = plan.plan_hash,
    };
    try std.json.Stringify.value(result, .{ .whitespace = .indent_2 }, report_writer);
    try report_writer.writeByte('\n');
}

fn writeFailure(
    writer: *std.Io.Writer,
    err: anyerror,
    logical: usize,
    components: usize,
    budget: u64,
) !void {
    const result = .{ .fits = false, .failure = @errorName(err), .logical_buffers = logical, .component_subepochs = components, .budget_bytes = budget };
    try std.json.Stringify.value(result, .{ .whitespace = .indent_2 }, writer);
    try writer.writeByte('\n');
}

fn requireResidentPreprocessedCoefficients(composition_requested: bool, populated: bool) !void {
    if (composition_requested and !populated) return error.MissingPreprocessedCoefficients;
}

test "resident composition requires preprocessed coefficients" {
    try requireResidentPreprocessedCoefficients(false, false);
    try requireResidentPreprocessedCoefficients(true, true);
    try std.testing.expectError(
        error.MissingPreprocessedCoefficients,
        requireResidentPreprocessedCoefficients(true, false),
    );
}

test "runtime verifier geometry follows projected composition degree" {
    const config_words = [_]u32{ 26, 1, 70, 0, 3, 0, 0, 0 };
    var composition = composition_bundle_mod.Bundle{
        .allocator = undefined,
        .format_version = composition_bundle_mod.projected_version,
        .max_kernel_instructions = 1,
        .total_constraints = 1,
        .max_evaluation_log_size = 21,
        .plan_hash = 1,
        .components = &.{},
    };
    const fib = try runtimeVerifierGeometry(&config_words, composition);
    try std.testing.expectEqual(@as(usize, 4), fib.trace_tree_count);
    try std.testing.expectEqual(@as(usize, 7), fib.fri_layer_count);
    try std.testing.expectEqual(@as(u32, 20), fib.max_log_degree_bound);
    try std.testing.expect(fib.matchesTranscript(&config_words));

    composition.format_version = composition_bundle_mod.version;
    composition.max_evaluation_log_size = 24;
    const sn2 = try runtimeVerifierGeometry(&config_words, composition);
    try std.testing.expectEqual(@as(usize, 8), sn2.fri_layer_count);
    try std.testing.expectEqual(@as(u32, 24), sn2.max_log_degree_bound);
    try std.testing.expectError(
        error.InvalidProtocolGeometry,
        runtimeVerifierGeometry(&config_words, .{
            .allocator = undefined,
            .max_kernel_instructions = 1,
            .total_constraints = 1,
            .max_evaluation_log_size = 0,
            .plan_hash = 1,
            .components = &.{},
        }),
    );
}

test "canonical proof protocol uses the exact report contract" {
    const encoded =
        \\{"channel":"blake2s","channel_salt":0,"log_blowup_factor":1,"n_queries":70,"interaction_pow_bits":24,"query_pow_bits":26,"fri_fold_step":3,"fri_lifting":null,"fri_log_last_layer_degree_bound":0}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, encoded, .{});
    defer parsed.deinit();
    try std.testing.expect(protocolObjectIsCanonical(parsed.value));

    const invalid = [_][]const u8{
        // Extra and missing fields are rejected, not ignored.
        "{\"channel\":\"blake2s\",\"channel_salt\":0,\"log_blowup_factor\":1,\"n_queries\":70,\"interaction_pow_bits\":24,\"query_pow_bits\":26,\"fri_fold_step\":3,\"fri_lifting\":null,\"fri_log_last_layer_degree_bound\":0,\"extra\":0}",
        "{\"channel\":\"blake2s\",\"channel_salt\":0,\"log_blowup_factor\":1,\"n_queries\":70,\"interaction_pow_bits\":24,\"query_pow_bits\":26,\"fri_fold_step\":3,\"fri_lifting\":null}",
        // JSON booleans and floats never coerce into protocol integers.
        "{\"channel\":\"blake2s\",\"channel_salt\":false,\"log_blowup_factor\":1,\"n_queries\":70,\"interaction_pow_bits\":24,\"query_pow_bits\":26,\"fri_fold_step\":3,\"fri_lifting\":null,\"fri_log_last_layer_degree_bound\":0}",
        "{\"channel\":\"blake2s\",\"channel_salt\":0,\"log_blowup_factor\":1,\"n_queries\":70.0,\"interaction_pow_bits\":24,\"query_pow_bits\":26,\"fri_fold_step\":3,\"fri_lifting\":null,\"fri_log_last_layer_degree_bound\":0}",
        // Null lifting and every fixed value are part of the proof identity.
        "{\"channel\":\"blake2s\",\"channel_salt\":0,\"log_blowup_factor\":1,\"n_queries\":71,\"interaction_pow_bits\":24,\"query_pow_bits\":26,\"fri_fold_step\":3,\"fri_lifting\":null,\"fri_log_last_layer_degree_bound\":0}",
        "{\"channel\":\"blake2s\",\"channel_salt\":0,\"log_blowup_factor\":1,\"n_queries\":70,\"interaction_pow_bits\":24,\"query_pow_bits\":26,\"fri_fold_step\":3,\"fri_lifting\":0,\"fri_log_last_layer_degree_bound\":0}",
    };
    for (invalid) |document| {
        var candidate = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, document, .{});
        defer candidate.deinit();
        try std.testing.expect(!protocolObjectIsCanonical(candidate.value));
    }
}
