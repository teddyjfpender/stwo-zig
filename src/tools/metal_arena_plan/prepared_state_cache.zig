const std = @import("std");
const stwo = @import("stwo");
const arena = stwo.backends.metal.arena_plan;
const metal_runtime = stwo.backends.metal.runtime;
const protocol_recipes = stwo.backends.metal.protocol_recipes;
const arena_binding_mod = stwo.integrations.cairo_metal.arena_binding;
const PreparedStateKey = @import("host_geometry.zig").PreparedStateKey;
const prepared_geometry = @import("prepared_geometry_cache.zig");
const PreparedGeometryCache = prepared_geometry.PreparedGeometryCache;
const PreparedGeometryHandle = prepared_geometry.PreparedGeometryHandle;
const PreparedGeometryPlanTransfer = prepared_geometry.PreparedGeometryPlanTransfer;
const PreparedStateAdmission = prepared_geometry.PreparedStateAdmission;
const PreparedStateIdentity = prepared_geometry.PreparedStateIdentity;
const PreparedStateTelemetry = @import("timing.zig").PreparedStateTelemetry;
const schedule_addressing = @import("schedule_addressing.zig");
const logicalIdOf = schedule_addressing.logicalIdOf;
const purposeOf = schedule_addressing.purposeOf;

pub const PreparedStateAcquire = struct {
    resident_arena: *arena.ResidentArena,
    cache_hit: bool,
};

pub const PreparedCompactSlot = enum {
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

    pub fn clearResidentResources(self: *PreparedStateCache) void {
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

    pub fn compactSlot(self: *PreparedStateCache, slot: PreparedCompactSlot) *?protocol_recipes.CompactRecipe {
        return switch (slot) {
            .verify_instruction => &self.compact_verify,
            .pedersen => &self.compact_pedersen,
            .poseidon => &self.compact_poseidon,
        };
    }

    pub fn installCompact(
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

    pub fn borrowCompact(
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

    pub fn installBaseAotWitness(
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

    pub fn borrowBaseAotWitness(self: *PreparedStateCache) !*protocol_recipes.AotWitnessBatchRecipe {
        errdefer self.poison();
        if (self.admission.status != .borrowed) return error.PreparedStateNotBorrowed;
        const recipe = if (self.base_aot_witness) |*value| value else return error.PreparedStateMissingBaseAotWitness;
        const resident = if (self.resident_arena) |*value| value else return error.PreparedStateMissingArena;
        if (recipe.arena != resident) return error.PreparedStateBaseAotWitnessArenaMismatch;
        recipe.resetForRequest();
        return recipe;
    }

    pub fn installRecordedBaseInterpolation(
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

    pub fn borrowRecordedBaseInterpolation(
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

    pub fn installNativeBaseInterpolation(
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

    pub fn borrowNativeBaseInterpolation(
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

    pub fn installInteractionAotWitness(
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

    pub fn borrowInteractionAotWitness(self: *PreparedStateCache) !*protocol_recipes.AotWitnessBatchRecipe {
        errdefer self.poison();
        if (self.admission.status != .borrowed) return error.PreparedStateNotBorrowed;
        const recipe = if (self.interaction_aot_witness) |*value| value else return error.PreparedStateMissingInteractionAotWitness;
        const resident = if (self.resident_arena) |*value| value else return error.PreparedStateMissingArena;
        if (recipe.arena != resident) return error.PreparedStateInteractionAotWitnessArenaMismatch;
        recipe.resetForRequest();
        return recipe;
    }

    pub fn installFixedTables(
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

    pub fn borrowFixedTables(self: *PreparedStateCache) !*protocol_recipes.FixedTableBatchRecipe {
        errdefer self.poison();
        if (self.admission.status != .borrowed) return error.PreparedStateNotBorrowed;
        const recipe = if (self.fixed_tables) |*value| value else return error.PreparedStateMissingFixedTables;
        const resident = if (self.resident_arena) |*value| value else return error.PreparedStateMissingArena;
        if (recipe.arena != resident) return error.PreparedStateFixedTablesArenaMismatch;
        recipe.resetForRequest();
        return recipe;
    }

    pub fn installMultiplicityFeeds(
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

    pub fn borrowMultiplicityFeeds(self: *PreparedStateCache) !*arena_binding_mod.MultiplicityFeedBatch {
        errdefer self.poison();
        if (self.admission.status != .borrowed) return error.PreparedStateNotBorrowed;
        const recipe = if (self.multiplicity_feeds) |*value| value else return error.PreparedStateMissingMultiplicityFeeds;
        const resident = if (self.resident_arena) |*value| value else return error.PreparedStateMissingArena;
        if (recipe.batch.arena != resident) return error.PreparedStateMultiplicityFeedsArenaMismatch;
        recipe.resetForRequest();
        return recipe;
    }

    pub fn findCanonicalPlan(
        self: *PreparedStateCache,
        key: PreparedStateKey,
        logical_plan_hash: u64,
    ) !?PreparedGeometryHandle {
        return self.geometry.findCommitted(key, logical_plan_hash);
    }

    pub fn transition(
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

    pub fn begin(
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

    pub fn capture(
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

pub fn buildPreparedStateRanges(
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
