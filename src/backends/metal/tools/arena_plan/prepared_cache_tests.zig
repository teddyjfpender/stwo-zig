const std = @import("std");
const stwo = @import("stwo");
const arena = stwo.backends.metal.arena_plan;
const protocol_recipes = stwo.backends.metal.protocol_recipes;
const arena_binding_mod = stwo.integrations.cairo_metal.arena_binding;
const host_geometry = @import("host_geometry.zig");
const prepared_geometry = @import("prepared_geometry_cache.zig");
const prepared_state = @import("prepared_state_cache.zig");
const timing_mod = @import("timing.zig");

const PreparedHostGeometry = host_geometry.PreparedHostGeometry;
const PreparedStateKey = host_geometry.PreparedStateKey;
const PreparedGeometryCache = prepared_geometry.PreparedGeometryCache;
const PreparedStateAdmission = prepared_geometry.PreparedStateAdmission;
const PreparedStateIdentity = prepared_geometry.PreparedStateIdentity;
const prepared_geometry_capacity = prepared_geometry.prepared_geometry_capacity;
const logicalPlanHash = prepared_geometry.logicalPlanHash;
const PreparedStateCache = prepared_state.PreparedStateCache;
const buildPreparedStateRanges = prepared_state.buildPreparedStateRanges;
const RunnerPhaseTiming = timing_mod.RunnerPhaseTiming;
const RecipePreparationTiming = timing_mod.RecipePreparationTiming;
const CanonicalFullProofPlanMode = timing_mod.CanonicalFullProofPlanMode;

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
