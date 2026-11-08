const std = @import("std");
const F = @import("coordinator_fixture.zig");
const Original = @import("../fixture.zig");
const C = @import("coordinator.zig");
const Fixed = @import("fixed_authority.zig");
const FixedSet = @import("fixed_authority_set.zig").Set;
const Candidate = @import("../../../word16_execution/om31_security_candidate.zig");
const W = @import("worker_protocol.zig");
const a = std.testing.allocator;
test "resident fixed catalogue reuses only frozen owned sources and revalidates new bodies" {
    const Authority = @import("fixed_authority_set.zig");
    var keys = try F.Keys.init(a);
    defer keys.deinit();
    var cache = try Fixed.Fixed.Cache.init(a, 1 << 30);
    defer cache.deinit();
    var catalogue = Authority.ValidatedCatalogue{ .allocator = a };
    defer catalogue.deinit();
    const config = Candidate.config();
    var first = try FixedSet.initWithValidatedCatalogue(a, &cache, &.{keys.cpus[0]}, &.{}, config, &catalogue);
    defer first.deinit();
    try std.testing.expectEqual(@as(usize, 1), first.source_validations);
    var second = try FixedSet.initWithValidatedCatalogue(a, &cache, &.{keys.cpus[0]}, &.{}, config, &catalogue);
    defer second.deinit();
    try std.testing.expectEqual(@as(usize, 0), second.source_validations);
    try std.testing.expectEqual(@as(usize, 0), second.source_coefficient_cells);
    try std.testing.expectEqual(first.at(0).fixed_identity, second.at(0).fixed_identity);
    try second.require(&.{keys.cpus[0]}, &.{}, config);
    // A distinct source object with the SAME sealed root cannot borrow the
    // session owner's provenance. Its actual body must still be validated.
    var copied = keys.cpus[0].*;
    const coefficients = try a.dupe(@TypeOf(copied.key.tree.coefficients.?[0]), copied.key.tree.coefficients.?);
    defer a.free(coefficients);
    const values = try a.dupe(@import("stwo_core").fields.m31.M31, coefficients[0].coeffs);
    defer a.free(values);
    values[0] = values[0].add(@import("stwo_core").fields.m31.M31.one());
    coefficients[0].coeffs = values;
    copied.key.tree.coefficients = coefficients;
    var changed = try FixedSet.initWithValidatedCatalogue(a, &cache, &.{&copied}, &.{}, config, &catalogue);
    defer changed.deinit();
    try std.testing.expectEqual(@as(usize, 1), changed.source_validations);
    try std.testing.expect(!std.mem.eql(u8, &changed.at(0).fixed_identity, &first.at(0).fixed_identity));
    try std.testing.expectError(error.FixedSetupIdentityMismatch, first.at(0).revalidateSource(&copied.key, config));
    // Receiver-selected profile authority remains separate from reusable trees.
    const other_config = Candidate.configFor(.conjectured128_b2_q108_p20_fold4);
    var other_profile = try FixedSet.initWithValidatedCatalogue(a, &cache, &.{keys.cpus[0]}, &.{}, other_config, &catalogue);
    defer other_profile.deinit();
    try std.testing.expectEqual(@as(usize, 1), other_profile.source_validations);
    try std.testing.expectError(error.WideCandidateProfileMismatch, first.at(0).require(&keys.cpus[0].key, other_config));
    var wrong = other_config;
    wrong.fri_config.n_queries -= 1;
    if (FixedSet.initWithValidatedCatalogue(a, &cache, &.{keys.cpus[0]}, &.{}, wrong, &catalogue)) |accepted| {
        var cleanup = accepted;
        cleanup.deinit();
        return error.AcceptedUnadmittedResidentConfig;
    } else |_| {}
    catalogue.clear();
    var after_eviction = try FixedSet.initWithValidatedCatalogue(a, &cache, &.{keys.cpus[0]}, &.{}, config, &catalogue);
    defer after_eviction.deinit();
    try std.testing.expectEqual(@as(usize, 1), after_eviction.source_validations);
    // Clearing the catalogue does not revoke already retained request leases.
    try first.require(&.{keys.cpus[0]}, &.{}, config);
    try std.testing.checkAllAllocationFailures(a, catalogueAllocationCase, .{ &cache, keys.cpus[0] });
    const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const metadata_budget = try Budget.create(a, 1 << 20);
    defer metadata_budget.destroy();
    var bounded = Authority.ValidatedCatalogue{ .allocator = metadata_budget.allocator() };
    defer bounded.deinit();
    var charged = try FixedSet.initWithValidatedCatalogue(a, &cache, &.{keys.cpus[0]}, &.{}, config, &bounded);
    defer charged.deinit();
    try std.testing.expect(metadata_budget.snapshot().live_bytes > 0);
    bounded.clear();
    try std.testing.expectEqual(@as(usize, 0), metadata_budget.snapshot().live_bytes);
}
fn catalogueAllocationCase(allocator: std.mem.Allocator, cache: *const Fixed.Fixed.Cache, setup: *const @import("../roster.zig").CpuSetup) !void {
    var catalogue = @import("fixed_authority_set.zig").ValidatedCatalogue{ .allocator = allocator };
    defer catalogue.deinit();
    var set = try FixedSet.initWithValidatedCatalogue(allocator, cache, &.{setup}, &.{}, Candidate.config(), &catalogue);
    defer set.deinit();
    try set.require(&.{setup}, &.{}, Candidate.config());
}
test "beta2 candidate two CPU and K ADD DOUBLE execution verifies from independent fixed leases" {
    var captured = try Original.Captured.init(a);
    defer captured.deinit();
    var keys = try F.Keys.init(a);
    defer keys.deinit();
    const config = Candidate.config();
    const expected = Original.expectedFor(captured.program.identity);
    var cache = try Fixed.Fixed.Cache.init(a, 1 << 30);
    var cache_alive = true;
    defer if (cache_alive) cache.deinit();
    var authority = try FixedSet.init(a, &cache, &keys.pointers(), &keys.truths(), config);
    defer authority.deinit();
    // All leases retain their allocator independently of the cache handle.
    cache.deinit();
    cache_alive = false;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const path = try temp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var store = try C.Store.initFullyParked(path, 256 << 20);
    defer store.deinit();
    // Fault injection deliberately violates the frozen-source contract. Fast
    // provenance checks do not detect stale-root body mutation; explicit full
    // revalidation does. The independently owned candidate key must not change.
    const source_coefficients = keys.cpus[0].key.tree.coefficients.?;
    const source_values = @constCast(source_coefficients[0].coeffs);
    const original_coefficient = source_values[0];
    const candidate_coefficient = authority.at(0).lease.key.tree.coefficients.?[0].coeffs[0];
    source_values[0] = original_coefficient.add(@import("stwo_core").fields.m31.M31.one());
    defer source_values[0] = original_coefficient;
    try authority.at(0).require(&keys.cpus[0].key, config);
    try std.testing.expectError(error.FixedSetupIdentityMismatch, authority.at(0).revalidateSource(&keys.cpus[0].key, config));
    try std.testing.expect(candidate_coefficient.eql(authority.at(0).lease.key.tree.coefficients.?[0].coeffs[0]));
    var bundle = try C.produceWithAuthority(a, &keys.pointers(), &keys.truths(), &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expected, config, .{ .gkr_budget = 2 << 30, .retained_store = &store, .max_workers = 32, .schedule = .{ .lanes = 2, .workers_per_lane = 2, .memory_cap_bytes = 4 << 30 } }, &authority);
    defer bundle.deinit(a);
    source_values[0] = original_coefficient;
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
    try std.testing.expect(store.stats().total_bytes > 0);
    const first = try bundle.verifyWithAuthority(a, &keys.pointers(), &keys.truths(), expected, config, &authority);
    try std.testing.expect(first.completed);
    try std.testing.expectEqual(@as(u64, 7), first.total_steps);
    try std.testing.expectEqual(@as(usize, 5), first.physical_proofs);
    try std.testing.expectError(error.UnsupportedWideServicesConfig, bundle.verify(a, &keys.pointers(), &keys.truths(), expected, config));
    // Fresh receiver budget exists before trusted source key construction,
    // not merely around the later candidate cache. Partially built legacy
    // source keys must unwind on cap refusal.
    const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const refused = try Budget.create(a, 1 << 20);
    defer refused.destroy();
    try std.testing.expectError(error.OutOfMemory, F.Keys.init(refused.allocator()));
    try std.testing.expectEqual(@as(usize, 0), refused.snapshot().live_bytes);
    try std.testing.expect(refused.snapshot().exceeded);
    const receiver = try Budget.create(a, 8 << 30);
    defer receiver.destroy();
    const receiver_allocator = receiver.allocator();
    var fresh = try F.Keys.init(receiver_allocator);
    defer fresh.deinit();
    var fresh_cache = try Fixed.Fixed.Cache.init(receiver_allocator, 1 << 30);
    defer fresh_cache.deinit();
    var equivalent_sources = try FixedSet.init(a, &fresh_cache, &.{ keys.cpus[0], fresh.cpus[0] }, &.{}, config);
    defer equivalent_sources.deinit();
    try std.testing.expect(keys.cpus[0] != fresh.cpus[0]);
    try std.testing.expectEqual(@as(usize, 1), equivalent_sources.source_validations);
    try std.testing.expectEqual(equivalent_sources.at(0).source_coefficient_cells, equivalent_sources.source_coefficient_cells);
    try std.testing.expect(equivalent_sources.at(0).lease.key == equivalent_sources.at(1).lease.key);
    var independently_derived = try FixedSet.init(receiver_allocator, &fresh_cache, &fresh.pointers(), &fresh.truths(), config);
    defer independently_derived.deinit();
    try std.testing.expect(authority.at(0).lease.key != independently_derived.at(0).lease.key);
    const accepted = try bundle.verifyWithAuthority(receiver_allocator, &fresh.pointers(), &fresh.truths(), expected, config, &independently_derived);
    try std.testing.expect(receiver.snapshot().peak_live_bytes > 0);
    try std.testing.expect(receiver.snapshot().peak_live_bytes <= receiver.snapshot().limit);
    try std.testing.expectEqualDeep(first, accepted);
    var wrong = config;
    wrong.fri_config.n_queries -= 1;
    try std.testing.expectError(error.WideBeta2FixedInventoryMismatch, bundle.verifyWithAuthority(a, &fresh.pointers(), &fresh.truths(), expected, wrong, &independently_derived));
    std.mem.swap(Fixed.Binding, &independently_derived.bindings[0], &independently_derived.bindings[1]);
    try std.testing.expectError(error.FixedSetupIdentityMismatch, bundle.verifyWithAuthority(a, &fresh.pointers(), &fresh.truths(), expected, config, &independently_derived));
    std.mem.swap(Fixed.Binding, &independently_derived.bindings[0], &independently_derived.bindings[1]);
    const claim = bundle.truths[0].claims[3];
    bundle.truths[0].claims[3] = claim.add(W.O.one());
    if (bundle.verifyWithAuthority(a, &fresh.pointers(), &fresh.truths(), expected, config, &independently_derived)) |_| return error.AcceptedBeta2ChangedGlobalDebt else |_| {}
    bundle.truths[0].claims[3] = claim;
    std.mem.swap(@TypeOf(bundle.cpus[0]), &bundle.cpus[0], &bundle.cpus[1]);
    if (bundle.verifyWithAuthority(a, &fresh.pointers(), &fresh.truths(), expected, config, &independently_derived)) |_| return error.AcceptedBeta2SwappedPhysicalProofs else |_| {}
    std.mem.swap(@TypeOf(bundle.cpus[0]), &bundle.cpus[0], &bundle.cpus[1]);
    // Successful candidate arithmetic cannot promote the security label.
    try std.testing.expectError(error.NoReviewedWholeProtocol128Certificate, Candidate.requireWholeProtocolPromotion(.{ .beta2_immutable_setup_qualified = true, .all_native_and_global_arguments_om31 = true, .circle_fri_actual_query_layout_theorem = true, .quotient_only_degree_corrected_relation = true, .source_weight_and_characteristic_proof = true, .gkr_binding_and_late_mix_theorem = true, .adaptive_raw_mod_rom_theorem = true, .all_recursive_layers_om31_and_raw_channel = true }));
}

fn setCallerAllocationCase(allocator: std.mem.Allocator, cache: *const Fixed.Fixed.Cache, keys: *const F.Keys) !void {
    var set = try FixedSet.init(allocator, cache, &keys.pointers(), &keys.truths(), Candidate.config());
    defer set.deinit();
    try set.require(&keys.pointers(), &keys.truths(), Candidate.config());
}
test "beta2 fixed set unwinds caller OOM and a later uncached worker seal failure" {
    var keys = try F.Keys.init(a);
    defer keys.deinit();
    var cache = try Fixed.Fixed.Cache.init(a, 1 << 30);
    defer cache.deinit();
    var populated = try FixedSet.init(a, &cache, &keys.pointers(), &keys.truths(), Candidate.config());
    defer populated.deinit();
    try std.testing.checkAllAllocationFailures(a, setCallerAllocationCase, .{ &cache, &keys });
    var probe = try Fixed.Fixed.Cache.init(a, 1 << 30);
    var first = try Fixed.Binding.acquire(&probe, &keys.cpus[0].key, Candidate.config());
    const first_peak = probe.snapshot().peak_bytes;
    first.deinit();
    probe.deinit();
    var limited = try Fixed.Fixed.Cache.init(a, first_peak);
    defer limited.deinit();
    try std.testing.expectError(error.OutOfMemory, FixedSet.init(a, &limited, &keys.pointers(), &keys.truths(), Candidate.config()));
    try std.testing.expect(limited.snapshot().seals >= 1);
    var retry = try Fixed.Binding.acquire(&limited, &keys.cpus[0].key, Candidate.config());
    defer retry.deinit();
    try retry.require(&keys.cpus[0].key, Candidate.config());
}
