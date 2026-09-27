//! Pure policy, original spool transport and equations. No PCS/proof invocation.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Sources = @import("block_v5_initial_sources_v1.zig");
const Selection = @import("block_v5_readonly_input_selection_v1.zig");
const Collection = @import("block_v5_readonly_input_collection_v1.zig");
const Proposal = @import("block_v5_readonly_input_proposal_v1.zig");
const Classification = @import("block_v5_readonly_input_proof_v1.zig");
const Replay = @import("block_memory_replay.zig").Replay;
const Policy = @import("block_v5_readonly_input_test_policy_v1.zig");
const base = Policy.base;
const input = Policy.input;
const selected = Policy.selected;
const sources = Policy.sources;
const options = Policy.selection;
const pin = Policy.pins;
fn proposal(selection: *const Selection.Owned) !Proposal.Proposal {
    // Labelled normative physical metadata proposal, never a verified proof.
    return .{ .expected = .{ .source = .{ .kind = .native, .index = 0, .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 1 }, .roots = .{ @splat(3), @splat(4) }, .access_root = @splat(5), .roster_digest = @splat(6), .all_rw_events = 2, .row_log = 1, .config = .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) } }, .selection_digest = selection.digest, .classifier_roots = .{ @splat(7), @splat(8) }, .census = .{ .all_rw = 2, .mutable = 1, .readonly = 1 }, .counter_digest = @splat(9), .event_digest = @splat(10), .limits = .{} } };
}
fn ownedCycle(a: std.mem.Allocator) !void {
    const actual = try sources();
    var selection = try options(a, actual);
    defer selection.deinit();
    var owned = try Collection.Owned.init(a, .{ .selection = pin(&selection) }, &input, 1, 1024 * 1024);
    defer owned.deinit();
    try std.testing.expectError(error.IncompleteReadonlyInputCollection, owned.authority());
    try std.testing.expectError(error.IncompleteReadonlyInputCollection, owned.bind(actual));
    try owned.append(try proposal(&selection));
    try owned.bind(actual);
    const borrowed = try owned.nativeBinding(0);
    try std.testing.expect(borrowed.plan == &owned.plan.?);
    const authority = try owned.authority();
    try std.testing.expect(authority.input.ptr == owned.input.ptr);
    var late = try authority.admit(a);
    defer late.deinit();
    try std.testing.expectEqualDeep(late.digest, borrowed.plan.digest);
    try std.testing.expectError(error.StaleReadonlyInputCollection, owned.append(try proposal(&selection)));
}
test "readonly collection: owned source late binding and every allocation rollback" {
    try ownedCycle(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, ownedCycle, .{});
}
test "readonly collection: independent input selection source and census mutations" {
    const a = std.testing.allocator;
    const actual = try sources();
    var selection = try options(a, actual);
    defer selection.deinit();
    var owned = try Collection.Owned.init(a, .{ .selection = pin(&selection) }, &input, 1, 1024 * 1024);
    defer owned.deinit();
    var bad = try proposal(&selection);
    bad.expected.census.mutable = 2;
    try std.testing.expectError(error.StaleReadonlyInputCensus, owned.append(bad));
    try owned.append(try proposal(&selection));
    var changed = actual;
    changed.initial_rw_root[0] ^= 1;
    try std.testing.expectError(error.StaleReadonlyInputSourceAuthority, owned.bind(changed));
    try owned.bind(actual);
    owned.input[0] ^= 1;
    const authority = try owned.authority();
    const rejected = authority.admit(a);
    if (rejected) |value| {
        var wrong = value;
        wrong.deinit();
        return error.TestExpectedError;
    } else |err| try std.testing.expect(err == error.UntrustedReadonlyInputBytes);
}
fn replay(a: std.mem.Allocator, dir: std.fs.Dir, actual: Sources.Pins) !Replay {
    const words = [_]@import("../runner/memory_state.zig").WordState{ .{ .addr = base, .initial_word = 7, .final_word = 7, .final_clock = 0, .role = .{ .is_public_input = true } }, .{ .addr = base + 4, .initial_word = 0x070809, .final_word = 0x070809, .final_clock = 0, .role = .{ .is_public_input = true } } };
    var result = try Replay.init(a, dir, @splat(0), &words, 8);
    result.layout = actual.layout;
    result.register_custody_mode = 1;
    result.next_cycle = @as(u64, 1) << 32;
    return result;
}
test "readonly collection: original spool retains mutable input and complete global clocks" {
    const a = std.testing.allocator;
    const actual = try sources();
    var selection = try options(a, actual);
    defer selection.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var original = try replay(a, tmp.dir, actual);
    defer original.deinit();
    const accesses = [_]@import("../runner/state_chain.zig").Access{ .{ .addr_space = 1, .addr = base, .clk = 1, .value = 7, .clk_prev = 0 }, .{ .addr_space = 1, .addr = base + 4, .clk = 2, .value = 5, .clk_prev = 0 }, .{ .addr_space = 0, .addr = 1, .clk = 3, .value = 42, .clk_prev = 0 } };
    const census = try original.appendSelected(.{ .clock_frame = .leaf_local, .global_first_cycle = @as(u64, 1) << 32, .cycle_count = 1 }, &accesses, &selection);
    try std.testing.expectEqualDeep(Proposal.Census{ .all_rw = 2, .mutable = 1, .readonly = 1 }, census);
    var reader = try original.finish();
    defer reader.deinit();
    const event = (try reader.next()).?;
    try std.testing.expectEqual(base + 4, event.address);
    try std.testing.expectEqual(@as(u64, (1 << 34) - 2), event.clock);
    try std.testing.expectEqual(@as(u32, 0x070809), event.before);
    try std.testing.expectEqual(@as(u32, 5), event.after);
    try std.testing.expectEqual(@as(?@import("../air/block/memory_transition.zig").Transition, null), try reader.next());
}
test "readonly collection: selected mutation poisons candidate but original mutable default accepts" {
    const a = std.testing.allocator;
    const actual = try sources();
    var selection = try options(a, actual);
    defer selection.deinit();
    var first_dir = std.testing.tmpDir(.{});
    defer first_dir.cleanup();
    var rejected = try replay(a, first_dir.dir, actual);
    defer rejected.deinit();
    const accesses = [_]@import("../runner/state_chain.zig").Access{.{ .addr_space = 1, .addr = base, .clk = 1, .value = 8, .clk_prev = 0 }};
    const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = @as(u64, 1) << 32, .cycle_count = 1 };
    try std.testing.expectError(error.ReadonlyInputWrite, rejected.appendSelected(frame, &accesses, &selection));
    try std.testing.expect(rejected.spooler.poisoned);
    var second_dir = std.testing.tmpDir(.{});
    defer second_dir.cleanup();
    var writable = try replay(a, second_dir.dir, actual);
    defer writable.deinit();
    try writable.append(frame, &accesses);
    var reader = try writable.finish();
    defer reader.deinit();
    try std.testing.expectEqual(@as(u32, 8), (try reader.next()).?.after);
}
test "readonly collection: source equation rejects count sign and overflow mutations" {
    const check = @import("block_v5_readonly_input_receiver_v1.zig").checkSourceEquation;
    const candidate = Classification.Open{ .claim = .{ .source_sum = Q.one().neg(), .mutable_sum = Q.one(), .classification_sum = Q.zero(), .read_sum = Q.zero(), .readonly_count = 1 }, .mutable_events = 1, .source_identity = @splat(1), .plan_digest = @splat(2), .sealed_digest = @splat(3) };
    const expected = Classification.Pin{ .events = 2, .row_log = 1, .plan_digest = @splat(2), .source_identity = @splat(1), .roots = .{ @splat(4), @splat(5) }, .config = .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) } };
    try check(candidate, Q.one(), 2, expected);
    try std.testing.expectError(error.UnclosedReadonlyInputSource, check(candidate, Q.one().neg(), 2, expected));
    var bad = candidate;
    bad.mutable_events = std.math.maxInt(u64);
    try std.testing.expectError(error.Overflow, check(bad, Q.one(), 2, expected));
}
test "readonly collection: transport counter census rejected before denied allocation" {
    const Codec = @import("block_v5_cpu_stark_codec_v1.zig");
    const expected = try @import("block_v5_readonly_input_transport_policy_v1.zig").native(.{ .plan_digest = @splat(1), .source_identity = @splat(2), .events = 1, .row_log = 1, .roots = .{ @splat(3), @splat(4) }, .config = .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) } }, 0, 3, @splat(5));
    var bytes: [64 + 76 + 1]u8 = @splat(0);
    @memcpy(bytes[0..8], "B5STOR01");
    std.mem.writeInt(u32, bytes[8..12], @intFromEnum(Codec.Family.native_readonly), .little);
    @memcpy(bytes[16..48], &expected.policy_digest);
    std.mem.writeInt(u32, bytes[48..52], 1, .little);
    std.mem.writeInt(u32, bytes[52..56], 76, .little);
    std.mem.writeInt(u64, bytes[56..64], 1, .little);
    std.mem.writeInt(u32, bytes[136..140], std.math.maxInt(u32), .little);
    var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.UntrustedV5ReadonlyCounterCount, Codec.decode(.native_readonly, fail.allocator(), &bytes, expected, .{ .artifact_bytes = 1024, .proof_bytes = 512, .max_claims = 8 }));
    try std.testing.expectEqual(@as(usize, 0), fail.alloc_index);
    var old = expected;
    old.family = .caller_fused;
    try std.testing.expectError(error.InvalidV5BundleExpected, old.validate());
}

const Seal = @import("block_v5_source_seal_v1.zig");
const Roster = @import("block_v5_readonly_input_roster_v1.zig");
const FixtureSeal = struct { pins: Seal.Pins, entries: [4]Seal.Entry };
fn fixtureSeal(source: Sources.Pins, expected: Proposal.Expected) !FixtureSeal {
    var counts: [Seal.family_count]u32 = @splat(0);
    inline for (.{ Seal.Family.program, Seal.Family.execution, Seal.Family.execution_sidecar, Seal.Family.program_request }) |family| counts[@intFromEnum(family) - 1] = 1;
    // Scope-only normative proposals: there are no base proofs or receipts.
    return .{ .pins = .{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = @splat(6), .initial_source_plan_digest = try source.digest(), .register_endpoint_plan_digest = @splat(7), .register_custody_mode = 1, .config = expected.source.config, .counts = counts }, .entries = .{
        .{ .family = .program, .index = 0, .instance_id = @splat(8), .roots = .{ @splat(9), @splat(10) } },
        .{ .family = .execution, .index = 0, .instance_id = @splat(11), .roots = expected.source.roots },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(12), .roots = .{ expected.source.access_root, @splat(0) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(13), .roots = .{ @splat(14), @splat(0) } },
    } };
}
fn oldSealBytes(pins: Seal.Pins, entries: []const Seal.Entry) [32]u8 {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ Seal.TAG, Seal.REGISTER_WINDOW_VERSION });
    channel.mixU32s(&.{1});
    channel.mixRoot(pins.job_id);
    channel.mixRoot(pins.source_image_digest);
    channel.mixU32s(&.{0});
    channel.mixRoot(pins.native_template_id);
    inline for (.{ "program_root", "program_plan_digest", "memory_plan_digest", "initial_source_plan_digest", "expected_final_rw_root", "rw_endpoint_plan_digest", "register_endpoint_plan_digest" }) |field| channel.mixRoot(@field(pins, field));
    pins.config.mixInto(&channel);
    for (pins.counts) |count| channel.mixU32s(&.{count});
    for (entries) |entry| {
        channel.mixU32s(&.{ @intFromEnum(entry.family), entry.index });
        channel.mixRoot(entry.instance_id);
        for (entry.roots) |root| channel.mixRoot(root);
    }
    return channel.digestBytes();
}
test "readonly collection: roster exact sparse census absence and ordered roots" {
    const census = Proposal.Census{ .all_rw = 2, .mutable = 1, .readonly = 1 };
    var builder = try Roster.Builder.init(@splat(1), @splat(2), 3, 1);
    try std.testing.expectError(error.IncompleteReadonlyInputRoster, builder.finish());
    try std.testing.expectError(error.InvalidReadonlyInputRoster, builder.native(1, 2, 1, .{ @splat(3), @splat(4) }, census));
    try builder.native(0, 2, 1, .{ @splat(3), @splat(4) }, census);
    try builder.native(1, 0, 0, null, .{ .all_rw = 0, .mutable = 0, .readonly = 0 });
    try builder.native(2, 2, 1, .{ @splat(5), @splat(6) }, census);
    try builder.caller(2, census);
    const digest = try builder.finish();
    try std.testing.expectError(error.InvalidReadonlyInputRoster, builder.caller(2, census));
    var changed = try Roster.Builder.init(@splat(1), @splat(2), 3, 1);
    try changed.native(0, 2, 1, .{ @splat(3), @splat(4) }, census);
    try changed.native(1, 0, 0, null, .{ .all_rw = 0, .mutable = 0, .readonly = 0 });
    try changed.native(2, 2, 1, .{ @splat(5), @splat(6) }, census);
    try changed.caller(1, census);
    try std.testing.expect(!std.meta.eql(digest, try changed.finish()));
    var absent = try Roster.Builder.init(@splat(1), @splat(2), 1, 0);
    try std.testing.expectError(error.InvalidReadonlyInputRoster, absent.native(0, 0, 1, null, .{ .all_rw = 0, .mutable = 0, .readonly = 0 }));
}
test "readonly collection: seal binds classifier roots before word challenges and keeps writable bytes" {
    const a = std.testing.allocator;
    const actual = try sources();
    var selection = try options(a, actual);
    defer selection.deinit();
    const expected = (try proposal(&selection)).expected;
    var fixture = try fixtureSeal(actual, expected);
    const old = try Seal.seal(fixture.pins, &fixture.entries);
    try std.testing.expectEqualDeep(oldSealBytes(fixture.pins, &fixture.entries), old.digest);
    fixture.pins.readonly_roster_digest = @splat(15);
    const selected_seal = try Seal.seal(fixture.pins, &fixture.entries);
    try std.testing.expect(!std.meta.eql(old.digest, selected_seal.digest));
    try std.testing.expect(!std.meta.eql(old.native_roster_digest, selected_seal.native_roster_digest));
    try std.testing.expectError(error.UntrustedBlockV5SourceSeal, old.require(fixture.pins, &fixture.entries));
    const Word = @import("block_v5_word_memory_protocol_v1.zig");
    const first = try Word.Challenges.draw(a, selected_seal);
    fixture.pins.readonly_roster_digest[0] ^= 1;
    const changed = try Word.Challenges.draw(a, try Seal.seal(fixture.pins, &fixture.entries));
    try std.testing.expect(!std.meta.eql(first.transition, changed.transition));
    try std.testing.expect(!std.meta.eql(first.universal_prefix, changed.universal_prefix));
    fixture.pins.register_custody_mode = 0;
    try std.testing.expectError(error.InvalidBlockV5RegisterCustodyMode, Seal.seal(fixture.pins, &fixture.entries));
}
fn rosterPolicyCycle(a: std.mem.Allocator) !void {
    const actual = try sources();
    var selection = try options(a, actual);
    defer selection.deinit();
    var owned = try Collection.Owned.init(a, .{ .selection = pin(&selection) }, &input, 1, 1024 * 1024);
    defer owned.deinit();
    const physical = try proposal(&selection);
    try owned.append(physical);
    try owned.bind(actual);
    var fixture = try fixtureSeal(actual, physical.expected);
    var roster = try Roster.Builder.init(owned.plan.?.digest, selection.digest, 1, 0);
    try roster.native(0, 2, 1, physical.expected.classifier_roots, physical.expected.census);
    fixture.pins.readonly_roster_digest = try roster.finish();
    try owned.bindRoster(fixture.pins.readonly_roster_digest);
    // Identical retry after a later assembly OOM is safe; changing authority is not.
    try owned.bindRoster(fixture.pins.readonly_roster_digest);
    const sealed = try Seal.seal(fixture.pins, &fixture.entries);
    const binding = try owned.nativeBinding(0);
    const native = [_]@import("block_v5_readonly_input_memory_policy_v1.zig").Native{.{ .pin = try binding.pinAfterSeal(fixture.entries[1].instance_id, sealed, fixture.pins, &fixture.entries), .census = physical.expected.census }};
    const policy = @import("block_v5_readonly_input_memory_policy_v1.zig").Pins{ .authority = try owned.authority(), .native = &native, .caller = &.{} };
    try policy.require(a, sealed, fixture.pins, &fixture.entries, &.{2}, &.{}, 1);
}
test "readonly collection: genuine policy roster reconstruction every allocation rollback" {
    try rosterPolicyCycle(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, rosterPolicyCycle, .{});
}
test "readonly collection: detached policy cannot change classifier roots census plan or epoch" {
    const a = std.testing.allocator;
    const actual = try sources();
    var selection = try options(a, actual);
    defer selection.deinit();
    var owned = try Collection.Owned.init(a, .{ .selection = pin(&selection) }, &input, 1, 1024 * 1024);
    defer owned.deinit();
    const physical = try proposal(&selection);
    try owned.append(physical);
    try owned.bind(actual);
    var fixture = try fixtureSeal(actual, physical.expected);
    var roster = try Roster.Builder.init(owned.plan.?.digest, selection.digest, 1, 0);
    try roster.native(0, 2, 1, physical.expected.classifier_roots, physical.expected.census);
    fixture.pins.readonly_roster_digest = try roster.finish();
    try owned.bindRoster(fixture.pins.readonly_roster_digest);
    const sealed = try Seal.seal(fixture.pins, &fixture.entries);
    const binding = try owned.nativeBinding(0);
    var native = [_]@import("block_v5_readonly_input_memory_policy_v1.zig").Native{.{ .pin = try binding.pinAfterSeal(fixture.entries[1].instance_id, sealed, fixture.pins, &fixture.entries), .census = physical.expected.census }};
    const policy = @import("block_v5_readonly_input_memory_policy_v1.zig").Pins{ .authority = try owned.authority(), .native = &native, .caller = &.{} };
    native[0].pin.?.roots[1][31] ^= 1;
    try std.testing.expectError(error.UntrustedReadonlyInputRoster, policy.require(a, sealed, fixture.pins, &fixture.entries, &.{2}, &.{}, 1));
    native[0].pin.?.roots[1][31] ^= 1;
    native[0].census = .{ .all_rw = 2, .mutable = 0, .readonly = 2 };
    try std.testing.expectError(error.UntrustedReadonlyInputRoster, policy.require(a, sealed, fixture.pins, &fixture.entries, &.{2}, &.{}, 0));
    native[0].census = physical.expected.census;
    fixture.pins.readonly_roster_digest = @splat(0);
    const downgraded = try Seal.seal(fixture.pins, &fixture.entries);
    try std.testing.expectError(error.MissingReadonlyInputRoster, policy.require(a, downgraded, fixture.pins, &fixture.entries, &.{2}, &.{}, 1));
    try std.testing.expectError(error.StaleReadonlyInputRoster, binding.pinAfterSeal(fixture.entries[1].instance_id, downgraded, fixture.pins, &fixture.entries));
}
