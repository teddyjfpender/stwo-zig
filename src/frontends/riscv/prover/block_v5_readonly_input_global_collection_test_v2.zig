//! Original scalar metadata, files and OOM only. No PCS/STARK/guest/device calls.
const std = @import("std");
const core = @import("stwo_core");
const Collection = @import("block_v5_readonly_input_counter_collection_v2.zig");
const Staging = @import("block_v5_readonly_input_counter_staging_v2.zig");
const Roster = @import("block_v5_readonly_input_global_roster_v2.zig");
const Original = @import("block_v5_readonly_input_collection_v1.zig");
const Proposal = @import("block_v5_readonly_input_proposal_v1.zig");
const Provider = @import("block_v5_readonly_input_provider_v2.zig");
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Policy = @import("block_v5_readonly_input_test_policy_v1.zig");
const Hash = std.crypto.hash.sha2.Sha256;
const intervals = [_]Plan.Interval{ .{ .lower = 0, .upper = 1, .readonly = false, .value = 0 }, .{ .lower = 1, .upper = 2, .readonly = true, .value = 7 }, .{ .lower = 2, .upper = Plan.WORD_LIMIT, .readonly = false, .value = 0 } };
fn put(hash: *Hash, value: u64) void {
    var raw: [8]u8 = undefined;
    std.mem.writeInt(u64, &raw, value, .little);
    hash.update(&raw);
}
fn config() !core.pcs.PcsConfig {
    return .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
}
/// Labelled normative metadata; never a generated or verified source proof.
fn native(index: u32, selection: [32]u8, counters: []const u64, readonly_index: usize) !Proposal.Proposal {
    var hash = Hash.init(.{});
    hash.update("stwo-zig/block-v5/readonly-input-interval-census/v1\x00");
    hash.update(&selection);
    var events: u64 = 0;
    for (counters) |count| {
        put(&hash, count);
        events = try std.math.add(u64, events, count);
    }
    const readonly = counters[readonly_index];
    return .{ .expected = .{ .source = .{ .kind = .native, .index = index, .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = @intCast(@max(1, events)) }, .roots = .{ @splat(3), @splat(4) }, .access_root = @splat(5), .roster_digest = @splat(6), .all_rw_events = @intCast(events), .row_log = if (events == 0) 0 else @max(1, std.math.log2_int_ceil(u64, events)), .config = try config() }, .selection_digest = selection, .classifier_roots = if (events == 0) null else .{ @splat(7), @splat(8) }, .census = .{ .all_rw = events, .mutable = events - readonly, .readonly = readonly }, .counter_digest = hash.finalResult(), .event_digest = @splat(10), .limits = .{ .proof = .{ .max_matrix_bytes = 16 * 1024 * 1024 * 1024 } } } };
}
const Copies = struct {
    groups: [4]Collection.Group = undefined,
    counts: [4][3]u64 = undefined,
    used: usize = 0,
    reject: bool = false,
    fn sink(self: *Copies) Collection.Sink {
        return .{ .context = self, .put_group = append };
    }
    fn append(raw: *anyopaque, view: Collection.GroupView) !void {
        const self: *Copies = @ptrCast(@alignCast(raw));
        if (self.reject) return error.InjectedGroupFailure;
        if (self.used == self.groups.len or view.counts.len != 3) return error.UnexpectedGroupShape;
        self.groups[self.used] = view.group;
        @memcpy(&self.counts[self.used], view.counts);
        self.used += 1;
    }
};
fn ownership(a: std.mem.Allocator) !void {
    var copies = Copies{};
    var owned = try Collection.Owned.init(a, @splat(1), &intervals, 2, .{ .sink = copies.sink(), .limits = .{ .max_group_events = 200_000 } });
    defer owned.deinit();
    try owned.appendNative(try native(0, @splat(1), &.{ 0, 150_000, 0 }, 1), &.{ 0, 150_000, 0 });
    try owned.appendNative(try native(1, @splat(1), &.{ 1, 50_000, 0 }, 1), &.{ 1, 50_000, 0 });
    try owned.finish();
    try std.testing.expectEqual(@as(usize, 2), copies.used);
    try std.testing.expectEqual(@as(u64, 150_000), copies.counts[0][1]);
    try std.testing.expectEqual(@as(u64, 50_000), copies.counts[1][1]);
    try std.testing.expectEqual(@as(u32, 1), (try owned.sourceRecords())[1].group_id);
    for (owned.counts) |count| try std.testing.expectEqual(@as(u64, 0), count);
}
test "global readonly collection: one vector exact greedy groups and every allocation unwind" {
    try ownership(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, ownership, .{});
}
test "global readonly collection: multi-billion census remains integer exact and each group field safe" {
    var copies = Copies{};
    var owned = try Collection.Owned.init(std.testing.allocator, @splat(1), &intervals, 300, .{ .sink = copies.sink() });
    defer owned.deinit();
    for (0..300) |index| try owned.appendNative(try native(@intCast(index), @splat(1), &.{ 0, 16_000_000, 0 }, 1), &.{ 0, 16_000_000, 0 });
    try owned.finish();
    try std.testing.expectEqual(@as(u64, 4_800_000_000), owned.census.all_rw);
    try std.testing.expectEqual(@as(usize, 3), copies.used);
    for (try owned.groupRecords()) |group| try std.testing.expect(group.census.all_rw < core.fields.m31.Modulus);
}
test "global readonly collection: changed counters duplicate sparse caller and sink failure reject without release" {
    var copies = Copies{};
    var owned = try Collection.Owned.init(std.testing.allocator, @splat(1), &intervals, 2, .{ .sink = copies.sink() });
    defer owned.deinit();
    const first = try native(0, @splat(1), &.{ 1, 2, 0 }, 1);
    try std.testing.expectError(error.StaleReadonlyCounterCensus, owned.appendNative(first, &.{ 0, 3, 0 }));
    try std.testing.expectEqual(@as(usize, 0), owned.source_count);
    try owned.appendNative(first, &.{ 1, 2, 0 });
    try std.testing.expectError(error.InvalidReadonlyCounterSourceOrder, owned.appendNative(first, &.{ 1, 2, 0 }));
    const Slot = struct { counters: []const u64, events: u64 };
    const slots = [_]Slot{.{ .counters = &.{ 2, 4, 0 }, .events = 6 }};
    var hash = Hash.init(.{});
    hash.update("stwo-zig/block-v5/caller-readonly-physical-counters/v1\x00");
    hash.update(&@as([32]u8, @splat(1)));
    for (slots[0].counters) |count| put(&hash, count);
    const physical = .{ .roots = @as([3][32]u8, .{ @splat(11), @splat(12), @splat(13) }), .selection_digest = @as([32]u8, @splat(1)), .all_rw_events = @as(u64, 6), .readonly_events = @as(u64, 4), .counter_digest = hash.finalResult() };
    try owned.appendCaller(0, physical, &slots);
    try std.testing.expectError(error.InvalidReadonlyCounterSourceOrder, owned.appendCaller(0, physical, &slots));
    try owned.appendNative(try native(1, @splat(1), &.{ 0, 0, 0 }, 1), &.{ 0, 0, 0 });
    copies.reject = true;
    try std.testing.expectError(error.InjectedGroupFailure, owned.finish());
    try std.testing.expect(owned.poisoned);
    try std.testing.expectEqual(@as(u64, 6), owned.counts[1]);
    try std.testing.expectError(error.ReadonlyCounterCollectionClosed, owned.finish());
}
test "global readonly collection: impossible metadata limits reject before allocation" {
    var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var copies = Copies{};
    try std.testing.expectError(error.ReadonlyCounterCollectionResourceLimit, Collection.Owned.init(fail.allocator(), @splat(1), &intervals, 1, .{ .sink = copies.sink(), .limits = .{ .max_metadata_bytes = 1 } }));
    try std.testing.expectEqual(@as(usize, 0), fail.alloc_index);
}
test "global readonly collection: streamed fragment transport scope hash non-overwrite and bounded reader" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var writer = try Staging.Writer.init(a, tmp.dir, @splat(1), 2, .{});
    defer writer.deinit();
    const sink = writer.sink();
    try sink.put_group(sink.context, .{ .group = .{ .index = 0, .first_source = 0, .source_count = 1, .census = .{ .all_rw = 150_001, .mutable = 1, .readonly = 150_000 } }, .counts = &.{ 1, 150_000, 0 } });
    const pin = writer.records()[0];
    try std.testing.expectEqual(@as(u64, 4), pin.fragment_count);
    var reader = try Staging.Reader.open(tmp.dir, pin, .{});
    defer reader.deinit();
    var shard = (try reader.nextShard(a)).?;
    defer shard.deinit();
    try std.testing.expectEqual(@as(usize, 4), shard.fragments.len);
    try std.testing.expectEqual(@as(u16, 65535), shard.fragments[1].count);
    try std.testing.expectEqual(@as(u16, 18930), shard.fragments[3].count);
    try std.testing.expectEqual(@as(?Staging.ShardView, null), try reader.nextShard(a));
    var changed = pin;
    changed.selection_digest[0] ^= 1;
    try std.testing.expectError(error.StaleReadonlyCounterScope, Staging.Reader.open(tmp.dir, changed, .{}));
    var repeat = try Staging.Writer.init(a, tmp.dir, @splat(1), 1, .{});
    defer repeat.deinit();
    const duplicate = repeat.sink();
    try std.testing.expectError(error.PathAlreadyExists, duplicate.put_group(duplicate.context, .{ .group = pin.group, .counts = &.{ 1, 150_000, 0 } }));
    var path_buf: [80]u8 = undefined;
    var file = try tmp.dir.openFile(try Staging.name(0, &path_buf), .{ .mode = .read_write });
    defer file.close();
    try file.pwriteAll(&.{9}, 84);
    try std.testing.expectError(error.StaleReadonlyCounterFile, Staging.Reader.open(tmp.dir, pin, .{}));
}
test "global readonly collection: zero census stages exact absence and file cap leaves no artifact" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var writer = try Staging.Writer.init(a, tmp.dir, @splat(1), 2, .{ .max_group_file_bytes = 84 });
    defer writer.deinit();
    const sink = writer.sink();
    try std.testing.expectError(error.ReadonlyCounterStagingResourceLimit, sink.put_group(sink.context, .{ .group = .{ .index = 0, .first_source = 0, .source_count = 1, .census = .{ .all_rw = 1, .mutable = 1, .readonly = 0 } }, .counts = &.{ 1, 0, 0 } }));
    try std.testing.expectEqual(@as(usize, 0), writer.used);
    try sink.put_group(sink.context, .{ .group = .{ .index = 0, .first_source = 0, .source_count = 1, .census = .{ .all_rw = 0, .mutable = 0, .readonly = 0 } }, .counts = &.{ 0, 0, 0 } });
    var reader = try Staging.Reader.open(tmp.dir, writer.records()[0], .{});
    defer reader.deinit();
    try std.testing.expectEqual(@as(?Staging.ShardView, null), try reader.nextShard(a));
}
const Inventory = struct {
    sources: [1]Collection.SourceRecord,
    groups: [1]Collection.Group,
    providers: [1]Roster.ProviderPin,
    ranges: [1]Roster.RangePin,
    fn init(plan_digest: [32]u8, selection: [32]u8, source_digest: [32]u8) !Inventory {
        const cfg = try config();
        const shape = try Provider.shard(0, 0, 0, &intervals, &.{.{ .interval_index = 1, .count = 2 }});
        _ = selection;
        _ = source_digest;
        return .{ .sources = .{.{ .kind = .native, .index = 0, .group_id = 0, .roots = .{ @splat(3), @splat(4), @splat(5) }, .classifier_roots = .{ @splat(7), @splat(8) }, .row_log = 1, .counter_digest = @splat(9), .census = .{ .all_rw = 2, .mutable = 0, .readonly = 2 } }}, .groups = .{.{ .index = 0, .first_source = 0, .source_count = 1, .census = .{ .all_rw = 2, .mutable = 0, .readonly = 2 } }}, .providers = .{.{ .shape = shape, .roots = .{ @splat(21), @splat(22) }, .ordinal_digest = @splat(23), .plan_digest = plan_digest, .config = cfg, .range_index = 0 }}, .ranges = .{.{ .index = 0, .group_id = 0, .provider_index = 0, .shard = .{ .index = 0, .first_instance = 0, .instance_count = 1, .request_count = shape.counts.range_requests }, .plan_digest = Roster.rangePlanDigest(plan_digest, shape), .roots = .{ @splat(24), @splat(25) }, .counter_digest = @splat(26), .config = cfg }} };
    }
    fn inputs(self: *const Inventory, plan: [32]u8, selection: [32]u8, source: [32]u8) !Roster.Inputs {
        return .{ .plan_digest = plan, .selection_digest = selection, .initial_source_plan_digest = source, .config = try config(), .sources = &self.sources, .groups = &self.groups, .providers = &self.providers, .ranges = &self.ranges };
    }
};
test "global readonly collection: exact roster pins source provider range geometry census and mass groups" {
    var inventory = try Inventory.init(@splat(1), @splat(2), @splat(3));
    const input = try inventory.inputs(@splat(1), @splat(2), @splat(3));
    const hash = try Roster.digest(input);
    inventory.sources[0].roots[1][0] ^= 1;
    try std.testing.expect(!std.meta.eql(hash, try Roster.digest(input)));
    inventory.sources[0].roots[1][0] ^= 1;
    inventory.providers[0].shape.group_id = 1;
    try std.testing.expectError(error.IncompleteGlobalReadonlyProviders, Roster.digest(input));
    inventory.providers[0].shape.group_id = 0;
    inventory.ranges[0].shard.request_count += 1;
    try std.testing.expectError(error.InvalidGlobalReadonlyRange, Roster.digest(input));
    inventory.ranges[0].shard.request_count -= 1;
    inventory.groups[0].census.all_rw = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidGlobalReadonlyGroup, Roster.digest(input));
}
fn authorityOwnership(a: std.mem.Allocator) !void {
    const actual = try Policy.sources();
    var selected = try Policy.selection(a, actual);
    defer selected.deinit();
    var plan = try Plan.derive(a, actual, &Policy.input, &Policy.selected, .{});
    defer plan.deinit();
    var inventory = try Inventory.init(plan.digest, selected.digest, try actual.digest());
    const inputs = try inventory.inputs(plan.digest, selected.digest, try actual.digest());
    var counts: [Seal.family_count]u32 = @splat(0);
    counts[@intFromEnum(Seal.Family.program) - 1] = 1;
    counts[@intFromEnum(Seal.Family.execution) - 1] = 1;
    counts[@intFromEnum(Seal.Family.execution_sidecar) - 1] = 1;
    counts[@intFromEnum(Seal.Family.program_request) - 1] = 1;
    const pins = Seal.Pins{ .job_id = @splat(30), .source_image_digest = @splat(31), .native_template_id = @splat(32), .program_root = @splat(33), .program_plan_digest = @splat(34), .memory_plan_digest = @splat(35), .initial_source_plan_digest = try actual.digest(), .register_endpoint_plan_digest = @splat(36), .register_custody_mode = 1, .readonly_roster_digest = try Roster.digest(inputs), .config = try config(), .counts = counts };
    const entries = [_]Seal.Entry{ .{ .family = .program, .index = 0, .instance_id = @splat(37), .roots = .{ @splat(38), @splat(39) } }, .{ .family = .execution, .index = 0, .instance_id = @splat(40), .roots = .{ @splat(3), @splat(4) } }, .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(41), .roots = .{ @splat(5), @splat(0) } }, .{ .family = .program_request, .index = 0, .instance_id = @splat(42), .roots = .{ @splat(43), @splat(0) } } };
    const sealed = try Seal.seal(pins, &entries);
    const original = @import("block_v5_caller_readonly_protocol_v1.zig").Authority{ .selection = Policy.pins(&selected), .plan = .{ .source = actual, .addresses = &Policy.selected, .expected_digest = plan.digest }, .input = &Policy.input };
    var authority = try Roster.Authority.admit(a, inputs, original, sealed, pins, &entries, .{});
    defer authority.deinit();
    const borrowed = try authority.borrowedPlan(sealed);
    try std.testing.expectEqualDeep(plan.intervals, borrowed.intervals);
    const source = try authority.source(0);
    const identity = try authority.sourceIdentity(0);
    try authority.requireSource(0, source.kind, source.index, source.group_id, source.roots, source.census, identity);
    try std.testing.expectError(error.UntrustedGlobalReadonlySource, authority.requireSource(0, source.kind, source.index, 1, source.roots, source.census, identity));
    const expected_provider = try authority.provider(0);
    inventory.providers[0].roots[0][0] ^= 1;
    try authority.requireProvider(expected_provider);
    try std.testing.expectError(error.UntrustedGlobalReadonlyProvider, authority.requireProvider(inventory.providers[0]));
    var changed = sealed;
    changed.digest[0] ^= 1;
    try std.testing.expectError(error.StaleGlobalReadonlyEpoch, authority.borrowedPlan(changed));
}
test "global readonly collection: actual late Plan epoch immutable ownership and every allocation failure" {
    try authorityOwnership(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, authorityOwnership, .{});
}

fn stagedOwnership(a: std.mem.Allocator) !void {
    const actual = try Policy.sources();
    var selected = try Policy.selection(a, actual);
    defer selected.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const first = try native(0, selected.digest, &.{ 0, 2, 0 }, 1);
    var owned = try Original.Owned.initWithStaging(a, .{ .selection = Policy.pins(&selected), .native = first.expected.limits, .shared_provider_staging = .{} }, &Policy.input, 1, 1024 * 1024, tmp.dir);
    defer owned.deinit();
    try owned.counter_groups.?.appendNative(first, &.{ 0, 2, 0 });
    try owned.append(first);
    try owned.counter_groups.?.finish();
    try owned.bind(actual);
    try std.testing.expectEqual(@as(usize, 1), owned.counter_staging.?.records().len);
    var reader = try Staging.Reader.open(tmp.dir, owned.counter_staging.?.records()[0], .{});
    defer reader.deinit();
    var view = (try reader.nextShard(a)).?;
    defer view.deinit();
    try std.testing.expectEqual(@as(u16, 2), view.fragments[0].count);
    try std.testing.expectEqual(@as(u32, 1), view.fragments[0].interval_index);
}
test "global readonly collection: real collection owner staged sink lifetime and allocation rollback" {
    try stagedOwnership(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, stagedOwnership, .{});
}
