//! Scalar host metadata/real file transport/witness equations only. No PCS,
//! STARK, guest, segment, forest or device functions are invoked by these tests.
const std = @import("std");
const core = @import("stwo_core");
const Counters = @import("block_v5_readonly_input_counter_collection_v2.zig");
const Files = @import("block_v5_readonly_input_counter_staging_v2.zig");
const Stage = @import("block_v5_readonly_input_global_staging_v2.zig");
const Table = @import("block_v5_readonly_input_provider_v2.zig");
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
const intervals = [_]Plan.Interval{
    .{ .lower = 0, .upper = 1, .readonly = false, .value = 0 },
    .{ .lower = 1, .upper = 2, .readonly = true, .value = 7 },
    .{ .lower = 2, .upper = Plan.WORD_LIMIT, .readonly = false, .value = 0 },
};
const Copies = struct {
    used: usize = 0,
    groups: [4]Counters.Group = undefined,
    counts: [4][3]u64 = undefined,
    fn sink(self: *Copies) Counters.Sink {
        return .{ .context = self, .put_group = append };
    }
    fn append(raw: *anyopaque, view: Counters.GroupView) !void {
        const self: *Copies = @ptrCast(@alignCast(raw));
        if (self.used == self.groups.len or view.counts.len != 3) return error.UnexpectedStreamingShape;
        self.groups[self.used] = view.group;
        @memcpy(&self.counts[self.used], view.counts);
        self.used += 1;
    }
};
/// Normative host physical metadata, explicitly not fresh commitment/proof
/// evidence. Positive scalar tests cannot authorize RAM subtraction.
fn record(token: Counters.Token, readonly: u64) Counters.SourceRecord {
    return .{ .kind = token.kind, .index = token.index, .group_id = token.group_id, .roots = .{ @splat(3), @splat(4), @splat(5) }, .classifier_roots = if (token.kind == .native and token.expected_events != 0) .{ @splat(6), @splat(7) } else null, .row_log = if (token.kind == .native and token.expected_events != 0) @max(1, std.math.log2_int_ceil(u64, token.expected_events)) else 0, .counter_digest = @splat(99), .census = .{ .all_rw = token.expected_events, .mutable = token.expected_events - readonly, .readonly = readonly } };
}
fn streaming(a: std.mem.Allocator) !void {
    var copies = Copies{};
    var collector = try Counters.Owned.init(a, @splat(1), &intervals, 2, .{ .sink = copies.sink(), .limits = .{ .max_group_events = 4 } });
    defer collector.deinit();
    const first = try collector.beginSource(.native, 0, 3);
    try collector.observe(first, 1, 2);
    try collector.observe(first, 2, 1);
    const native = try collector.endSource(first, record(first, 2));
    try std.testing.expectEqual(Counters.CounterSchema.interval_stream_v2, native.counter_schema);
    try std.testing.expect(!std.meta.eql(native.counter_digest, @as([32]u8, @splat(99))));
    try std.testing.expectError(error.StaleReadonlyCounterSourceToken, collector.observe(first, 1, 1));
    const caller = try collector.beginSource(.caller, 0, 2);
    try std.testing.expectEqual(@as(u32, 1), caller.group_id);
    try std.testing.expectEqual(@as(usize, 1), copies.used);
    try collector.observe(caller, 0, 1);
    try collector.observe(caller, 1, 1);
    _ = try collector.endSource(caller, record(caller, 1));
    const last = try collector.beginSource(.native, 1, 0);
    _ = try collector.endSource(last, record(last, 0));
    try collector.finish();
    try std.testing.expectEqual(@as(u64, 5), collector.census.all_rw);
    try std.testing.expectEqual(@as(u64, 3), collector.census.readonly);
    try std.testing.expectEqual(@as(usize, 2), copies.used);
    try std.testing.expectEqual(@as(u32, 2), copies.groups[1].source_count);
    try std.testing.expectEqualSlices(u64, &.{ 0, 2, 1 }, &copies.counts[0]);
    try std.testing.expectEqualSlices(u64, &.{ 1, 1, 0 }, &copies.counts[1]);
    for (collector.counts) |value| try std.testing.expectEqual(@as(u64, 0), value);
}
test "global readonly staging: streaming source lifetime exact counts group boundary and allocation unwind" {
    try streaming(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, streaming, .{});
}
test "global readonly staging: every token field cross-owner stale reuse and overflow reject before mutation" {
    const a = std.testing.allocator;
    var copies = Copies{};
    var left = try Counters.Owned.init(a, @splat(1), &intervals, 1, .{ .sink = copies.sink() });
    defer left.deinit();
    var right = try Counters.Owned.init(a, @splat(1), &intervals, 1, .{ .sink = copies.sink() });
    defer right.deinit();
    const original = try left.beginSource(.native, 0, 2);
    const other = try right.beginSource(.native, 0, 2);
    try std.testing.expect(original.owner_id != other.owner_id);
    try std.testing.expectError(error.StaleReadonlyCounterSourceToken, right.observe(original, 1, 1));
    inline for (std.meta.fields(Counters.Token)) |field| {
        var changed = original;
        if (comptime std.mem.eql(u8, field.name, "kind")) @field(changed, field.name) = .caller else @field(changed, field.name) += 1;
        try std.testing.expectError(error.StaleReadonlyCounterSourceToken, left.observe(changed, 1, 1));
        try std.testing.expectError(error.StaleReadonlyCounterSourceToken, left.abortSource(changed));
    }
    try std.testing.expectEqual(@as(u64, 0), left.counts[1]);
    try std.testing.expectError(error.InvalidReadonlyCounterObservation, left.observe(original, 1, 0));
    try std.testing.expectError(error.InvalidReadonlyCounterObservation, left.observe(original, 3, 1));
    try std.testing.expectError(error.StaleReadonlyCounterCensus, left.observe(original, 1, 3));
    try left.observe(original, 1, 2);
    _ = try left.endSource(original, record(original, 2));
    const fresh = try left.beginSource(.caller, 0, 0);
    try std.testing.expectError(error.StaleReadonlyCounterSourceToken, left.observe(original, 0, 1));
    _ = try left.endSource(fresh, record(fresh, 0));
    try right.abortSource(other);
    try std.testing.expectError(error.ReadonlyCounterCollectionClosed, right.finish());
    // Same Owned address after destruction receives a distinct owner identity.
    var replacement = try Counters.Owned.init(a, @splat(1), &intervals, 1, .{ .sink = copies.sink() });
    const retired = try replacement.beginSource(.native, 0, 0);
    replacement.deinit();
    replacement = try Counters.Owned.init(a, @splat(1), &intervals, 1, .{ .sink = copies.sink() });
    defer replacement.deinit();
    const active = try replacement.beginSource(.native, 0, 0);
    try std.testing.expect(active.owner_id != retired.owner_id);
    try std.testing.expectError(error.StaleReadonlyCounterSourceToken, replacement.endSource(retired, record(retired, 0)));
    try replacement.abortSource(active);
}
test "global readonly staging: physical completion and selection borrow fail closed without partial source admission" {
    var copies = Copies{};
    var owned = try Counters.Owned.init(std.testing.allocator, @splat(1), &intervals, 1, .{ .sink = copies.sink() });
    defer owned.deinit();
    var cloned_intervals = intervals;
    try std.testing.expectError(error.StaleReadonlyCounterSelectionBorrow, owned.requireSelectionBorrow(@splat(1), &cloned_intervals));
    try owned.requireSelectionBorrow(@splat(1), &intervals);
    owned.token_generation = std.math.maxInt(u64);
    try std.testing.expectError(error.ReadonlyCounterGenerationExhausted, owned.beginSource(.native, 0, 2));
    try std.testing.expect(owned.pending == null);
    owned.token_generation = 0;
    const token = try owned.beginSource(.native, 0, 2);
    try std.testing.expectError(error.ReadonlyCounterCollectionClosed, owned.beginSource(.native, 0, 0));
    try std.testing.expectError(error.ReadonlyCounterCollectionClosed, owned.finish());
    try std.testing.expectError(error.StaleReadonlyCounterCensus, owned.endSource(token, record(token, 2)));
    try owned.observe(token, 1, 2);
    var physical = record(token, 2);
    physical.group_id += 1;
    try std.testing.expectError(error.StaleReadonlyCounterCensus, owned.endSource(token, physical));
    physical = record(token, 2);
    physical.roots[0] = @splat(0);
    try std.testing.expectError(error.InvalidReadonlyCounterSourceRoots, owned.endSource(token, physical));
    physical = record(token, 2);
    physical.classifier_roots = null;
    try std.testing.expectError(error.InvalidReadonlyCounterSourceRoots, owned.endSource(token, physical));
    try std.testing.expectEqual(@as(usize, 0), owned.source_count);
    try owned.abortSource(token);
    try std.testing.expectEqual(@as(u64, 2), owned.counts[1]);
    try std.testing.expectError(error.ReadonlyCounterCollectionClosed, owned.beginSource(.native, 0, 0));
    try std.testing.expectError(error.ReadonlyCounterCollectionClosed, owned.sourceRecords());
}
fn witness(a: std.mem.Allocator) !void {
    const fragments = [_]Table.Fragment{ .{ .interval_index = 0, .count = 2 }, .{ .interval_index = 1, .count = 65535 }, .{ .interval_index = 1, .count = 6 } };
    const shape = try Table.shard(0, 0, 0, &intervals, &fragments);
    const config = core.pcs.PcsConfig{ .pow_bits = 26, .fri_config = try core.fri.FriConfig.init(2, 70, 8) };
    var prepared = try Stage.Witness.init(a, &intervals, &fragments, shape, @splat(1), config, .{});
    defer prepared.deinit();
    try std.testing.expectEqual(@as(u64, 36), prepared.counter.total);
    try std.testing.expectEqual(@as(u64, 65543), prepared.provider_pin.shape.counts.events);
    try std.testing.expectEqual(@as(u64, 65541), prepared.provider_pin.shape.counts.readonly);
    try std.testing.expectEqualSlices(u32, &.{ 0, 1, 1 }, prepared.ordinals);
    var provider_pin = prepared.provider_pin;
    var range_pin = prepared.range_pin;
    provider_pin.roots = .{ @splat(3), @splat(4) };
    range_pin.roots = .{ @splat(5), @splat(6) };
    try prepared.requirePins(provider_pin, range_pin);
    provider_pin.ordinal_digest[0] ^= 1;
    try std.testing.expectError(error.StaleGlobalReadonlyStagingWitness, prepared.requirePins(provider_pin, range_pin));
    provider_pin = prepared.provider_pin;
    range_pin.counter_digest[0] ^= 1;
    try std.testing.expectError(error.StaleGlobalReadonlyStagingWitness, prepared.requirePins(provider_pin, range_pin));
}
test "global readonly staging: actual padded provider range census witness and allocation unwind" {
    try witness(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, witness, .{});
    const fragments = [_]Table.Fragment{.{ .interval_index = 1, .count = 1 }};
    const shape = try Table.shard(0, 0, 0, &intervals, &fragments);
    var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.GlobalReadonlyWitnessResourceLimit, Stage.Witness.init(fail.allocator(), &intervals, &fragments, shape, @splat(1), .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) }, .{ .max_witness_bytes = 1 }));
    try std.testing.expectEqual(@as(usize, 0), fail.alloc_index);
}
fn chunkRead(a: std.mem.Allocator, dir: std.fs.Dir, pin: Files.Pin, chunk: Files.ChunkPin) !void {
    var view = try Files.readChunk(a, dir, pin, chunk, .{});
    defer view.deinit();
    try std.testing.expectEqual(@as(usize, 1), view.fragments.len);
    try std.testing.expectEqual(@as(u16, 1), view.fragments[0].count);
}
test "global readonly staging: batched group reader direct chunk scope mutation and allocation unwind" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var writer = try Files.Writer.init(a, tmp.dir, @splat(1), 1, .{});
    defer writer.deinit();
    const mass = @as(u64, Table.MAX_FRAGMENTS) * 65535 + 1;
    const sink = writer.sink();
    try sink.put_group(sink.context, .{ .group = .{ .index = 0, .first_source = 0, .source_count = 1, .census = .{ .all_rw = mass, .mutable = 0, .readonly = mass } }, .counts = &.{ 0, mass, 0 } });
    const pin = writer.records()[0];
    var reader = try Files.Reader.open(tmp.dir, pin, .{});
    defer reader.deinit();
    var first = (try reader.nextShard(a)).?;
    defer first.deinit();
    var last = (try reader.nextShard(a)).?;
    defer last.deinit();
    const first_pin = try first.chunkPin(0);
    const last_pin = try last.chunkPin(0);
    try std.testing.expectEqual(@as(?Files.ShardView, null), try reader.nextShard(a));
    try chunkRead(a, tmp.dir, pin, last_pin);
    try std.testing.checkAllAllocationFailures(a, chunkRead, .{ tmp.dir, pin, last_pin });
    var changed = last_pin;
    changed.group_index = 1;
    try std.testing.expectError(error.InvalidReadonlyCounterChunk, Files.readChunk(a, tmp.dir, pin, changed, .{}));
    changed = last_pin;
    changed.sha256[0] ^= 1;
    try std.testing.expectError(error.StaleReadonlyCounterChunk, Files.readChunk(a, tmp.dir, pin, changed, .{}));
    var name_buffer: [80]u8 = undefined;
    var file = try tmp.dir.openFile(try Files.name(0, &name_buffer), .{ .mode = .read_write });
    defer file.close();
    // Mutation outside the last independently pinned chunk is detected by its
    // own consumer and by whole-file admission, without rescanning it here.
    try file.pwriteAll(&.{0xfe}, 84 + 4);
    try chunkRead(a, tmp.dir, pin, last_pin);
    try std.testing.expectError(error.InvalidReadonlyProviderFragments, Files.readChunk(a, tmp.dir, pin, first_pin, .{}));
    try std.testing.expectError(error.StaleReadonlyCounterFile, Files.Reader.open(tmp.dir, pin, .{}));
    try file.pwriteAll(&.{0xff}, 84 + 4);
    try file.pwriteAll(&.{2}, 84 + last_pin.first_fragment * 6 + 4);
    try std.testing.expectError(error.StaleReadonlyCounterChunk, Files.readChunk(a, tmp.dir, pin, last_pin, .{}));
    try file.setEndPos(pin.bytes - 1);
    try std.testing.expectError(error.StaleReadonlyCounterFile, Files.readChunk(a, tmp.dir, pin, last_pin, .{}));
}
test "global readonly staging: exact shard count no count rounding zero absence and metadata cap" {
    const mass = @as(u64, Table.MAX_FRAGMENTS) * 65535 + 1;
    const group = Counters.Group{ .index = 0, .first_source = 0, .source_count = 1, .census = .{ .all_rw = mass, .mutable = 0, .readonly = mass } };
    var files = [_]Files.Pin{.{ .group = group, .selection_digest = @splat(1), .interval_count = 3, .fragment_count = Table.MAX_FRAGMENTS + 1, .bytes = 84 + (Table.MAX_FRAGMENTS + 1) * 6, .sha256 = @splat(2) }};
    try std.testing.expectEqual(@as(usize, 2), try Stage.providerCount(&files, &.{group}, @splat(1), 3, .{}));
    try std.testing.expectError(error.GlobalReadonlyStagingResourceLimit, Stage.providerCount(&files, &.{group}, @splat(1), 3, .{ .max_provider_count = 1 }));
    try std.testing.expectError(error.GlobalReadonlyStagingResourceLimit, Stage.providerCount(&files, &.{group}, @splat(1), 3, .{ .max_metadata_bytes = 1 }));
    files[0].group.index = 1;
    try std.testing.expectError(error.StaleGlobalReadonlyStaging, Stage.providerCount(&files, &.{group}, @splat(1), 3, .{}));
    const absent = Counters.Group{ .index = 0, .first_source = 0, .source_count = 1, .census = .{ .all_rw = 0, .mutable = 0, .readonly = 0 } };
    files[0] = .{ .group = absent, .selection_digest = @splat(1), .interval_count = 3, .fragment_count = 0, .bytes = 84, .sha256 = @splat(2) };
    try std.testing.expectEqual(@as(usize, 0), try Stage.providerCount(&files, &.{absent}, @splat(1), 3, .{}));
}
