//! Genuine pre-seal provider/range preparation and bounded post-seal replay.
//! Only value metadata survives each shard. No staging pin is proof authority.
const std = @import("std");
const core = @import("stwo_core");
const Collection = @import("block_v5_readonly_input_collection_v1.zig");
const Counters = @import("block_v5_readonly_input_counter_collection_v2.zig");
const Files = @import("block_v5_readonly_input_counter_staging_v2.zig");
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
const Table = @import("block_v5_readonly_input_provider_v2.zig");
const Provider = @import("block_v5_readonly_input_provider_proof_v2.zig");
const Roster = @import("block_v5_readonly_input_global_roster_v2.zig");
const Range = @import("block_v5_range16_v1.zig");
const RangeProof = @import("block_v5_range16_proof_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
pub const Limits = struct {
    max_metadata_bytes: usize = 64 * 1024 * 1024,
    max_provider_count: usize = 1_000_000,
    /// Witness/fragments/ordinals/counter only. PCS uses the caller's original
    /// aggregate allocator and is not represented as a process RSS bound here.
    max_witness_bytes: usize = 16 * 1024 * 1024,
    table: Table.Limits = .{},
    files: Files.Limits = .{},
};
pub fn providerCount(files: []const Files.Pin, groups: []const Counters.Group, selection: [32]u8, interval_count: usize, limits: Limits) !usize {
    if (files.len != groups.len or groups.len == 0 or interval_count == 0 or interval_count > std.math.maxInt(u32) or
        std.mem.allEqual(u8, &selection, 0)) return error.IncompleteGlobalReadonlyStaging;
    var count: usize = 0;
    var bytes: u64 = 0;
    for (files, groups, 0..) |file, group, index| {
        try file.require(limits.files);
        if (group.index != index or !std.meta.eql(file.group, group) or !std.meta.eql(file.selection_digest, selection) or
            file.interval_count != interval_count or (file.fragment_count == 0) != (group.census.all_rw == 0) or
            file.fragment_count > group.census.all_rw or file.bytes > limits.files.max_group_file_bytes) return error.StaleGlobalReadonlyStaging;
        try group.census.require(group.census.all_rw);
        if (group.census.all_rw > limits.files.counters.max_group_events or group.census.all_rw >= core.fields.m31.Modulus) return error.InvalidGlobalReadonlyStagingMass;
        bytes = try std.math.add(u64, bytes, file.bytes);
        if (bytes > limits.files.max_total_file_bytes) return error.GlobalReadonlyStagingResourceLimit;
        const shards = file.fragment_count / Table.MAX_FRAGMENTS + @intFromBool(file.fragment_count % Table.MAX_FRAGMENTS != 0);
        count = try std.math.add(usize, count, std.math.cast(usize, shards) orelse return error.GlobalReadonlyStagingResourceLimit);
        if (count > limits.max_provider_count or count > std.math.maxInt(u32)) return error.GlobalReadonlyStagingResourceLimit;
    }
    _ = try metadataBytes(groups.len, count, limits);
    return count;
}
pub fn metadataBytes(group_count: usize, provider_count: usize, limits: Limits) !usize {
    if (group_count == 0 or provider_count > limits.max_provider_count or provider_count > std.math.maxInt(u32)) return error.GlobalReadonlyStagingResourceLimit;
    const bytes = try std.math.add(usize, @sizeOf(Owned), try std.math.add(usize, try std.math.mul(usize, group_count, @sizeOf(Files.Pin)), try std.math.mul(usize, provider_count, @sizeOf(Roster.ProviderPin) + @sizeOf(Roster.RangePin) + @sizeOf(Files.ChunkPin))));
    if (bytes > limits.max_metadata_bytes) return error.GlobalReadonlyStagingResourceLimit;
    return bytes;
}
fn witnessBytes(shape: Table.Shard, limits: Limits) !usize {
    try shape.require();
    const rows: usize = @as(usize, 1) << @intCast(shape.row_log);
    const matrix = try std.math.mul(usize, rows, (Table.Layout.fixed + Table.Layout.main) * @sizeOf(core.fields.m31.M31));
    // Columns.init temporarily derives its own bounded ordinal view.
    const fragments = try std.math.mul(usize, shape.fragment_count, @sizeOf(Table.Fragment) + 2 * @sizeOf(u32));
    const bytes = try std.math.add(usize, @sizeOf(Witness), try std.math.add(usize, matrix, try std.math.add(usize, fragments, Range.TABLE_SIZE * @sizeOf(u32))));
    if (matrix > limits.table.max_matrix_bytes or bytes > limits.max_witness_bytes) return error.GlobalReadonlyWitnessResourceLimit;
    return bytes;
}
/// Actual provider columns plus its dedicated range counter. Neither matrix
/// census nor expected roots creates a fresh verification receipt.
pub const Witness = struct {
    a: std.mem.Allocator,
    columns: Table.Columns,
    counter: Range.Counter,
    ordinals: []u32,
    provider_pin: Roster.ProviderPin,
    range_pin: Roster.RangePin,
    pub fn init(a: std.mem.Allocator, intervals: []const Plan.Interval, fragments: []const Table.Fragment, shape: Table.Shard, plan_digest: [32]u8, config: core.pcs.PcsConfig, limits: Limits) !Witness {
        _ = try witnessBytes(shape, limits);
        if (std.mem.allEqual(u8, &plan_digest, 0)) return error.UnboundGlobalReadonlyStagingPlan;
        var columns = try Table.Columns.init(a, intervals, fragments, shape, limits.table);
        errdefer columns.deinit();
        var counter = try Range.Counter.init(a);
        errdefer counter.deinit();
        try columns.addRangeCounters(&counter);
        if (counter.total != shape.counts.range_requests) return error.StaleGlobalReadonlyStagingCensus;
        const ordinals = try a.alloc(u32, fragments.len);
        errdefer a.free(ordinals);
        for (ordinals, fragments) |*ordinal, fragment| ordinal.* = fragment.interval_index;
        return .{ .a = a, .columns = columns, .counter = counter, .ordinals = ordinals, .provider_pin = .{ .shape = shape, .roots = .{ @splat(0), @splat(0) }, .ordinal_digest = try Table.ordinalDigest(shape, plan_digest, ordinals), .plan_digest = plan_digest, .config = config, .range_index = shape.index }, .range_pin = .{ .index = shape.index, .group_id = shape.group_id, .provider_index = shape.index, .shard = .{ .index = shape.index, .first_instance = shape.index, .instance_count = 1, .request_count = counter.total }, .plan_digest = Roster.rangePlanDigest(plan_digest, shape), .roots = .{ @splat(0), @splat(0) }, .counter_digest = counter.digest(), .config = config } };
    }
    pub fn deinit(self: *Witness) void {
        self.a.free(self.ordinals);
        self.counter.deinit();
        self.columns.deinit();
        self.* = undefined;
    }
    pub fn requirePins(self: *const Witness, provider_pin: Roster.ProviderPin, range_pin: Roster.RangePin) !void {
        var physical_provider = provider_pin;
        var physical_range = range_pin;
        physical_provider.roots = .{ @splat(0), @splat(0) };
        physical_range.roots = .{ @splat(0), @splat(0) };
        if (!std.meta.eql(self.provider_pin, physical_provider) or !std.meta.eql(self.range_pin, physical_range)) return error.StaleGlobalReadonlyStagingWitness;
    }
};
pub const Pair = struct {
    provider: Provider.Proof,
    range: RangeProof.Proof,
    pub fn deinit(self: *Pair, a: std.mem.Allocator) void {
        self.range.deinit(a);
        self.provider.deinit(a);
        self.* = undefined;
    }
};
/// Completed pre-seal metadata. Group file pins are copied, so their writer may
/// release metadata; exact collection/Plan custody remains with its original job.
pub const Owned = struct {
    a: std.mem.Allocator,
    group_files: []Files.Pin,
    providers: []Roster.ProviderPin,
    ranges: []Roster.RangePin,
    chunks: []Files.ChunkPin,
    plan_digest: [32]u8,
    selection_digest: [32]u8,
    initial_source_plan_digest: [32]u8,
    config: core.pcs.PcsConfig,
    limits: Limits,
    pub fn deinit(self: *Owned) void {
        self.a.free(self.chunks);
        self.a.free(self.ranges);
        self.a.free(self.providers);
        self.a.free(self.group_files);
        self.* = undefined;
    }
    pub fn inputs(self: *const Owned, collection: *const Collection.Owned) !Roster.Inputs {
        const groups = if (collection.counter_groups) |*owned_groups| owned_groups else return error.IncompleteGlobalReadonlyStaging;
        const plan = if (collection.plan) |*owned_plan| owned_plan else return error.UnboundGlobalReadonlyStagingPlan;
        if (!std.meta.eql(plan.digest, self.plan_digest) or !std.meta.eql(collection.selection.digest, self.selection_digest) or
            !std.meta.eql(try (collection.source orelse return error.UnboundGlobalReadonlyStagingPlan).digest(), self.initial_source_plan_digest) or
            groups.limits.max_group_events != self.limits.files.counters.max_group_events) return error.StaleGlobalReadonlyStaging;
        const source_records = try groups.sourceRecords();
        const group_records = try groups.groupRecords();
        if (group_records.len != self.group_files.len) return error.StaleGlobalReadonlyStaging;
        for (group_records, self.group_files) |group, file| if (!std.meta.eql(group, file.group)) return error.StaleGlobalReadonlyStaging;
        return .{ .plan_digest = self.plan_digest, .selection_digest = self.selection_digest, .initial_source_plan_digest = self.initial_source_plan_digest, .config = self.config, .max_group_events = groups.limits.max_group_events, .sources = source_records, .groups = group_records, .providers = self.providers, .ranges = self.ranges };
    }
    /// Whole-roster validation and binding happen before the original B5SS
    /// challenge seal. No future post-seal identity participates in these roots.
    pub fn bindRoster(self: *const Owned, collection: *Collection.Owned) ![32]u8 {
        const value = try Roster.digest(try self.inputs(collection));
        try collection.bindRoster(value);
        return value;
    }
    /// One shard per worker, with no full group-file rehash or interval-sized
    /// histogram. Expected authority pins are checked before witness allocation.
    pub fn load(self: *const Owned, a: std.mem.Allocator, dir: std.fs.Dir, authority: *const Roster.Authority, sealed: Seal.Sealed, index: u32) !Witness {
        try authority.requireEpoch(sealed);
        if (index >= self.providers.len or index >= self.ranges.len or index >= self.chunks.len or
            !std.meta.eql(authority.epoch().plan_digest, self.plan_digest) or !std.meta.eql(authority.config(), self.config)) return error.StaleGlobalReadonlyStaging;
        const expected_provider = self.providers[index];
        const expected_range = self.ranges[index];
        try authority.requireProvider(expected_provider);
        try authority.requireRange(expected_range);
        _ = try witnessBytes(expected_provider.shape, self.limits);
        const group_index = expected_provider.shape.group_id;
        if (group_index >= self.group_files.len) return error.StaleGlobalReadonlyStaging;
        var chunk = try Files.readChunk(a, dir, self.group_files[group_index], self.chunks[index], self.limits.files);
        defer chunk.deinit();
        var witness = try Witness.init(a, authority.intervals(), chunk.fragments, expected_provider.shape, self.plan_digest, self.config, self.limits);
        errdefer witness.deinit();
        try witness.requirePins(expected_provider, expected_range);
        return witness;
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const ProviderApi = Provider.ForBackend(Backend);
        const RangeApi = RangeProof.ForAdmission(Backend);
        pub const First = struct {
            provider: ProviderApi.First,
            range: RangeApi.FirstRound,
            provider_pin: Roster.ProviderPin,
            range_pin: Roster.RangePin,
            pub fn deinit(self: *First, a: std.mem.Allocator) void {
                self.range.deinit(a);
                self.provider.deinit(a);
                self.* = undefined;
            }
        };
        /// Actual independent first-round commitment bodies, shared by pre-seal
        /// collection and mandatory post-seal replay. No global draws occur here.
        pub fn commit(a: std.mem.Allocator, witness: *const Witness) !First {
            var provider = try ProviderApi.commit(a, &witness.columns, witness.provider_pin);
            errdefer provider.deinit(a);
            var range = try RangeApi.commitFirstRound(a, &witness.counter, witness.range_pin.shard, witness.range_pin.plan_digest, witness.range_pin.config, false);
            errdefer range.deinit(a);
            var provider_pin = witness.provider_pin;
            provider_pin.roots = provider.roots;
            var range_pin = witness.range_pin;
            range_pin.roots = range.roots();
            return .{ .provider = provider, .range = range, .provider_pin = provider_pin, .range_pin = range_pin };
        }
        pub fn collect(a: std.mem.Allocator, dir: std.fs.Dir, collection: *const Collection.Owned, config: core.pcs.PcsConfig, limits: Limits) !Owned {
            const groups = if (collection.counter_groups) |*owned_groups| owned_groups else return error.IncompleteGlobalReadonlyStaging;
            const writer = collection.counter_staging orelse return error.IncompleteGlobalReadonlyStaging;
            const plan = if (collection.plan) |*owned_plan| owned_plan else return error.UnboundGlobalReadonlyStagingPlan;
            const initial_source_digest = try (collection.source orelse return error.UnboundGlobalReadonlyStagingPlan).digest();
            try groups.requirePlan(collection.selection.digest, plan);
            if (groups.limits.max_group_events != limits.files.counters.max_group_events) return error.StaleGlobalReadonlyStaging;
            const group_records = try groups.groupRecords();
            const count = try providerCount(writer.records(), group_records, collection.selection.digest, plan.intervals.len, limits);
            const files = try a.dupe(Files.Pin, writer.records());
            errdefer a.free(files);
            const providers = try a.alloc(Roster.ProviderPin, count);
            errdefer a.free(providers);
            const ranges = try a.alloc(Roster.RangePin, count);
            errdefer a.free(ranges);
            const chunks = try a.alloc(Files.ChunkPin, count);
            errdefer a.free(chunks);
            var at: usize = 0;
            for (files) |file| {
                var reader = try Files.Reader.open(dir, file, limits.files);
                defer reader.deinit();
                var events: u64 = 0;
                var readonly: u64 = 0;
                while (try reader.nextShard(a)) |view| {
                    var chunk = view;
                    defer chunk.deinit();
                    if (at >= count) return error.StaleGlobalReadonlyStaging;
                    const shape = try Table.shard(@intCast(at), file.group.index, chunk.first_fragment, plan.intervals, chunk.fragments);
                    var witness = try Witness.init(a, plan.intervals, chunk.fragments, shape, plan.digest, config, limits);
                    defer witness.deinit();
                    var first = try commit(a, &witness);
                    defer first.deinit(a);
                    providers[at] = first.provider_pin;
                    ranges[at] = first.range_pin;
                    chunks[at] = try chunk.chunkPin(file.group.index);
                    events = try std.math.add(u64, events, shape.counts.events);
                    readonly = try std.math.add(u64, readonly, shape.counts.readonly);
                    at += 1;
                }
                if (events != file.group.census.all_rw or readonly != file.group.census.readonly) return error.StaleGlobalReadonlyStagingCensus;
            }
            if (at != count) return error.StaleGlobalReadonlyStaging;
            return .{ .a = a, .group_files = files, .providers = providers, .ranges = ranges, .chunks = chunks, .plan_digest = plan.digest, .selection_digest = collection.selection.digest, .initial_source_plan_digest = initial_source_digest, .config = config, .limits = limits };
        }
        /// Consumes the genuine replay commitment and both original proof
        /// families. The caller's original shared inverse table is reused.
        pub fn provePair(a: std.mem.Allocator, first: *First, witness: *const Witness, authority: *const Roster.Authority, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, inverses: *const @import("block_v5_range16_inverse_table_v1.zig").Table) !Pair {
            try witness.requirePins(first.provider_pin, first.range_pin);
            try authority.requireEpoch(sealed);
            try authority.requireProvider(first.provider_pin);
            try authority.requireRange(first.range_pin);
            var provider = try ProviderApi.prove(a, &first.provider, &witness.columns, first.provider_pin, authority, sealed, pins, entries);
            errdefer provider.deinit(a);
            const range = try RangeApi.provePreparedWithAdmission(a, &first.range, &witness.counter, first.range_pin.shard, first.range_pin.plan_digest, sealed, pins, entries, inverses, Provider.RangeAdmission{ .authority = authority, .pin = first.range_pin });
            return .{ .provider = provider, .range = range };
        }
        pub fn proveStaged(a: std.mem.Allocator, dir: std.fs.Dir, staged: *const Owned, authority: *const Roster.Authority, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, inverses: *const @import("block_v5_range16_inverse_table_v1.zig").Table, index: u32) !Pair {
            var witness = try staged.load(a, dir, authority, sealed, index);
            defer witness.deinit();
            var first = try commit(a, &witness);
            defer first.deinit(a);
            // Compare mandatory recommit before any interaction/proof work.
            if (!std.meta.eql(first.provider_pin, staged.providers[index]) or !std.meta.eql(first.range_pin, staged.ranges[index])) return error.StaleGlobalReadonlyStagingCommitment;
            return provePair(a, &first, &witness, authority, sealed, pins, entries, inverses);
        }
    };
}
