//! Actual raw/core PAGE commitments and durable operand replay. No core matrix
//! is stored: replay reconstructs original SHA AIRs and table multiplicities,
//! recommits every retained root, and rejects drift before a proof can consume.
//! This ownership layer is not a source arithmetic proof or verified receipt.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Schema = @import("block_v5_memory_source_batch_raw_schema_v1.zig");
const Columns = @import("block_v5_memory_source_packed_sha_columns_v1.zig");
const Shared = @import("block_v5_shared_first_round_v1.zig");
const Budget = engine.host_budget_allocator.HostBudgetAllocator;
pub const TAG: u32 = 0x42355348; // B5SH: packed SOURCE SHA operands, not B5SC
pub const Limits = struct {
    first: Schema.Protocol.Limits = .{},
    stored: Schema.Store.Limits = .{},
    cores: Columns.Limits = .{},
    max_page_heap_bytes: usize = 1 << 30,
};
pub fn abiId() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/source-packed-sha-operands/v1\x00");
    hash.update(&Schema.abiId());
    inline for (Columns.Airs) |Air| hash.update(&Air.SEMANTIC_DIGEST);
    hash.update("raw0/1;cores-and-two-original-tables2/3;connector-fixed4/captures5;exact-raw-kind-calls;replay-all-roots;not-source-authority\x00");
    return hash.finalResult();
}
pub const Pin = struct {
    raw: Schema.Protocol.Pin,
    geometry: Columns.Geometry,
    roots: [6][32]u8,
    pub fn require(self: Pin, admitted: *const Source.Admitted, plan: Schema.Protocol.Plan, limits: Limits) !void {
        try plan.require(admitted, limits.first);
        try self.raw.require(plan);
        if (limits.max_page_heap_bytes == 0 or !std.meta.eql(self.geometry, try Columns.Geometry.fromPage(admitted, self.raw.page, limits.cores)) or !std.meta.eql(self.roots[0..2].*, self.raw.roots)) return error.UntrustedSourcePackedPagePin;
        for (self.roots) |root| if (std.mem.allEqual(u8, &root, 0)) return error.UntrustedSourcePackedPagePin;
    }
    pub fn identity(self: Pin, admitted: *const Source.Admitted, plan: Schema.Protocol.Plan, limits: Limits) ![32]u8 {
        try self.require(admitted, plan, limits);
        const channel = try replayChannel(plan, self);
        return channel.digestBytes();
    }
};
/// Exact post-six-root transcript only. Independent Pin.require and actual
/// commitment verification remain the caller's responsibility.
pub fn replayChannel(plan: Schema.Protocol.Plan, pin: Pin) !suite.Channel {
    var channel = suite.Channel{};
    try replayInto(&channel, plan, pin);
    return channel;
}
/// Exact original raw/core first-six-root grammar; no restart or copied schema.
pub fn replayInto(channel: anytype, plan: Schema.Protocol.Plan, pin: Pin) !void {
    try pin.raw.require(plan);
    if (!std.meta.eql(pin.roots[0..2].*, pin.raw.roots)) return error.UntrustedSourcePackedPagePin;
    for (pin.roots) |root| if (std.mem.allEqual(u8, &root, 0)) return error.UntrustedSourcePackedPagePin;
    Schema.Protocol.mixFirst(channel, plan, pin.raw.page);
    for (pin.roots, 0..) |root, i| {
        if (i == 2) mixCoreRoster(channel, pin.geometry);
        channel.mixRoot(root);
    }
}
pub fn firstChannel(plan: Schema.Protocol.Plan, page: Schema.Protocol.Page, geometry: Columns.Geometry) suite.Channel {
    const channel = Schema.Protocol.firstChannel(plan, page);
    // Raw roots retain their original channel grammar. This suffix follows the
    // two real raw-tree commitments; see append's exact replay order.
    _ = geometry;
    return channel;
}
fn mixCoreRoster(channel: anytype, geometry: Columns.Geometry) void {
    channel.mixRoot(abiId());
    channel.mixU32s(&(.{ TAG, 1, geometry.compressions, geometry.connector_log } ++ geometry.logs));
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Api = @This();
        const RawRound = Schema.Round.ForBackend(Backend);
        const RawReplay = Schema.Replay.ForBackend(Backend);
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        pub const Owner = struct {
            child: std.mem.Allocator,
            budget: Budget,
            raw: ?*RawRound.FirstRound = null,
            cores: ?Columns.Columns = null,
            scheme: ?Scheme = null,
            pin: ?Pin = null,
            active_leases: usize = 0,
            snapshot: [32]u8 = @splat(0),
            pub fn allocator(self: *Owner) std.mem.Allocator {
                return self.budget.allocator();
            }
            pub fn deinit(self: *Owner) !void {
                if (self.active_leases != 0) return error.SourcePackedPageLeaseLive;
                if (self.raw) |raw| if (raw.active_leases != 0) return error.SourcePackedPageLeaseLive;
                if (self.scheme) |*scheme| for (scheme.trees.items, 0..) |tree, i| if (tree.shared_owner) |shared| {
                    // Original raw owner and this combined owner each hold a
                    // genuine tree reference; a third reference is a live lease.
                    const own_references: usize = if (i < 2) 2 else 1;
                    if (shared.references.load(.acquire) != own_references) return error.SourcePackedPageLeaseLive;
                };
                if (self.scheme) |*scheme| scheme.deinit(self.allocator());
                self.scheme = null;
                if (self.cores) |*columns| columns.deinit();
                self.cores = null;
                if (self.raw) |raw| try raw.deinit();
                self.raw = null;
                if (self.budget.live_bytes != 0) @panic("packed source page budget ownership invariant");
                const child = self.child;
                child.destroy(self);
            }
            pub fn require(self: *Owner, admitted: *const Source.Admitted, plan: Schema.Protocol.Plan, expected: Pin, limits: Limits) !void {
                try expected.require(admitted, plan, limits);
                if (self.raw == null or self.cores == null or self.scheme == null or self.pin == null or !std.meta.eql(self.pin.?, expected) or !std.meta.eql(self.cores.?.geometry, expected.geometry) or !std.meta.eql(self.cores.?.snapshot(), self.snapshot)) return error.ChangedSourcePackedPage;
                try self.raw.?.require(admitted, plan, expected.raw, limits.first);
                var roots = try self.scheme.?.roots(self.allocator());
                defer roots.deinit(self.allocator());
                if (roots.items.len != 6 or !std.meta.eql(roots.items[0..6].*, expected.roots)) return error.ChangedSourcePackedPage;
            }
        };
        fn new(a: std.mem.Allocator, limits: Limits) !*Owner {
            if (limits.max_page_heap_bytes == 0) return error.SourcePackedPageResourceLimit;
            const owner = try a.create(Owner);
            owner.* = .{ .child = a, .budget = Budget.init(a, limits.max_page_heap_bytes) };
            return owner;
        }
        fn append(owner: *Owner, admitted: *const Source.Admitted, plan: Schema.Protocol.Plan, limits: Limits, expected: ?Pin, setup: ?*const Columns.Setup) !void {
            const a = owner.allocator();
            const raw = owner.raw orelse return error.InvalidSourcePackedPage;
            const raw_pin = raw.pin orelse return error.InvalidSourcePackedPage;
            try raw.require(admitted, plan, raw_pin, limits.first);
            const columns = if (setup) |shared|
                try Columns.Columns.regenerateWithSetup(a, admitted, &raw.columns.?, limits.cores, shared)
            else
                try Columns.Columns.regenerate(a, admitted, &raw.columns.?, limits.cores);
            owner.cores = columns;
            owner.snapshot = columns.snapshot();
            var channel = firstChannel(plan, raw_pin.page, columns.geometry);
            var scheme = try Shared.copyWithSourceAllocator(Backend, a, raw.allocator(), &raw.scheme.?, &channel);
            errdefer scheme.deinit(a);
            mixCoreRoster(&channel, columns.geometry);
            try scheme.commitBorrowedStreaming(a, columns.fixed.items, 16, &channel);
            try scheme.commitBorrowedStreaming(a, columns.main, 16, &channel);
            try scheme.commitBorrowedStreaming(a, columns.connector_fixed.columns, 16, &channel);
            try scheme.commitBorrowedStreaming(a, columns.captures.columns, 16, &channel);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != 6) return error.InvalidSourcePackedPage;
            const pin = Pin{ .raw = raw_pin, .geometry = columns.geometry, .roots = roots.items[0..6].* };
            try pin.require(admitted, plan, limits);
            if (expected) |original| if (!std.meta.eql(pin, original)) return error.UntrustedSourcePackedReplayRoots;
            owner.scheme = scheme;
            owner.pin = pin;
        }
        /// Canonical raw collection has no opening callback. One page owner and
        /// one-compression stack scratch; exact cores/tables share its budget.
        pub fn collect(a: std.mem.Allocator, collector: *Schema.Round.Collector, limits: Limits) !*Owner {
            return collectUsing(a, collector, limits, null);
        }
        pub fn collectWithSetup(a: std.mem.Allocator, collector: *Schema.Round.Collector, limits: Limits, setup: *const Columns.Setup) !*Owner {
            return collectUsing(a, collector, limits, setup);
        }
        fn collectUsing(a: std.mem.Allocator, collector: *Schema.Round.Collector, limits: Limits, setup: ?*const Columns.Setup) !*Owner {
            if (!std.meta.eql(collector.limits, limits.first)) return error.InvalidSourcePackedPage;
            const owner = try new(a, limits);
            errdefer owner.deinit() catch @panic("packed collection rollback lease invariant");
            owner.raw = try RawRound.collectPage(owner.allocator(), collector);
            errdefer collector.failed = true; // cursor cannot retry a skipped core page
            try append(owner, Schema.cursorAdmission(&collector.cursor), collector.plan, limits, null, setup);
            return owner;
        }
        pub fn persist(dir: std.fs.Dir, name: []const u8, owner: *Owner, admitted: *const Source.Admitted, plan: Schema.Protocol.Plan, expected: Pin, limits: Limits) !Schema.Store.Pin {
            try owner.require(admitted, plan, expected, limits);
            return RawReplay.persist(dir, name, owner.raw.?, admitted, plan, expected.raw, limits.first, limits.stored);
        }
        /// The caller supplies the independently collected full Pin, not roots
        /// decoded from the replay file. Both raw and all four new roots match.
        pub fn replay(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, admitted: *const Source.Admitted, plan: Schema.Protocol.Plan, expected: Pin, stored: Schema.Store.Pin, limits: Limits) !*Owner {
            return replayUsing(a, dir, name, admitted, plan, expected, stored, limits, null);
        }
        pub fn replayWithSetup(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, admitted: *const Source.Admitted, plan: Schema.Protocol.Plan, expected: Pin, stored: Schema.Store.Pin, limits: Limits, setup: *const Columns.Setup) !*Owner {
            return replayUsing(a, dir, name, admitted, plan, expected, stored, limits, setup);
        }
        fn replayUsing(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, admitted: *const Source.Admitted, plan: Schema.Protocol.Plan, expected: Pin, stored: Schema.Store.Pin, limits: Limits, setup: ?*const Columns.Setup) !*Owner {
            try expected.require(admitted, plan, limits);
            const owner = try new(a, limits);
            errdefer owner.deinit() catch @panic("packed replay rollback lease invariant");
            owner.raw = try RawReplay.loadRecommitted(owner.allocator(), dir, name, admitted, plan, expected.raw, stored, limits.first, limits.stored);
            try append(owner, admitted, plan, limits, expected, setup);
            return owner;
        }
        /// Canonical warm residency context: one raw/core page and no whole-
        /// image owner. Failure to release a live proof lease retains its token.
        pub const Reader = struct {
            active: bool = false,
            live: bool = true,
            pub fn deinit(self: *Reader) !void {
                if (!self.live or self.active) return error.SourcePackedPageLeaseLive;
                self.live = false;
            }
            pub fn take(self: *Reader, a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, admitted: *const Source.Admitted, plan: Schema.Protocol.Plan, expected: Pin, stored: Schema.Store.Pin, limits: Limits) !Loaded {
                if (!self.live or self.active) return error.SourcePackedPageLeaseLive;
                const owner = try Api.replay(a, dir, name, admitted, plan, expected, stored, limits);
                self.active = true;
                return .{ .reader = self, .owner = owner };
            }
        };
        pub const Loaded = struct {
            reader: *Reader,
            owner: *Owner,
            pub fn deinit(self: *Loaded) !void {
                if (!self.reader.live or !self.reader.active) return error.SourcePackedPageLeaseLive;
                try self.owner.deinit();
                self.reader.active = false;
                self.* = undefined;
            }
        };
        pub const Lease = struct {
            owner: *Owner,
            scheme: Scheme,
            owns_scheme: bool = true,
            pub fn takeScheme(self: *Lease) !Scheme {
                if (!self.owns_scheme) return error.InvalidSourcePackedPageLease;
                self.owns_scheme = false;
                return self.scheme;
            }
            pub fn deinit(self: *Lease) void {
                if (self.owns_scheme) self.scheme.deinit(self.owner.allocator());
                std.debug.assert(self.owner.active_leases > 0);
                self.owner.active_leases -= 1;
                self.* = undefined;
            }
        };
        pub fn lease(owner: *Owner, admitted: *const Source.Admitted, plan: Schema.Protocol.Plan, expected: Pin, limits: Limits, channel: *suite.Channel) !Lease {
            try owner.require(admitted, plan, expected, limits);
            if (owner.active_leases == std.math.maxInt(usize)) return error.SourcePackedPageResourceLimit;
            var copied = try Scheme.init(owner.allocator(), expected.raw.config);
            errdefer copied.deinit(owner.allocator());
            copied.setCoefficientRetentionPolicy(.never);
            channel.* = firstChannel(plan, expected.raw.page, expected.geometry);
            for (owner.scheme.?.trees.items, 0..) |*tree, i| {
                if (i == 2) mixCoreRoster(channel, expected.geometry);
                try tree.share(owner.allocator());
                var retained = tree.retainShared();
                var owns = true;
                defer if (owns) retained.deinit(owner.allocator());
                try copied.appendCommittedTree(owner.allocator(), retained, channel);
                owns = false;
            }
            owner.active_leases += 1;
            return .{ .owner = owner, .scheme = copied };
        }
        comptime {
            _ = Api;
        }
    };
}
