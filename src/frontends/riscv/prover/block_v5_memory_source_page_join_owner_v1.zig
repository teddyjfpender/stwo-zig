//! Bounded actual CPU PAGE+lane+range fresh receiver. Source streams are proved
//! by original PAGE equations; this path never calls host Sources.check and
//! never promotes an old Scoped receipt which discarded initial/final sums.
//! Its transition remains OPEN for native/caller/global and public authority.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Pages = @import("block_v5_memory_source_unified_page_proof_v1.zig");
const Components = @import("block_v5_memory_source_unified_page_components_v1.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Raw = Pages.ForKind(.raw);
const Fold = Pages.ForKind(.fold);
const RawSetup = Components.ForKind(.raw).CoreColumns.Setup;
const FoldSetup = Components.ForKind(.fold).CoreColumns.Setup;
const Lane = @import("block_v5_ram_lanes_proof_v1.zig");
const LaneReceiver = @import("block_v5_ram_lanes_receiver_v1.zig");
const LanePlan = @import("block_v5_ram_lanes_plan_v1.zig");
const LaneJoin = @import("block_v5_ram_lanes_join_v1.zig");
const Range = @import("block_v5_range16_proof_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Algebra = @import("block_v5_memory_source_page_join_algebra_v1.zig");
pub const Limits = struct {
    pages: Pages.Limits = .{},
    max_pages: usize = 524288,
    max_memory_instances: usize = 32768,
    max_setup_bytes: usize = 1 << 30,
    max_live_bytes: usize = 4 << 30,
};
pub const Loader = struct {
    context: *anyopaque,
    /// All decoded allocations belong to the supplied bounded allocator.
    /// Success transfers proof ownership; an error retains no allocation.
    raw: *const fn (*anyopaque, std.mem.Allocator, u32) anyerror!Raw.Proof,
    fold: *const fn (*anyopaque, std.mem.Allocator, u32) anyerror!Fold.Proof,
    /// Public original descriptor inventory, validated against independently
    /// sealed pin/fixed roots by the actual original PAGE receiver.
    fold_rows: *const fn (*anyopaque, std.mem.Allocator, u32, u32) anyerror![]Semantic.FoldRow,
    /// Nested recipe owners must provide this synchronous release. Null is
    /// permitted only for flat rows with borrowed/static recipe slices.
    release_fold_rows: ?*const fn (*anyopaque, std.mem.Allocator, []const Semantic.FoldRow) void = null,
    memory: *const fn (*anyopaque, std.mem.Allocator, u32) anyerror!Lane.Proof,
    range: *const fn (*anyopaque, std.mem.Allocator, u32) anyerror!Range.Proof,
};
pub const Open = struct {
    transition_sum: Q,
    events: u64,
    first_touches: u64,
    endpoints: u64,
    range_requests: u64,
    memory_instances: u32,
    range_shards: u32,
    raw_pages: u32,
    fold_pages: u32,
    base_seal: [32]u8,
    page_seal: [32]u8,
    epoch: [32]u8,
    source_identity: [32]u8,
    memory_plan: [32]u8,
    initial_root: [32]u8,
    final_root: [32]u8,
    pub const complete_block_authority = false;
};
pub const Owner = struct {
    budget: *Budget,
    arena: std.heap.ArenaAllocator,
    context: Pages.Context,
    memory: LaneReceiver.Pins,
    limits: Limits,
    raw_setup: *const RawSetup,
    fold_setup: *const FoldSetup,
    arithmetic_setup: *const Components.ArithmeticSetup,
    raw_lease: ?RawSetup.Lease = null,
    fold_lease: ?FoldSetup.Lease = null,
    arithmetic_lease: ?Components.ArithmeticSetup.Lease = null,
    consumed: bool = false,
    pub fn create(backing: std.mem.Allocator, context: *const Pages.Context, memory: LaneReceiver.Pins, limits: Limits) !*Owner {
        return createInternal(backing, context, memory, limits, null);
    }
    const Setups = struct { raw: *const RawSetup, fold: *const FoldSetup, arithmetic: *const Components.ArithmeticSetup };
    /// Reuse immutable typed programs only. Full context, source, lane policy
    /// and epoch admission remain identical to the independent cold path.
    pub fn createWithSetups(backing: std.mem.Allocator, context: *const Pages.Context, memory: LaneReceiver.Pins, limits: Limits, raw: *const RawSetup, fold: *const FoldSetup, arithmetic: *const Components.ArithmeticSetup) !*Owner {
        return createInternal(backing, context, memory, limits, .{ .raw = raw, .fold = fold, .arithmetic = arithmetic });
    }
    fn createInternal(backing: std.mem.Allocator, context: *const Pages.Context, memory: LaneReceiver.Pins, limits: Limits, setups: ?Setups) !*Owner {
        if (limits.max_setup_bytes == 0 or limits.max_live_bytes == 0 or limits.max_pages == 0 or limits.max_memory_instances == 0 or
            try std.math.add(usize, context.raw.len, context.fold.len) > limits.max_pages or memory.pins.len > limits.max_memory_instances)
            return error.SourcePageJoinResourceLimit;
        const budget = try Budget.createRetainingParent(backing, limits.max_setup_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        // Include independent epoch/range-plan admission scratch in the same
        // setup budget; limits do not cover only retained metadata.
        try context.require(a, limits.pages);
        try LaneReceiver.admit(a, memory, context.base, memory.limits);
        try authority(context, memory);
        const self = try a.create(Owner);
        errdefer a.destroy(self);
        self.budget = budget;
        self.arena = std.heap.ArenaAllocator.init(a);
        errdefer self.arena.deinit();
        const meta = self.arena.allocator();
        self.context = try Pages.Context.init(meta, context.admitted, context.raw_plan, context.fold_plan, context.raw, context.fold, context.sealed, context.independent_digest, context.base, limits.pages);
        self.memory = memory;
        self.memory.first_round = try meta.dupe(Seal.Entry, memory.first_round);
        self.memory.pins = try meta.dupe(Lane.Pin, memory.pins);
        self.memory.range_roots = try meta.dupe([2][32]u8, memory.range_roots);
        self.limits = limits;
        self.consumed = false;
        self.raw_lease = null;
        self.fold_lease = null;
        self.arithmetic_lease = null;
        if (setups) |shared| {
            self.raw_lease = try shared.raw.lease();
            errdefer self.raw_lease.?.deinit();
            self.fold_lease = try shared.fold.lease();
            errdefer self.fold_lease.?.deinit();
            self.arithmetic_lease = try shared.arithmetic.lease();
            self.raw_setup = shared.raw;
            self.fold_setup = shared.fold;
            self.arithmetic_setup = shared.arithmetic;
        } else {
            self.raw_setup = try RawSetup.create(a);
            errdefer self.raw_setup.release();
            self.fold_setup = try FoldSetup.create(a);
            errdefer self.fold_setup.release();
            self.arithmetic_setup = try Components.ArithmeticSetup.create(a);
        }
        return self;
    }
    pub fn deinit(self: *Owner) void {
        const budget = self.budget;
        if (self.arithmetic_lease) |*lease| lease.deinit() else self.arithmetic_setup.release();
        if (self.fold_lease) |*lease| lease.deinit() else self.fold_setup.release();
        if (self.raw_lease) |*lease| lease.deinit() else self.raw_setup.release();
        self.context.deinit();
        self.arena.deinit();
        budget.allocator().destroy(self);
        budget.destroy();
    }
    pub fn verify(self: *Owner, backing: std.mem.Allocator, loader: Loader) !Open {
        if (self.consumed) return error.SourcePageJoinAlreadyConsumed;
        self.consumed = true; // Any partial proof take consumes this session.
        const live = try Budget.create(backing, self.limits.max_live_bytes);
        defer live.destroy();
        const a = live.allocator();
        try self.context.require(a, self.limits.pages);
        try LaneReceiver.admit(a, self.memory, self.context.base, self.memory.limits);
        try authority(&self.context, self.memory);
        // These exact original challenges are redrawn by both Lane and
        // Range.verifyOwned below. PAGE extends this channel only AFTER that
        // prefix; old SourceAuth challenges are a different epoch entirely.
        const word = try @import("block_v5_word_memory_protocol_v1.zig").Challenges.draw(a, self.context.base);
        if (!std.meta.eql(word, self.context.epoch.challenges.source.word)) return error.UntrustedSourcePageJoinWordEpoch;
        var totals = Algebra.Totals{};
        // No proof/graph/operand page is retained after its genuine receiver.
        var raw_loader = PageLoader(.raw){ .loader = loader, .context = &self.context, .totals = &totals, .limits = self.limits.pages };
        try Raw.verifyRosterOwned(a, &self.context, self.raw_setup, self.arithmetic_setup, self.limits.pages, &raw_loader);
        var fold_loader = PageLoader(.fold){ .loader = loader, .context = &self.context, .totals = &totals, .limits = self.limits.pages };
        try Fold.verifyRosterOwned(a, &self.context, self.fold_setup, self.arithmetic_setup, self.limits.pages, &fold_loader);
        var plan = try LanePlan.rangePlan(a, self.memory.pins, self.memory.expected_total_events, self.memory.limits.plan);
        defer plan.deinit(a);
        const ranges = try a.alloc(Q, self.memory.pins.len);
        defer a.free(ranges);
        var transition = Q.zero();
        var endpoints: u64 = 0;
        var range_count: u64 = 0;
        for (self.memory.pins, 0..) |pin, index| {
            const proof = try loader.memory(loader.context, a, @intCast(index));
            const fresh = try Lane.ForBackend(@import("stwo_cpu_backend").CpuBackend).verifyOwned(a, proof, pin, self.context.base, self.memory.seal, self.memory.first_round, self.memory.limits.proof);
            const buses = LaneJoin.buses(fresh.sums);
            if (fresh.registerEndpointCount() != 0 or !fresh.registerEndpointSum().isZero()) return error.MixedV5RegisterCustody;
            transition = transition.add(buses.transition_sum);
            totals.predecessor = totals.predecessor.add(buses.link_sum);
            totals.initial = totals.initial.add(buses.initial_sum);
            totals.endpoint = totals.endpoint.add(buses.endpoint_sum);
            endpoints = try std.math.add(u64, endpoints, buses.endpoint_count);
            range_count = try std.math.add(u64, range_count, buses.range_count);
            ranges[index] = buses.rangeSum();
        }
        for (plan.shards, self.memory.range_roots) |shard, roots| {
            const proof = try loader.range(loader.context, a, shard.index);
            const fresh = try Range.ForBackend(@import("stwo_cpu_backend").CpuBackend).verifyOwned(a, proof, shard, plan.digest, roots, self.context.base, self.memory.seal, self.memory.first_round);
            var closure = fresh.claim.sum;
            for (ranges[shard.first_instance..][0..shard.instance_count]) |request| closure = closure.add(request);
            if (!closure.isZero()) return error.UnclosedV5Range16Relation;
        }
        const source = &self.context.admitted.source;
        if (endpoints != source.records(.endpoints) or source.records(.first_touches) > self.memory.expected_total_events)
            return error.UntrustedSourcePageJoinCensus;
        try Algebra.close(&self.context.admitted, totals);
        return .{ .transition_sum = transition, .events = self.memory.expected_total_events, .first_touches = source.records(.first_touches), .endpoints = endpoints, .range_requests = range_count, .memory_instances = @intCast(self.memory.pins.len), .range_shards = @intCast(plan.shards.len), .raw_pages = @intCast(self.context.raw.len), .fold_pages = @intCast(self.context.fold.len), .base_seal = self.context.base.digest, .page_seal = self.context.sealed.digest, .epoch = self.context.epoch.after_draw_digest, .source_identity = source.identity, .memory_plan = self.memory.seal.memory_plan_digest, .initial_root = source.pins.initial.initial_rw_root, .final_root = source.pins.expected_final_rw_root };
    }
};
fn PageLoader(comptime kind: Semantic.Kind) type {
    return struct {
        loader: Loader,
        context: *const Pages.Context,
        totals: *Algebra.Totals,
        limits: Pages.Limits,
        next: u32 = 0,
        pub fn take(self: *@This(), a: std.mem.Allocator, index: u32) !Pages.ForKind(kind).Proof {
            if (index != self.next) return error.UntrustedSourcePageJoinInventory;
            return if (kind == .raw) self.loader.raw(self.loader.context, a, index) else self.loader.fold(self.loader.context, a, index);
        }
        pub fn rows(self: *@This(), a: std.mem.Allocator, index: u32, count: u32) ![]Semantic.FoldRow {
            if (kind != .fold or index != self.next) return error.UntrustedSourcePageJoinInventory;
            return self.loader.fold_rows(self.loader.context, a, index, count);
        }
        pub fn releaseRows(self: *@This(), a: std.mem.Allocator, rows_owned: []const Semantic.FoldRow) void {
            if (self.loader.release_fold_rows) |release| release(self.loader.context, a, rows_owned) else a.free(rows_owned);
        }
        pub fn accept(self: *@This(), fresh: Pages.ForKind(kind).VerifiedPage) !void {
            try requirePage(kind, self.context, fresh, self.next, self.limits);
            if (kind == .raw) {
                add(&self.totals.raw, fresh.claims.source);
                self.totals.indexed = self.totals.indexed.add(fresh.claims.indexed);
            } else {
                add(&self.totals.fold, fresh.claims.fold);
            }
            self.next = try std.math.add(u32, self.next, 1);
        }
    };
}
fn authority(context: *const Pages.Context, memory: LaneReceiver.Pins) !void {
    if (!std.meta.eql(context.admitted.source.pins, memory.source) or !std.meta.eql(context.base.digest, memory.expected_seal_digest)) return error.UntrustedSourcePageJoinAuthority;
    for (memory.pins) |pin| if (!std.meta.eql(pin.config, context.fold_plan.config)) return error.UntrustedSourcePageJoinSecurity;
}
fn add(out: anytype, value: anytype) void {
    inline for (std.meta.fields(@TypeOf(value))) |field| @field(out.*, field.name) = @field(out.*, field.name).add(@field(value, field.name));
}
fn requirePage(comptime kind: Semantic.Kind, context: *const Pages.Context, fresh: Pages.ForKind(kind).VerifiedPage, index: usize, limits: Pages.Limits) !void {
    if (fresh.kind != kind or fresh.page_index != index or !std.meta.eql(fresh.admission_id, context.admitted.identity) or !std.meta.eql(fresh.source_seal, context.sealed.digest) or
        !std.meta.eql(fresh.premix_identity, try Pages.ForKind(kind).identity(context, if (kind == .raw) context.raw[index] else context.fold[index], limits))) return error.UntrustedSourcePageJoinReceipt;
    try Algebra.canonical(fresh.claims);
    if (kind == .raw) {
        inline for (std.meta.fields(@TypeOf(fresh.claims.fold))) |field| if (!@field(fresh.claims.fold, field.name).isZero()) return error.UntrustedSourcePageJoinReceipt;
    } else {
        inline for (std.meta.fields(@TypeOf(fresh.claims.source))) |field| if (!@field(fresh.claims.source, field.name).isZero()) return error.UntrustedSourcePageJoinReceipt;
        if (!fresh.claims.indexed.isZero()) return error.UntrustedSourcePageJoinReceipt;
    }
}
pub const testing = struct {
    pub const requireAuthority = authority;
    pub const requirePageReceipt = requirePage;
};
