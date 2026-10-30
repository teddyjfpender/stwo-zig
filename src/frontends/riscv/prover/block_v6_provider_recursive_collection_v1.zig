//! Original artifact -> fresh verifier capture -> direct verifier rows. Each
//! decoded proof/capture dies before the next artifact is loaded. No recursive
//! parent is proved here and claim records grant no independent authority.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Sources = @import("block_v6_recursive_sources_v1.zig");
const Store = @import("block_v5_cpu_bundle_store_v1.zig");
const Provider = @import("../recursion/block_v6_provider_batch_prepare_v1.zig");
const Auxiliary = @import("../recursion/block_v6_auxiliary_direct_prepare_v1.zig");
const Mixed = @import("../recursion/block_v6_mixed_direct_public_v1.zig");
const MixedPrep = @import("../recursion/block_v6_mixed_direct_prepare_v1.zig");
const Claims = @import("../recursion/block_v6_mixed_claim_types_v1.zig");
const Reconstruct = @import("../recursion/block_v6_mixed_claim_reconstruct_v1.zig");
const Scalars = @import("../recursion/block_v6_mixed_claim_scalars_v1.zig");
const CallerCapture = @import("block_v5_caller_arithmetic_recursive_capture_v1.zig");
const FusedCapture = @import("block_v5_caller_fused_recursive_capture_v1.zig");
const Caller = @import("block_v5_precompile_family_proof_v1.zig");

pub const Limits = struct {
    store: Store.Limits,
    max_children: usize = Mixed.MAX_CHILDREN,
    max_owned_bytes: usize = 8 << 30,
    /// Maximum rejection-sampling attempts in each transcript draw.
    /// This is not an AIR row or memory capacity.
    circuit_capacity: u32 = 2,
};
pub const Owner = struct {
    a: std.mem.Allocator,
    budget: *Budget,
    providers: []Provider.Prepared = &.{},
    auxiliaries: []Auxiliary.Prepared = &.{},
    records: []Claims.Record = &.{},
    expected: []Mixed.Expected = &.{},
    /// Borrowed independent admission geometry. Sources.Owner must outlive it.
    admissions: []Reconstruct.Input = &.{},
    provider_count: usize = 0,
    auxiliary_count: usize = 0,
    record_count: usize = 0,
    pub fn deinit(self: *Owner) void {
        for (self.providers[0..self.provider_count]) |*value| value.deinit();
        for (self.auxiliaries[0..self.auxiliary_count]) |*value| value.deinit();
        for (self.records[0..self.record_count]) |record| switch (record.claim) {
            inline else => |value| Scalars.free(self.a, value),
        };
        self.a.free(self.providers);
        self.a.free(self.auxiliaries);
        self.a.free(self.records);
        self.a.free(self.expected);
        self.a.free(self.admissions);
        self.budget.destroy();
        self.* = undefined;
    }
    /// Caller owns the returned pointer array, while this owner retains pieces.
    pub fn mixedInputs(self: *Owner, a: std.mem.Allocator) ![]MixedPrep.Input {
        const inputs = try a.alloc(MixedPrep.Input, self.providers.len + self.auxiliaries.len);
        for (self.providers, inputs[0..self.providers.len]) |*piece, *input| input.* = .{ .provider = piece };
        for (self.auxiliaries, inputs[self.providers.len..]) |*piece, *input| input.* = .{ .auxiliary = piece };
        return inputs;
    }
    fn appendRecord(self: *Owner, expected: Mixed.Expected, input: Reconstruct.Input, record: Claims.Record) !void {
        try Claims.require(record, expected);
        if (self.record_count >= self.records.len) return error.InvalidProviderCollectionRoster;
        self.records[self.record_count] = record;
        self.expected[self.record_count] = expected;
        self.admissions[self.record_count] = input;
        self.record_count += 1;
    }
};
fn selected(family: Store.Family) bool {
    return switch (family) {
        .range16, .ram_lanes, .rom, .native_provider, .caller, .caller_fused => true,
        else => false,
    };
}
fn sourceCount(sources: *const Sources.Owner, family: Store.Family) usize {
    return switch (family) {
        .range16 => sources.ranges.len,
        .ram_lanes => sources.lanes.len,
        .rom => 1,
        .native_provider => sources.lookups.len,
        .caller, .caller_fused => sources.callers.?.entries.len,
        else => 0,
    };
}
fn sourceIndex(sources: *const Sources.Owner, family: Store.Family, ordinal: usize) u32 {
    return switch (family) {
        .caller, .caller_fused => sources.callers.?.entries[ordinal].index,
        else => @intCast(ordinal),
    };
}

pub fn collect(backing: std.mem.Allocator, dir: std.fs.Dir, sources: *const Sources.Owner, policies: []const Store.Policy, files: []const Store.FilePin, limits: Limits) !Owner {
    try sources.require();
    try limits.store.validate();
    const provider_count = try std.math.add(usize, 1, try std.math.add(usize, sources.ranges.len, try std.math.add(usize, sources.lanes.len, sources.lookups.len)));
    const auxiliary_count = try std.math.mul(usize, 2, sources.callers.?.entries.len);
    const count = try std.math.add(usize, provider_count, auxiliary_count);
    if (limits.max_children == 0 or count > limits.max_children or count > Mixed.MAX_CHILDREN or limits.max_owned_bytes == 0 or limits.circuit_capacity == 0 or policies.len != files.len or policies.len > limits.store.max_files)
        return error.ProviderCollectionResourceLimit;
    // Accept exactly the independent partitioned-provider policy selection.
    // Native and PAGE families belong to separate collectors; legacy separate
    // companion providers must not be silently discarded. Source geometry,
    // never artifact cardinality, determines how many records must be present.
    var counts: [@typeInfo(Store.Family).@"enum".fields.len]usize = @splat(0);
    var selected_count: usize = 0;
    for (policies, files, 0..) |policy, file, i| {
        const pin = policy.expected;
        if (pin.family != file.family or pin.index != file.index or !std.meta.eql(pin.config, sources.roster.pins.config)) return error.InvalidProviderCollectionRoster;
        if (i != 0) {
            const prior = policies[i - 1].expected;
            if (@intFromEnum(prior.family) > @intFromEnum(pin.family) or (prior.family == pin.family and prior.index >= pin.index)) return error.InvalidProviderCollectionRoster;
        }
        if (!selected(pin.family)) return error.UnsupportedProviderCollectionFamily;
        const slot = @intFromEnum(pin.family) - 1;
        const ordinal = counts[slot];
        if (ordinal >= sourceCount(sources, pin.family) or pin.index != sourceIndex(sources, pin.family, ordinal)) return error.InvalidProviderCollectionRoster;
        counts[slot] += 1;
        selected_count += 1;
    }
    if (selected_count != count) return error.InvalidProviderCollectionRoster;
    inline for ([_]Store.Family{ .range16, .ram_lanes, .rom, .native_provider, .caller, .caller_fused }) |family| {
        if (counts[@intFromEnum(family) - 1] != sourceCount(sources, family)) return error.InvalidProviderCollectionRoster;
    }
    const budget = try Budget.createRetainingParent(backing, limits.max_owned_bytes);
    var out = Owner{ .a = budget.allocator(), .budget = budget };
    errdefer out.deinit();
    const a = out.a;
    out.providers = try a.alloc(Provider.Prepared, provider_count);
    out.auxiliaries = try a.alloc(Auxiliary.Prepared, auxiliary_count);
    out.records = try a.alloc(Claims.Record, count);
    out.expected = try a.alloc(Mixed.Expected, count);
    out.admissions = try a.alloc(Reconstruct.Input, count);
    var reader = try Store.Store.initReader(a, dir, policies, files, sources.roster.pins.config, limits.store);
    defer reader.deinit();
    for (sources.ranges) |*admitted| try appendProvider(.range16, &out, &reader, admitted, limits.circuit_capacity);
    for (sources.lanes) |*admitted| try appendProvider(.ram_lanes, &out, &reader, admitted, limits.circuit_capacity);
    try appendProvider(.program_table, &out, &reader, &sources.program.?, limits.circuit_capacity);
    for (sources.lookups) |*admitted| try appendProvider(.native_lookup, &out, &reader, admitted, limits.circuit_capacity);
    // Only fresh in-session receipts survive arithmetic capture teardown; they
    // authorize original fused verification and never substitute for its proof.
    const fresh = try a.alloc(Caller.OpenReceipt, sources.callers.?.entries.len);
    defer a.free(fresh);
    for (sources.callers.?.entries, fresh) |entry, *receipt| {
        const admitted = &entry.admissions.arithmetic;
        var proof = try reader.take(.caller, entry.index);
        defer proof.deinit(a);
        var capture = try CallerCapture.ForBackend(Cpu).verifyBorrowed(a, &proof, admitted);
        defer capture.deinit();
        const input = Auxiliary.Input{ .caller_arithmetic = .{ .admitted = admitted, .capture = &capture } };
        const expected = input.expected();
        out.auxiliaries[out.auxiliary_count] = try Auxiliary.prepare(a, &.{input}, &.{expected}, limits.circuit_capacity);
        const piece = &out.auxiliaries[out.auxiliary_count];
        out.auxiliary_count += 1;
        const parity = @import("block_v6_fixed_parity_v1.zig");
        if (try parity.enabled(a)) {
            var cold = try @import("../recursion/block_v6_provider_fixed_singletons_v1.zig").CallerArithmetic.Owned.derive(a, admitted, admitted.template_id, {}, limits.circuit_capacity, try parity.profile(admitted.config), .{});
            defer cold.deinit();
            try cold.validateLive(piece);
            std.debug.print("COLD_FIXED_PARITY caller_arithmetic index={d} passed\n", .{entry.index});
        }
        try out.appendRecord(.{ .auxiliary = expected }, .{ .caller_arithmetic = admitted }, .{ .index = entry.index, .claim = .{ .caller_arithmetic = piece.children[0].value.caller_arithmetic.claims } });
        receipt.* = capture.receipt;
    }
    for (sources.callers.?.entries, fresh) |entry, *receipt| {
        const admitted = &entry.admissions.fused;
        var proof = try reader.take(.caller_fused, entry.index);
        defer proof.deinit(a);
        var capture = try FusedCapture.ForBackend(Cpu).verifyAfterFreshCaller(a, &proof, receipt, admitted);
        defer capture.deinit();
        const input = Auxiliary.Input{ .caller_fused = .{ .admitted = admitted, .capture = &capture } };
        const expected = input.expected();
        out.auxiliaries[out.auxiliary_count] = try Auxiliary.prepare(a, &.{input}, &.{expected}, limits.circuit_capacity);
        out.auxiliary_count += 1;
        if (try @import("block_v6_fixed_parity_v1.zig").enabled(a)) {
            var cold = try @import("../recursion/block_v6_caller_fused_auxiliary_fixed_v1.zig").Owned.derive(a, admitted, admitted.template_id, capture.original.claims, limits.circuit_capacity, try @import("block_v6_fixed_parity_v1.zig").profile(admitted.config), .{});
            defer cold.deinit();
            try cold.validateLive(&out.auxiliaries[out.auxiliary_count - 1]);
            std.debug.print("FIXED_PARITY family=caller_fused index={d} matched=true\n", .{entry.index});
        }
        var claims = try @import("block_v5_caller_fused_proof_v1.zig").ClaimFrames.clone(a, capture.original.claims);
        errdefer claims.deinit(a);
        try out.appendRecord(.{ .auxiliary = expected }, .{ .caller_fused = admitted }, .{ .index = entry.index, .claim = .{ .caller_fused = claims } });
    }
    try reader.requireConsumed();
    if (out.provider_count != provider_count or out.auxiliary_count != auxiliary_count or out.record_count != count) return error.InvalidProviderCollectionRoster;
    _ = try Mixed.rosterDigest(out.expected);
    return out;
}

fn appendProvider(comptime family: Mixed.Provider.Family, out: *Owner, reader: *Store.Store, admitted: *const Mixed.Provider.Definition(family).Prepared, capacity: u32) !void {
    const D = Mixed.Provider.Definition(family);
    const original: Store.Family = switch (family) {
        .range16 => .range16,
        .ram_lanes => .ram_lanes,
        .program_table => .rom,
        .native_lookup => .native_provider,
    };
    const Capture = switch (family) {
        .range16 => @import("block_v5_range16_recursive_capture_v1.zig"),
        .ram_lanes => @import("block_v5_ram_lanes_recursive_capture_v1.zig"),
        .program_table => @import("block_v5_program_table_recursive_capture_v1.zig"),
        .native_lookup => @import("block_v5_native_lookup_recursive_capture_v1.zig"),
    };
    var proof = try reader.take(original, D.index(admitted));
    defer proof.deinit(out.a);
    var capture = Capture.ForBackend(Cpu).verifyBorrowed(out.a, &proof, admitted) catch |err| {
        std.debug.print("PROVIDER_COLLECTION family={s} index={d} stage=capture error={s}\n", .{ @tagName(family), D.index(admitted), @errorName(err) });
        return err;
    };
    defer capture.deinit();
    const expected = Mixed.Provider.Expected{ .family = family, .index = D.index(admitted), .template = admitted.template_id, .sealed = admitted.sealed.digest, .roots = admitted.roots };
    const input = @unionInit(Provider.Input, @tagName(family), .{ .admitted = admitted, .capture = &capture });
    out.providers[out.provider_count] = Provider.prepare(out.a, &.{input}, &.{expected}, capacity) catch |err| {
        std.debug.print("PROVIDER_COLLECTION family={s} index={d} stage=prepare error={s}\n", .{ @tagName(family), D.index(admitted), @errorName(err) });
        return err;
    };
    out.provider_count += 1;
    const parity = @import("block_v6_fixed_parity_v1.zig");
    if (try parity.enabled(out.a)) {
        var cold = try @import("../recursion/block_v6_provider_fixed_singletons_v1.zig").ForFamily(family).Owned.derive(out.a, admitted, admitted.template_id, {}, capacity, try parity.profile(admitted.config), .{});
        defer cold.deinit();
        try cold.validateLive(&out.providers[out.provider_count - 1]);
        std.debug.print("COLD_FIXED_PARITY provider={s} index={d} passed\n", .{ @tagName(family), D.index(admitted) });
    }
    try out.appendRecord(.{ .provider = expected }, @unionInit(Reconstruct.Input, @tagName(family), admitted), .{ .index = expected.index, .claim = @unionInit(Claims.Claim, @tagName(family), D.claim(capture.receipt)) });
}

test "provider recursive collection instantiates all original artifact capture routes" {
    std.mem.doNotOptimizeAway(&collect);
    try std.testing.expect(@intFromPtr(&collect) != 0);
}
