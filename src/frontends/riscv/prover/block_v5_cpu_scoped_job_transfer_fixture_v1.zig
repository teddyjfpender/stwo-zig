//! Unimported positive transfer harness for an independently admitted real
//! heterogeneous policy and original-row-derived node specifications.
//! Existing scoped tests only contain negative metadata models; this harness
//! never promotes those models or invents a receipt/key to satisfy admission.
//! Caller constructs/retains Prepared authority outside allocation injection.
const std = @import("std");
const Setup = @import("../recursion/block_v5_heterogeneous_scoped_owner_v1.zig");
const Full = @import("../recursion/block_v5_heterogeneous_policy_v1.zig");
const Coverage = @import("block_v5_recursive_coverage_plan_v1.zig");
const Frames = @import("../recursion/block_v5_heterogeneous_child_frames_v1.zig");
pub const Input = struct {
    full: Full.Policy,
    pins: Setup.Pins,
    /// These are genuine original verifier+merge row-derived specifications,
    /// independently reconstructed outside the harness. No received key input.
    specs: []const Setup.NodeSpec,
    limits: Setup.Limits,
    pub fn validate(self: Input) !void {
        try self.full.validate();
        if (self.specs.len == 0 or self.specs.len != self.pins.node_ids.len or
            self.specs.len > 32 or self.full.children.len > 32 or
            self.limits.max_owned_bytes == 0 or self.limits.max_policy_source_cells > 65536)
            return error.UnboundedScopedTransferFixture;
        if (!std.meta.eql(self.pins.coverage, self.full.plan.pinned_digest) or
            !std.meta.eql(self.pins.source, self.full.plan.meta.seal_digest) or
            self.pins.recipe != self.full.plan.meta.recipe)
            return error.UntrustedScopedTransferFixture;
    }
};
const Temporary = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    coverage: *Coverage.Plan,
    full: Full.Policy,
    pins: Setup.Pins,
    specs: []const Setup.NodeSpec,
    fn init(a: std.mem.Allocator, input: Input) !*Temporary {
        try input.validate();
        const self = try a.create(Temporary);
        errdefer a.destroy(self);
        self.allocator = a;
        self.arena = std.heap.ArenaAllocator.init(a);
        errdefer self.arena.deinit();
        const owned = self.arena.allocator();
        const coverage = try owned.create(Coverage.Plan);
        const original = input.full.plan;
        const logical = try owned.dupe(@TypeOf(original.logical_owner[0]), original.logical_owner);
        const mappings = try owned.dupe(Coverage.Mapping, original.mappings_owner);
        const physical = try owned.dupe(Coverage.Physical, original.physical_owner);
        const nodes = try owned.dupe(Coverage.Node, original.nodes_owner);
        var meta = original.meta;
        meta.logical = logical;
        meta.mappings = mappings;
        meta.physical = physical;
        meta.nodes = nodes[0..original.meta.nodes.len];
        coverage.* = .{ .a = owned, .meta = meta, .logical_owner = logical, .mappings_owner = mappings, .physical_owner = physical, .nodes_owner = nodes, .pinned_digest = original.pinned_digest };
        const expected = try Setup.testing.cloneOwned([]const Full.Expected, owned, input.full.expected);
        const children = try owned.alloc(Frames.Child, expected.len);
        var initialized: usize = 0;
        errdefer for (children[0..initialized]) |*child| child.deinit();
        for (expected, children, 0..) |policy, *child, ordinal| {
            child.* = try policy.normalize(owned, coverage, @intCast(ordinal));
            initialized += 1;
        }
        const full = Full.Policy{ .plan = coverage, .children = children, .expected = expected };
        try full.validate();
        const pins = try Setup.testing.cloneOwned(Setup.Pins, owned, input.pins);
        const specs = try Setup.testing.cloneOwned([]const Setup.NodeSpec, owned, input.specs);
        self.coverage = coverage;
        self.full = full;
        self.pins = pins;
        self.specs = specs;
        return self;
    }
    fn deinit(self: *Temporary) void {
        for (self.full.children) |*child| @constCast(child).deinit();
        self.arena.deinit();
        self.allocator.destroy(self);
    }
};
fn compare(original: *const Setup.Owner, transferred: *const Setup.Owner) !void {
    try std.testing.expect(original.ready and transferred.ready);
    try std.testing.expectEqualDeep(original.pins, transferred.pins);
    try std.testing.expectEqualDeep(original.pinned_identity, transferred.pinned_identity);
    try std.testing.expectEqualDeep(original.routes.digest, transferred.routes.digest);
    try std.testing.expectEqual(original.full.children.len, transferred.full.children.len);
    for (0..original.full.children.len) |ordinal| {
        const left = try original.source(.{ .leaf = @intCast(ordinal) });
        const right = try transferred.source(.{ .leaf = @intCast(ordinal) });
        try std.testing.expectEqualDeep(left.seal, right.seal);
        try std.testing.expect(left.cells.ptr != right.cells.ptr);
    }
    for (0..original.pins.node_ids.len) |index| {
        const left = try original.node(@intCast(index));
        const right = try transferred.node(@intCast(index));
        try left.validate();
        try right.validate();
        try std.testing.expectEqualDeep(left.key, right.key);
        try std.testing.expectEqualDeep(try left.publicInputIdentity(), try right.publicInputIdentity());
        try std.testing.expectEqualSlices(@import("../recursion/block_v5_heterogeneous_scoped_public_bus_v1.zig").Wire, left.wires, right.wires);
        try std.testing.expect(left.wires.ptr != right.wires.ptr);
        try std.testing.expectEqualDeep((try original.source(.{ .node = @intCast(index) })).seal, (try transferred.source(.{ .node = @intCast(index) })).seal);
    }
}
/// Positive old-init/new-transfer parity; only TEMPORARY source copies are
/// freed. The genuine independently admitted Prepared owners stay retained.
pub fn positive(a: std.mem.Allocator, input: Input) !void {
    const temporary = try Temporary.init(a, input);
    var live = true;
    defer if (live) temporary.deinit();
    const original = try Setup.init(a, temporary.full, temporary.pins, temporary.specs, input.limits);
    defer original.deinit();
    var setup = try Setup.prepareJob(a, temporary.full, .{ .job = temporary.pins.job, .coverage = temporary.pins.coverage, .source = temporary.pins.source, .recipe = temporary.pins.recipe }, input.limits);
    defer setup.deinit();
    const transferred = try setup.finish(temporary.pins, temporary.specs);
    defer transferred.deinit();
    try std.testing.expect(setup.owned == null);
    try std.testing.expectError(error.ScopedOwnerLifetime, setup.routes());
    // Destroy all copied coverage/proposal/schedule/node-ID source buffers.
    // Successful retained Owner calls below cannot read those allocations.
    temporary.deinit();
    live = false;
    try compare(original, transferred);
    var lease = try transferred.borrow();
    try std.testing.expectError(error.ActiveScopedOwnerBorrow, transferred.guard.requireUnused());
    lease.deinit();
    try transferred.guard.requireUnused();
}
/// Finish allocates through the original setup allocator. Activate the failing
/// allocator only AFTER real upstream policy/normative preparation succeeds,
/// enumerate each new finish allocation, and require consumed/deinit-safe state
/// on every failure. No allocator replacement or skip-admission API is used.
pub fn finishFailures(a: std.mem.Allocator, input: Input, max_attempts: usize) !void {
    try input.validate();
    if (max_attempts == 0 or max_attempts > 256) return error.UnboundedScopedTransferFixture;
    for (0..max_attempts) |offset| {
        var failing = std.testing.FailingAllocator.init(a, .{});
        var setup = try Setup.prepareJob(failing.allocator(), input.full, .{ .job = input.pins.job, .coverage = input.pins.coverage, .source = input.pins.source, .recipe = input.pins.recipe }, input.limits);
        defer setup.deinit();
        failing.fail_index = try std.math.add(usize, failing.alloc_index, offset);
        const result = setup.finish(input.pins, input.specs);
        try std.testing.expect(setup.owned == null);
        if (result) |owner| {
            defer owner.deinit();
            try owner.validateNode(0);
            try std.testing.expect(!failing.has_induced_failure);
            return;
        } else |err| {
            if (err != error.OutOfMemory) return err;
            try std.testing.expect(failing.has_induced_failure);
            setup.deinit(); // idempotent after failed consuming finish.
            try std.testing.expectError(error.ScopedOwnerLifetime, setup.routes());
        }
    }
    return error.ScopedTransferAllocationSweepIncomplete;
}
pub fn admissionFailures(a: std.mem.Allocator, input: Input) !void {
    try input.validate();
    var setup = try Setup.prepareJob(a, input.full, .{ .job = input.pins.job, .coverage = input.pins.coverage, .source = input.pins.source, .recipe = input.pins.recipe }, input.limits);
    defer setup.deinit();
    var stale = input.pins;
    stale.routing[0] ^= 1;
    try std.testing.expectError(error.UntrustedScopedOwnerPins, setup.finish(stale, input.specs));
    try std.testing.expect(setup.owned == null);
    // Retained independent original source remains usable after failed finish.
    try input.full.validate();
    var retry = try Setup.prepareJob(a, input.full, .{ .job = input.pins.job, .coverage = input.pins.coverage, .source = input.pins.source, .recipe = input.pins.recipe }, input.limits);
    defer retry.deinit();
    const owner = try retry.finish(input.pins, input.specs);
    defer owner.deinit();
    try owner.validateNode(0);
    const admission = try owner.node(0);
    // Mutation of an independent expected key is never accepted merely by
    // re-sealing the file/mutable constructor metadata.
    var changed = admission;
    changed.expected_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedReusableScopedOwnerKey, changed.validate());
}
/// Retention only. The harness has no default fake Input/test constructor.
pub export fn stwo_scoped_job_positive_transfer_fixture_body_gate() void {
    inline for (.{ &positive, &finishFailures, &admissionFailures }) |function| std.mem.doNotOptimizeAway(function);
}
