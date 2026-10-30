//! Detached final receiver for one reduction layer over bounded direct v7
//! batches. Every original public frame survives, and only this final stage
//! closes the full job. No original or intermediate proof files are required.
//! Current reduction fan-in is32: at most2048 original children per root.
const std = @import("std");
const Inputs = @import("block_v7_mixed_inputs_v1.zig");
const Direct = @import("block_v7_mixed_public_v1.zig");
const DirectProtocol = @import("block_v7_mixed_protocol_v1.zig");
const Capture = @import("block_v7_mixed_batch_capture_v1.zig");
const Ranges = @import("block_v7_mixed_batch_ranges_v1.zig");
const Bus = @import("block_v7_mixed_batch_public_v1.zig");
const Protocol = @import("block_v7_mixed_batch_protocol_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Global = @import("../prover/block_v7_global_public_closure_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const DirectPin = struct { key: DirectProtocol.Key, wires: []const Direct.Wire };
pub const Limits = struct {
    max_metadata_bytes: usize = 512 << 20,
    max_proof_bytes: usize = 128 << 20,
    capture: Capture.Limits = .{},
    global: Global.Limits = .{},
};
/// Canonical metadata and original verifier policies only. Sources do not
/// assert that any batch proof exists; the final parent proves those equations.
pub const Metadata = struct {
    a: std.mem.Allocator,
    canonical: Inputs.Owned,
    plan: Ranges.Plan,
    policies: []Capture.Policy,
    sources: []*const Capture.Source,
    expected: []Bus.Expected,
    flattened: []Direct.Child,
    pub const complete_block_authority = false;
    pub fn init(a: std.mem.Allocator, input: Inputs.Input, counts: []const u32, pins: []const DirectPin, limits: Limits) !Metadata {
        if (pins.len == 0 or pins.len != counts.len or pins.len > Bus.MAX_CHILDREN) return error.InvalidMixedBatchFanIn;
        var canonical = try Inputs.Owned.initWhole(a, input, limits.global.max_entries);
        errdefer canonical.deinit();
        const scope = Ranges.Scope{ .epoch = input.epoch, .profile = pins[0].key.profile, .public_input_identity = input.epoch.statement };
        var plan = try Ranges.create(a, scope, canonical.expected, counts, limits.capture.ranges);
        errdefer plan.deinit();
        const policies = try a.alloc(Capture.Policy, pins.len);
        errdefer a.free(policies);
        const sources = try a.alloc(*const Capture.Source, pins.len);
        var completed: usize = 0;
        errdefer {
            for (sources[0..completed]) |source| @constCast(source).deinit();
            a.free(sources);
        }
        const expected = try a.alloc(Bus.Expected, pins.len);
        errdefer a.free(expected);
        const flattened = try a.alloc(Direct.Child, canonical.children.len);
        errdefer a.free(flattened);
        for (plan.ranges, pins, policies, sources, expected) |range, pin, *policy, *source, *out| {
            const window_values = try canonical.window(range.first, range.count);
            const original = try DirectProtocol.Admission.init(pin.key, try pin.key.identity(), pin.wires, window_values, canonical.expected[range.first..][0..range.count]);
            policy.* = .{ .scope = scope, .whole_roster = canonical.expected, .counts = counts, .ordinal = range.ordinal, .key = pin.key, .expected_key = try pin.key.identity(), .wires = pin.wires, .values = window_values, .expected_public_input_identity = try original.publicInputIdentity() };
            source.* = try Capture.Source.create(a, policy.*, limits.capture);
            completed += 1;
            out.* = try Bus.Expected.fromPolicy(a, policy.*, limits.capture);
            // Borrow the cloned original family frames. Their owner is Source.
            @memcpy(flattened[range.first..][0..range.count], source.*.children);
        }
        try canonical.requireSameWhole(flattened);
        try (Bus.Values{ .children = sources }).requireRoster(expected);
        return .{ .a = a, .canonical = canonical, .plan = plan, .policies = policies, .sources = sources, .expected = expected, .flattened = flattened };
    }
    pub fn values(self: *const Metadata) Bus.Values {
        return .{ .children = self.sources };
    }
    pub fn requireCoverage(self: *const Metadata, limits: Ranges.Limits) !void {
        var proposals: [Bus.MAX_CHILDREN]Ranges.Batch = undefined;
        var pins: [Bus.MAX_CHILDREN]Ranges.ExpectedProof = undefined;
        for (self.sources, 0..) |source, i| {
            proposals[i] = .{ .job_identity = source.job_identity, .range = source.range, .epoch = source.scope.epoch, .config = source.original_key.config, .public_input_identity = source.public_input_digest, .key_id = source.expected_id };
            pins[i] = .{ .key_id = self.policies[i].expected_key, .public_input_identity = self.policies[i].expected_public_input_identity };
        }
        try Ranges.requireCoverage(self.a, self.plan.scope, self.canonical.expected, self.policies[0].counts, proposals[0..self.sources.len], pins[0..self.sources.len], limits);
        try self.canonical.requireSameWhole(self.flattened);
    }
    pub fn deinit(self: *Metadata) void {
        for (self.sources) |source| @constCast(source).deinit();
        self.a.free(self.sources);
        self.a.free(self.policies);
        self.a.free(self.expected);
        self.a.free(self.flattened);
        self.plan.deinit();
        self.canonical.deinit();
        self.* = undefined;
    }
};
pub const Verified = struct {
    equation: @import("blake3_native_parent_verifier.zig").Verified,
    summary: Global.Summary,
    pub fn deinit(self: *Verified) void {
        self.equation.deinit();
        self.* = undefined;
    }
};
/// All keys, schedules, partition counts and admission profiles are selected
/// independently by the receiver. Only the final parent proof is deserialized.
pub fn verify(a: std.mem.Allocator, bytes: []const u8, trusted: Global.Trusted, input: Inputs.Input, counts: []const u32, direct_pins: []const DirectPin, root_key: Protocol.Key, root_wires: []const Bus.Wire, limits: Limits) !Verified {
    try @import("block_v7_receiver_security_v1.zig").require(root_key.config, trusted.config, input.epoch.config);
    if (bytes.len == 0 or bytes.len > limits.max_proof_bytes or limits.max_metadata_bytes == 0) return error.MixedBatchResourceLimit;
    const budget = try Budget.createRetainingParent(a, limits.max_metadata_bytes);
    defer budget.destroy();
    var metadata = try Metadata.init(budget.allocator(), input, counts, direct_pins, limits);
    defer metadata.deinit();
    try metadata.requireCoverage(limits.capture.ranges);
    const expected_id = try root_key.identity();
    const admission = try Protocol.Admission.init(root_key, expected_id, root_wires, metadata.values(), metadata.expected);
    var decoded = try Parent.codec.decode(a, bytes, &admission);
    var equation = try Parent.verify(&decoded, &admission);
    errdefer equation.deinit();
    try equation.validate(&admission, expected_id);
    const summary = try Global.closeWholePublic(a, trusted, input, metadata.flattened, limits.global);
    return .{ .equation = equation, .summary = summary };
}
