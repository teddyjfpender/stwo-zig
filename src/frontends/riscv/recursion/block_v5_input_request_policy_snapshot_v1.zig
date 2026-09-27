//! Stable independently pinned original capacity policy custody. No captures,
//! verified flags or proof-file keys are manufactured by this metadata owner.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Input = @import("block_v5_input_tail_public_v1.zig");
const Carrier = @import("block_v5_input_tail_receiver_v1.zig");
const Native = @import("block_v5_wide_original_child_source_v1.zig").ForSubtype(.capacity_v1);
const Prepared = @import("../prover/block_v5_native_capacity_recursive_admission_v1.zig").Prepared;
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Coverage = @import("../prover/block_v5_recursive_coverage_plan_v1.zig");
const Seal = @import("../prover/block_v5_source_seal_v1.zig");
const Catalog = @import("../prover/block_v5_native_capacity_catalog_v1.zig");
const NativeBus = @import("block_v5_capacity_recursive_public_bus_v1.zig");
const TailProtocol = @import("block_v5_input_tail_protocol_v1.zig");
pub const VERSION: u32 = 1;
pub const Limits = struct {
    max_metadata_bytes: usize = 1 << 30,
    max_windows: usize = 8192,
    max_logical: usize = 32768,
    max_physical: usize = 32768,
    max_node_metadata: usize = 32768,
    max_schedule_terms: usize = 1 << 20,
    original: @import("block_v5_wide_original_child_source_v1.zig").Limits = .{},
};
pub const Pins = struct {
    input: Input.Pin,
    coverage: [32]u8,
    original_roster: [32]u8,
    carrier_key: [32]u8,
};
/// Canonical ordered original policy identity. The expected Pins must come
/// from the independent job/source admission, never from transported metadata.
pub fn pins(a: std.mem.Allocator, coverage: *const Coverage.Plan, input: *Input.Owned, natives: []const Native.Policy, carrier: Carrier.Policy, limits: Limits) !Pins {
    try requireCounts(coverage, natives.len, limits);
    try coverage.requireExact(coverage.meta);
    try input.require(carrier.expected_input);
    if (carrier.public != input or natives.len != input.job.expected().windows.len) return error.UntrustedInputRequestPolicyRoster;
    const admitted = try TailProtocol.Admission.init(carrier.key, carrier.expected_id, input, carrier.expected_input);
    try admitted.validate();
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x4235494f, VERSION, @intCast(natives.len) });
    channel.mixRoot(coverage.pinned_digest);
    channel.mixRoot(input.pin.root);
    channel.mixU32s(&.{input.pin.word_count});
    channel.mixRoot(carrier.expected_id);
    for (natives, 0..) |policy, index| {
        if (policy.admitted.index != index or policy.physical.index != index or policy.physical.kind != .native_arithmetic or policy.physical.subtype != .capacity_v1 or policy.wires.len > limits.max_schedule_terms) return error.UntrustedInputRequestPolicyRoster;
        try policy.admitted.validate(policy.admitted.template_id);
        if (!std.meta.eql(try policy.key.identity(), policy.key_id)) return error.UntrustedInputRequestPolicyKey;
        var source = try Native.Source.init(a, policy, limits.original);
        defer source.deinit();
        channel.mixU32s(&.{ @intCast(index), policy.admitted.external_retirements, policy.admitted.shape.total_steps });
        channel.mixRoot(policy.key_id);
        channel.mixRoot(try NativeBus.scheduleDigest(policy.wires));
        channel.mixRoot(source.public_input_digest);
        channel.mixRoot(policy.admitted.pin.expected_id);
        channel.mixRoot(policy.admitted.template_id);
    }
    return .{ .input = input.pin, .coverage = coverage.pinned_digest, .original_roster = channel.digestBytes(), .carrier_key = carrier.expected_id };
}
pub fn requireCounts(coverage: *const Coverage.Plan, count: usize, limits: Limits) !void {
    if (limits.max_metadata_bytes == 0 or count == 0 or count > limits.max_windows or count > std.math.maxInt(u32) or coverage.meta.logical.len > limits.max_logical or coverage.meta.physical.len > limits.max_physical or coverage.meta.nodes.len > limits.max_node_metadata) return error.InputRequestPolicyResourceLimit;
}
/// Copies only actual owned/public slices. The common input aliases its one
/// retained immutable expected job; inactive shape-array entries are not read.
pub fn cloneIo(a: std.mem.Allocator, io: @import("../air/public_data.zig").IoEntries, shared_input: []const u32) !@import("../air/public_data.zig").IoEntries {
    if (!std.mem.eql(u32, shared_input, io.input_words)) return error.UntrustedInputRequestPolicyInput;
    var result = io;
    result.input_words = shared_input;
    result.output_words = try a.dupe(@import("../air/public_data.zig").OutputWord, io.output_words);
    return result;
}
pub fn cloneShape(a: std.mem.Allocator, shape: *const Shape, shared_input: []const u32) !Shape {
    if (!std.mem.eql(u32, shared_input, shape.public_data.io_entries.input_words)) return error.UntrustedInputRequestPolicyInput;
    var result = shape.*;
    result.public_data.io_entries = try cloneIo(a, shape.public_data.io_entries, shared_input);
    return result;
}
pub fn cloneCoverageStorage(a: std.mem.Allocator, original: *const Coverage.Plan) !Coverage.Plan {
    const logical = try a.dupe(Seal.Entry, original.meta.logical);
    errdefer a.free(logical);
    const mappings = try a.dupe(Coverage.Mapping, original.meta.mappings);
    errdefer a.free(mappings);
    const physical = try a.dupe(Coverage.Physical, original.meta.physical);
    errdefer a.free(physical);
    const nodes = try a.dupe(Coverage.Node, original.meta.nodes);
    errdefer a.free(nodes);
    var meta = original.meta;
    meta.logical = logical;
    meta.mappings = mappings;
    meta.physical = physical;
    meta.nodes = nodes;
    return .{ .a = a, .meta = meta, .logical_owner = logical, .mappings_owner = mappings, .physical_owner = physical, .nodes_owner = nodes, .pinned_digest = original.pinned_digest };
}
pub const Owner = struct {
    budget: *Budget,
    arena: std.heap.ArenaAllocator,
    refs: std.atomic.Value(usize),
    expected: Pins,
    limits: Limits,
    input: *Input.Owned,
    coverage: Coverage.Plan,
    natives: []Native.Policy,
    carrier: Carrier.Policy,
    pub const complete_source_authority = false;
    pub fn create(backing: std.mem.Allocator, original: *const Coverage.Plan, input: *Input.Owned, native_policies: []const Native.Policy, carrier: Carrier.Policy, independently_expected: Pins, limits: Limits) !*Owner {
        const budget = try Budget.createRetainingParent(backing, limits.max_metadata_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        if (!std.meta.eql(try pins(a, original, input, native_policies, carrier, limits), independently_expected)) return error.UntrustedInputRequestPolicyPin;
        const self = try a.create(Owner);
        errdefer a.destroy(self);
        self.budget = budget;
        self.arena = std.heap.ArenaAllocator.init(a);
        errdefer self.arena.deinit();
        const owned = self.arena.allocator();
        self.refs = std.atomic.Value(usize).init(1);
        self.expected = independently_expected;
        self.limits = limits;
        self.input = input.retain();
        errdefer self.input.deinit();
        self.coverage = try cloneCoverageStorage(owned, original);
        self.carrier = carrier;
        self.carrier.public = self.input;
        self.natives = try owned.alloc(Native.Policy, native_policies.len);
        const common = native_policies[0].admitted;
        const entries = try owned.dupe(Seal.Entry, common.entries);
        const catalog: ?Catalog.Admission = if (common.catalog) |value| .{ .records = try owned.dupe(Catalog.Record, value.records), .limits = value.limits } else null;
        for (self.natives, native_policies) |*policy, proposed| {
            const previous = proposed.admitted;
            if (previous.entries.len != common.entries.len or !std.meta.eql(previous.sealed, common.sealed) or !std.meta.eql(previous.pins, common.pins) or (previous.catalog != null) != (catalog != null)) return error.InconsistentInputRequestPolicySeal;
            for (previous.entries, entries) |entry, expected_entry| if (!std.meta.eql(entry, expected_entry)) return error.InconsistentInputRequestPolicySeal;
            if (previous.catalog) |previous_catalog| if (!std.meta.eql(try previous_catalog.digest(), try catalog.?.digest())) return error.InconsistentInputRequestPolicyCatalog;
            const shape = try owned.create(Shape);
            shape.* = try cloneShape(owned, previous.shape, input.job.expected().input_words);
            const prepared = try owned.create(Prepared);
            prepared.* = try Prepared.init(owned, shape, previous.external_retirements, previous.pin, previous.template, previous.template_id, previous.index, previous.sealed, previous.pins, entries, catalog, previous.limits);
            prepared.reusable_public_inputs = previous.reusable_public_inputs;
            policy.* = proposed;
            policy.admitted = prepared;
            policy.wires = try @import("block_v5_input_request_schedule_custody_v1.zig").ForWire(NativeBus.Wire, NativeBus.scheduleDigest).copy(owned, proposed.wires, try NativeBus.scheduleDigest(proposed.wires), limits.max_schedule_terms);
        }
        try self.validate(independently_expected);
        return self;
    }
    pub fn validate(self: *const Owner, independently_expected: Pins) !void {
        if (!std.meta.eql(self.expected, independently_expected) or !std.meta.eql(try pins(self.budget.allocator(), &self.coverage, self.input, self.natives, self.carrier, self.limits), independently_expected)) return error.UntrustedInputRequestPolicyPin;
    }
    pub fn retain(self: *Owner) *Owner {
        const previous = self.refs.fetchAdd(1, .monotonic);
        std.debug.assert(previous > 0 and previous < std.math.maxInt(usize));
        return self;
    }
    pub fn deinit(self: *Owner) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        const budget = self.budget;
        self.input.deinit();
        self.arena.deinit();
        budget.allocator().destroy(self);
        budget.destroy();
    }
};
