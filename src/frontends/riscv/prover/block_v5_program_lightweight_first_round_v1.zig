//! Plan-free v3 census/replay adapter. IDs here guard deterministic host replay;
//! fresh same-root proofs and independent admission retain receiver authority.
const std = @import("std");
const core = @import("stwo_core");
const census = @import("block_v5_program_census_v1.zig");
const shape = @import("../air/statement.zig");
const request = @import("block_v5_program_request_proof_v1.zig");
const extension = @import("block_v5_program_extension_proof_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");

pub fn fetchIdentity(root: [32]u8, fetches: []const census.Fetch) ![32]u8 {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x42355046, 1 }); // B5PF
    channel.mixRoot(root);
    channel.mixU64(fetches.len);
    var previous: ?u32 = null;
    for (fetches) |fetch| {
        if (previous != null and fetch.address <= previous.?) return error.NonCanonicalV5ProgramFetches;
        previous = fetch.address;
        channel.mixU32s(&.{fetch.address});
        channel.mixU64(fetch.multiplicity);
    }
    return channel.digestBytes();
}

pub fn add(self: anytype, fetches: []const census.Fetch, statement: *const shape.Blake3ExecutionStatement, template_id: [32]u8, instance_id: [32]u8, roots: seal.Roots, request_roots: seal.Roots) !void {
    if (self.table_roots != null or self.next >= self.native_entries.len or
        !std.meta.eql(roots, request_roots)) return error.InvalidV5ProgramFirstRound;
    const slots = try request.slotsFromStatement(self.allocator, statement);
    defer self.allocator.free(slots);
    if (slots.len == 0) try @import("block_v5_empty_program_request_v1.zig").validateShape(statement, statement.total_steps);
    const identity = try fetchIdentity(self.census.program_root.bytes, fetches);
    var total: u64 = 0;
    for (fetches) |fetch| total = try std.math.add(u64, total, fetch.multiplicity);
    const opcode_count = try @import("block_v5_program_request_source_v1.zig").exactOpcodeFetchCount(statement.component_descs[0..statement.n_components]);
    const boundary_count: u64 = if (@import("commitment_program_witness.zig").completionFetch(statement.public_data.completion) != null) 1 else 0;
    const covered = try std.math.add(u64, opcode_count, boundary_count);
    if (covered > total) return error.InvalidV5ProgramFetchPartition;
    try self.census.addFetches(fetches);
    const index = self.next;
    self.native_key_ids[index] = template_id;
    self.plan_ids[index] = identity;
    self.legacy_request_ids[index] = false;
    self.extension_fetches[index] = total - covered;
    self.native_entries[index] = .{ .family = .execution, .index = index, .instance_id = instance_id, .roots = roots };
    self.request_entries[index] = .{ .family = .program_request, .index = index, .instance_id = request.nativeV5InstanceId(template_id, instance_id, index, slots), .roots = roots };
    self.next += 1;
}

pub fn addExtension(self: anytype, index: u32, complete: []const census.Fetch, subset: []const census.Fetch, expected_calls: u64, pin: anytype) !void {
    if (self.table_roots != null or index >= self.next or self.extension_recorded[index])
        return error.InvalidV5ProgramExtensionCensus;
    if (!std.meta.eql(try fetchIdentity(self.census.program_root.bytes, complete), self.plan_ids[index]))
        return error.ChangedV5ProgramExtensionPlan;
    const count = try self.census.validateFetchSubset(complete, subset);
    try recordExtension(self, index, count, expected_calls, pin);
}

pub fn recordExtension(self: anytype, index: u32, count: u64, expected_calls: u64, request_pin: anytype) !void {
    if (count != expected_calls or count != self.extension_fetches[index])
        return error.IncompleteV5ProgramExtensionCensus;
    if (count == 0) {
        if (request_pin != null) return error.InvalidV5ProgramExtensionCensus;
    } else {
        const pin = request_pin orelse return error.MissingV5ProgramExtensionRoot;
        if (self.extension_next != 0 and index <= self.extension_entries[self.extension_next - 1].index)
            return error.InvalidV5ProgramExtensionCensus;
        var slot_calls: u64 = 0;
        for (pin.slots) |slot| slot_calls = try std.math.add(u64, slot_calls, slot.active_calls);
        if (slot_calls != count) return error.IncompleteV5ProgramExtensionCensus;
        self.extension_entries[self.extension_next] = .{ .family = .program_extension_request, .index = index, .instance_id = extension.instanceId(pin.precompile_instance_id, self.native_entries[index].instance_id, index, pin.slots), .roots = pin.roots };
        self.extension_next += 1;
    }
    self.extension_recorded[index] = true;
}

test "block-v5 lightweight fetch replay identity rejects reordered or changed counts" {
    const root: [32]u8 = @splat(7);
    const fetches = [_]census.Fetch{ .{ .address = 4, .multiplicity = 2 }, .{ .address = 8, .multiplicity = 1 } };
    const original = try fetchIdentity(root, &fetches);
    var changed = fetches;
    changed[0].multiplicity += 1;
    try std.testing.expect(!std.meta.eql(original, try fetchIdentity(root, &changed)));
    try std.testing.expectError(error.NonCanonicalV5ProgramFetches, fetchIdentity(root, &.{ fetches[1], fetches[0] }));
}
