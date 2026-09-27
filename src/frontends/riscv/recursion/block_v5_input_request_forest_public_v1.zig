//! Independent bounded request/public layout for each genuine forest node.
//! It exports the ORIGINAL prefix/frontier request, exact range/leaf census and
//! full-u64 endpoints. No received descriptors or scalar closure receipts.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Plan = @import("block_v5_input_request_forest_plan_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Bus = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig");
pub const VERSION: u32 = 1;
pub const Spec = struct {
    geometry: Base.Key,
    schedule: []const Bus.Wire,
    expected_id: [32]u8,
};
pub const Coordinate = struct { first_cell: u32, word_count: u32 };
pub const Limits = struct { max_cells: usize = 512 };
pub const Policy = struct {
    forest: *const Plan.Owned,
    specs: []const Spec,
    index: u32,
    carrier: @import("block_v5_input_tail_receiver_v1.zig").Policy,
    pub fn validate(self: Policy) !void {
        try self.forest.validate();
        if (self.carrier.public != self.forest.input or !std.meta.eql(self.carrier.expected_input, self.forest.expected_input)) return error.UntrustedInputRequestNode;
        if (self.index >= self.forest.geometry.nodes.len or self.specs.len != self.forest.geometry.nodes.len) return error.UntrustedInputRequestNode;
        const config = self.specs[self.index].geometry.config;
        if (!std.meta.eql(config, self.specs[self.index].geometry.context.child_config)) return error.UntrustedInputRequestNode;
        if (!std.meta.eql(config, self.carrier.key.config)) return error.UntrustedInputRequestNode;
        for (self.forest.policies) |p| if (!std.meta.eql(config, p.key.config)) return error.UntrustedInputRequestNode;
        for (self.specs) |spec| if (!std.meta.eql(config, spec.geometry.config) or !std.meta.eql(config, spec.geometry.context.child_config)) return error.UntrustedInputRequestNode;
    }
};
const Writer = struct {
    words: [512]u32 = undefined,
    len: u32 = 0,
    failure: ?anyerror = null,
    pub fn mixU32s(self: *Writer, words: []const u32) void {
        if (self.failure != null) return;
        const end = std.math.add(usize, self.len, words.len) catch {
            self.failure = error.InputRequestNodeResourceLimit;
            return;
        };
        if (end > self.words.len) {
            self.failure = error.InputRequestNodeResourceLimit;
            return;
        }
        @memcpy(self.words[self.len..end], words);
        self.len = @intCast(end);
    }
    pub fn mixRoot(self: *Writer, root: [32]u8) void {
        var words: [8]u32 = undefined;
        for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, root[4 * i ..][0..4], .little);
        self.mixU32s(&words);
    }
    pub fn mixFelts(self: *Writer, values: []const Q) void {
        for (values) |value| {
            var words: [4]u32 = undefined;
            for (&words, value.toM31Array()) |*word, limb| word.* = limb.v;
            self.mixU32s(&words);
        }
    }
};
/// Compact self statement only; descendant statements are supplied as original
/// child coordinates during this node's verifier, never replayed into exports.
pub fn mix(policy: Policy, channel: anytype) !void {
    try policy.validate();
    const node = policy.forest.geometry.nodes[policy.index];
    const job = policy.forest.input.job.expected();
    const end = try std.math.add(u32, node.range.first, node.range.count);
    if (end > job.windows.len) return error.UntrustedInputRequestNode;
    const first_cycle = job.windows[node.range.first].first_cycle;
    const last_cycle = job.windows[end - 1].last_cycle;
    channel.mixU32s(&.{ 0x42354952, VERSION, policy.index, @intFromEnum(node.kind), node.range.first, node.range.count, node.range.leaves, @intCast(job.windows.len) });
    channel.mixRoot(policy.forest.geometry.digest);
    channel.mixRoot(job.coverage_digest);
    channel.mixRoot(job.seal_digest);
    channel.mixU32s(&.{ @truncate(first_cycle), @truncate(first_cycle >> 32), @truncate(last_cycle), @truncate(last_cycle >> 32) });
    // Original provider public bytes, including word length and canonical CV
    // ranges. Same-parent equations must connect these to actual child cells.
    policy.forest.input.mix(channel);
}
pub const Owned = struct {
    policy: Policy,
    limits: Limits,
    words: [512]u32,
    len: u32,
    pub const complete_source_authority = false;
    pub fn init(policy: Policy, limits: Limits) !Owned {
        if (limits.max_cells == 0 or limits.max_cells > 512) return error.InputRequestNodeResourceLimit;
        var writer = Writer{};
        try mix(policy, &writer);
        if (writer.failure) |failure| return failure;
        if (writer.len > limits.max_cells) return error.InputRequestNodeResourceLimit;
        return .{ .policy = policy, .limits = limits, .words = writer.words, .len = writer.len };
    }
    pub fn validate(self: *const Owned) !void {
        const expected = try Owned.init(self.policy, self.limits);
        if (expected.len != self.len or !std.mem.eql(u32, expected.words[0..expected.len], self.words[0..self.len])) return error.MutatedInputRequestNode;
    }
    pub fn cell(self: *const Owned, coordinate: u32) ![4]M {
        if (coordinate >= self.len) return error.InvalidInputRequestNodeCell;
        var bytes: [4]M = undefined;
        for (&bytes, 0..) |*byte, part| byte.* = M.fromCanonical((self.words[coordinate] >> @as(u5, @intCast(8 * part))) & 255);
        return bytes;
    }
    pub fn rangeCoordinates(_: *const Owned) struct { first: u32, count: u32, leaves: u32, job_windows: u32 } {
        return .{ .first = 4, .count = 5, .leaves = 6, .job_windows = 7 };
    }
    pub fn firstCycle(_: *const Owned) Coordinate {
        return .{ .first_cell = 32, .word_count = 2 };
    }
    pub fn lastCycle(_: *const Owned) Coordinate {
        return .{ .first_cell = 34, .word_count = 2 };
    }
    pub fn inputRoot(_: *const Owned) Coordinate {
        return .{ .first_cell = 49, .word_count = 8 };
    }
    pub fn inputLength(_: *const Owned) Coordinate {
        return .{ .first_cell = 38, .word_count = 1 };
    }
    pub fn inputPrefix(self: *const Owned) Coordinate {
        return .{ .first_cell = 57, .word_count = @intCast(self.policy.forest.input.prefix_count) };
    }
    pub fn frontier(self: *const Owned, ordinal: usize) !Coordinate {
        if (ordinal >= self.policy.forest.input.frontier.len) return error.InvalidInputRequestNodeCell;
        return .{ .first_cell = 57 + @as(u32, @intCast(self.policy.forest.input.prefix_count + 10 * ordinal + 2)), .word_count = 8 };
    }
};
