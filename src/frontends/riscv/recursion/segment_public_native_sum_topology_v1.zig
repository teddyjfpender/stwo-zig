//! Minimal public-statement topology that changes the native-sum arithmetic graph.
//! The four retained-section counts live in the detached key separately. Values,
//! clocks, roots and relation sums remain dynamic circuit inputs.
const std = @import("std");
const wire = @import("segment_statement_v2.zig");
const layout_mod = @import("segment_statement_v2_transcript_layout.zig");

pub const Completion = struct {
    kind: wire.CompletionKindV2,
    value: u32,
};

pub const Topology = struct {
    /// Concatenated section addresses, in canonical section order.
    addresses: []const u32,
    completion: ?Completion,

    pub fn fromView(
        allocator: std.mem.Allocator,
        view: *const wire.CanonicalWireViewV2,
    ) !Topology {
        const layout = try layout_mod.Layout.fromView(view);
        const count = std.math.cast(usize, @as(u64, layout.counts[0]) +
            layout.counts[1] + layout.counts[2] + layout.counts[3]) orelse
            return error.InvalidPublicNativeSumTopology;
        const addresses = try allocator.alloc(u32, count);
        errdefer allocator.free(addresses);
        var at: usize = 0;
        for (layout.sections, 0..) |section, section_index| {
            for (0..section.count) |index| {
                addresses[at] = if (section_index < 2)
                    view.sparseEntry(section, index).address
                else
                    view.clockEntry(section, index).address;
                at += 1;
            }
        }
        const result = Topology{
            .addresses = addresses,
            .completion = if (view.statement.completion) |value|
                .{ .kind = value.kind, .value = value.value }
            else
                null,
        };
        try result.validate(layout.counts);
        return result;
    }

    pub fn deinit(self: *Topology, allocator: std.mem.Allocator) void {
        allocator.free(self.addresses);
        self.* = undefined;
    }

    pub fn validate(self: Topology, counts: [layout_mod.SECTIONS.len]u32) !void {
        const layout = try layout_mod.Layout.init(counts);
        const count = std.math.cast(usize, @as(u64, counts[0]) +
            counts[1] + counts[2] + counts[3]) orelse
            return error.InvalidPublicNativeSumTopology;
        if (self.addresses.len != count) return error.InvalidPublicNativeSumTopology;
        var at: usize = 0;
        for (layout.sections) |section| {
            var previous: ?u32 = null;
            for (0..section.count) |_| {
                const address = self.addresses[at];
                if (address >= wire.MAX_RW_ADDRESS_EXCLUSIVE or
                    (previous != null and address <= previous.?))
                    return error.InvalidPublicNativeSumTopology;
                previous = address;
                at += 1;
            }
        }
        if (self.completion) |completion| {
            if (completion.kind == .unretired_self_loop)
                _ = @import("../air/program/decode.zig").decodeProgramWord(completion.value) catch
                    return error.InvalidPublicNativeSumTopology;
        }
    }

    pub fn validateAgainstView(
        self: Topology,
        view: *const wire.CanonicalWireViewV2,
    ) !void {
        const layout = try layout_mod.Layout.fromView(view);
        try self.validate(layout.counts);
        const expected_completion: ?Completion = if (view.statement.completion) |value|
            .{ .kind = value.kind, .value = value.value }
        else
            null;
        if (!std.meta.eql(self.completion, expected_completion))
            return error.PublicNativeSumTopologyMismatch;
        var at: usize = 0;
        for (layout.sections, 0..) |section, section_index| {
            for (0..section.count) |index| {
                const address = if (section_index < 2)
                    view.sparseEntry(section, index).address
                else
                    view.clockEntry(section, index).address;
                if (self.addresses[at] != address)
                    return error.PublicNativeSumTopologyMismatch;
                at += 1;
            }
        }
    }

    pub fn addressAt(
        self: Topology,
        counts: [layout_mod.SECTIONS.len]u32,
        section_index: usize,
        index: usize,
    ) u32 {
        std.debug.assert(section_index < counts.len and index < counts[section_index]);
        var offset: usize = 0;
        for (counts[0..section_index]) |count| offset += count;
        return self.addresses[offset + index];
    }

    pub fn nextMemoryAddress(
        self: Topology,
        counts: [layout_mod.SECTIONS.len]u32,
        positions: [layout_mod.SECTIONS.len]usize,
    ) ?u32 {
        var result: ?u32 = null;
        for (counts, positions, 0..) |count, position, section_index| {
            if (position >= count) continue;
            const candidate = self.addressAt(counts, section_index, position);
            if (result == null or candidate < result.?) result = candidate;
        }
        return result;
    }
};

test "native-sum topology binds address arrangement, not retained values" {
    const fixture = try @import("../air/public_data_v2_test_support.zig").Fixture.init();
    const source = fixture.leftSource();
    const words = try @import("../air/public_data_v2_test_support.zig").encode(
        std.testing.allocator,
        &source,
    );
    defer std.testing.allocator.free(words);
    const view = try wire.authenticateCanonicalWire(words);
    var topology = try Topology.fromView(std.testing.allocator, &view);
    defer topology.deinit(std.testing.allocator);
    try topology.validateAgainstView(&view);
    if (topology.addresses.len != 0) {
        const saved = topology.addresses[0];
        @constCast(topology.addresses)[0] = saved + 4;
        try std.testing.expectError(error.PublicNativeSumTopologyMismatch, topology.validateAgainstView(&view));
        @constCast(topology.addresses)[0] = saved;
    }
}
