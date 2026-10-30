//! Exact cross-namespace bridge: no producer-chosen routes or multiplicities.
const std = @import("std");
const core = @import("stwo_core");
const T = @import("air/blake3_transcript_witness.zig");
const Prefix = @import("block_v7_shared_epoch_prefix_v1.zig");
const Rebase = @import("air/blake3_parent_rebase.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Direct = @import("air/blake3_direct_cohort_columns_v1.zig");
pub const Child = struct { state: u32, challenges: u32, uses: [8]u32 };
pub const Owned = struct {
    allocator: std.mem.Allocator,
    words: []T.route.Row,
    scalars: []Storage.Airs[12].Row,
    identity: [32]u8,
    pub fn create(a: std.mem.Allocator, prefix: *const Prefix.Owned, namespace: *const Rebase.Plan, children: []const Child, live: bool) !Owned {
        if (children.len != prefix.consumers or children.len == 0) return error.InvalidSharedEpochBridges;
        const state = prefix.state().source;
        const state_circuit = namespace.map(state.circuit) orelse return error.InvalidSharedEpochBridges;
        const challenge_circuit = namespace.map(Prefix.FANOUT_CIRCUIT) orelse return error.InvalidSharedEpochBridges;
        const words = try a.alloc(T.route.Row, 8 * children.len);
        errdefer a.free(words);
        const scalars = try a.alloc(Storage.Airs[12].Row, 424 * children.len);
        errdefer a.free(scalars);
        const digest = if (live) (try prefix.epoch.draw(a)).channel.digestBytes() else @as([32]u8, @splat(0));
        const fields = if (live) try prefix.scalarValues() else @as([424]core.fields.m31.M31, @splat(core.fields.m31.M31.zero()));
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42374542, 1, @intCast(children.len) });
        for (children, 0..) |child, index| {
            if (child.state == child.challenges or child.state >= namespace.first or child.challenges >= namespace.first or child.state == 0 or child.challenges == 0) return error.InvalidSharedEpochBridges;
            for (children[0..index]) |previous| if (child.state == previous.state or child.challenges == previous.challenges or child.state == previous.challenges or child.challenges == previous.state) return error.InvalidSharedEpochBridges;
            for (0..8) |word| {
                const schedule = T.route.Schedule{ .sources = .{ .{ .circuit = state_circuit, .wire = state.first_wire + @as(u32, @intCast(word)) }, null }, .destination = .{ .circuit = child.state, .wire = @intCast(word) }, .uses = child.uses[word], .bytes = .{ .{ .source = .{ .word = 0, .byte = 0 } }, .{ .source = .{ .word = 0, .byte = 1 } }, .{ .source = .{ .word = 0, .byte = 2 } }, .{ .source = .{ .word = 0, .byte = 3 } } } };
                words[index * 8 + word] = try T.route.logicalRow(schedule, .{ std.mem.readInt(u32, digest[4 * word ..][0..4], .little), 0 });
                // The second source is disabled (weight and all coefficients
                // are zero), but namespace validation checks every declared
                // circuit coordinate. Use this child's admitted namespace for
                // the inactive port as ordinary rebasing would, without adding
                // another lookup consumption or weakening namespace checks.
                if (!words[index * 8 + word][13].isZero()) return error.InvalidSharedEpochBridges;
                words[index * 8 + word][16] = core.fields.m31.M31.fromCanonical(child.state);
                for (Storage.compactFixed(T.route, words[index * 8 + word])) |value| channel.mixU32s(&.{value.toU32()});
            }
            for (fields, 0..) |value, word| {
                scalars[index * 424 + word] = try Storage.Airs[12].routedRow(child.challenges, @intCast(word), 1, challenge_circuit, @intCast(word), value);
                for (Storage.compactFixed(Storage.Airs[12], scalars[index * 424 + word])) |fixed| channel.mixU32s(&.{fixed.toU32()});
            }
        }
        return .{ .allocator = a, .words = words, .scalars = scalars, .identity = channel.digestBytes() };
    }
    pub fn emit(self: *const Owned) !Storage.Prepared {
        var result = Storage.Prepared{ .allocator = self.allocator, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
        inline for (0..Storage.Airs.len) |i| result.fixed[i] = &.{};
        errdefer result.deinit();
        inline for (Storage.Airs, 0..) |Air, slot| {
            var owner = try Direct.ForAir(Air).init(self.allocator, if (slot == 7) self.words.len else if (slot == 12) self.scalars.len else 0);
            defer owner.deinit();
            if (slot == 7) for (self.words) |row| try owner.append(row);
            if (slot == 12) for (self.scalars) |row| try owner.append(row);
            const taken = try owner.take();
            result.main[slot] = taken.main;
            result.fixed[slot] = taken.fixed;
        }
        return result;
    }
    pub fn deinit(self: *Owned) void {
        self.allocator.free(self.words);
        self.allocator.free(self.scalars);
        self.* = undefined;
    }
};
