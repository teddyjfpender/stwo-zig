//! Thirteen-relation challenge view for the Poseidon2 extension profile.
//!
//! Drawing deliberately calls the unchanged twelve-pair base routine first,
//! then performs one exact two-felt draw for the guest pair.  The base type,
//! allocation pattern, and schedule are not widened.

const std = @import("std");
const base = @import("../relation_challenges.zig");

pub const guest_relation_arity: usize = 32;
pub const relation_count: usize = base.RELATION_COUNT + 1;

pub const Poseidon2V1Relations = struct {
    base: base.Relations,
    guest_poseidon2_io: base.RelationElements(guest_relation_arity),

    pub fn draw(
        allocator: std.mem.Allocator,
        channel: anytype,
    ) !Poseidon2V1Relations {
        const base_relations = try base.Relations.draw(allocator, channel);
        return drawAfterBase(allocator, channel, base_relations);
    }

    /// Reuse the universal BLAKE3 provider's native challenges exactly.
    pub fn drawAfterBase(allocator: std.mem.Allocator, channel: anytype, base_relations: base.Relations) !Poseidon2V1Relations {
        const guest_pair = try channel.drawSecureFelts(allocator, 2);
        defer allocator.free(guest_pair);
        if (guest_pair.len != 2) return error.InvalidChallengeDraw;
        return .{
            .base = base_relations,
            .guest_poseidon2_io = .init(guest_pair[0], guest_pair[1]),
        };
    }

    pub fn fromDraws(native: base.Relations, pair: *const [2]@import("stwo_core").fields.qm31.QM31) !Poseidon2V1Relations {
        return .{ .base = native, .guest_poseidon2_io = .init(pair[0], pair[1]) };
    }
    pub fn draws(self: *const Poseidon2V1Relations) [2]@import("stwo_core").fields.qm31.QM31 {
        return .{ self.guest_poseidon2_io.z, self.guest_poseidon2_io.alpha };
    }

    pub fn dummy() Poseidon2V1Relations {
        return .{
            .base = .dummy(),
            .guest_poseidon2_io = .dummy(),
        };
    }
};

comptime {
    if (base.RELATION_COUNT != 12 or relation_count != 13) {
        @compileError("guest challenge must append to the exact base schedule");
    }
}
