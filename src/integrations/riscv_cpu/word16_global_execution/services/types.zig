//! One explicit LE-word service inventory; no ISA/profile enumeration changes.
const A = @import("stwo_riscv_frontend").rv64_air;
const Q = A.evaluation.Q;
pub const Family = enum(u8) { keccak = 0, add = 1, double = 2 };
pub const Logs = struct {
    keccak: ?u32 = null,
    add: ?u32 = null,
    double: ?u32 = null,
    pub fn at(self: @This(), family: Family) ?u32 {
        return switch (family) {
            .keccak => self.keccak,
            .add => self.add,
            .double => self.double,
        };
    }
};
pub const ExtraClaims = struct {
    ram: Q,
    owner: Q,
    truth: Q,
    range16: Q,
    range8: Q,
    pub fn zero() @This() {
        return .{ .ram = Q.zero(), .owner = Q.zero(), .truth = Q.zero(), .range16 = Q.zero(), .range8 = Q.zero() };
    }
    pub fn values(self: @This()) [5]Q {
        return .{ self.ram, self.owner, self.truth, self.range16, self.range8 };
    }
    pub fn fromK(c: A.crypto.keccak.word16_bridge.types.Claims) @This() {
        return .{ .ram = c.ram, .owner = c.owner, .truth = c.io, .range16 = c.range16, .range8 = c.range8 };
    }
    pub fn fromSecp(c: A.crypto.secp256k1.word16_bridge.types.Claims) @This() {
        return .{ .ram = c.ram, .owner = c.owner, .truth = c.wire, .range16 = c.range16, .range8 = c.range8 };
    }
    pub fn toK(c: @This()) A.crypto.keccak.word16_bridge.types.Claims {
        return .{ .ram = c.ram, .owner = c.owner, .io = c.truth, .range16 = c.range16, .range8 = c.range8 };
    }
    pub fn toSecp(c: @This()) A.crypto.secp256k1.word16_bridge.types.Claims {
        return .{ .ram = c.ram, .owner = c.owner, .wire = c.truth, .range16 = c.range16, .range8 = c.range8 };
    }
};
pub fn widths(family: Family) [3]usize {
    return if (family == .keccak) A.crypto.keccak.word16_bridge.layout.widths(.bridge) else A.crypto.secp256k1.word16_bridge.layout.widths(.bridge);
}
