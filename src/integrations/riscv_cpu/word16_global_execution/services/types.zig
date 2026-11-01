//! One explicit LE-word service inventory; no ISA/profile enumeration changes.
const A = @import("stwo_riscv_frontend").rv64_air;
const Q = A.evaluation.Q;
pub const Family = enum(u8) { keccak = 0, add = 1, double = 2 };
pub const Logs = struct {
    keccak: ?u32 = null,
    add: ?u32 = null,
    double: ?u32 = null,
    /// Admitted bulk-memory bridges (ethereum_services_v3). Absent in v2 rosters;
    /// omitted from JSON when empty so v2 metadata stays byte-identical.
    bulk: Bulk = .{},
    pub fn jsonStringify(self: @This(), jws: anytype) !void {
        try jws.beginObject();
        inline for (.{ "keccak", "add", "double" }) |name| {
            try jws.objectField(name);
            try jws.write(@field(self, name));
        }
        if (self.bulk.any()) {
            try jws.objectField("bulk");
            try jws.write(self.bulk);
        }
        try jws.endObject();
    }
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

/// Bulk-memory bridge logs: descriptor (one row per call), copy and set bodies
/// (one row per word). Each present kind is one component of the CPU proof.
pub const BulkKind = A.crypto.bulk_memory.layout.Kind;
pub const bulk_kinds = [_]BulkKind{ .desc, .copy, .set };
pub const Bulk = struct {
    desc: ?u32 = null,
    copy: ?u32 = null,
    set: ?u32 = null,
    pub fn at(self: @This(), kind: BulkKind) ?u32 {
        return switch (kind) {
            .desc => self.desc,
            .copy => self.copy,
            .set => self.set,
        };
    }
    pub fn any(self: @This()) bool {
        return self.desc != null or self.copy != null or self.set != null;
    }
};
/// Public bulk rows of one CPU proof: calls (descriptor rows) and words.
pub const BulkCounts = struct {
    calls: u32 = 0,
    copy_words: u32 = 0,
    set_words: u32 = 0,
    pub fn rows(self: @This(), kind: BulkKind) u32 {
        return switch (kind) {
            .desc => self.calls,
            .copy => self.copy_words,
            .set => self.set_words,
        };
    }
    pub fn any(self: @This()) bool {
        return self.calls != 0 or self.copy_words != 0 or self.set_words != 0;
    }
};
pub const BulkClaims = A.crypto.bulk_memory.types.Claims;
pub fn bulkWidths(kind: BulkKind) [3]usize {
    return A.crypto.bulk_memory.layout.widths(kind);
}
