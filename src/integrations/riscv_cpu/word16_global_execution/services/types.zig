//! One explicit LE-word service inventory; no ISA/profile enumeration changes.
const A = @import("stwo_riscv_frontend").rv64_air;
const Q = A.evaluation.Q;
/// Families 0..2 are the v2 roster; `sha256` (v3) is appended so every v2
/// ordinal, offset, column, claim and transcript word is unchanged when absent.
/// Extension point: a further v3 family appends here with its own bridge.
/// `arith256_mod` (v3, tag 0x30021) is family 4.
/// Curve/field families 5..11 (v3) follow; family ordinal = Wire35 kind =
/// bridge kind = curves.Op ordinal (BN254 G1 add/double, BN254 Fp2 mul,
/// BLS12-381 Fp2 mul, arith384_mont, BLS12-381 G1 add/double).
pub const Family = enum(u8) { keccak = 0, add = 1, double = 2, sha256 = 3, arith256_mod = 4, bn254_g1_add = 5, bn254_g1_double = 6, bn254_fp2_mul = 7, bls12_381_fp2_mul = 8, arith384_mont = 9, bls12_381_g1_add = 10, bls12_381_g1_double = 11 };
pub const FAMILIES = 12;
/// v3 families in transcript/claim order; each is mixed only when present.
pub const V3 = [_]Family{ .sha256, .arith256_mod, .bn254_g1_add, .bn254_g1_double, .bn254_fp2_mul, .bls12_381_fp2_mul, .arith384_mont, .bls12_381_g1_add, .bls12_381_g1_double };
pub const CurveOp = A.crypto.curves.Op;
pub const CURVES = A.crypto.curves.spec.COUNT;
pub const FIRST_CURVE = 5;
pub fn curveOp(family: Family) ?CurveOp {
    return if (@intFromEnum(family) >= FIRST_CURVE) @enumFromInt(@intFromEnum(family)) else null;
}
pub fn curveIndex(op: CurveOp) usize {
    return @intFromEnum(op) - FIRST_CURVE;
}
pub fn curveOpOfTag(tag: u64) ?CurveOp {
    return A.crypto.curves.spec.opOfTag(tag);
}
pub fn curveFamily(op: CurveOp) Family {
    return @enumFromInt(@intFromEnum(op));
}
pub const V2_FAMILIES = 3;
pub const Logs = struct {
    keccak: ?u32 = null,
    add: ?u32 = null,
    double: ?u32 = null,
    sha256: ?u32 = null,
    arith256_mod: ?u32 = null,
    bn254_g1_add: ?u32 = null,
    bn254_g1_double: ?u32 = null,
    bn254_fp2_mul: ?u32 = null,
    bls12_381_fp2_mul: ?u32 = null,
    arith384_mont: ?u32 = null,
    bls12_381_g1_add: ?u32 = null,
    bls12_381_g1_double: ?u32 = null,
    /// Admitted bulk-memory bridges (v3), a separate block after the families.
    bulk: Bulk = .{},
    pub fn at(self: @This(), family: Family) ?u32 {
        return switch (family) {
            .keccak => self.keccak,
            .add => self.add,
            .double => self.double,
            .sha256 => self.sha256,
            .arith256_mod => self.arith256_mod,
            inline else => |f| @field(self, @tagName(f)),
        };
    }
    pub fn set(self: *@This(), family: Family, log: ?u32) void {
        switch (family) {
            inline else => |f| @field(self, @tagName(f)) = log,
        }
    }
    /// v2 transport bytes are unchanged: the v3 field is omitted when absent.
    pub fn jsonStringify(self: @This(), jws: anytype) !void {
        try jws.beginObject();
        inline for (.{ "keccak", "add", "double" }) |name| {
            try jws.objectField(name);
            try jws.write(@field(self, name));
        }
        if (self.sha256) |log| {
            try jws.objectField("sha256");
            try jws.write(log);
        }
        if (self.arith256_mod) |log| {
            try jws.objectField("arith256_mod");
            try jws.write(log);
        }
        inline for (.{ "bn254_g1_add", "bn254_g1_double", "bn254_fp2_mul", "bls12_381_fp2_mul", "arith384_mont", "bls12_381_g1_add", "bls12_381_g1_double" }) |name| if (@field(self, name)) |log| {
            try jws.objectField(name);
            try jws.write(log);
        };
        if (self.bulk.any()) {
            try jws.objectField("bulk");
            try jws.write(self.bulk);
        }
        try jws.endObject();
    }
};
/// Wire35 bridge kind of a non-Keccak family.
pub fn bridgeKind(family: Family) A.crypto.secp256k1.word16_bridge.types.Kind {
    return switch (family) {
        .keccak => unreachable,
        .add => .add,
        .double => .double,
        .sha256 => .sha256,
        .arith256_mod => .arith256_mod,
        else => A.crypto.secp256k1.word16_bridge.types.curveKind(curveOp(family).?),
    };
}
/// Packet RAM words per call (each contributes one before and one after term).
pub fn words(family: Family) u64 {
    return if (family == .keccak) 25 else 4 * A.crypto.secp256k1.word16_bridge.types.coordinates(bridgeKind(family));
}
/// Bridge-side Wire35 terms per call: every input coordinate plus outputs.
pub fn bridgeWires(family: Family) u64 {
    if (family == .keccak) return 0;
    const T = A.crypto.secp256k1.word16_bridge.types;
    const kind = bridgeKind(family);
    return T.coordinates(kind) + T.written(kind);
}
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
