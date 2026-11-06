//! The Stage2 claims buffer layout: ONE authority for where each slot's
//! global-interaction claims live in the device claims buffer that Stage2
//! mixes (mixManifestAndClaims: `claim_count` OM31 felts, 8 words each).
//!
//! The order is the legacy one, by construction: cpu_components.Plan gives
//! slot i the claim range [claim_offset, claim_offset + claimCount(origin)),
//! claim_offset being the running sum of claimCount over the slots before it;
//! inside a slot the RAM claim comes first, then the KIO or Wire claim
//! (global_cpu.claimsFromVector). Three consumers use this file:
//!   * native_global.zig writes a slot's group claims ([ram | other], 8 words
//!     per group) at `Slot.buffer(claims)`; Plan.init checks its groups
//!     against `Slot.of(origin)`;
//!   * Stage2 mixes the whole buffer (`Layout.count` claims);
//!   * the composition roles builder (m8_native_composition_roles.zig) maps a
//!     role's claim parameter P.claims + r (r = ram 0 / kio 1 / wire 2) to
//!     `Slot.index[r]`, the claim index its ClaimSlot patches from.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const api = @import("api.zig");
const Global = CPU.rv64_gkr_global_cpu;
const DG = CPU.rv64_gkr_cpu_worker.DeviceGlobal;

pub const Origin = @FieldType(@FieldType(DG.Item, "descriptor"), "origin");
/// Claim parameter r of a composition role is P.claims + r.
pub const Relation = enum(u2) { ram = 0, kio = 1, wire = 2 };
pub const claim_words = 8;

/// One slot's claims inside the buffer.
pub const Slot = struct {
    /// First claim index of the slot (cpu_components.Slot.claim_offset).
    offset: u32,
    /// claimCount(origin): 0, 1 or 2.
    count: u32,
    /// Absolute claim index per relation (ram, kio, wire); null = the
    /// relation is absent for this origin and its claim is zero.
    index: [3]?u32,
    /// The slot's groups in native_global order: [ram | other].
    pub fn of(origin: Origin, offset: u32) Slot {
        const l = Global.layout(origin);
        var out = Slot{ .offset = offset, .count = @intCast(Global.claimCount(origin)), .index = .{ null, null, null } };
        var at = offset;
        if (l.ram_queries != 0) {
            out.index[@intFromEnum(Relation.ram)] = at;
            at += 1;
        }
        if (l.other_queries != 0) out.index[@intFromEnum(if (Global.isKio(origin)) Relation.kio else Relation.wire)] = at;
        return out;
    }
    pub fn claim(self: Slot, relation: Relation) ?u32 {
        return self.index[@intFromEnum(relation)];
    }
    /// The slot's words in the claims buffer (native_global Outputs.claims).
    pub fn buffer(self: Slot, claims: api.DeviceBuffer) !api.DeviceBuffer {
        return claims.slice(claim_words * @as(usize, self.offset), claim_words * @as(usize, self.count));
    }
};

/// The whole buffer: one Slot per cpu_components.Plan slot, in slot order.
pub const Layout = struct {
    a: std.mem.Allocator,
    slots: []Slot,
    /// claim_count (Stage2.claim_count, cpu_components.Plan.claim_count).
    count: u32,
    pub fn init(a: std.mem.Allocator, origins: []const Origin) !Layout {
        const slots = try a.alloc(Slot, origins.len);
        var offset: u32 = 0;
        for (origins, slots) |origin, *s| {
            s.* = Slot.of(origin, offset);
            offset += s.count;
        }
        return .{ .a = a, .slots = slots, .count = offset };
    }
    pub fn deinit(self: *Layout) void {
        self.a.free(self.slots);
        self.* = undefined;
    }
    pub fn words(self: *const Layout) usize {
        return claim_words * @as(usize, self.count);
    }
};

test "claims layout follows cpu_components.Plan claim offsets and claimsFromVector order" {
    const a = std.testing.allocator;
    const origins = [_]Origin{
        .{ .core = .ls }, // ram only
        .{ .core = .cpu }, // no global claims
        .{ .bridge = .keccak }, // ram + kio
        .{ .core = .initial }, // ram only
        .{ .bridge = .sha256 }, // ram + wire
    };
    var layout = try Layout.init(a, &origins);
    defer layout.deinit();
    try std.testing.expectEqual(@as(u32, 1 + 0 + 2 + 1 + 2), layout.count);
    try std.testing.expectEqual(@as(usize, 8 * 6), layout.words());
    const expect = [_][3]?u32{ .{ 0, null, null }, .{ null, null, null }, .{ 1, 2, null }, .{ 3, null, null }, .{ 4, null, 5 } };
    var offset: u32 = 0;
    for (layout.slots, expect, origins) |s, e, origin| {
        try std.testing.expectEqual(offset, s.offset);
        try std.testing.expectEqual(e, s.index);
        // The legacy decoder reads the same claims from the same offsets.
        const Id = struct {
            v: u32,
            pub fn zero() @This() {
                return .{ .v = std.math.maxInt(u32) };
            }
        };
        var vector: [6]Id = undefined;
        for (&vector, 0..) |*x, i| x.* = .{ .v = @intCast(i) };
        const c = try Global.claimsFromVector(Id, origin, vector[s.offset..][0..s.count]);
        inline for (.{ "ram", "kio", "wire" }, 0..) |name, r| {
            const got = @field(c, name).v;
            if (s.index[r]) |want| try std.testing.expectEqual(want, got) else try std.testing.expectEqual(std.math.maxInt(u32), got);
        }
        offset += s.count;
    }
    var backing: [64]u32 = undefined;
    const buf = api.DeviceBuffer{ .ptr = &backing, .words = layout.words() };
    const b = try layout.slots[2].buffer(buf);
    try std.testing.expectEqual(@as(usize, 16), b.words);
    try std.testing.expectEqual(@intFromPtr(&backing[8]), @intFromPtr(b.ptr));
    try std.testing.expectError(error.DeviceBufferOutOfRange, layout.slots[4].buffer(try buf.slice(0, 40)));
}
