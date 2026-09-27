//! Trusted word-memory selectors and full u64 ordinals in four16-bit limbs.
//! Global first/last selectors are derived from pinned claim geometry, not
//! committed a second time. Every verifier reconstructs these twelve columns.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Claim = @import("memory_component.zig").Claim;
pub const COLUMN_COUNT = 12;
pub const Layout = struct {
    pub const active = 0;
    pub const first = 1;
    pub const last = 2;
    pub const domain_last = 3;
    pub const ordinal = 4;
    pub const previous_ordinal = 8;
};
pub const Trace = struct {
    a: std.mem.Allocator,
    claim: Claim,
    storage: []M,
    pub fn init(a: std.mem.Allocator, claim: Claim) !Trace {
        try claim.validate();
        const size = @as(usize, 1) << @intCast(claim.log_size);
        const storage = try a.alloc(M, try std.math.mul(usize, size, COLUMN_COUNT));
        errdefer a.free(storage);
        @memset(storage, M.zero());
        for (0..claim.rows) |logical| {
            const at = @import("memory_component_trace.zig").committedRow(logical, claim.log_size);
            storage[Layout.active * size + at] = M.one();
            if (logical == 0) storage[Layout.first * size + at] = M.one();
            if (logical + 1 == claim.rows) storage[Layout.last * size + at] = M.one();
            const ordinal = try std.math.add(u64, claim.first_row, logical);
            for (0..4) |limb| {
                storage[(Layout.ordinal + limb) * size + at] = M.fromCanonical(@as(u16, @truncate(ordinal >> @intCast(16 * limb))));
                if (ordinal != 0) storage[(Layout.previous_ordinal + limb) * size + at] = M.fromCanonical(@as(u16, @truncate((ordinal - 1) >> @intCast(16 * limb))));
            }
        }
        storage[Layout.domain_last * size + @import("memory_component_trace.zig").committedRow(size - 1, claim.log_size)] = M.one();
        return .{ .a = a, .claim = claim, .storage = storage };
    }
    pub fn deinit(self: *Trace) void {
        self.a.free(self.storage);
        self.* = undefined;
    }
    pub fn column(self: *const Trace, i: usize) []const M {
        std.debug.assert(i < COLUMN_COUNT);
        const size = @as(usize, 1) << @intCast(self.claim.log_size);
        return self.storage[i * size ..][0..size];
    }
};
