//! Compact-global statement and exact first-round identity. These bind public
//! policy/geometry only; canonical source tuple validity remains conditional
//! on freshly verified local originals plus the late endpoint-root bridge.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("block_v7_execution_epoch_v1.zig");
const Window = @import("block_v7_real_window_policy_v2.zig");
pub const TAG: u32 = 0x4238434d;
pub const VERSION: u32 = 1;
pub const Policy = struct {
    window: *const Window.Owned,
    config: core.pcs.PcsConfig,
    event_count: u32,
    pub fn validate(self: Policy) !void {
        try self.window.validate();
        try @import("blake3_execution_protocol.zig").validateConfig(self.config);
        if (self.window.span_mode != .endpoint_cohorts or self.window.selection == null or self.event_count == 0 or self.event_count > 1 << 24 or self.config.lifting_log_size != null) return error.InvalidCompactRamPolicy;
        const cohort = self.window.span_mode.endpoint_cohorts;
        if (self.event_count < cohort.cohort_count or @as(u64, self.event_count) * 3 >= core.fields.m31.Modulus) return error.InvalidCompactRamPolicy;
    }
    pub fn cohortCount(self: Policy) u32 {
        return self.window.span_mode.endpoint_cohorts.cohort_count;
    }
    pub fn ramLog(self: Policy) u32 {
        return @max(@as(u32, 4), std.math.log2_int_ceil(u32, self.event_count));
    }
    pub fn boundaryLog(self: Policy) u32 {
        return @max(@as(u32, 4), std.math.log2_int_ceil(usize, self.window.selection.?.addresses.len));
    }
    pub fn digest(self: Policy) ![32]u8 {
        try self.validate();
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ TAG, VERSION, 1, 12, 6, self.event_count, self.cohortCount() });
        self.config.mixInto(&channel);
        self.window.mix(&channel);
        return channel.digestBytes();
    }
    pub fn entry(self: Policy, roots: [4][32]u8) !E.Entry {
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ TAG, VERSION, 2, self.ramLog(), self.boundaryLog(), 16, 7 });
        channel.mixRoot(try self.digest());
        return E.Entry.init(.window_memory_joint, 0, channel.digestBytes(), &roots);
    }
    pub fn requireEpoch(self: Policy, epoch: E.Epoch, roster: []const E.Entry, roots: [4][32]u8) !void {
        if (!std.meta.eql(epoch.config, self.config) or !std.meta.eql(epoch.statement, try self.digest()) or epoch.counts[@intFromEnum(E.Family.native)] != self.cohortCount() or epoch.counts[@intFromEnum(E.Family.window_memory_joint)] != 1) return error.UntrustedCompactRamEpoch;
        inline for (std.meta.fields(E.Family)) |field| {
            const family = @field(E.Family, field.name);
            if (family != .native and family != .window_memory_joint and epoch.counts[@intFromEnum(family)] != 0) return error.UntrustedCompactRamEpoch;
        }
        try epoch.requireEntry(roster, try self.entry(roots));
    }
};
pub fn recordClaims(ch: anytype, epoch: E.Epoch, roots: [4][32]u8, ram: [6]core.fields.qm31.QM31, boundary: [2]core.fields.qm31.QM31, ranges: [2]core.fields.qm31.QM31) !void {
    ch.mixU32s(&.{ TAG, VERSION, 3, 7 });
    ch.mixRoot(epoch.digest);
    for (roots) |root| ch.mixRoot(root);
    inline for (.{ ram, boundary, ranges }) |claims| for (claims) |claim| {
        for (claim.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.NonCanonicalCompactRamClaim;
        ch.mixFelts(&.{claim});
    };
}
