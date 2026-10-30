//! Active-family v7 caller: separately framed epoch entry and physical claims.
//! The finite layout is derived independently; no proof-carried mask is trusted.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Suite = core.proof_suites.Blake3;
const E = @import("block_v7_execution_epoch_v1.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Original = @import("block_v5_precompile_protocol_v1.zig");
const Fused = @import("block_v5_caller_fused_proof_v1.zig");
const Schedule = @import("block_v5_caller_fused_schedule_v1.zig");
const ActiveSchedule = @import("block_v7_caller_active_schedule_v1.zig");
const Layout = @import("block_v7_caller_active_layout_v1.zig").Layout;
const Schema = @import("../air/lookups/tables/schema.zig");
pub const TAG: u32 = 0x42374143;
pub const VERSION: u32 = 2;
pub const Pin = struct {
    index: u32,
    execution_index: u32,
    execution_identity: [32]u8,
    statement: *const Profile.admission.Statement,
    total_steps: u32,
    frame: @import("../air/block/memory_event.zig").Frame,
    roots: [2][32]u8,
    access_root: [32]u8,
    config: core.pcs.PcsConfig,
    pub fn entry(self: Pin, a: std.mem.Allocator) !E.Entry {
        if (self.statement.ethereum.localZeroCustody()) return error.UnqualifiedV7CallerLocalZero;
        try Original.validate(self.statement, self.total_steps, self.config);
        try @import("block_v5_precompile_witness_v1.zig").validateAdmission(a, self.statement);
        if (self.frame.clock_frame != .leaf_local or self.frame.global_first_cycle == 0 or self.frame.cycle_count != self.total_steps or std.mem.allEqual(u8, &self.execution_identity, 0)) return error.InvalidV7CallerFrame;
        var schedule = try ActiveSchedule.derive(a, self.statement, self.total_steps, self.frame);
        defer schedule.deinit();
        const demand = try @import("block_v5_memory_byte_demand_v1.zig").externalDemandForMode(self.statement, schedule.memory, 1);
        var ch = Suite.Channel{};
        ch.mixU32s(&.{ TAG, VERSION, 0, self.index, self.execution_index, self.total_steps, 1, 5, 6 });
        self.config.mixInto(&ch);
        // Original key commits the entire independent component inventory and
        // fixed root. The new epoch/entry, not its old protocol ID, is authority.
        ch.mixRoot(try Original.keyId(self.statement, self.total_steps, self.config, self.roots[0]));
        ch.mixRoot(self.execution_identity);
        ch.mixU64(self.frame.global_first_cycle);
        ch.mixU32s(&.{self.frame.cycle_count});
        ch.mixU64(demand.event_count);
        ch.mixU64(demand.request_count);
        const layout = try Layout.derive(self.statement, self.total_steps);
        layout.mix(&ch);
        Schedule.mix(&ch, &schedule);
        return E.Entry.init(.caller_fused, self.index, ch.digestBytes(), &(self.roots ++ .{self.access_root}));
    }
    pub fn require(self: Pin, a: std.mem.Allocator, epoch: E.Epoch, entries: []const E.Entry) !E.Entry {
        if (!std.meta.eql(self.config, epoch.config) or self.execution_index >= epoch.counts[@intFromEnum(E.Family.native)]) return error.InvalidV7CallerEpoch;
        const own = try self.entry(a);
        try epoch.requireEntry(entries, own);
        for (entries) |candidate| if (candidate.family == .native and candidate.index == self.execution_index) {
            if (!std.meta.eql(candidate.identity, self.execution_identity)) return error.UntrustedV7CallerExecution;
            return own;
        };
        return error.MissingV7CallerExecution;
    }
};
pub const Drawn = struct { epoch: E.Drawn, relations: Profile.Relations, channel: Suite.Channel };
pub fn draw(a: std.mem.Allocator, epoch: E.Epoch, entry: E.Entry) !Drawn {
    const shared = try epoch.draw(a);
    var ch = shared.channel;
    ch.mixU32s(&.{ TAG, VERSION, 1 });
    entry.mix(&ch);
    const relations = try Profile.Relations.drawAfterVm(a, &ch, shared.word.universal_prefix);
    return .{ .epoch = shared, .relations = relations, .channel = ch };
}
pub fn channel(drawn: *const Drawn, pin: Pin, entry: E.Entry, schedule: *const Schedule.Schedule, arithmetic: *const Profile.ExtensionClaim, relations: *const Fused.ClaimFrames) !Suite.Channel {
    var ch = drawn.channel;
    try recordAfterChallenges(&ch, pin, entry, schedule, arithmetic, relations);
    return ch;
}
pub fn recordAfterChallenges(ch: anytype, pin: Pin, entry: E.Entry, schedule: *const Schedule.Schedule, arithmetic: *const Profile.ExtensionClaim, relations: *const Fused.ClaimFrames) !void {
    const layout = try Layout.derive(pin.statement, pin.total_steps);
    try layout.requireClaims(pin.statement, arithmetic);
    ch.mixU32s(&.{ TAG, VERSION, 2, @intCast(schedule.program.len), @intCast(schedule.tables.len), @intCast(schedule.memory.len) });
    entry.mix(ch);
    arithmetic.mixInto(ch);
    try Fused.mixClaimBodies(ch, schedule, relations.program_claims, relations.state_claims, relations.table_claims, relations.memory_claims);
}
pub const Exports = @import("block_v7_caller_joint_source_v1.zig").Exports;
pub const exports = @import("block_v7_caller_joint_source_v1.zig").exports;
