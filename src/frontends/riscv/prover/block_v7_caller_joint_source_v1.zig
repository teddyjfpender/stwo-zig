//! Explicit v7 caller admission and typed open accounting. No old source seal,
//! old success receipt, or synthetic caller binding supplies authority.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Suite = core.proof_suites.Blake3;
const E = @import("block_v7_execution_epoch_v1.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Original = @import("block_v5_precompile_protocol_v1.zig");
const Fused = @import("block_v5_caller_fused_proof_v1.zig");
const Schedule = @import("block_v5_caller_fused_schedule_v1.zig");
const Schema = @import("../air/lookups/tables/schema.zig");
pub const TAG: u32 = 0x4237434a;
pub const VERSION: u32 = 1;
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
        var schedule = try Schedule.Schedule.init(a, self.statement, self.total_steps, self.frame, 1);
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
    try arithmetic.validate(pin.statement);
    ch.mixU32s(&.{ TAG, VERSION, 2, @intCast(schedule.program.len), @intCast(schedule.tables.len), @intCast(schedule.memory.len) });
    entry.mix(ch);
    arithmetic.mixInto(ch);
    try Fused.mixClaimBodies(ch, schedule, relations.program_claims, relations.state_claims, relations.table_claims, relations.memory_claims);
}
pub const Exports = struct {
    arithmetic_sum: Q,
    program_sum: Q,
    fetch_count: u64,
    state_sum: Q,
    register_sum: Q,
    table_requests: [Schema.KIND_COUNT]Q,
    auxiliary_clock_memory: Q,
    transition_sum: Q,
    event_count: u64,
    universal_opposite: Q,
    byte_requests: Q,
    internal_residual: Q,
};
/// Pure accounting only. The owning proof verifier must succeed before these
/// values can enter global per-window state/register/provider closure.
pub fn exports(schedule: *const Schedule.Schedule, arithmetic: *const Profile.ExtensionClaim, claims: *const Fused.ClaimFrames) !Exports {
    // Validate every scalar and physical census before indexing parallel arrays.
    try arithmetic.validateCanonicalFields();
    var ch = Suite.Channel{};
    try Fused.mixClaimBodies(&ch, schedule, claims.program_claims, claims.state_claims, claims.table_claims, claims.memory_claims);
    var out = Exports{ .arithmetic_sum = arithmetic.componentSum(), .program_sum = Q.zero(), .fetch_count = 0, .state_sum = Q.zero(), .register_sum = Q.zero(), .table_requests = @splat(Q.zero()), .auxiliary_clock_memory = Q.zero(), .transition_sum = Q.zero(), .event_count = 0, .universal_opposite = Q.zero(), .byte_requests = Q.zero(), .internal_residual = Q.zero() };
    for (claims.program_claims, claims.state_claims) |p, s| {
        out.program_sum = out.program_sum.add(p.sum);
        out.state_sum = out.state_sum.add(s.sum);
        out.fetch_count = try std.math.add(u64, out.fetch_count, p.fetch_count);
    }
    for (schedule.tables, claims.table_claims) |slot, claim| {
        if (slot.table == .register_memory) out.register_sum = out.register_sum.add(claim.sum) else out.table_requests[@intFromEnum(slot.table)] = out.table_requests[@intFromEnum(slot.table)].add(claim.sum);
    }
    for (claims.memory_claims) |claim| {
        out.transition_sum = out.transition_sum.add(claim.transition_sum);
        out.universal_opposite = out.universal_opposite.add(claim.universal_sum);
        out.event_count = try std.math.add(u64, out.event_count, claim.active_count);
        for (claim.range_claims) |part| out.byte_requests = out.byte_requests.add(part);
    }
    out.internal_residual = out.arithmetic_sum.sub(out.program_sum).sub(out.state_sum).sub(out.register_sum).add(out.universal_opposite);
    for (out.table_requests) |part| out.internal_residual = out.internal_residual.sub(part);
    return out;
}
