//! Isolated two-event sorted RAM protocol. Tuple/challenge semantics remain
//! word-v4; geometry and proof identity are new and cannot relabel v4 proofs.
const std = @import("std");
const core = @import("stwo_core");
const Word = @import("block_v5_word_memory_protocol_v1.zig");
const LegacyClaim = @import("../air/block/memory_component.zig").Claim;
const Transition = @import("../air/block/memory_transition.zig").Transition;
pub const Challenges = Word.Challenges;
pub const LANES: u32 = 2;
pub const VERSION: u32 = 1;
pub const TAG: u32 = 0x42355232; // B5R2
pub const MAIN_COLUMNS: usize = 54;
pub const FIXED_COLUMNS: usize = 24;
pub const INTERACTION_COLUMNS: usize = 92;
pub const DEGREE: u8 = 4;
pub const DIRECT_CONSTRAINTS: usize = 94;
pub const INTERACTION_CONSTRAINTS: usize = 23;
/// M31 polynomial cells in one physical row. Divide by two only for fully
/// occupied even traces; padding still occupies the full committed domain.
pub const CELLS_PER_ROW: usize = MAIN_COLUMNS + FIXED_COLUMNS + INTERACTION_COLUMNS;
pub const VARIABLE_INVERSE_SLOTS_PER_ROW: usize = 8;

pub const Accounting = struct {
    row_capacity: u64,
    events: u64,
    main_cells: u64,
    fixed_cells: u64,
    interaction_cells: u64,
    total_cells: u64,
    variable_inverse_slots: u64,
};
pub fn accounting(claim: Claim) !Accounting {
    try claim.validate();
    const rows: u64 = claim.rowCapacity();
    return .{ .row_capacity = rows, .events = claim.events, .main_cells = rows * MAIN_COLUMNS, .fixed_cells = rows * FIXED_COLUMNS, .interaction_cells = rows * INTERACTION_COLUMNS, .total_cells = rows * CELLS_PER_ROW, .variable_inverse_slots = rows * VARIABLE_INVERSE_SLOTS_PER_ROW };
}

pub const Claim = struct {
    first_event: u64,
    total_events: u64,
    events: u32,
    row_log: u32,
    first: Transition,
    last: Transition,
    preceding: ?Transition,
    register_custody_mode: u32 = 1,
    pub fn validate(self: Claim) !void {
        if (self.register_custody_mode != 1 or self.row_log < 1 or self.row_log > 24 or self.events == 0 or
            @as(u64, self.events) > self.eventCapacity()) return error.InvalidV5RamLanesGeometry;
        try self.legacy().validate();
        if (self.first.space != 1 or self.last.space != 1 or (if (self.preceding) |prior| prior.space != 1 else false))
            return error.InvalidV5RamLanesSpace;
        if (self.preceding) |prior| _ = try @import("../air/block/memory_transition.zig").adjacency(prior, self.first);
    }
    pub fn rowCapacity(self: Claim) u32 {
        return @as(u32, 1) << @intCast(self.row_log);
    }
    pub fn eventCapacity(self: Claim) u64 {
        return @as(u64, 2) << @intCast(self.row_log);
    }
    pub fn occupiedRows(self: Claim) u32 {
        return self.events / 2 + self.events % 2;
    }
    /// Only a typed endpoint/census oracle; this virtual event log is never
    /// used as the lane trace's commitment or opening domain.
    pub fn legacy(self: Claim) LegacyClaim {
        return .{ .first_row = self.first_event, .total_rows = self.total_events, .rows = self.events, .log_size = self.row_log + 1, .first = self.first, .last = self.last, .preceding = self.preceding };
    }
    pub fn mix(self: Claim, channel: anytype) void {
        channel.mixU32s(&.{ TAG, VERSION, LANES, self.row_log, self.events, self.register_custody_mode });
        channel.mixU64(self.first_event);
        channel.mixU64(self.total_events);
        mixEvent(channel, self.first);
        mixEvent(channel, self.last);
        channel.mixU32s(&.{@intFromBool(self.preceding != null)});
        if (self.preceding) |prior| mixEvent(channel, prior);
    }
};
pub fn admitSequence(claims: []const Claim, total_events: u64) !void {
    if (claims.len == 0 or total_events == 0) return error.InvalidV5RamLanesCensus;
    var next: u64 = 0;
    var previous: ?Transition = null;
    for (claims) |claim| {
        try claim.validate();
        if (claim.first_event != next or claim.total_events != total_events or !std.meta.eql(claim.preceding, previous)) return error.InvalidV5RamLanesCensus;
        next = try std.math.add(u64, next, claim.events);
        previous = claim.last;
    }
    if (next != total_events) return error.InvalidV5RamLanesCensus;
}
pub fn abiId() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/two-event-ram-lanes/v1\x00");
    hash.update(&Word.abiId());
    hash.update("custody-mode1;space1-only;rows=2^rowlog;events<=2*rows;lane0-previous-row-lane1;lane1-current-row-lane0;odd-tail-lane1-inactive\x00");
    hash.update("main54;fixed24;direct94;interaction92;interaction23;degree4;u64-event-ordinals-and-clocks;new-claim-census\x00");
    hash.update("one-transition,link,initial,endpoint,endpoint-count,range-count-prefix;17-range-prefixes=sum-same-index-two-lane-queries;one-shared-range16-inverse-table\x00");
    hash.update("link-interior-lane-cancellation;public-first-consume-constant;row-outgoing-endpoint-selected-by-fixed-lane1-active;endpoint-public-constants-cleared-before-two-variable-denominators\x00");
    hash.update("current-main-all;previous-main-lane1-key-clock-after-only;fixed-current;interaction-current-previous;public-shard-predecessor-and-global-last-exact-once\x00");
    return hash.finalResult();
}
pub fn instanceId(claim: Claim, roots: [2][32]u8) ![32]u8 {
    try claim.validate();
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixRoot(abiId());
    claim.mix(&channel);
    channel.mixRoot(roots[0]);
    channel.mixRoot(roots[1]);
    return channel.digestBytes();
}
fn mixEvent(channel: anytype, event: Transition) void {
    channel.mixU32s(&.{ event.space, event.address, event.before, event.after });
    channel.mixU64(event.clock);
}
