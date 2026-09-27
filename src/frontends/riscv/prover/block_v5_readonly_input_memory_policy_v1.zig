//! Independently supplied readonly census/pins; no verified scalar surrogates.
const std = @import("std");
const Classification = @import("block_v5_readonly_input_proof_v1.zig");
const Census = @import("block_v5_readonly_input_proposal_v1.zig").Census;
const Caller = @import("block_v5_caller_readonly_protocol_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
pub const Native = struct { pin: ?Classification.Pin, census: Census };
pub const Pins = struct {
    authority: Caller.Authority,
    native: []const Native,
    /// Sparse caller order is the original execution index order.
    caller: []const Census,
    pub fn require(self: Pins, a: std.mem.Allocator, sealed: Seal.Sealed, seal_pins: Seal.Pins, entries: []const Seal.Entry, native_events: []const u64, caller_events: []const u64, mutable_events: u64) !void {
        try sealed.require(seal_pins, entries);
        if (sealed.register_custody_mode != 1 or self.native.len != native_events.len or self.caller.len != caller_events.len or !std.meta.eql(try self.authority.plan.source.digest(), sealed.initialSourcePlanDigest())) return error.UntrustedReadonlyMemoryPolicy;
        var plan = try self.authority.admit(a);
        defer plan.deinit();
        if (std.mem.allEqual(u8, &sealed.readonly_roster_digest, 0)) return error.MissingReadonlyInputRoster;
        var roster = try @import("block_v5_readonly_input_roster_v1.zig").Builder.init(plan.digest, self.authority.selection.expected_digest, std.math.cast(u32, self.native.len) orelse return error.ReadonlyInputCollectionResourceLimit, std.math.cast(u32, self.caller.len) orelse return error.ReadonlyInputCollectionResourceLimit);
        var total: u64 = 0;
        for (self.native, native_events, 0..) |native, all, index| {
            try native.census.require(all);
            total = try std.math.add(u64, total, native.census.mutable);
            if (native.pin) |pin| {
                try pin.validate();
                if (pin.events != all or !std.meta.eql(pin.plan_digest, plan.digest) or !std.meta.eql(pin.config, seal_pins.config)) return error.UntrustedReadonlyMemoryPolicy;
                for (pin.roots) |root| if (std.mem.allEqual(u8, &root, 0)) return error.UntrustedReadonlyMemoryPolicy;
            } else if (all != 0) return error.MissingReadonlyInputPin;
            try roster.native(@intCast(index), std.math.cast(u32, all) orelse return error.ReadonlyInputProofResourceLimit, if (native.pin) |pin| pin.row_log else 0, if (native.pin) |pin| pin.roots else null, native.census);
        }
        for (self.caller, caller_events) |census, all| {
            try census.require(all);
            total = try std.math.add(u64, total, census.mutable);
        }
        var next_caller: usize = 0;
        for (entries) |entry| if (entry.family == .precompile) {
            if (next_caller >= self.caller.len) return error.UntrustedReadonlyMemoryPolicy;
            try roster.caller(entry.index, self.caller[next_caller]);
            next_caller += 1;
        };
        if (!std.meta.eql(try roster.finish(), sealed.readonly_roster_digest)) return error.UntrustedReadonlyInputRoster;
        if (total != mutable_events) return error.StaleReadonlyInputCensus;
    }
};
