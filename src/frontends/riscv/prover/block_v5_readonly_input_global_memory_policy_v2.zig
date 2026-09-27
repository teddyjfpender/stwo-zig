//! Independently reconstructed ordinal/census routing, admitted once per complete
//! synchronous receive. It owns bounded maps; the actual roster owner is borrowed.
const std = @import("std");
const Roster = @import("block_v5_readonly_input_global_roster_v2.zig");
const Caller = @import("block_v5_caller_readonly_global_proof_v2.zig");
const Original = @import("block_v5_caller_readonly_protocol_v1.zig");
const Native = @import("block_v5_native_readonly_source_proof_v2.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
pub const global = true;
pub const MemoryPolicy = @This();
pub const CallerProof = Caller;
pub const CallerReceiver = @import("block_v5_caller_readonly_global_receiver_v2.zig");
pub const CallerAuthority = Caller.Authority;
pub const NativeProof = Native.Proof;
pub const Limits = struct { max_metadata_bytes: usize = 64 << 20, classifier: @import("block_v5_readonly_input_proof_v1.zig").Limits = .{} };
pub const NativeExpected = struct { ordinal: u32, pin: ?Native.Pin, census: Roster.Census };
pub const Pins = struct {
    authority: Original.Authority,
    roster: *const Roster.Authority,
    native: []const NativeExpected,
    caller: []const Roster.Census,
    caller_ordinals: []const u32,
    classifier_limits: @import("block_v5_readonly_input_proof_v1.zig").Limits,
    pub fn callerAuthority(self: Pins, sealed: Seal.Sealed, ordinal: usize) !Caller.Authority {
        if (ordinal >= self.caller_ordinals.len) return error.StaleReadonlyInputCensus;
        return Caller.Authority.init(self.authority, self.roster, sealed, self.caller_ordinals[ordinal]);
    }
    pub fn require(self: Pins, a: std.mem.Allocator, sealed: Seal.Sealed, seal_pins: Seal.Pins, entries: []const Seal.Entry, native_events: []const u64, caller_events: []const u64, mutable_events: u64) !void {
        _ = a;
        try sealed.require(seal_pins, entries);
        try self.roster.requireEpoch(sealed);
        try self.roster.requireOriginalPolicy(self.authority);
        if (self.native.len != native_events.len or self.caller.len != caller_events.len or self.caller_ordinals.len != self.caller.len or
            try std.math.add(usize, self.native.len, self.caller.len) != self.roster.sources().len) return error.UntrustedReadonlyMemoryPolicy;
        var next_native: usize = 0;
        var next_caller: usize = 0;
        var total: u64 = 0;
        for (self.roster.sources(), 0..) |record, ordinal| {
            if (record.kind == .native) {
                if (next_native >= self.native.len or record.index != next_native) return error.UntrustedReadonlyMemoryPolicy;
                const current = self.native[next_native];
                if (current.ordinal != ordinal or !std.meta.eql(current.census, record.census)) return error.UntrustedReadonlyMemoryPolicy;
                try current.census.require(native_events[next_native]);
                if (record.census.all_rw == 0) {
                    if (current.pin != null) return error.UntrustedReadonlyInputAbsence;
                } else {
                    const pin = current.pin orelse return error.MissingReadonlyInputPin;
                    const independently = try Native.Pin.fromAuthority(self.roster, @intCast(ordinal), seal_pins.config, self.classifier_limits);
                    if (!std.meta.eql(pin, independently)) return error.UntrustedReadonlyMemoryPolicy;
                }
                next_native += 1;
            } else {
                if (next_caller >= self.caller.len or self.caller_ordinals[next_caller] != ordinal or !std.meta.eql(self.caller[next_caller], record.census)) return error.UntrustedReadonlyMemoryPolicy;
                try record.census.require(caller_events[next_caller]);
                next_caller += 1;
            }
            total = try std.math.add(u64, total, record.census.mutable);
        }
        if (next_native != self.native.len or next_caller != self.caller.len or total != mutable_events) return error.StaleReadonlyInputCensus;
    }
};
pub const Owned = struct {
    allocator: std.mem.Allocator,
    pins: Pins,
    pub fn init(a: std.mem.Allocator, roster: *const Roster.Authority, original: Original.Authority, sealed: Seal.Sealed, limits: Limits) !Owned {
        try roster.requireEpoch(sealed);
        try roster.requireOriginalPolicy(original);
        var native_count: usize = 0;
        var caller_count: usize = 0;
        for (roster.sources()) |record| if (record.kind == .native) {
            native_count += 1;
        } else {
            caller_count += 1;
        };
        const bytes = try std.math.add(usize, @sizeOf(Owned), try std.math.add(usize, try std.math.mul(usize, native_count, @sizeOf(NativeExpected)), try std.math.mul(usize, caller_count, @sizeOf(Roster.Census) + @sizeOf(u32))));
        if (bytes > limits.max_metadata_bytes) return error.GlobalReadonlyMemoryPolicyResourceLimit;
        const natives = try a.alloc(NativeExpected, native_count);
        errdefer a.free(natives);
        const callers = try a.alloc(Roster.Census, caller_count);
        errdefer a.free(callers);
        const ordinals = try a.alloc(u32, caller_count);
        errdefer a.free(ordinals);
        var ni: usize = 0;
        var ci: usize = 0;
        for (roster.sources(), 0..) |record, ordinal| {
            if (record.kind == .native) {
                natives[ni] = .{ .ordinal = @intCast(ordinal), .census = record.census, .pin = if (record.census.all_rw == 0) null else try Native.Pin.fromAuthority(roster, @intCast(ordinal), roster.config(), limits.classifier) };
                ni += 1;
            } else {
                callers[ci] = record.census;
                ordinals[ci] = @intCast(ordinal);
                ci += 1;
            }
        }
        return .{ .allocator = a, .pins = .{ .authority = original, .roster = roster, .native = natives, .caller = callers, .caller_ordinals = ordinals, .classifier_limits = limits.classifier } };
    }
    pub fn deinit(self: *Owned) void {
        self.allocator.free(self.pins.caller_ordinals);
        self.allocator.free(self.pins.caller);
        self.allocator.free(self.pins.native);
        self.* = undefined;
    }
};
