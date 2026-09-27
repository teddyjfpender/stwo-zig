//! Independent presealed B5IR source membership and complete public providers.
//! The classifier source/mutable sums remain open to original native closures.
const std = @import("std");
const core = @import("stwo_core");
const Native = @import("block_v5_readonly_input_proof_v1.zig");
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
const Policy = @import("block_v5_readonly_input_memory_policy_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
pub const VERSION: u32 = 1;
pub const Limits = struct {
    max_intervals: usize = 4096,
    max_capture_bytes: usize = 128 << 20,
    max_preparation_bytes: usize = 512 << 20,
};
pub fn templateId(pin: Native.Pin, plan: Plan.Owned) [32]u8 {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x4235494b, VERSION, pin.events, pin.row_log, 1, 103, 20, 2 });
    channel.mixRoot(@import("block_v5_readonly_input_protocol_v1.zig").abiId());
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(@embedFile("block_v5_readonly_input_component_v1.zig"));
    hash.update(@embedFile("block_v5_readonly_input_proof_v1.zig"));
    hash.update(@embedFile("../recursion/air/block_v5_readonly_public_provider_graph_v1.zig"));
    channel.mixRoot(hash.finalResult());
    channel.mixRoot(pin.roots[0]);
    channel.mixRoot(plan.digest);
    channel.mixU64(plan.intervals.len);
    pin.config.mixInto(&channel);
    return channel.digestBytes();
}
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    policy: Policy.Pins,
    index: u32,
    native_events: []const u64,
    caller_events: []const u64,
    mutable_events: u64,
    pin: Native.Pin,
    plan: Plan.Owned,
    roots: [2][32]u8,
    sealed: Seal.Sealed,
    pins: Seal.Pins,
    entries: []const Seal.Entry,
    config: core.pcs.PcsConfig,
    template_id: [32]u8,
    logs: [3][]u32,
    limits: Limits,
    /// Policy/roster/input are immutable borrows and outlive this preparation.
    /// No proof-carried metadata selects root membership, intervals or limits.
    pub fn init(a: std.mem.Allocator, policy: Policy.Pins, index: u32, native_events: []const u64, caller_events: []const u64, mutable_events: u64, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, limits: Limits) !Prepared {
        if (index >= policy.native.len or limits.max_intervals == 0 or limits.max_capture_bytes == 0 or limits.max_preparation_bytes == 0) return error.UntrustedNativeReadonlyRecursiveAdmission;
        try policy.require(a, sealed, pins, entries, native_events, caller_events, mutable_events);
        const pin = policy.native[index].pin orelse return error.UntrustedReadonlyInputAbsence;
        var plan = try policy.authority.admit(a);
        errdefer plan.deinit();
        if (plan.intervals.len > limits.max_intervals) return error.NativeReadonlyRecursiveResourceLimit;
        var self = Prepared{ .allocator = a, .policy = policy, .index = index, .native_events = native_events, .caller_events = caller_events, .mutable_events = mutable_events, .pin = pin, .plan = plan, .roots = pin.roots, .sealed = sealed, .pins = pins, .entries = entries, .config = pins.config, .template_id = templateId(pin, plan), .logs = undefined, .limits = limits };
        try self.validateAuthority(self.template_id);
        inline for (.{ 1, 103, 20 }, 0..) |width, tree| {
            self.logs[tree] = try a.alloc(u32, width);
            @memset(self.logs[tree], pin.row_log);
            errdefer a.free(self.logs[tree]);
        }
        return self;
    }
    pub fn deinit(self: *Prepared) void {
        for (self.logs) |logs| self.allocator.free(logs);
        self.plan.deinit();
        self.* = undefined;
    }
    pub fn validate(self: *const Prepared, expected: [32]u8) !void {
        try self.validateAuthority(expected);
        inline for (.{ 1, 103, 20 }, 0..) |width, tree| {
            if (self.logs[tree].len != width) return error.UntrustedNativeReadonlyRecursiveGeometry;
            for (self.logs[tree]) |log| if (log != self.pin.row_log) return error.UntrustedNativeReadonlyRecursiveGeometry;
        }
    }
    fn validateAuthority(self: *const Prepared, expected: [32]u8) !void {
        if (self.index >= self.policy.native.len or self.plan.intervals.len == 0 or self.plan.intervals.len > self.limits.max_intervals or self.limits.max_capture_bytes == 0 or self.limits.max_preparation_bytes == 0) return error.UntrustedNativeReadonlyRecursiveAdmission;
        try self.policy.require(self.allocator, self.sealed, self.pins, self.entries, self.native_events, self.caller_events, self.mutable_events);
        const pin = self.policy.native[self.index].pin orelse return error.UntrustedReadonlyInputAbsence;
        if (!std.meta.eql(pin, self.pin) or !std.meta.eql(pin.roots, self.roots) or !std.meta.eql(pin.config, self.config) or !std.meta.eql(self.template_id, expected) or !std.meta.eql(expected, templateId(pin, self.plan)) or !std.meta.eql(self.plan.digest, pin.plan_digest)) return error.UntrustedNativeReadonlyRecursiveAdmission;
        var canonical = try self.policy.authority.admit(self.allocator);
        defer canonical.deinit();
        if (!std.meta.eql(self.plan.digest, canonical.digest) or !intervalsEqual(self.plan.intervals, canonical.intervals)) return error.UntrustedNativeReadonlyRecursivePlan;
        var native_entry: ?Seal.Entry = null;
        var access_root: ?[32]u8 = null;
        for (self.entries) |entry| {
            if (entry.index != self.index) continue;
            if (entry.family == .execution) native_entry = entry;
            if (entry.family == .execution_sidecar) access_root = entry.roots[0];
        }
        const native = native_entry orelse return error.MissingReadonlyInputSourceEntry;
        const access = access_root orelse return error.MissingReadonlyInputSourceEntry;
        if (!std.meta.eql(pin.source_identity, Native.sourceIdentity(.native, self.index, self.sealed.digest, native.instance_id, native.roots, access))) return error.UntrustedReadonlyInputSourceIdentity;
    }
};

fn intervalsEqual(left: []const Plan.Interval, right: []const Plan.Interval) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!std.meta.eql(a, b)) return false;
    return true;
}
