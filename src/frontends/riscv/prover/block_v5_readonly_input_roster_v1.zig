//! Allocation-free prechallenge inventory. Roots are original classifier main
//! and fixed commitments; no post-seal source identity enters this digest.
const std = @import("std");
const core = @import("stwo_core");
const Census = @import("block_v5_readonly_input_proposal_v1.zig").Census;
pub const Digest = [32]u8;
pub const Builder = struct {
    channel: core.proof_suites.Blake3.Channel,
    native_count: u32,
    caller_count: u32,
    next_native: u32 = 0,
    next_caller: u32 = 0,
    previous_caller: ?u32 = null,
    pub fn init(plan: Digest, selection: Digest, native_count: u32, caller_count: u32) !Builder {
        if (native_count == 0 or caller_count > native_count or std.mem.allEqual(u8, &plan, 0) or std.mem.allEqual(u8, &selection, 0)) return error.InvalidReadonlyInputRoster;
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ 0x42354952, 2, native_count, caller_count });
        channel.mixRoot(plan);
        channel.mixRoot(selection);
        return .{ .channel = channel, .native_count = native_count, .caller_count = caller_count };
    }
    pub fn native(self: *Builder, index: u32, events: u32, row_log: u32, roots: ?[2]Digest, census: Census) !void {
        if (index != self.next_native or index >= self.native_count or self.next_caller != 0 or (events == 0) != (roots == null) or (events == 0 and row_log != 0)) return error.InvalidReadonlyInputRoster;
        try census.require(events);
        if (roots) |values| {
            if (row_log == 0 or row_log > 24) return error.InvalidReadonlyInputRoster;
            for (values) |root| if (std.mem.allEqual(u8, &root, 0)) return error.InvalidReadonlyInputRoster;
        }
        self.channel.mixU32s(&.{ 1, index, events, row_log, @intFromBool(roots != null) });
        if (roots) |values| for (values) |root| self.channel.mixRoot(root);
        self.mixCensus(census);
        self.next_native += 1;
    }
    pub fn caller(self: *Builder, execution_index: u32, census: Census) !void {
        if (self.next_native != self.native_count or self.next_caller >= self.caller_count or execution_index >= self.native_count or (self.previous_caller != null and execution_index <= self.previous_caller.?)) return error.InvalidReadonlyInputRoster;
        try census.require(census.all_rw);
        self.channel.mixU32s(&.{ 2, execution_index });
        self.mixCensus(census);
        self.previous_caller = execution_index;
        self.next_caller += 1;
    }
    fn mixCensus(self: *Builder, census: Census) void {
        self.channel.mixU64(census.all_rw);
        self.channel.mixU64(census.mutable);
        self.channel.mixU64(census.readonly);
    }
    pub fn finish(self: *const Builder) !Digest {
        if (self.next_native != self.native_count or self.next_caller != self.caller_count) return error.IncompleteReadonlyInputRoster;
        return self.channel.digestBytes();
    }
};
