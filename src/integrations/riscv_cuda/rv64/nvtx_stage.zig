//! Opt-in host ranges on the exact persistent GPU owner thread. No CUDA
//! events, transfers or synchronization are introduced. These standalone
//! ranges use a single-range runtime ABI. An admitted stage already owns its
//! named m7 range and must not push a second annotation onto that context.
const std = @import("std");
const Push = *const fn (*anyopaque, [*:0]const u8) callconv(.c) c_int;
const Pop = *const fn (*anyopaque) callconv(.c) c_int;

pub const Stage = enum { native_stage1, native_stage2, truth_stage1, truth_stage2, seal, leaf, fold, root };

/// The caller keeps this buffer alive until the range closes. No heap,
/// CUDA events, transfers or synchronization are used for annotations.
pub fn formatLabel(buffer: []u8, stage: Stage, ordinal: u32) ![:0]const u8 {
    return std.fmt.bufPrintZ(buffer, "rv64/gpu/{s}/{d}", .{ @tagName(stage), ordinal });
}

pub const Symbols = struct {
    push: ?Push = null,
    pop: ?Pop = null,
    pub fn load(library: *std.DynLib, enabled: bool) !Symbols {
        if (!enabled) return .{};
        return .{
            .push = library.lookup(Push, "stwo_exec_context_nvtx_push") orelse return error.MissingNvtxStageRuntime,
            .pop = library.lookup(Pop, "stwo_exec_context_nvtx_pop") orelse return error.MissingNvtxStageRuntime,
        };
    }
    pub fn fromEnv(library: *std.DynLib) !Symbols {
        const enabled = if (std.posix.getenv("STWO_RV64_NVTX")) |value| std.mem.eql(u8, value, "1") else false;
        return load(library, enabled);
    }
    pub fn begin(self: Symbols, raw: *anyopaque, name: [:0]const u8) !Range {
        const push = self.push orelse return .{ .raw = raw };
        const pop = self.pop orelse return error.MissingNvtxStageRuntime;
        if (push(raw, name) != 0) return error.NvtxStagePushFailed;
        return .{ .raw = raw, .pop = pop };
    }
};
pub const Range = struct {
    raw: *anyopaque,
    pop: ?Pop = null,
    pub fn beginUnlessAdmitted(library: *std.DynLib, raw: *anyopaque, label: [:0]const u8, admitted: bool) !Range {
        if (admitted) return .{ .raw = raw };
        return begin(library, raw, label);
    }
    pub fn begin(library: *std.DynLib, raw: *anyopaque, label: [:0]const u8) !Range {
        return (try Symbols.fromEnv(library)).begin(raw, label);
    }
    pub fn deinit(self: *Range) void {
        if (self.pop) |pop| {
            const status = pop(self.raw);
            // A missing close invalidates attribution; preserve that fact in
            // the diagnostic log rather than changing proof error unwinding.
            if (status != 0) std.debug.print("NVTX_STAGE_POP_FAILED status={}\n", .{status});
            self.pop = null;
        }
    }
};

test "native trace labels are bounded and disabled ranges own no close" {
    var buffer: [80]u8 = undefined;
    try std.testing.expectEqualStrings("rv64/gpu/native_stage1/4294967295", try formatLabel(&buffer, .native_stage1, std.math.maxInt(u32)));
    var short: [2]u8 = undefined;
    try std.testing.expectError(error.NoSpaceLeft, formatLabel(&short, .root, 0));
    var range = try (Symbols{}).begin(@ptrFromInt(1), "disabled");
    try std.testing.expect(range.pop == null);
    range.deinit();
}

test "trace range closes once and failed push owns no pop" {
    const Fake = struct {
        var pushes: usize = 0;
        var pops: usize = 0;
        var fail = false;
        fn push(_: *anyopaque, _: [*:0]const u8) callconv(.c) c_int {
            pushes += 1;
            return @intFromBool(fail);
        }
        fn pop(_: *anyopaque) callconv(.c) c_int {
            pops += 1;
            return 0;
        }
    };
    const symbols = Symbols{ .push = Fake.push, .pop = Fake.pop };
    var range = try symbols.begin(@ptrFromInt(1), "owned");
    range.deinit();
    range.deinit();
    try std.testing.expectEqual(@as(usize, 1), Fake.pops);
    Fake.fail = true;
    try std.testing.expectError(error.NvtxStagePushFailed, symbols.begin(@ptrFromInt(1), "failed"));
    try std.testing.expectEqual(@as(usize, 2), Fake.pushes);
    try std.testing.expectEqual(@as(usize, 1), Fake.pops);
}
