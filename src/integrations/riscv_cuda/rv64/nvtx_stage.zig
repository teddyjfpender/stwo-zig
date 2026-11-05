//! Opt-in host ranges on the exact persistent GPU owner thread. No CUDA
//! events, transfers or synchronization are introduced. These standalone
//! ranges use the existing runtime ABI; global admission must be disabled
//! until that ABI supports nested annotations.
const std = @import("std");
const Push = *const fn (*anyopaque, [*:0]const u8) callconv(.c) c_int;
const Pop = *const fn (*anyopaque) callconv(.c) c_int;
pub const Range = struct {
    raw: *anyopaque,
    pop: ?Pop = null,
    pub fn begin(library: *std.DynLib, raw: *anyopaque, label: [:0]const u8) !Range {
        const enabled = if (std.posix.getenv("STWO_RV64_NVTX")) |value| std.mem.eql(u8, value, "1") else false;
        if (!enabled) return .{ .raw = raw };
        const push = library.lookup(Push, "stwo_exec_context_nvtx_push") orelse return error.MissingNvtxStageRuntime;
        const pop = library.lookup(Pop, "stwo_exec_context_nvtx_pop") orelse return error.MissingNvtxStageRuntime;
        if (push(raw, label) != 0) return error.NvtxStagePushFailed;
        return .{ .raw = raw, .pop = pop };
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
