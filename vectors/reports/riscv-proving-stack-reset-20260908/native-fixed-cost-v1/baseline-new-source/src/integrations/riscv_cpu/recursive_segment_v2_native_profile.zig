//! Opt-in native-stage evidence for the small complete-proof development route.
//! Profiling records the ordinary request without changing its execution policy.
const std = @import("std");
const stage_profile = @import("stwo_prover_api").stage_profile;

pub const Probe = struct {
    allocator: std.mem.Allocator,
    capture: ?stage_profile.Recorder,

    pub fn init(allocator: std.mem.Allocator) Probe {
        return .{
            .allocator = allocator,
            .capture = if (std.process.hasEnvVarConstant("STWO_RISCV_NATIVE_PROFILE"))
                stage_profile.Recorder.init(allocator, "zig", "small_recursive_native")
            else
                null,
        };
    }

    pub fn deinit(self: *Probe) void {
        if (self.capture) |*capture| capture.deinit();
        self.* = undefined;
    }

    pub fn recorder(self: *Probe) ?*stage_profile.Recorder {
        return if (self.capture) |*capture| capture else null;
    }

    pub fn finish(self: *Probe) !void {
        const capture = self.recorder() orelse return;
        var stages = try capture.snapshot(self.allocator);
        defer stages.deinit(self.allocator);
        var tasks = try capture.taskSnapshot(self.allocator);
        defer tasks.deinit(self.allocator);
        const json = try std.json.Stringify.valueAlloc(self.allocator, .{
            .stages = stages,
            .tasks = tasks,
        }, .{});
        defer self.allocator.free(json);
        std.debug.print("SEGMENT_V2_NATIVE_PROFILE {s}\n", .{json});
    }
};
