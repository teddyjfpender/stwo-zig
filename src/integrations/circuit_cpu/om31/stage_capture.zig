//! Opt-in, per-proof CPU recursion profiling. No transcript or shared recorder.
const std = @import("std");
const Profile = @import("stwo_prover_engine").stage_profile;
pub const Scope = Profile.StageScope;

pub const Capture = struct {
    allocator: std.mem.Allocator,
    directory: []u8,
    recorder: Profile.Recorder,

    pub fn init(a: std.mem.Allocator) !?Capture {
        const directory = std.process.getEnvVarOwned(a, "STWO_CIRCUIT_OM31_PROFILE_DIR") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => return null,
            else => return err,
        };
        errdefer a.free(directory);
        if (directory.len == 0) return error.EmptyOm31ProfileDirectory;
        try std.fs.cwd().makePath(directory);
        return .{ .allocator = a, .directory = directory, .recorder = Profile.Recorder.initWithOptions(a, "cpu", "circuit-om31", .{ .capture_tasks = false, .capture_process_usage = true }) };
    }

    pub fn deinit(self: *Capture) void {
        self.recorder.deinit();
        self.allocator.free(self.directory);
        self.* = undefined;
    }

    /// Identity is descriptive only. Receiver authority never reads profiles.
    pub fn save(self: *Capture, identity: [32]u8) !void {
        var snapshot = try self.recorder.snapshot(self.allocator);
        defer snapshot.deinit(self.allocator);
        const authority = std.fmt.bytesToHex(identity, .lower);
        const bytes = try std.json.Stringify.valueAlloc(self.allocator, .{ .authority = authority[0..], .profile = snapshot }, .{ .whitespace = .indent_2 });
        defer self.allocator.free(bytes);
        const path = try std.fmt.allocPrint(self.allocator, "{s}/outer-{d}.stages.json", .{ self.directory, std.time.nanoTimestamp() });
        defer self.allocator.free(path);
        const file = try std.fs.cwd().createFile(path, .{ .exclusive = true });
        defer file.close();
        try file.writeAll(bytes);
    }
};
