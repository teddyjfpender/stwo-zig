//! Optional capture owner; callers close only after their actual workers/callbacks drain.
const std = @import("std");
const R = @import("stwo_riscv_cuda_integration").rv64.execution.pcs.pcs_native.Recording;
const Inputs = @import("capture_inputs.zig");
pub const Purpose = R.Purpose;
pub const Session = struct {
    dataset: ?*R.Dataset = null,
    success: bool = false,
    pub fn args(a: std.mem.Allocator, arguments: []const [:0]const u8) Session {
        const path = Inputs.configForArgs(arguments) orelse return .{};
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("rv64/diagnostic/command/v1\x00");
        for (arguments) |arg| {
            var length: [8]u8 = undefined;
            std.mem.writeInt(u64, &length, arg.len, .little);
            hash.update(&length);
            hash.update(arg);
        }
        return config(a, path, hash.finalResult(), .execution);
    }
    pub fn argsForExecution(a: std.mem.Allocator, arguments: []const [:0]const u8, execution: [32]u8) Session {
        return config(a, Inputs.configForArgs(arguments) orelse return .{}, execution, .execution);
    }
    pub fn process(a: std.mem.Allocator) Session {
        // Preserve the disabled path: no argument allocation or file reads.
        const root = R.rootFromEnv(a) catch |err| {
            report(err);
            return .{};
        } orelse return .{};
        a.free(root);
        const arguments = std.process.argsAlloc(a) catch |err| {
            report(err);
            return .{};
        };
        defer std.process.argsFree(a, arguments);
        return args(a, arguments);
    }
    pub fn config(a: std.mem.Allocator, path: []const u8, execution: [32]u8, purpose: Purpose) Session {
        const root = R.rootFromEnv(a) catch |err| {
            report(err);
            return .{};
        } orelse return .{};
        defer a.free(root);
        const identity = Inputs.read(a, path) catch |err| {
            report(err);
            return .{};
        };
        var attempt: [16]u8 = undefined;
        std.crypto.random.bytes(&attempt);
        return .{ .dataset = R.Dataset.create(a, root, .{ .execution = execution, .program = identity.program, .input = identity.input, .request = identity.config, .attempt = attempt, .purpose = purpose }) catch |err| {
            report(err);
            return .{};
        } };
    }
    pub fn attach(self: *Session, slot: *R.Slot) void {
        slot.attach(self.dataset) catch |err| {
            if (self.dataset) |dataset| dataset.fail(err);
            report(err);
        };
    }
    pub fn deinit(self: *Session) void {
        if (self.dataset) |dataset| {
            dataset.finish(self.success) catch |err| report(err);
            dataset.destroy() catch |err| report(err); // Never free an owner with live borrows.
        }
        self.* = .{};
    }
};
fn report(err: anyerror) void {
    std.debug.print("RV64_CAPTURE error={s} complete=false proof_authority=false\n", .{@errorName(err)});
}
