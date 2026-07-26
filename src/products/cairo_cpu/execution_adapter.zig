//! Process boundary for the pinned official Cairo VM execution sidecar.

const std = @import("std");
const builtin = @import("builtin");

pub const environment_variable = "STWO_CAIRO_VM_ADAPTER";

pub const Request = struct {
    program: []const u8,
    program_type: []const u8,
    arguments: ?[]const u8,
    prover_input_out: []const u8,
};

pub const Receipt = struct {
    program_type: []const u8,
    program_sha256: [32]u8,
    arguments_sha256: ?[32]u8,
    adapter_sha256: [32]u8,
    execution_ns: u64,
};

pub fn run(
    allocator: std.mem.Allocator,
    request: Request,
) !Receipt {
    if (request.program.len == 0 or request.prover_input_out.len == 0)
        return error.InvalidExecutionPath;
    const adapter = try adapterPath(allocator);
    defer allocator.free(adapter);
    try validateExecutable(adapter);

    const started = std.time.Instant.now() catch
        return error.ClockUnavailable;
    const term = if (request.arguments) |arguments|
        try runChild(allocator, &.{
            adapter,
            "run",
            "--program",
            request.program,
            "--program-type",
            request.program_type,
            "--arguments",
            arguments,
            "--prover-input-out",
            request.prover_input_out,
        })
    else
        try runChild(allocator, &.{
            adapter,
            "run",
            "--program",
            request.program,
            "--program-type",
            request.program_type,
            "--prover-input-out",
            request.prover_input_out,
        });
    try requireSuccess(term);
    const execution_ns = (std.time.Instant.now() catch
        return error.ClockUnavailable).since(started);

    return .{
        .program_type = request.program_type,
        .program_sha256 = try fileSha256(request.program),
        .arguments_sha256 = if (request.arguments) |path|
            try fileSha256(path)
        else
            null,
        .adapter_sha256 = try fileSha256(adapter),
        .execution_ns = execution_ns,
    };
}

pub fn fileSha256(path: []const u8) ![32]u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const stat = try file.stat();
    if (stat.kind != .file) return error.InvalidExecutionPath;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var storage: [256 * 1024]u8 = undefined;
    while (true) {
        const count = try file.read(&storage);
        if (count == 0) break;
        hasher.update(storage[0..count]);
    }
    return hasher.finalResult();
}

fn adapterPath(allocator: std.mem.Allocator) ![]u8 {
    const overridden = std.process.getEnvVarOwned(
        allocator,
        environment_variable,
    ) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    if (overridden) |path| {
        if (!std.fs.path.isAbsolute(path)) {
            allocator.free(path);
            return error.ExecutionAdapterPathNotAbsolute;
        }
        return path;
    }
    const executable_dir = try std.fs.selfExeDirPathAlloc(allocator);
    defer allocator.free(executable_dir);
    const name = if (builtin.os.tag == .windows)
        "stwo-cairo-vm-adapter.exe"
    else
        "stwo-cairo-vm-adapter";
    return std.fs.path.join(allocator, &.{ executable_dir, name });
}

fn validateExecutable(path: []const u8) !void {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const stat = try file.stat();
    if (stat.kind != .file or stat.size == 0)
        return error.InvalidExecutionAdapter;
}

fn runChild(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
) !std.process.Child.Term {
    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Inherit;
    child.expand_arg0 = .no_expand;
    try child.spawn();
    return child.wait();
}

fn requireSuccess(term: std.process.Child.Term) !void {
    switch (term) {
        .Exited => |code| if (code != 0)
            return error.ExecutionAdapterFailed,
        else => return error.ExecutionAdapterTerminated,
    }
}

test "execution adapter exit status fails closed" {
    try requireSuccess(.{ .Exited = 0 });
    try std.testing.expectError(
        error.ExecutionAdapterFailed,
        requireSuccess(.{ .Exited = 7 }),
    );
    try std.testing.expectError(
        error.ExecutionAdapterTerminated,
        requireSuccess(.{ .Signal = 9 }),
    );
}
