//! Optional Apple-Silicon CUDA portability and execution evidence.

const std = @import("std");

const audit_script = "scripts/cuda_cumetal_audit.py";
const ledger = "conformance/cuda-cumetal-compatibility-v1.json";
const native_root = "src/backends/cuda/native";
const execution_harness = "tests/cuda/cumetal/powers_execution.cu";

pub const Options = struct {
    compiler: ?[]const u8,
    root: ?[]const u8,
    inspect: ?[]const u8,
    validate: ?[]const u8,
};

pub fn addStep(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    options: Options,
) void {
    const check = addCommand(b, .check, null, null, null, null, false);
    b.step(
        "cuda-cumetal-ledger",
        "Validate the complete checked CuMetal compatibility ledger",
    ).dependOn(&check.step);

    const floor_step = b.step(
        "cuda-cumetal-portability",
        "Translate the maintained positive CUDA floor with pinned CuMetal",
    );
    const audit_step = b.step(
        "cuda-cumetal-audit",
        "Ratchet all CUDA statuses and run exact Apple-GPU differential evidence",
    );
    const compiler = options.compiler orelse {
        const message =
            "CuMetal steps require -Dcuda-cumetalc=/absolute/path/to/cumetalc";
        floor_step.dependOn(&b.addFail(message).step);
        audit_step.dependOn(&b.addFail(message).step);
        return;
    };
    if (target.result.os.tag != .macos) {
        const message = "CuMetal development evidence requires macOS";
        floor_step.dependOn(&b.addFail(message).step);
        audit_step.dependOn(&b.addFail(message).step);
        return;
    }
    const root = options.root orelse {
        const message =
            "CuMetal steps require -Dcuda-cumetal-root=/absolute/path/to/cuda-metal";
        floor_step.dependOn(&b.addFail(message).step);
        audit_step.dependOn(&b.addFail(message).step);
        return;
    };
    const inspect = options.inspect;
    const validate = options.validate;
    const floor = addCommand(
        b,
        .floor,
        compiler,
        root,
        inspect,
        validate,
        false,
    );
    floor.step.dependOn(&check.step);
    floor_step.dependOn(&floor.step);
    const audit = addCommand(
        b,
        .audit,
        compiler,
        root,
        inspect,
        validate,
        true,
    );
    audit.step.dependOn(&check.step);
    audit_step.dependOn(&audit.step);
}

const Mode = enum { check, floor, audit };

fn addCommand(
    b: *std.Build,
    mode: Mode,
    compiler: ?[]const u8,
    root: ?[]const u8,
    inspect: ?[]const u8,
    validate: ?[]const u8,
    execute: bool,
) *std.Build.Step.Run {
    const command = b.addSystemCommand(&.{"python3"});
    command.addFileArg(b.path(audit_script));
    command.addArgs(&.{ "--mode", @tagName(mode), "--ledger" });
    command.addFileArg(b.path(ledger));
    command.addFileInput(b.path(execution_harness));
    addDirectoryInputs(b, command, native_root);
    if (compiler) |path| {
        command.addArg("--compiler");
        command.addFileArg(.{ .cwd_relative = path });
    }
    if (root) |path| {
        command.addArg("--cumetal-root");
        command.addDirectoryArg(.{ .cwd_relative = path });
    }
    if (inspect) |path| {
        command.addArg("--air-inspect");
        command.addFileArg(.{ .cwd_relative = path });
    }
    if (validate) |path| {
        command.addArg("--air-validate");
        command.addFileArg(.{ .cwd_relative = path });
    }
    if (execute) command.addArg("--execute");
    command.addArg("--receipt");
    _ = command.addOutputFileArg(b.fmt(
        "cuda-cumetal-{s}-receipt.json",
        .{@tagName(mode)},
    ));
    return command;
}

fn addDirectoryInputs(
    b: *std.Build,
    command: *std.Build.Step.Run,
    relative_root: []const u8,
) void {
    var directory = b.build_root.handle.openDir(
        relative_root,
        .{ .iterate = true },
    ) catch |err| std.debug.panic(
        "cannot open CuMetal input directory {s}: {s}",
        .{ relative_root, @errorName(err) },
    );
    defer directory.close();
    var walker = directory.walk(b.allocator) catch @panic("OOM");
    defer walker.deinit();
    while (walker.next() catch @panic("cannot enumerate CuMetal inputs")) |entry| {
        if (entry.kind != .file) continue;
        command.addFileInput(b.path(b.pathJoin(&.{
            relative_root,
            entry.path,
        })));
    }
}
