//! Interop CLI process lifecycle and mode dispatch.

const std = @import("std");
const stwo = @import("root").stwo;
const artifact = @import("artifact.zig");
const bench = @import("bench.zig");
const cli_mod = @import("cli.zig");

const blake2_hash = stwo.core.vcs.blake2_hash;
const parseArgs = cli_mod.parseArgs;
const printUsage = cli_mod.printUsage;
const runBench = bench.runBench;
const runGenerate = artifact.runGenerate;
const runVerify = artifact.runVerify;
const runVerifyStdShims = artifact.runVerifyStdShims;

pub fn main() !void {
    const gpa = std.heap.c_allocator;

    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);

    const cli = parseArgs(args) catch |err| {
        printUsage();
        return err;
    };
    if (cli.stage_profile_out != null and cli.mode != .generate) {
        return error.UnsupportedStageProfileMode;
    }
    blake2_hash.setDefaultBackendMode(cli.blake2_backend);

    switch (cli.mode) {
        .generate => try runGenerate(gpa, cli),
        .verify => try runVerify(gpa, cli),
        .verify_std_shims => try runVerifyStdShims(gpa, cli),
        .bench => try runBench(gpa, cli),
    }
}
