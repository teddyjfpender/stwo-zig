//! Test-only deterministic envelope mutator for fresh-process rejection gates.

const std = @import("std");
const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const support = @import("ethereum_precompile_artifact_support.zig");

const Mutation = enum { version, identity };

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    if (arguments.len != 4) return error.InvalidArguments;
    const mutation = std.meta.stringToEnum(Mutation, arguments[1]) orelse
        return error.InvalidArguments;
    const input = try artifact_io.readFileBounded(
        allocator,
        arguments[2],
        support.artifact_limits.max_artifact_bytes,
    );
    defer allocator.free(input);
    const output = try allocator.dupe(u8, input);
    defer allocator.free(output);
    switch (mutation) {
        .version => output[support.proof_artifact.HeaderOffset.version] ^= 1,
        .identity => {
            const statement_length = readHeaderU32(
                output,
                support.proof_artifact.HeaderOffset.statement_length,
            );
            const extension_length = readHeaderU32(
                output,
                support.proof_artifact.HeaderOffset.extension_length,
            );
            const identity = support.proof_artifact.header_size +
                @as(usize, statement_length) + @as(usize, extension_length);
            output[identity + 20] ^= 1;
        },
    }
    try artifact_io.publishCreateOnly(arguments[3], output);
}

fn readHeaderU32(bytes: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}
