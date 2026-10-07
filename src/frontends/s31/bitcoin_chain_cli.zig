//! Standalone native verifier and key/statement writer for Bitcoin folds.
const std = @import("std");
const chain = @import("bitcoin_chain_verifier.zig");

fn expectedDigest(hex: []const u8) ![32]u8 {
    if (hex.len != 64) return error.InvalidKeyDigestHex;
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, hex) catch return error.InvalidKeyDigestHex;
    if (!std.mem.eql(u8, hex, &std.fmt.bytesToHex(digest, .lower))) return error.InvalidKeyDigestHex;
    return digest;
}

fn writeFile(path: []const u8, bytes: []const u8) !void {
    try std.fs.cwd().makePath(std.fs.path.dirname(path) orelse ".");
    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = bytes });
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const args = try std.process.argsAlloc(allocator);
    if (args.len < 2) return error.ExpectedCommand;
    if (std.mem.eql(u8, args[1], "keygen")) {
        if (args.len != 5) return error.ExpectedCheckpointMaxStepAndKeyPath;
        const max_step = try std.fmt.parseInt(u32, args[3], 10);
        const key_bytes = try chain.generateKeyJson(allocator, args[2], max_step);
        try writeFile(args[4], key_bytes);
        std.debug.print("Bitcoin chain key: path={s} sha256={s}\n", .{
            args[4], &std.fmt.bytesToHex(chain.sha256(key_bytes), .lower),
        });
        return;
    }
    if (std.mem.eql(u8, args[1], "statement")) {
        if (args.len != 8) return error.ExpectedKeyDigestStepHashTimesAndOutput;
        const key_bytes = try std.fs.cwd().readFileAlloc(allocator, args[2], 8192);
        const key = try chain.validateKey(allocator, key_bytes, try expectedDigest(args[3]));
        const step = try std.fmt.parseInt(u32, args[4], 10);
        const times_bytes = try std.fs.cwd().readFileAlloc(allocator, args[6], 8192);
        const parsed_times = try std.json.parseFromSlice([11]u32, allocator, times_bytes, .{ .ignore_unknown_fields = false });
        const encoded = try chain.generateStatementJson(allocator, key, step, args[5], parsed_times.value);
        try writeFile(args[7], encoded);
        std.debug.print("Bitcoin chain statement: step={d} path={s}\n", .{ step, args[7] });
        return;
    }
    if (std.mem.eql(u8, args[1], "verify")) {
        if (args.len != 6) return error.ExpectedKeyDigestStatementAndProof;
        const key_bytes = try std.fs.cwd().readFileAlloc(allocator, args[2], 8192);
        const key = try chain.validateKey(allocator, key_bytes, try expectedDigest(args[3]));
        const statement_bytes = try std.fs.cwd().readFileAlloc(allocator, args[4], 8192);
        const proof_bytes = try std.fs.cwd().readFileAlloc(allocator, args[5], 16 << 20);
        try chain.verifyProof(allocator, key, statement_bytes, proof_bytes);
        std.debug.print("Bitcoin chain proof accepted: statement={s} proof={s}\n", .{ args[4], args[5] });
        return;
    }
    return error.UnknownCommand;
}
