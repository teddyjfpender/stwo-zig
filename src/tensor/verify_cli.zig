//! tensor-verify: verifies a tensor proof from files (wire.zig format).
//!
//!   tensor-verify <dir>                       reads <dir>/statement.bin, key.bin, proof.bin
//!   tensor-verify <statement> <key> <proof>   explicit paths
//!
//! `tensor-bench ... --emit <dir>` writes the three files. The statement file
//! carries the statement and the verifier config; its Blake2s digest is
//! printed so a client can pin the statement it expects. The key file holds
//! the weight key and its one-time key proof (range + proximity), verified
//! first. Prints one JSON line; exits 1 (with the error name) on rejection.
const std = @import("std");
const t = @import("stwo_tensor");
const wire = t.wire;
const proto = t.protocol;

fn now() std.time.Instant {
    return std.time.Instant.now() catch unreachable;
}
fn since(t0: std.time.Instant) f64 {
    return @as(f64, @floatFromInt(now().since(t0))) / 1e9;
}

fn readFile(a: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.fs.cwd().readFileAlloc(a, path, wire.MAX_FILE_BYTES);
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const a = gpa.allocator();
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    var paths: [3][]const u8 = undefined;
    var owned: [3]?[]u8 = .{ null, null, null };
    defer for (owned) |o| if (o) |p| a.free(p);
    if (args.len == 2) {
        for ([_][]const u8{ "statement.bin", "key.bin", "proof.bin" }, 0..) |name, i| {
            owned[i] = try std.fs.path.join(a, &.{ args[1], name });
            paths[i] = owned[i].?;
        }
    } else if (args.len == 4) {
        for (0..3) |i| paths[i] = args[i + 1];
    } else {
        std.debug.print("usage: tensor-verify <dir> | tensor-verify <statement.bin> <key.bin> <proof.bin>\n", .{});
        std.process.exit(2);
    }
    const out = std.fs.File.stdout().deprecatedWriter();
    run(a, paths, out) catch |e| {
        try out.print("{{\"ok\":false,\"error\":\"{s}\"}}\n", .{@errorName(e)});
        std.process.exit(1);
    };
}

fn run(a: std.mem.Allocator, paths: [3][]const u8, out: anytype) !void {
    const sb = try readFile(a, paths[0]);
    defer a.free(sb);
    const kb = try readFile(a, paths[1]);
    defer a.free(kb);
    const pb = try readFile(a, paths[2]);
    defer a.free(pb);
    var digest: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(sb, &digest, .{});

    var t0 = now();
    var sf = try wire.decodeStatement(a, sb);
    defer sf.deinit();
    var kf = try wire.decodeKey(a, kb, sf.cfg, sf.st);
    defer kf.deinit();
    const key_decode_s = since(t0);
    t0 = now();
    try t.weight_key.verify(a, sf.cfg, kf.key, &kf.proof);
    const key_verify_s = since(t0);

    t0 = now();
    var caps = try wire.proofCaps(a, sf.cfg, sf.st, kf.key);
    defer caps.deinit(a);
    var pf = try wire.decodeProof(a, pb, caps);
    defer pf.deinit();
    const decode_s = since(t0);
    t0 = now();
    try proto.verify(a, sf.cfg, sf.st, kf.key, &pf.proof);
    const verify_s = since(t0);
    // a non-custom level: the statement's own account must reach the target
    t0 = now();
    var rep = try t.security.accountProof(a, sf.cfg, sf.st, kf.key, &pf.proof, &kf.proof);
    defer rep.deinit();
    try t.security.checkLevel(rep, sf.cfg.security);
    const level_check_s = since(t0);

    try out.print("{{\"ok\":true,\"statement_digest\":\"{s}\",\"statement_bytes\":{d},\"key_bytes\":{d},\"proof_bytes\":{d},", .{ std.fmt.bytesToHex(digest, .lower), sb.len, kb.len, pb.len });
    // the level and field the proof was checked at: the statement's header
    // sets them, so a client that does not pin statement_digest must check
    // these (a custom-level statement accepts a custom-level proof)
    try out.print("\"security_level\":\"{s}\",\"challenge_degree\":{d},\"level_target_bits\":{d:.0},\"bits_all_rounds_without_work\":{d:.2},\"level_check_s\":{d:.5},", .{ sf.cfg.security.name(), t.field.CHALLENGE_DEGREE, sf.cfg.security.targetBits(), rep.total.summary().sum_without, level_check_s });
    try out.print("\"witness_tensors\":{d},\"weights\":{d},\"ops\":{d},\"ext_ops\":{d},", .{ sf.st.witness.len, sf.st.weights.len, sf.st.ops.len, sf.st.ext.ops.len });
    if (sf.cfg.two_level) |tl| {
        try out.print("\"pcs\":\"pcs2\",\"depth\":{d},\"conjectured_bits\":{d:.1},\"query_bits_unique\":{d:.1},", .{ tl.depth, tl.conjecturedBits(), tl.provenBits() });
    } else {
        try out.print("\"pcs\":\"flat\",\"conjectured_bits\":{d:.1},\"query_bits_unique\":{d:.1},", .{ sf.cfg.pcs.conjecturedBits(), sf.cfg.pcs.provenBits() });
    }
    try out.print("\"key_decode_s\":{d:.5},\"key_verify_s\":{d:.5},\"proof_decode_s\":{d:.5},\"verify_s\":{d:.5}}}\n", .{ key_decode_s, key_verify_s, decode_s, verify_s });
}
