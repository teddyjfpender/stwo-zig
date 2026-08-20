//! Output, timing, and reproducibility helpers for the RISC-V benchmark.

const std = @import("std");
const stage_profile = @import("stwo_prover_api").stage_profile;
const pcs_core = @import("stwo_core").pcs;
const Sha256 = std.crypto.hash.sha2.Sha256;

const PROOF_IDENTITY_FLAG = "--proof-identity";
const POW24_Q70_PCS_CONFIG = pcs_core.PcsConfig{
    .pow_bits = 24,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 70,
    },
};

pub fn isProofIdentityFlag(arg: []const u8) bool {
    return std.mem.eql(u8, arg, PROOF_IDENTITY_FLAG);
}

pub fn printUsage(secure: pcs_core.PcsConfig) !void {
    return writeUsage(std.fs.File.stderr().deprecatedWriter(), secure);
}

/// The profile parameters are formatted from the constants themselves, so the
/// help text cannot describe a profile the flags no longer select.
pub fn writeUsage(writer: anytype, secure: pcs_core.PcsConfig) !void {
    try writer.print(
        \\Usage: riscv-bench [options]
        \\
        \\  --fib-n N         Prove a generated fib(N) guest (default: 10000)
        \\  --elf PATH        Prove an RV32IM ELF instead of the generated guest
        \\  --input PATH      Load bytes into the ELF's linker-defined input region
        \\  --input-u32 N     Pass one little-endian u32 to the guest
        \\  --max-steps N     Execution limit for --elf (default: 10000000)
        \\  --hosted          Enable host-call support
        \\  --hint PATH       Host hint input
        \\  --pow-bits N      Proof-of-work bits (default: 0)
        \\  --n-queries N     FRI query count (default: 3)
        \\  --pow24-q70       Older stark-v comparison config (pow_bits={d}, n_queries={d})
        \\  --secure          The published SECURE_PCS_CONFIG (pow_bits={d}, n_queries={d})
        \\  --run-only        Execute the guest without proving
        \\  --profile         Print stage timings and raw task-graph records
        \\  --proof-identity  Correctness-only: print canonical proof byte count and SHA-256
        \\  -h, --help        Show this help
        \\
    , .{
        POW24_Q70_PCS_CONFIG.pow_bits,
        POW24_Q70_PCS_CONFIG.fri_config.n_queries,
        secure.pow_bits,
        secure.fri_config.n_queries,
    });
}

pub const ProofIdentity = struct {
    canonical_bytes: usize,
    sha256: [std.crypto.hash.sha2.Sha256.digest_length]u8,

    pub fn fromCanonicalBytes(canonical_proof: []const u8) ProofIdentity {
        var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(canonical_proof, &digest, .{});
        return .{ .canonical_bytes = canonical_proof.len, .sha256 = digest };
    }
};

pub fn writeProofIdentity(writer: anytype, identity: ProofIdentity) !void {
    const digest_hex = std.fmt.bytesToHex(identity.sha256, .lower);
    try writer.print(
        "Proof identity: canonical_bytes={d} sha256={s}\n",
        .{ identity.canonical_bytes, &digest_hex },
    );
}

pub fn printProfileNodes(nodes: []const stage_profile.StageNode, depth: usize) void {
    for (nodes) |node| {
        for (0..depth) |_| std.debug.print("  ", .{});
        std.debug.print("{s}: {d:.3}s\n", .{ node.id, node.seconds });
        if (node.children) |children| printProfileNodes(children, depth + 1);
    }
}

pub fn nanosecondsToMilliseconds(nanoseconds: u64) f64 {
    return @as(f64, @floatFromInt(nanoseconds)) / std.time.ns_per_ms;
}

pub fn checkedTimingSum(values: [4]u64) !u64 {
    var total: u64 = 0;
    for (values) |value| total = std.math.add(u64, total, value) catch
        return error.BenchmarkClockOverflow;
    return total;
}

pub fn hashSelfExecutable() ![Sha256.digest_length]u8 {
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fs.selfExePath(&path_buffer);
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const before = try file.stat();
    if (before.kind != .file or before.size == 0)
        return error.InvalidBenchmarkExecutable;

    var hash = Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var measured: u64 = 0;
    while (true) {
        const count = try file.read(&buffer);
        if (count == 0) break;
        hash.update(buffer[0..count]);
        measured = std.math.add(u64, measured, count) catch
            return error.InvalidBenchmarkExecutable;
    }
    const after = try file.stat();
    if (measured != before.size or before.size != after.size or
        before.inode != after.inode or before.mtime != after.mtime)
    {
        return error.BenchmarkExecutableChangedDuringMeasurement;
    }
    return hash.finalResult();
}

pub fn runtimeWorkloadDigest(
    elf: []const u8,
    input: []const u8,
    hints: []const u8,
    hosted: bool,
) [Sha256.digest_length]u8 {
    var hash = Sha256.init(.{});
    hash.update("stwo-zig/riscv-bench/runtime-workload/v1\x00");
    hashBytes(&hash, elf);
    hashBytes(&hash, input);
    hashBytes(&hash, hints);
    hashInt(&hash, u8, @intFromBool(hosted));
    return hash.finalResult();
}

pub fn runtimeProtocolDigest(
    config: pcs_core.PcsConfig,
    witness_layout_digest: [Sha256.digest_length]u8,
) [Sha256.digest_length]u8 {
    var hash = Sha256.init(.{});
    hash.update("stwo-zig/riscv-bench/runtime-protocol/v1\x00");
    hashInt(&hash, u32, config.pow_bits);
    hashInt(&hash, u32, config.fri_config.log_blowup_factor);
    hashInt(&hash, u32, config.fri_config.log_last_layer_degree_bound);
    hashInt(&hash, u64, config.fri_config.n_queries);
    hashInt(&hash, u32, config.fri_config.fold_step);
    if (config.lifting_log_size) |lifting| {
        hashInt(&hash, u8, 1);
        hashInt(&hash, u32, lifting);
    } else {
        hashInt(&hash, u8, 0);
    }
    hash.update(&witness_layout_digest);
    return hash.finalResult();
}

pub fn hashBytes(hash: *Sha256, bytes: []const u8) void {
    hashInt(hash, u64, bytes.len);
    hash.update(bytes);
}

pub fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    const encoded: T = std.math.cast(T, value) orelse unreachable;
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, encoded, .little);
    hash.update(&bytes);
}
