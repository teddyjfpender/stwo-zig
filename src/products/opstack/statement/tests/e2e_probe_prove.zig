//! `test-e2e-probe` end-to-end driver (design/opstack/integration.md §6.1):
//! prove the golden ABI probe with `stwo-opstack-native`, receive it in a
//! fresh process, then require three corruptions to be rejected. Arguments:
//! RUNNER VECTORS_DIR WORK_DIR. Child processes keep stdout away from the
//! build runner's test protocol; no environment variable is read.
const std = @import("std");

const profile = "conjectured128_b2_q108_p20_fold4";
const fixed_setup_bytes = "1073741824";
const receiver_bytes = "6442450944";
const resources =
    \\{"gkr_bytes": 2147483648, "global_bytes": 1073741824, "retained_frontend_bytes": 2147483648,
    \\ "disk_bytes": 8589934592, "fixed_setup_bytes": 1073741824, "park_main": true,
    \\ "recycler_cache_bytes": 67108864, "keccak_max_log": 16, "capture_options": {"execution_workers": 0},
    \\ "schedule": {"lanes": 1, "workers_per_lane": 1, "memory_cap_bytes": 2147483648}}
    \\
;

const Run = struct { code: u8, stdout: []const u8, stderr: []const u8 };

fn run(a: std.mem.Allocator, argv: []const []const u8) !Run {
    const result = try std.process.Child.run(.{ .allocator = a, .argv = argv, .max_output_bytes = 64 << 20 });
    const code: u8 = switch (result.term) {
        .Exited => |c| c,
        else => 255,
    };
    return .{ .code = code, .stdout = result.stdout, .stderr = result.stderr };
}

fn field(v: std.json.Value, name: []const u8) !std.json.Value {
    if (v != .object) return error.ProbeManifestNotAnObject;
    return v.object.get(name) orelse error.ProbeManifestFieldMissing;
}

fn sha256Hex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn writeJson(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, value: std.json.Value) !void {
    try dir.writeFile(.{ .sub_path = name, .data = try std.json.Stringify.valueAlloc(a, value, .{}) });
}

/// The fresh receiver's report must accept the complete execution and carry
/// exactly the pinned 43-byte output (a string or a byte array).
fn checkReport(a: std.mem.Allocator, stdout: []const u8, expected: []const u8) !void {
    const report = try std.json.parseFromSliceLeaky(std.json.Value, a, stdout, .{});
    const accepted = try field(report, "accepted");
    if (accepted != .bool or !accepted.bool) return error.ProbeNotAccepted;
    const output = try field(report, "output");
    switch (output) {
        .string => |s| if (!std.mem.eql(u8, s, expected)) return error.ProbeOutputMismatch,
        .array => |items| {
            if (items.items.len != expected.len) return error.ProbeOutputMismatch;
            for (items.items, expected) |item, byte| if (item != .integer or item.integer != byte) return error.ProbeOutputMismatch;
        },
        else => return error.ProbeOutputMismatch,
    }
}

fn expectRejected(r: Run, comptime reason: ?[]const u8) !void {
    if (r.code == 0) return error.CorruptionAccepted;
    if (reason) |name| if (!std.mem.endsWith(u8, std.mem.trim(u8, r.stderr, " \r\n"), "error: " ++ name)) {
        std.debug.print("expected rejection {s}, got:\n{s}\n", .{ name, r.stderr });
        return error.UnexpectedRejection;
    };
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const args = try std.process.argsAlloc(a);
    if (args.len != 4) return error.ExpectedRunnerVectorsAndWorkDirectory;
    const cwd = std.fs.cwd();
    const runner = try cwd.realpathAlloc(a, args[1]);
    var vectors = try cwd.openDir(args[2], .{});
    defer vectors.close();
    var work = try cwd.openDir(args[3], .{});
    defer work.close();
    const root = try work.realpathAlloc(a, ".");

    const manifest = try std.json.parseFromSliceLeaky(std.json.Value, a, try vectors.readFileAlloc(a, "abi-probe.json", 1 << 20), .{});
    const request = try field(manifest, "request");
    const elf = try vectors.readFileAlloc(a, "abi-probe.elf", 1 << 20);
    const elf_sha256 = (try field(manifest, "elf_sha256")).string;
    if (!std.mem.eql(u8, &sha256Hex(elf), elf_sha256)) return error.ProbeElfPinMismatch;
    const input_hex = (try field(request, "input_hex")).string;
    const input = try a.alloc(u8, input_hex.len / 2);
    _ = try std.fmt.hexToBytes(input, input_hex);
    const input_sha256 = (try field(request, "input_sha256")).string;
    if (!std.mem.eql(u8, &sha256Hex(input), input_sha256)) return error.ProbeInputPinMismatch;
    const expected_hex = (try field(request, "expected_output")).string;
    var expected: [43]u8 = undefined;
    if (expected_hex.len != 2 * expected.len) return error.ProbeExpectedOutputLength;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);

    // Fresh, absolute inputs: the pipeline reads every path from the request.
    work.deleteTree("proof") catch {};
    try work.writeFile(.{ .sub_path = "input.bin", .data = input });
    try work.writeFile(.{ .sub_path = "resources.json", .data = resources });
    const proof = try std.fs.path.join(a, &.{ root, "proof" });
    var config = std.json.ObjectMap.init(a);
    try config.put("elf", .{ .string = try vectors.realpathAlloc(a, "abi-probe.elf") });
    try config.put("input", .{ .string = try std.fs.path.join(a, &.{ root, "input.bin" }) });
    try config.put("elf_sha256", .{ .string = elf_sha256 });
    try config.put("input_sha256", .{ .string = input_sha256 });
    try config.put("expected_output", .{ .string = expected_hex });
    try config.put("symbols", try field(manifest, "symbols"));
    try config.put("output_directory", .{ .string = proof });
    try config.put("terminal_pc", try field(request, "terminal_pc"));
    try config.put("batch_steps", .{ .integer = (1 << 20) - 1 });
    try config.put("max_steps", try field(request, "max_steps"));
    try config.put("max_batches", .{ .integer = 0 });
    try config.put("workers", .{ .integer = 1 });
    try config.put("execution_profile", try field(request, "execution_profile"));
    try writeJson(a, work, "request.json", .{ .object = config });
    const request_path = try std.fs.path.join(a, &.{ root, "request.json" });
    const resources_path = try std.fs.path.join(a, &.{ root, "resources.json" });

    const produced = try run(a, &.{ runner, "--security-profile", profile, "prove", request_path, "-", proof, "0", resources_path });
    if (produced.code != 0) {
        std.debug.print("probe production failed:\n{s}\n", .{produced.stderr});
        return error.ProbeProductionFailed;
    }
    const verify = [_][]const u8{ runner, "--security-profile", profile, "verify", request_path, proof, fixed_setup_bytes, receiver_bytes };
    const received = try run(a, &verify);
    if (received.code != 0) {
        std.debug.print("fresh receiver rejected the probe:\n{s}\n", .{received.stderr});
        return error.ProbeReceptionFailed;
    }
    try checkReport(a, received.stdout, &expected);

    // Corruption 1: one flipped proof byte breaks the bundle file binding.
    var bundle = try work.openDir("proof", .{});
    defer bundle.close();
    const cpu_proof = try bundle.readFileAlloc(a, "cpu-0.bin", 1 << 30);
    if (cpu_proof.len == 0) return error.MissingCpuProofBytes;
    const metadata = try bundle.readFileAlloc(a, "bundle.json", 64 << 20);
    const mutated = try a.dupe(u8, cpu_proof);
    mutated[mutated.len / 2] ^= 1;
    try bundle.writeFile(.{ .sub_path = "cpu-0.bin", .data = mutated });
    try expectRejected(try run(a, &verify), "WideBundleFileChanged");

    // Corruption 2: the same bytes with a rehashed manifest reach the verifier.
    const rehashed = try std.json.parseFromSliceLeaky(std.json.Value, a, metadata, .{});
    const cpus = try field(rehashed, "cpus");
    if (cpus != .array or cpus.array.items.len == 0) return error.MissingCpuProofEntry;
    if (cpus.array.items[0] != .object) return error.MissingCpuProofEntry;
    const proof_entry = cpus.array.items[0].object.getPtr("proof") orelse return error.MissingCpuProofEntry;
    if (proof_entry.* != .object) return error.MissingCpuProofEntry;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(mutated, &digest, .{});
    var digest_items = std.json.Array.init(a);
    for (digest) |byte| try digest_items.append(.{ .integer = byte });
    try proof_entry.object.put("sha256", .{ .array = digest_items });
    try writeJson(a, bundle, "bundle.json", rehashed);
    try expectRejected(try run(a, &verify), "RootMismatch");
    try bundle.writeFile(.{ .sub_path = "cpu-0.bin", .data = cpu_proof });
    try bundle.writeFile(.{ .sub_path = "bundle.json", .data = metadata });

    // Corruption 3: an intact proof does not bind a different statement.
    var wrong = expected;
    wrong[0] ^= 1;
    const wrong_hex = std.fmt.bytesToHex(wrong, .lower);
    try config.put("expected_output", .{ .string = &wrong_hex });
    try writeJson(a, work, "request-wrong-output.json", .{ .object = config });
    const wrong_request = try std.fs.path.join(a, &.{ root, "request-wrong-output.json" });
    try expectRejected(try run(a, &.{ runner, "--security-profile", profile, "verify", wrong_request, proof, fixed_setup_bytes, receiver_bytes }), null);

    // The restored bundle is accepted again by a fresh receiver.
    const restored = try run(a, &verify);
    if (restored.code != 0) return error.RestoredProbeRejected;
    try checkReport(a, restored.stdout, &expected);
    std.debug.print("opstack abi probe: proved, freshly received, 3/3 corruptions rejected\n", .{});
}
