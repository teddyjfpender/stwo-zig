//! Durable diagnostic SHIFT/table/U16 proof; no CPU, register or RAM acceptance claim.
const std = @import("std");
const core = @import("stwo_core");
const Profile = @import("word16/fixture_profile.zig");
const F = @import("word16/shift_word_packed_fixture.zig");

pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 3) return error.ExpectedProduceOrVerifyAndDirectory;
    try std.fs.cwd().makePath(args[2]);
    var dir = try std.fs.cwd().openDir(args[2], .{});
    defer dir.close();
    if (std.mem.eql(u8, args[1], "produce")) {
        var recorder = Profile.Recorder.initWithOptions(a, "cpu-simd16", "rv64_word16_shift_packed_fixture_main", .{ .capture_tasks = false, .capture_work = false });
        defer recorder.deinit();
        const encoded = try F.produceWithRecorder(a, .none, &recorder);
        defer a.free(encoded.bytes);
        try dir.writeFile(.{ .sub_path = "proof.bin", .data = encoded.bytes });
        const claims = try std.json.Stringify.valueAlloc(a, encoded.claims, .{});
        defer a.free(claims);
        try dir.writeFile(.{ .sub_path = "claims.json", .data = claims });
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(encoded.bytes, &digest, .{});
        const receipt = .{
            .scope = "diagnostic-public-io-packed-word16-shift-table-u16-one-pcs",
            .proof_bytes = encoded.bytes.len,
            .proof_sha256 = std.fmt.bytesToHex(digest, .lower),
            .queries = 70,
            .pow_bits = 26,
            .log_blowup = 1,
            .nominal_config_bits = 96,
            .source_cells = 5379040,
            .source_bytes = 21516160,
            .trace_oods_masks = 265,
            .shift = .{ .log = 5, .fixed = 2, .main = 53, .interaction = 48 },
            .shift_table = .{ .log = 16, .fixed = 18, .main = 16, .interaction = 36 },
            .public_consumer = .{ .log = 5, .fixed = 34, .main = 14, .interaction = 8 },
            .u16 = .{ .log = 16, .fixed = 3, .main = 1, .interaction = 8 },
            .positive_function_mass = 7,
            .shift_mass_including_padding = 160,
            .range_mass_including_padding = 288,
            .max_degree = 3,
            .quotient_factor = 2,
            .cpu_bound = false,
            .ram_bound = false,
        };
        const json = try std.json.Stringify.valueAlloc(a, receipt, .{});
        defer a.free(json);
        try dir.writeFile(.{ .sub_path = "producer.json", .data = json });
        var stages = try recorder.snapshot(a);
        defer stages.deinit(a);
        const stage_json = try std.json.Stringify.valueAlloc(a, stages, .{});
        defer a.free(stage_json);
        try dir.writeFile(.{ .sub_path = "stages.json", .data = stage_json });
    } else if (std.mem.eql(u8, args[1], "verify")) {
        const bytes = try dir.readFileAlloc(a, "proof.bin", 32 * 1024 * 1024);
        defer a.free(bytes);
        const json = try dir.readFileAlloc(a, "claims.json", 65536);
        defer a.free(json);
        const claims = try std.json.parseFromSlice([6]core.fields.qm31.QM31, a, json, .{});
        defer claims.deinit();
        try F.verify(a, .{ .bytes = bytes, .claims = claims.value }, false);
        try dir.writeFile(.{ .sub_path = "receiver.json", .data = "{\"accepted\":true,\"independently_expected_roster_and_fixed_root\":true,\"cpu_bound\":false,\"ram_bound\":false}\n" });
    } else return error.ExpectedProduceOrVerifyAndDirectory;
}
