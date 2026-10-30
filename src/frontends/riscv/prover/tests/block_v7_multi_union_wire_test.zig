//! Fresh-process saved proof receiver. JSON is a typed fixture importer; ELF,
//! execution/output and security are selected independently of artifact fields.
const std = @import("std");
const Multi = @import("../block_v7_multi_union_proof_v1.zig");
const Receiver = @import("../block_v7_execution_receiver_v1.zig");
const Guest = @import("block_v7_scaling_guest_test_support.zig");
const Check = @import("block_v7_multi_union_wire_test_support.zig");
test "v7 multi union saved bounded artifact verifies with independent policy" {
    const a = std.testing.allocator;
    const path = std.posix.getenv("STWO_V7_MULTI_UNION_RELOAD_DIR") orelse "vectors/reports/block-v7-active-caller-v3-20261029/two-windows";
    const iterations = if (std.posix.getenv("STWO_V7_MULTI_UNION_RELOAD_ITERATIONS")) |raw| try std.fmt.parseInt(u32, raw, 10) else 4096;
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    const elf = try dir.readFileAlloc(a, "guest.elf", 1 << 20);
    defer a.free(elf);
    const code = try Guest.instructions(iterations);
    const expected_elf = Guest.releaseElf(&code);
    try std.testing.expectEqualSlices(u8, &expected_elf, elf);
    const hash = @import("../block_v5_initial_sources_v1.zig").sha256(&expected_elf);
    var initial = try @import("../block_v7_initial_intervals_v1.zig").Owned.derive(a, elf, hash, .rv32im_zkvm_ethereum_sha_v1, .{});
    defer initial.deinit();
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    const trusted = Receiver.Trusted{ .elf = elf, .elf_sha256 = hash, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = config, .terminal = .{ .final_cycle = try Guest.cycles(iterations), .halt_address = initial.info.halt_flag, .length_address = initial.info.output_len, .data_address = initial.info.output_data, .output_end = initial.info.output_end, .output = try Guest.output(iterations) } };
    const json = try dir.readFileAlloc(a, "public-metadata.json", 16 << 20);
    defer a.free(json);
    const Metadata = struct { version: u32, tag: u32, input: Multi.Input };
    var parsed = try std.json.parseFromSlice(Metadata, a, json, .{ .allocate = .alloc_always });
    defer parsed.deinit();
    try std.testing.expectEqual(Multi.VERSION, parsed.value.version);
    try std.testing.expectEqual(Multi.TAG, parsed.value.tag);
    const raw = try dir.readFileAlloc(a, "proof.b7mun", 128 << 20);
    defer a.free(raw);
    const limits: Multi.Limits = .{ .max_retained_pcs_bytes = 8 << 30, .max_windows = 16, .max_trace_trees = 128 };
    const result = try Check.check(a, raw, trusted, parsed.value.input, limits);
    try std.testing.expectEqual(try Guest.cycles(iterations), result.cycles);
    try std.testing.expectEqualDeep(try Guest.output(iterations), result.output);
    var wrong = trusted;
    wrong.terminal.output[0] ^= 1;
    const Codec = @import("../block_v7_multi_union_codec_v1.zig");
    if (Codec.verifyBytes(a, raw, wrong, parsed.value.input, .{ .scope = limits })) |_| return error.AcceptedWrongMultiUnionOutput else |err| if (err == error.OutOfMemory) return err;
    std.debug.print("V7_MULTI_UNION_FRESH_PROCESS cycles={d} windows={d} canonical_q70_pow26=true producer_present=false\n", .{ result.cycles, result.segments });
}
