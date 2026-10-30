//! Reload the saved canonical original-STARK in a new process. JSON is a
//! test-fixture import only; trusted policy is independently rebuilt below.
const std = @import("std");
const core = @import("stwo_core");
const postcard = @import("interop_postcard");
const Union = @import("../block_v7_complete_union_proof_v1.zig");
const Codec = @import("../block_v7_complete_union_codec_v1.zig");
const Receiver = @import("../block_v7_execution_receiver_v1.zig");
const Memory = @import("../block_v7_memory_joint_air_v1.zig");
const Guest = @import("block_v7_scaling_guest_test_support.zig");
const Published = struct {
    version: u32,
    tag: u32,
    input: Union.Input,
    trusted: Receiver.Trusted,
    native: @FieldType(Union.Proof, "native"),
    access: @FieldType(Union.Proof, "access"),
    arithmetic: @FieldType(Union.Proof, "arithmetic"),
    relations: @FieldType(Union.Proof, "relations"),
    program: @FieldType(Union.Proof, "program"),
    lookup: @FieldType(Union.Proof, "lookup"),
    memory: Memory.Claims,
};
test "v7 complete union bounded wire reload and hostile framing" {
    const a = std.testing.allocator;
    const directory = std.posix.getenv("STWO_V7_UNION_RELOAD_DIR") orelse "vectors/reports/block-v7-active-caller-v3-20261029/one-window";
    var dir = try std.fs.cwd().openDir(directory, .{});
    defer dir.close();
    const elf = try dir.readFileAlloc(a, "guest.elf", 1 << 20);
    defer a.free(elf);
    var expected_hash_storage: [32]u8 = undefined;
    const expected_hash = try std.fmt.hexToBytes(&expected_hash_storage, "53be4c1452a40786acf5fafa67aa3cc3372057cfc942f6290e7f1bd68d8afa4d");
    const hash = @import("../block_v5_initial_sources_v1.zig").sha256(elf);
    try std.testing.expectEqualSlices(u8, expected_hash, &hash);
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    var initial = try @import("../block_v7_initial_intervals_v1.zig").Owned.derive(a, elf, hash, .rv32im_zkvm_ethereum_sha_v1, .{});
    defer initial.deinit();
    // Neither the JSON's trusted section nor a producer receipt selects policy.
    const trusted = Receiver.Trusted{ .elf = elf, .elf_sha256 = hash, .profile = .rv32im_zkvm_ethereum_sha_v1, .terminal = .{ .final_cycle = try Guest.cycles(4096), .halt_address = initial.info.halt_flag, .length_address = initial.info.output_len, .data_address = initial.info.output_data, .output_end = initial.info.output_end, .output = try Guest.output(4096) }, .config = config };
    const json = try dir.readFileAlloc(a, "public-metadata.json", 8 << 20);
    defer a.free(json);
    var meta = try std.json.parseFromSlice(Published, a, json, .{ .allocate = .alloc_always });
    defer meta.deinit();
    try std.testing.expectEqual(Union.VERSION, meta.value.version);
    try std.testing.expectEqual(Union.TAG, meta.value.tag);
    const raw = try dir.readFileAlloc(a, "proof.stark.postcard", 64 << 20);
    defer a.free(raw);
    // This pinned, already-qualified fixture is the encoding oracle. Public
    // artifact bytes below always pass the bounded codec before allocation.
    var stream = std.io.fixedBufferStream(raw);
    var stark = try postcard.deserializeProof(core.proof_suites.Blake3.Hasher, a, stream.reader());
    var stark_live = true;
    defer if (stark_live) stark.deinit(a);
    const proof = Union.Proof{ .stark = stark, .native = meta.value.native, .access = meta.value.access, .arithmetic = meta.value.arithmetic, .relations = meta.value.relations, .program = meta.value.program, .lookup = meta.value.lookup, .ram = @constCast(meta.value.memory.ram), .interval = meta.value.memory.interval, .range16 = meta.value.memory.range16, .terminal = meta.value.memory.terminal };
    const encoded = try Codec.encode(a, &proof, meta.value.input, .{});
    defer a.free(encoded);
    stark.deinit(a);
    stark_live = false;
    var decoded = try Codec.decode(a, encoded, trusted, meta.value.input, .{});
    defer decoded.deinit();
    const fresh = decoded.view();
    const verified = try Codec.verifyBytes(a, encoded, trusted, meta.value.input, .{});
    try std.testing.expectEqual(try Guest.cycles(4096), verified.cycles);
    try std.testing.expectEqualDeep(try Guest.output(4096), verified.output);
    const reencoded = try Codec.encode(a, &fresh, meta.value.input, .{});
    defer a.free(reencoded);
    try std.testing.expectEqualSlices(u8, encoded, reencoded);
    try std.testing.expectError(error.OutOfMemory, Codec.decode(a, encoded, trusted, meta.value.input, .{ .decode_bytes = 1 }));
    try std.testing.expectError(error.OutOfMemory, Codec.verifyBytes(a, encoded, trusted, meta.value.input, .{ .verification_bytes = 1 }));
    var explicit_lifting = trusted;
    explicit_lifting.config.lifting_log_size = 24;
    try std.testing.expectError(error.UnsupportedUnionWireLifting, Codec.decode(a, encoded, explicit_lifting, meta.value.input, .{}));
    try std.testing.expectError(error.UnionArtifactSizeLimit, Codec.decode(a, encoded, trusted, meta.value.input, .{ .artifact_bytes = Codec.HEADER_BYTES + 1, .proof_bytes = 1, .claim_bytes = 1 }));
    const altered = try a.dupe(u8, encoded);
    defer a.free(altered);
    altered[0] ^= 1;
    try std.testing.expectError(error.UntrustedUnionEnvelope, Codec.decode(a, altered, trusted, meta.value.input, .{}));
    @memcpy(altered, encoded);
    altered[8] ^= 1;
    try std.testing.expectError(error.UntrustedUnionEnvelope, Codec.decode(a, altered, trusted, meta.value.input, .{}));
    @memcpy(altered, encoded);
    altered[40] ^= 1;
    try std.testing.expectError(error.UntrustedUnionEnvelope, Codec.decode(a, altered, trusted, meta.value.input, .{}));
    @memcpy(altered, encoded);
    const claim_len = std.mem.readInt(u32, encoded[Codec.HEADER_BYTES - 12 ..][0..4], .little);
    altered[Codec.HEADER_BYTES + claim_len] ^= 1;
    try std.testing.expectError(error.InvalidProofConfig, Codec.decode(a, altered, trusted, meta.value.input, .{}));
    @memcpy(altered, encoded);
    std.mem.writeInt(u32, altered[Codec.HEADER_BYTES..][0..4], std.math.maxInt(u32), .little);
    try std.testing.expectError(error.UnionClaimCountLimit, Codec.decode(a, altered, trusted, meta.value.input, .{}));
    @memcpy(altered, encoded);
    std.mem.writeInt(u32, altered[Codec.HEADER_BYTES + 4 ..][0..4], core.fields.m31.Modulus, .little);
    try std.testing.expectError(error.NonCanonicalM31, Codec.decode(a, altered, trusted, meta.value.input, .{}));
    try std.testing.expectError(error.EndOfStream, Codec.decode(a, encoded[0 .. encoded.len - 1], trusted, meta.value.input, .{}));
    const trailer = try a.alloc(u8, encoded.len + 1);
    defer a.free(trailer);
    @memcpy(trailer[0..encoded.len], encoded);
    trailer[encoded.len] = 0;
    try std.testing.expectError(error.TrailingSectionBytes, Codec.decode(a, trailer, trusted, meta.value.input, .{}));
    if (std.posix.getenv("STWO_V7_UNION_WIRE_OUTPUT")) |path| {
        var file = try std.fs.cwd().createFile(path, .{});
        defer file.close();
        try file.writeAll(encoded);
        try file.sync();
    }
    std.debug.print("V7_COMPLETE_UNION_WIRE profile=canonical_q70_pow26 bytes={d} verified_cycles={d} decode_peak_bytes={d} independent_policy=true producers_present=false\n", .{ encoded.len, verified.cycles, decoded.budget.snapshot().peak_live_bytes });
}
