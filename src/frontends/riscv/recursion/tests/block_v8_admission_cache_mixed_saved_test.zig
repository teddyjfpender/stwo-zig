//! Retained 507-Keccak/66-recovery root -> independent cached admission -> fresh receiver.
//! No execution, source reproof or recursive proving. Nonterminal window only.
const std = @import("std");
const E = @import("stwo_prover_engine");
const C = @import("../../prover/block_v7_real_window_capture_v1.zig");
const Cache = @import("../block_v8_window_root_admission_cache_v1.zig");
const Upper = @import("../block_v8_window_root_receiver_v1.zig");
const Parent = @import("../blake3_execution_parent_proof.zig");
const Profile = @import("../block_v8_window_root_profile_v1.zig");
const Span = @import("../block_v8_window_root_statement_v1.zig").WindowSpan;
const Wire = @import("../block_v8_window_root_wire_v1.zig");
const Metadata = @import("../../prover/block_v8_endpoint_mixed_statement_wire_v1.zig");
const source = "vectors/reports/block-v7-real-window-corpus-20261029/source/";
const assembly = "vectors/reports/riscv-cpu-architecture-20261029/full-block-assembly-v1/";
const root_dir = assembly ++ "retained-139m-native4m-workers16-v1/proof/";
fn digest(text: []const u8) ![32]u8 {
    var out: [32]u8 = undefined;
    if (text.len != 64) return error.InvalidMixedCacheFixturePin;
    _ = try std.fmt.hexToBytes(&out, text);
    return out;
}
fn pinned(a: std.mem.Allocator, path: []const u8, pin: []const u8, maximum: usize) ![]u8 {
    const bytes = try std.fs.cwd().readFileAlloc(a, path, maximum);
    errdefer a.free(bytes);
    if (!std.meta.eql(C.sha(bytes), try digest(pin))) return error.UntrustedMixedCacheFixtureBytes;
    return bytes;
}
test "actual saved 507 Keccak 66 recovery root verifies cached mixed admission then fresh uncached receiver" {
    if (std.posix.getenv("STWO_B8_CACHE_MIXED_SAVED_ENABLE") == null) return error.SkipZigTest;
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 48 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: E.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const elf = try pinned(a, source ++ "guest.elf", "ef68fdca9e627a4969e64aa97119f52f2d9c9d6b6e8d5cbbeb541fb93dab0688", 32 << 20);
    defer a.free(elf);
    const private_input = try pinned(a, source ++ "input.bin", "737368031bfec21aa2bd557a3a71d2cbf253ec730199f7ec4c3bccd628df8e82", 4 << 20);
    defer a.free(private_input);
    const expected_output = try pinned(a, source ++ "expected-output.bin", "730396807814bc71f14405b3ecf27237778a5359732001b32c93692c3275a8c5", 43);
    defer a.free(expected_output);
    if (expected_output.len != 43) return error.InvalidMixedCacheFixtureOutput;
    const incoming_bytes = try pinned(a, assembly ++ "execution/checkpoints/state-24641536.b7win", "0e04ab9d1d5a640550febe122a9720503004e2adefb5138890dbe9e5dc1e3cd0", 256 << 20);
    defer a.free(incoming_bytes);
    const outgoing_bytes = try pinned(a, assembly ++ "execution/checkpoints/state-25690112.b7win", "e6d2b38785e219e98e5b75020a5b0c5dd023c6b9b1ff062014104962851e90ea", 256 << 20);
    defer a.free(outgoing_bytes);
    const incoming_id = try digest("c5451c86f85cc67fd88ee516aa66e976dac7db97453ac17b577545ad617abeab");
    const outgoing_id = try digest("daa921b1f758dfd6adea30e2a542dd5f278926c5d78bec3528df1609a441c4d7");
    var incoming = try C.Snapshot.decode(a, incoming_bytes, incoming_id, .{});
    defer incoming.deinit(a);
    var outgoing = try C.Snapshot.decode(a, outgoing_bytes, outgoing_id, .{});
    defer outgoing.deinit(a);
    const config = @import("../blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    const external = Upper.External{ .elf = elf, .incoming = incoming, .outgoing = outgoing, .trusted = .{ .elf_sha256 = C.sha(elf), .incoming_sha256 = incoming_id, .outgoing_sha256 = outgoing_id, .window = .{ .skip_cycles = 24641536, .cycles = 1048576 } }, .config = config };
    const root_bytes = try pinned(a, root_dir ++ "node-4.proof", "6bef94cdb26866099f863c7b0212d0934c8b7a81c9c6729519c478598b68235c", 16 << 20);
    defer a.free(root_bytes);
    const metadata_bytes = try pinned(a, root_dir ++ "node-4.public", "a20cd8a65b11e898caf46c7ca93f8f12fb59adf7e74b1f4be7f953c99f2116f5", 16 << 20);
    defer a.free(metadata_bytes);
    var leaf = try Wire.decodeMixedLeafOwned(a, metadata_bytes, .{});
    defer leaf.deinit();
    try std.testing.expect(leaf.value.global_g_repartition and leaf.value.input.global_g_repartition);
    try std.testing.expectEqual(@as(usize, 0), leaf.value.input.root.len);
    const decoded_metadata = try Metadata.decode(a, leaf.value.input.mixed_metadata, .{ .elf = elf, .elf_sha256 = C.sha(elf), .profile = .rv32im_zkvm_ethereum_sha_v1, .config = config, .cohort_count = 1 }, .{});
    defer decoded_metadata.deinit();
    try std.testing.expectEqual(@as(u32, 507), decoded_metadata.input.caller_statement.ethereum.counts.keccak_calls);
    try std.testing.expectEqual(@as(u32, 66), decoded_metadata.input.caller_statement.ethereum.counts.signer_calls);
    try std.testing.expectEqual(@as(u32, 0), decoded_metadata.input.caller_statement.sha.call_count);
    const tree = Upper.Tree{ .mixed_leaf = .{ .external = external, .input = leaf.value.input, .main_root = leaf.value.main_root, .global_g_repartition = leaf.value.global_g_repartition } };
    const frozen = try Cache.Frozen.clone(a, .{ .elf = elf, .private_input = private_input, .trusted = .{ .elf_sha256 = C.sha(elf), .input_sha256 = C.sha(private_input), .total_cycles = 139214856, .expected_output = expected_output[0..43].*, .config = config } }, &.{tree}, .{});
    const cache = Cache.Cache.create(a, frozen) catch |err| {
        frozen.deinit();
        return err;
    };
    frozen.deinit();
    var cache_live = true;
    defer if (cache_live) cache.deinit();
    const handle = try cache.root(0);
    const profile = try cache.profile(handle);
    var artifact = try Parent.codec.decode(a, root_bytes, &profile.admission);
    var verified = try Parent.verify(&artifact, &profile.admission);
    const capture = Profile.Capture.borrow(&verified);
    profile.requireCapture(&capture) catch |err| {
        verified.deinit();
        return err;
    };
    verified.deinit();
    const changed = try a.dupe(u8, root_bytes);
    defer a.free(changed);
    changed[12] ^= 1;
    try std.testing.expectError(error.UntrustedBlake3ParentKey, Parent.codec.decode(a, changed, &profile.admission));
    var wrong_handle = handle;
    wrong_handle.descriptor_id[0] ^= 1;
    try std.testing.expectError(error.MutatedAdmissionCacheEntry, cache.profile(wrong_handle));
    const stats = cache.stats();
    try std.testing.expectEqual(@as(usize, 1), stats.independent_derivations);
    cache.deinit();
    cache_live = false;
    // Actual pinned subset, not a full-block/initial/terminal statement.
    const expected = Span{ .elf_sha256 = C.sha(elf), .config = config, .first_cycle = 24641537, .cycles = 1048576, .incoming_snapshot_id = incoming_id, .outgoing_snapshot_id = outgoing_id, .initial_cpu = incoming.cpu, .final_cpu = outgoing.cpu };
    var fresh = try Upper.verify(a, root_bytes, tree, expected);
    fresh.deinit();
    std.debug.print("B8_CACHE_MIXED_SAVED keccak=507 recovery=66 cycles=1048576 global_g_repartition=true source_execution_count=0 source_proofs=0 parent_proofs=0 cached_mixed_verified=true final_uncached_window_receiver=true full_block=false retained_profile_peak_bytes={d} key_derivation_peak_bytes={d}\n", .{ stats.retained_profile_peak_bytes, stats.key_derivation_peak_bytes });
}
