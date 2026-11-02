//! Native hash work and source-cell model. Never reports proving speedups.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const ram = frontend.rv64_air.memory.commitment;
const provider = frontend.testing.component_proof.universal_air;
const hash_proof = @import("rv64_ram_hash_proof.zig");

fn cellTree(page: *const ram.Page) !ram.Digest {
    var frontier: [ram.PAGE_CELLS]ram.Digest = undefined;
    for (&frontier, page) |*digest, cell| digest.* = try cell.digest();
    var width: usize = ram.PAGE_CELLS;
    var height: u6 = 0;
    while (width > 1) : (height += 1) {
        for (0..width / 2) |i| frontier[i] = try ram.hash(height, frontier[2 * i], frontier[2 * i + 1]);
        width /= 2;
    }
    return frontier[0];
}

pub fn main() !void {
    const a = std.heap.smp_allocator;
    var page: ram.Page = undefined;
    for (&page, 0..) |*cell, i| cell.* = .{ .value = @as(u64, i) *% 0x1234_5678_9abc_def1, .permissions = 0x6db6db };
    var timer = try std.time.Timer.start();
    const reference = try ram.hashPage(&page, null);
    const tree_reference = try cellTree(&page);
    var flat: [9]u64 = undefined;
    var tree: [9]u64 = undefined;
    // Alternating order reduces systematic temperature/order bias. Hashes are
    // checked every round, so complete work remains observable to the optimizer.
    for (0..flat.len) |i| {
        if (i % 2 == 0) {
            timer.reset();
            const digest = try ram.hashPage(&page, null);
            flat[i] = timer.read();
            if (!ram.equal(digest, reference)) return error.HashMismatch;
            timer.reset();
            const other = try cellTree(&page);
            tree[i] = timer.read();
            if (!ram.equal(other, tree_reference)) return error.HashMismatch;
        } else {
            timer.reset();
            const other = try cellTree(&page);
            tree[i] = timer.read();
            if (!ram.equal(other, tree_reference)) return error.HashMismatch;
            timer.reset();
            const digest = try ram.hashPage(&page, null);
            flat[i] = timer.read();
            if (!ram.equal(digest, reference)) return error.HashMismatch;
        }
    }
    var sorted_flat = flat;
    var sorted_tree = tree;
    std.mem.sort(u64, &sorted_flat, {}, std.sort.asc(u64));
    std.mem.sort(u64, &sorted_tree, {}, std.sort.asc(u64));
    var memory = frontend.rv64.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = 0x1000, .size = 4096, .permissions = .{ .read = true, .write = true } });
    for (page, 0..) |cell, i| try memory.store(0x1000 + @as(u64, @intCast(i)) * 8, 8, cell.value);
    var witness = try frontend.rv64_air.memory.transition.Witness.build(a, &memory, &.{1}, &.{.{ .address = 0x1000, .value = 17, .byte_mask = 255 }});
    defer witness.deinit();
    timer.reset();
    const encoded = try hash_proof.prove(a, &witness);
    defer a.free(encoded);
    const produce_ns = timer.read();
    timer.reset();
    try hash_proof.verify(a, &witness, witness.before, witness.after, &.{1}, &.{.{ .address = 0x1000, .value = 17, .byte_mask = 255 }}, encoded);
    const verify_ns = timer.read();
    const proof_calls = std.mem.readInt(u32, encoded[4..8], .little);
    var proof_sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &proof_sha, .{});
    const report = .{
        .schema = "rv64-ram-native-cost-v1",
        .build_mode = @tagName(@import("builtin").mode),
        .full_execution_proof_claim = false,
        .scope = "One dense 4KiB page; alternating native hashes only. Different proposed commitment formats; not a proof comparison.",
        .page_bytes = 4096,
        .flat_page_permutations = ram.PAGE_PERMUTATIONS,
        .cell_tree_permutations = (ram.PAGE_CELLS - 1) * ram.node.CALLS,
        .unshared_page_path_permutations = ram.PAGE_DEPTH * ram.node.CALLS,
        .flat_ns = flat,
        .cell_tree_ns = tree,
        .flat_median_ns = sorted_flat[4],
        .cell_tree_median_ns = sorted_tree[4],
        .flat_digest = reference,
        .provider_main_columns = provider.N_MAIN_COLUMNS,
        .provider_interaction_columns = provider.N_INTERACTION_COLUMNS,
        .provider_identity = std.fmt.bytesToHex(provider.IDENTITY_DIGEST, .lower),
        .unrounded_page_provider_source_bytes = ram.PAGE_PERMUTATIONS * (provider.N_MAIN_COLUMNS + provider.N_INTERACTION_COLUMNS) * 4,
        .diagnostic_public_ledger_bytes_per_page = ram.PAGE_PERMUTATIONS * 64,
        .diagnostic_hash_stark = .{
            .public_page_count = 1,
            .changed_page_count = 1,
            .permutations = proof_calls,
            .provider_padded_rows = @as(u64, 1) << @intCast(std.math.log2_int_ceil(u32, proof_calls)),
            .provider_source_bytes = (@as(u64, 1) << @intCast(std.math.log2_int_ceil(u32, proof_calls))) * (1 + provider.N_MAIN_COLUMNS + provider.N_INTERACTION_COLUMNS) * 4,
            .artifact_bytes = encoded.len,
            .artifact_excludes_public_page_and_sibling_context = true,
            .permutation_ledger_bytes = @as(u64, proof_calls) * 64,
            .produce_ns = produce_ns,
            .fresh_verify_ns = verify_ns,
            .verified = true,
            .artifact_sha256 = std.fmt.bytesToHex(proof_sha, .lower),
            .pow_bits = 0,
            .fri_queries = 10,
            .security_admitted = false,
            .cpu_ram_relation = false,
            .private_caller_air = false,
        },
        .limits = "Page-only model excludes before/after and global multiproof work, padding and PCS/FRI. diagnostic_hash_stark includes its provider PCS/FRI, but excludes public page/sibling serialization, private caller AIR, CPU RAM relation, initialization authority and terminal output. No production continuation admission.",
    };
    const json = try std.json.Stringify.valueAlloc(a, report, .{ .whitespace = .indent_2 });
    defer a.free(json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}
