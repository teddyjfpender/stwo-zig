//! Rung R8b (design §8.2): the Zig leaf into the Zig tree, end to end.
//!
//! R8 wraps a test program under the leaf prover's registry and R9 folds the
//! Rust-made golden leaf; neither covers the leaf the recursive tree actually
//! consumes. This rung does. Upstream's `test_golden_four_leaves_e2e`
//! (`crates/stwo_run_and_prove_recursive_tree/src/tests.rs`,
//! https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230) runs `leaf_prover` on the leaf
//! simple bootloader executing one `simple_output` task with output
//! `[11, 13, 17]`, under the recursive-tree test registry, and folds four
//! copies of the result into the `four_leaves` goldens. Here:
//!
//! 1. the Zig lane proves the same execution (adapted by the upstream
//!    adapter, `vectors/circuit/r10/leaf_simple_bootloader.prover_input.json`)
//!    as a leaf Cairo proof and wraps it: root, circuit hash and proof must
//!    equal `four_leaves/leaf.json`;
//! 2. the `LeafInput` is assembled as upstream's backend does, from the
//!    bootloader's hashed-output preimage dump (`leaf_preimage.json`, hex
//!    felts re-encoded as decimal strings), and must equal `leaf.json` byte
//!    for byte;
//! 3. four copies of that Zig-made leaf fold to `root.proof`,
//!    `root_outputs.json` and `root_packed.json` byte for byte.
//!
//! Labelled large: a 2^23-row leaf circuit proof, then three 2^23-row
//! multiverifier proofs and the root (R8 and R9 together).

const std = @import("std");
const app = @import("app");
const prover = @import("stwo_prover_engine");
/// The provers under test: the CPU here, the Metal ones in `circuit_metal`'s
/// device R8b.
const under_test = @import("circuit_provers_under_test");

const wire = app.wire;
const goldens_dir = "vectors/circuit/official/recursive_tree/four_leaves";
const registry_path = "vectors/circuit/official/registries/recursive_tree_test.json";

test "R8b: a Zig leaf of the leaf simple bootloader folds to the four_leaves goldens" {
    const gpa = std.heap.smp_allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // 1. The leaf: Zig Cairo proof and wrap.
    const leaf_json = blk: {
        // The test runner has no process-global pool; the product CLI does.
        // Scope this pool to the leaf so foldTree can own its own pool later.
        var pool: prover.work_pool.WorkPool = undefined;
        try pool.initInPlace();
        defer pool.deinit();
        var binding = try prover.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        var timings = app.Timings{};
        var leaf = try app.leafWrap(gpa, .{
            .registry_path = registry_path,
            .program_path = "vectors/circuit/official/programs/leaf_simple_bootloader_compiled.json",
            .prover_input_path = "vectors/circuit/r10/leaf_simple_bootloader.prover_input.json",
            .options = .{ .compact_polynomial_min_log = 18 },
            .provers = under_test.provers,
        }, &timings);
        defer leaf.deinit();
        std.debug.print("R8b ({s}): cairo prove {d} ms, wrap {d} ms\n", .{ under_test.backend_name, timings.cairo_prove_ns / std.time.ns_per_ms, timings.wrap_ns / std.time.ns_per_ms });
        var written = std.Io.Writer.Allocating.init(arena);
        try leaf.writeJson(&written.writer);
        break :blk written.written();
    };
    const zig_leaf = try wire.leaf_proof_json.parseSerializedLeafProof(arena, leaf_json);

    const golden_text = try std.fs.cwd().readFileAlloc(arena, goldens_dir ++ "/leaf.json", 16 << 20);
    const golden = try wire.leaf_proof_json.parseLeafInput(arena, golden_text);
    try std.testing.expect(zig_leaf.value.circuit_preprocessed_root.eql(golden.value.proof.circuit_preprocessed_root));
    try std.testing.expect(zig_leaf.value.circuit_hash.eql(golden.value.proof.circuit_hash));
    try expectBytes("leaf proof", golden.value.proof.proof, zig_leaf.value.proof);

    // 2. The `LeafInput`, as the backend assembles it.
    const leaf_input: wire.leaf_proof_json.LeafInput = .{
        .proof = zig_leaf.value,
        .output_preimage = try decimalPreimage(arena, goldens_dir ++ "/leaf_preimage.json"),
    };
    var leaf_input_json = std.Io.Writer.Allocating.init(arena);
    try wire.leaf_proof_json.writeLeafInput(&leaf_input_json.writer, leaf_input);
    try expectBytes("leaf.json", golden_text, leaf_input_json.written());

    // 3. Four Zig leaves to the root.
    const registry = try wire.registry.parseRegistry(arena, try std.fs.cwd().readFileAlloc(arena, registry_path, 1 << 20));
    const leaves = [_]wire.leaf_proof_json.LeafInput{leaf_input} ** 4;
    var fold_timer = try std.time.Timer.start();
    var root = try app.foldTreeWith(gpa, registry.registry, &leaves, under_test.provers);
    std.debug.print("R8b ({s}): fold four leaves {d} ms\n", .{ under_test.backend_name, fold_timer.read() / std.time.ns_per_ms });
    defer root.deinit();
    try std.testing.expectEqual(@as(usize, 3), root.stats.n_pair_reductions);
    inline for (.{ .{ "root.proof", "proof" }, .{ "root_outputs.json", "outputs" }, .{ "root_packed.json", "packed_tree" } }) |pair| {
        const expected = try std.fs.cwd().readFileAlloc(arena, goldens_dir ++ "/" ++ pair[0], 8 << 20);
        try expectBytes(pair[0], expected, @field(root, pair[1]).written());
    }
}

/// `generate_leaf`'s preimage: the dump's `0x` hex felts as decimal strings
/// (`BigUint::parse_bytes(.., 16).to_string()`).
fn decimalPreimage(arena: std.mem.Allocator, path: []const u8) ![]const []const u8 {
    const text = try std.fs.cwd().readFileAlloc(arena, path, 1 << 20);
    const parsed = try std.json.parseFromSliceLeaky([]const []const u8, arena, text, .{});
    const out = try arena.alloc([]const u8, parsed.len);
    for (parsed, out) |hex, *decimal| {
        if (!std.mem.startsWith(u8, hex, "0x")) return error.InvalidPreimage;
        const value = try std.fmt.parseInt(u256, hex[2..], 16);
        decimal.* = try std.fmt.allocPrint(arena, "{d}", .{value});
    }
    return out;
}

fn expectBytes(label: []const u8, expected: []const u8, actual: []const u8) !void {
    if (std.mem.indexOfDiff(u8, expected, actual)) |offset| {
        std.debug.print("R8b {s}: {d} bytes, expected {d}; first difference at byte {d}\n", .{ label, actual.len, expected.len, offset });
        return error.TestExpectedEqual;
    }
}
