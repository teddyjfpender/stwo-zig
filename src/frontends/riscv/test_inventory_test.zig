//! The gate on `test_inventory.zig`: a test-bearing file this package forgets to
//! name there is compiled into nothing, and nothing else would say so.
//!
//! The inventory is a hand-written list because Zig's test collection needs a
//! literal `@import`, and a hand-written path list drifts. This walks
//! the package tree instead of trusting it. A test count floor catches tests
//! *dropped* from a binary; this catches tests that were never in one, which is
//! the failure that hid 142 of them.
//!
//! Fails closed. A run that cannot find the package directory reports that
//! rather than passing, because "the checker could not look" and "there is
//! nothing to find" are the two answers this repository has most often confused.

const std = @import("std");

/// The inventory's own text, embedded so the membership check needs no working
/// directory even though the tree walk does.
const INVENTORY = @embedFile("test_inventory.zig");

/// Files that hold tests and are deliberately absent from the inventory.
const excluded = [_]struct { path: []const u8, why: []const u8 }{
    .{
        .path = "recursion_poseidon_degree3_test_root.zig",
        .why = "backend-neutral semantic root, also consumed by scripts/recursive_poseidon_degree3_proof.py",
    },
    .{
        .path = "poseidon_merkle_test_root.zig",
        .why = "focused complete Poseidon Merkle scalar/SIMD parity root, run by test-poseidon-merkle",
    },
    .{
        .path = "mod.zig",
        .why = "the module root; the compiler always collects the root file's tests",
    },
    .{
        .path = "test_inventory.zig",
        .why = "the inventory itself, imported by mod.zig",
    },
    .{
        .path = "test_inventory_test.zig",
        .why = "this file, imported by mod.zig",
    },
    .{
        .path = "refinement_ir_export_test.zig",
        .why = "demands RISCV_AIR_IR_DIR; driven by the riscv-refinement-ir step, " ++
            "which is the only caller that sets it",
    },
    .{
        .path = "refinement_program_export_test.zig",
        .why = "demands RISCV_AIR_PROGRAM_IR_DIR; driven by the riscv-refinement-ir " ++
            "step, which supplies a fresh output directory",
    },
    .{
        .path = "build.zig",
        .why = "this package's build script, not part of the module",
    },
    .{
        .path = "r012_universal_adapter_test_root.zig",
        .why = "explicit focused evidence root; its tests are collected through the canonical root",
    },
    .{
        .path = "recursion_air_core_test_root.zig",
        .why = "explicit production-decoupled recursion edit root",
    },
    .{
        .path = "recursion_vm_composition_test_root.zig",
        .why = "compile-isolated row-18 VM composition edit root",
    },
    .{
        .path = "semantic_component_test_root.zig",
        .why = "explicit semantic-component prepared-domain edit root",
    },
    .{
        .path = "r012_fri_circuit_test_root.zig",
        .why = "temporary focused R-012 circuit evidence root",
    },
    .{
        .path = "recursion_air_r012_composition_circuit_dev_test_root.zig",
        .why = "temporary focused R-012 composition evidence root",
    },
    .{
        .path = "recursion_air_r012_dev_test_root.zig",
        .why = "temporary focused R-012 development root",
    },
    .{
        .path = "transcript_word_dev_test_root.zig",
        .why = "temporary focused row-4 development root",
    },
    .{
        .path = "transcript_binding_test_root.zig",
        .why = "temporary focused row-2 development root",
    },
    .{
        .path = "transcript_state_test_root.zig",
        .why = "temporary focused row-3 development root",
    },
    .{
        .path = "vm_public_claim_hash_test_root.zig",
        .why = "focused row-13 development root; its tests are collected through the canonical root",
    },
    .{
        .path = "vm_public_io_hash_test_root.zig",
        .why = "focused row-14 development root; its tests are collected through the canonical root",
    },
    .{
        .path = "pair_node_test_root.zig",
        .why = "focused pair-node evidence root; its tests are collected through the canonical root",
    },
    .{
        .path = "shifts_imm_private_test_root.zig",
        .why = "focused private-cutover evidence root",
    },
    .{
        .path = "shifts_reg_private_test_root.zig",
        .why = "focused private-cutover evidence root",
    },
    .{
        .path = "load_store_private_test_root.zig",
        .why = "focused private-cutover evidence root",
    },
    .{
        .path = "lt_reg_private_test_root.zig",
        .why = "focused private-cutover evidence root",
    },
    .{
        .path = "mul_private_test_root.zig",
        .why = "focused private-cutover evidence root",
    },
    .{
        .path = "mulh_private_test_root.zig",
        .why = "focused private-cutover evidence root",
    },
    .{
        .path = "div_private_test_root.zig",
        .why = "focused private-cutover evidence root",
    },
    .{
        .path = "hash_component_prepared_test_root.zig",
        .why = "focused prepared hash-component evidence root",
    },
    .{
        .path = "lookup_source_ingest_test_root.zig",
        .why = "focused lookup source-ingest evidence root",
    },
    .{
        .path = "lookup_table_interaction_test_root.zig",
        .why = "focused lookup-table interaction evidence root",
    },
    .{
        .path = "opcode_interaction_test_root.zig",
        .why = "focused opcode-interaction evidence root",
    },
    // The frontend package module does not import `stwo_cpu_backend`, so a
    // test that names it cannot compile under this package's test root. These
    // run only from a focused root whose import table carries the CPU backend.
    .{
        .path = "air/block/memory_component_receipt_test.zig",
        .why = "names stwo_cpu_backend; block-v2 receipt root block_memory_receipt_test_root.zig",
    },
    .{
        .path = "compact_commitment_test_root.zig",
        .why = "names stwo_cpu_backend; focused compact-commitment evidence root",
    },
    .{
        .path = "prover/blake3_native_prepared_template_test_root.zig",
        .why = "names stwo_cpu_backend; focused BLAKE3 prepared-template evidence root",
    },
    .{
        .path = "prover/block_memory_proof_v2.zig",
        .why = "names stwo_cpu_backend in its tests; paused block-v2 root block_memory_proof_test_root.zig",
    },
    .{
        .path = "prover/block_memory_shared_instance_proof_v2.zig",
        .why = "names stwo_cpu_backend in its tests; paused block-v2 shared-instance proof",
    },
    .{
        .path = "prover/block_memory_shared_table_proof_v2.zig",
        .why = "names stwo_cpu_backend in its tests; paused block-v2 shared-table proof",
    },
    .{
        .path = "prover/tests/blake3_paired_memory_test.zig",
        .why = "names stwo_cpu_backend; focused root blake3_paired_memory_test_root.zig",
    },
    .{
        .path = "prover/tests/blake3_partial_input_test.zig",
        .why = "names stwo_cpu_backend; focused root blake3_partial_input_test_root.zig",
    },
    .{
        .path = "recursion/air/tests/blake3_pcs_capture_test.zig",
        .why = "names stwo_cpu_backend; BLAKE3 PCS capture proof evidence",
    },
    .{
        .path = "recursion/air/tests/readonly_consistency_test.zig",
        .why = "proves on blake3_proof_fixture.Cpu (stwo_cpu_backend) through blake3_proof_gate_test_support",
    },
    .{
        .path = "air/block/memory_global_closure_test.zig",
        .why = "proves through prover/block_memory_proof_v2.zig, which names stwo_cpu_backend",
    },
    .{
        .path = "recursion/air/tests/blake3_fri_group_test.zig",
        .why = "proves through blake3_pcs_capture_test.roundtrip, which names stwo_cpu_backend",
    },
    // Real-proof gates on `blake3_proof_gate_test_support.runFor`, which proves
    // on `blake3_proof_fixture.Cpu` (stwo_cpu_backend).
    .{
        .path = "prover/tests/block_rw_initial_joint_proof_v2_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "air/guest_precompile/tests/sha256_compression_proof_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "air/guest_precompile/tests/sha256_memory_proof_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "recursion/air/tests/blake3_bounded_draw_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "recursion/air/tests/blake3_challenge_committed_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "recursion/air/tests/blake3_field_bytes_proof_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "recursion/air/tests/blake3_lifted_path_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "recursion/air/tests/blake3_memory_path_proof_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "recursion/air/tests/blake3_memory_update_chain_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "recursion/air/tests/blake3_memory_update_proof_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "recursion/air/tests/blake3_merkle_path_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "recursion/air/tests/blake3_private_committed_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "recursion/air/tests/blake3_private_draw_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "recursion/air/tests/blake3_public_subtree_proof_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "recursion/air/tests/blake3_query_path_proof_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "recursion/air/tests/blake3_query_proof_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "recursion/air/tests/blake3_retry_control_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "recursion/air/tests/blake3_routed_node_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "recursion/air/tests/blake3_routed_transcript_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "recursion/air/tests/blake3_span_identity_proof_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "recursion/air/tests/blake3_transcript_sequence_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "recursion/air/tests/blake3_transcript_transition_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "recursion/air/tests/blake3_two_level_frontier_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "recursion/air/tests/blake3_wide_committed_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "recursion/air/tests/blake3_committed_test.zig",
        .why = "CPU real-proof gate through blake3_proof_gate_test_support",
    },
    .{
        .path = "sha256_batch_test_root.zig",
        .why = "focused root over the CPU real-proof SHA-256 compression gate",
    },
};

/// Where this package's sources sit, relative to the test's working directory.
///
/// Both spellings are real: the product gate runs from the repository root and
/// the package's own `zig build test --build-file src/frontends/riscv/build.zig`
/// does too, while running that build file from inside the package directory
/// gives the second. A directory only counts as this package when it holds both
/// the contract and the inventory, so a partial match cannot be mistaken for a
/// hit.
const candidate_roots = [_][]const u8{ "src/frontends/riscv", "." };

fn openPackageRoot() !std.fs.Dir {
    for (candidate_roots) |candidate| {
        var dir = std.fs.cwd().openDir(candidate, .{ .iterate = true }) catch continue;
        const claimed = blk: {
            dir.access("package.contract.json", .{}) catch break :blk false;
            dir.access("test_inventory.zig", .{}) catch break :blk false;
            break :blk true;
        };
        if (claimed) return dir;
        dir.close();
    }
    std.debug.print(
        "the RISC-V frontend package directory is not reachable from the test working " ++
            "directory; tried {s} and {s}\n",
        .{ candidate_roots[0], candidate_roots[1] },
    );
    return error.PackageRootUnreachable;
}

/// True when `source` declares at least one `test` block. Matched on
/// line-leading `test` followed by `{` or `"`, which is how every test in this
/// package is written, including the ones nested inside a generic container.
fn declaresTests(source: []const u8) bool {
    var lines = std.mem.tokenizeAny(u8, source, "\r\n");
    while (lines.next()) |line| {
        const trimmed = std.mem.trimLeft(u8, line, " \t");
        if (!std.mem.startsWith(u8, trimmed, "test")) continue;
        const rest = std.mem.trimLeft(u8, trimmed["test".len..], " ");
        if (rest.len == 0) continue;
        if (rest[0] == '{' or rest[0] == '"') return true;
    }
    return false;
}

fn isExcluded(path: []const u8) bool {
    for (excluded) |entry| {
        if (std.mem.eql(u8, entry.path, path)) return true;
    }
    return false;
}

test "test inventory: every test-bearing file in this package is named" {
    const allocator = std.testing.allocator;
    var root = try openPackageRoot();
    defer root.close();

    var walker = try root.walk(allocator);
    defer walker.deinit();

    var missing: usize = 0;
    var named: usize = 0;
    while (try walker.next()) |entry| {
        if (entry.kind == .directory) continue;
        if (!std.mem.endsWith(u8, entry.basename, ".zig")) continue;
        // Build caches hold generated copies of these sources; they are not
        // part of the module and must not be required in the inventory.
        if (std.mem.indexOf(u8, entry.path, ".zig-cache") != null) continue;
        if (std.mem.startsWith(u8, entry.path, ".")) continue;
        if (isExcluded(entry.path)) continue;

        const source = try root.readFileAlloc(allocator, entry.path, 1 << 21);
        defer allocator.free(source);
        if (!declaresTests(source)) continue;

        const quoted = try std.fmt.allocPrint(allocator, "\"{s}\"", .{entry.path});
        defer allocator.free(quoted);
        if (std.mem.indexOf(u8, INVENTORY, quoted) != null) {
            named += 1;
            continue;
        }
        missing += 1;
        std.debug.print(
            "test_inventory.zig does not name {s}, so its tests are compiled by nothing\n",
            .{entry.path},
        );
    }
    if (missing != 0) return error.TestBearingFileNotInInventory;
    // A walk that matched nothing would report zero missing files and prove
    // nothing, which is the shape this file exists to reject.
    try std.testing.expect(named > 100);
}

test "test inventory: every path it names exists and holds tests" {
    // The other direction: a renamed or deleted file leaves an import that
    // still compiles only because Zig resolves it, so this is the pin that
    // makes the list's length mean something.
    const allocator = std.testing.allocator;
    var root = try openPackageRoot();
    defer root.close();

    var listed: usize = 0;
    // Comment lines are skipped before the scan. The doc comment above the list
    // quotes the import form it is explaining, and a scanner that cannot tell
    // prose from code pressures its author into garbling the explanation --
    // issue #152 item 10, twice over in this repository already.
    var lines = std.mem.tokenizeAny(u8, INVENTORY, "\r\n");
    while (lines.next()) |line| {
        const code = std.mem.trimLeft(u8, line, " \t");
        if (std.mem.startsWith(u8, code, "//")) continue;
        const needle = "_ = @import(\"";
        const hit = std.mem.indexOf(u8, code, needle) orelse continue;
        const start = hit + needle.len;
        const end = std.mem.indexOfScalarPos(u8, code, start, '"') orelse
            return error.UnterminatedInventoryPath;
        const path = code[start..end];
        const source = root.readFileAlloc(allocator, path, 1 << 21) catch |err| {
            std.debug.print(
                "test_inventory.zig names {s}, which is not readable: {s}\n",
                .{ path, @errorName(err) },
            );
            return error.InventoryPathMissing;
        };
        defer allocator.free(source);
        if (!declaresTests(source)) {
            std.debug.print(
                "test_inventory.zig names {s}, which declares no test\n",
                .{path},
            );
            return error.InventoryPathHasNoTests;
        }
        listed += 1;
    }
    try std.testing.expect(listed > 100);
}
