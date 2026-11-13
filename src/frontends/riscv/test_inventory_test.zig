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
const inventories = [_]struct { prefix: []const u8, module: []const u8, source: []const u8 }{
    .{ .prefix = "", .module = "stwo_riscv_frontend", .source = @embedFile("test_inventory.zig") },
    .{ .prefix = "air_lang", .module = "stwo_riscv_air_lang", .source = @import("stwo_riscv_air_lang").testing.inventory_source },
    .{ .prefix = "isa", .module = "stwo_riscv_isa", .source = @import("stwo_riscv_isa").testing.inventory_source },
    .{ .prefix = "memory", .module = "stwo_riscv_memory", .source = @import("stwo_riscv_memory").testing.inventory_source },
    .{ .prefix = "precompiles", .module = "stwo_riscv_precompiles", .source = @import("stwo_riscv_precompiles").testing.inventory_source },
    .{ .prefix = "recursion", .module = "stwo_riscv_recursion", .source = @import("stwo_riscv_recursion").testing.inventory_source },
    .{ .prefix = "recursion_air", .module = "stwo_riscv_recursion_air", .source = @import("stwo_riscv_recursion_air").testing.inventory_source },
    .{ .prefix = "rv32", .module = "stwo_riscv_rv32", .source = @import("stwo_riscv_rv32").testing.inventory_source },
    .{ .prefix = "rv64", .module = "stwo_riscv_rv64", .source = @import("stwo_riscv_rv64").testing.inventory_source },
    .{ .prefix = "testing", .module = "stwo_riscv_testing", .source = @import("stwo_riscv_testing").testing.inventory_source },
};

/// Files that hold tests and are deliberately absent from the inventory.
const excluded = [_]struct { path: []const u8, why: []const u8 }{
    .{ .path = "testing/cases/air/lang/tests/typed_base_alu_imm_witness_performance_test.zig", .why = "unchanged comparative timing contract, collected by non-blocking test-typed-witness-benchmarks (#330/#346)" },
    .{ .path = "testing/cases/air/lang/tests/typed_base_alu_reg_witness_performance_test.zig", .why = "unchanged comparative timing contract, collected by non-blocking test-typed-witness-benchmarks (#330/#346)" },
    .{ .path = "testing/cases/air/lang/tests/typed_mulh_witness_performance_test.zig", .why = "unchanged comparative timing contract, collected by non-blocking test-typed-witness-benchmarks (#330/#346)" },
    .{ .path = "testing/cases/air/lang/tests/typed_shifts_reg_witness_performance_test.zig", .why = "unchanged comparative timing contract, collected by non-blocking test-typed-witness-benchmarks (#330/#346)" },
    .{ .path = "compat/benchmarks/typed_legacy_benchmark_registration_test.zig", .why = "unchanged comparative timing contract, collected by non-blocking test-typed-witness-benchmarks (#330/#346)" },
    .{ .path = "focused_legacy_benchmarks_test_root.zig", .why = "unchanged comparative timing contract, collected by non-blocking test-typed-witness-benchmarks (#330/#346)" },
    .{ .path = "testing/focused_test_typed_witness_benchmarks_0.zig", .why = "owner-directed non-blocking typed witness benchmark, collected by test-typed-witness-benchmarks (#330)" },
    .{ .path = "testing/cases/air/lang/tests/typed_branch_eq_witness_performance_test.zig", .why = "owner-directed non-blocking typed witness benchmark, collected by test-typed-witness-benchmarks (#330)" },
    .{ .path = "testing/cases/air/lang/tests/typed_branch_lt_witness_performance_test.zig", .why = "owner-directed non-blocking typed witness benchmark, collected by test-typed-witness-benchmarks (#330)" },
    .{ .path = "testing/cases/air/lang/tests/typed_div_witness_performance_test.zig", .why = "owner-directed non-blocking typed witness benchmark, collected by test-typed-witness-benchmarks (#330)" },
    .{ .path = "testing/cases/air/lang/tests/typed_fence_witness_performance_test.zig", .why = "owner-directed non-blocking typed witness benchmark, collected by test-typed-witness-benchmarks (#330)" },
    .{ .path = "testing/cases/air/lang/tests/typed_load_store_witness_performance_test.zig", .why = "owner-directed non-blocking typed witness benchmark, collected by test-typed-witness-benchmarks (#330)" },
    .{ .path = "testing/cases/air/lang/tests/typed_lt_imm_witness_performance_test.zig", .why = "owner-directed non-blocking typed witness benchmark, collected by test-typed-witness-benchmarks (#330)" },
    .{ .path = "testing/cases/air/lang/tests/typed_lt_reg_witness_performance_test.zig", .why = "owner-directed non-blocking typed witness benchmark, collected by test-typed-witness-benchmarks (#330)" },
    .{ .path = "testing/cases/air/lang/tests/typed_shifts_imm_witness_performance_test.zig", .why = "owner-directed non-blocking typed witness benchmark, collected by test-typed-witness-benchmarks (#330)" },
    .{
        .path = "testing/cases/recursion_poseidon_degree3_test_root.zig",
        .why = "backend-neutral semantic root, also consumed by scripts/recursive_poseidon_degree3_proof.py",
    },
    .{
        .path = "testing/focused_poseidon_merkle_test_root.zig",
        .why = "focused complete Poseidon Merkle scalar/SIMD parity root, run by test-poseidon-merkle",
    },
    .{
        .path = "memory/focused_test_poseidon_merkle_0_1.zig",
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
        .path = "rv32/refinement_ir_export_test.zig",
        .why = "demands RISCV_AIR_IR_DIR; driven by the riscv-refinement-ir step, " ++
            "which is the only caller that sets it",
    },
    .{
        .path = "rv32/refinement_program_export_test.zig",
        .why = "demands RISCV_AIR_PROGRAM_IR_DIR; driven by the riscv-refinement-ir " ++
            "step, which supplies a fresh output directory",
    },
    .{
        .path = "build.zig",
        .why = "BUILD-only constructor contracts, executed by default and test-build-components",
    },
    .{
        .path = "testing/cases/r012_universal_adapter_test_root.zig",
        .why = "explicit focused evidence root; its tests are collected through the canonical root",
    },
    .{
        .path = "testing/focused_test_recursion_vm_composition_0.zig",
        .why = "compile-isolated row-18 VM composition edit root",
    },
    .{
        .path = "recursion/focused_test_recursion_vm_composition_0.zig",
        .why = "compile-isolated row-18 VM composition edit root",
    },
    .{
        .path = "rv32/focused_test_semantic_component_0.zig",
        .why = "explicit semantic-component prepared-domain edit root",
    },
    .{
        .path = "testing/cases/r012_fri_circuit_test_root.zig",
        .why = "temporary focused R-012 circuit evidence root",
    },
    .{
        .path = "rv32/focused_test_recursion_composition_recorder_0.zig",
        .why = "temporary focused R-012 composition evidence root",
    },
    .{
        .path = "testing/focused_test_recursion_composition_recorder_0.zig",
        .why = "temporary focused R-012 composition evidence root",
    },
    .{
        .path = "testing/cases/recursion_air_r012_dev_test_root.zig",
        .why = "temporary focused R-012 development root",
    },
    .{
        .path = "testing/cases/transcript_binding_test_root.zig",
        .why = "temporary focused row-2 development root",
    },
    .{
        .path = "recursion/focused_test_recursion_pair_node_0.zig",
        .why = "focused pair-node evidence root; its tests are collected through the canonical root",
    },
    .{
        .path = "testing/cases/shifts_imm_private_test_root.zig",
        .why = "focused private-cutover evidence root",
    },
    .{
        .path = "testing/cases/shifts_reg_private_test_root.zig",
        .why = "focused private-cutover evidence root",
    },
    .{
        .path = "testing/focused_load_store_private_test_root.zig",
        .why = "focused private-cutover evidence root",
    },
    .{
        .path = "testing/focused_test_load_store_private_0_1.zig",
        .why = "focused private-cutover evidence root",
    },
    .{
        .path = "rv32/focused_test_load_store_private_0_2.zig",
        .why = "focused private-cutover evidence root",
    },
    .{
        .path = "testing/cases/lt_reg_private_test_root.zig",
        .why = "focused private-cutover evidence root",
    },
    .{
        .path = "testing/cases/mul_private_test_root.zig",
        .why = "focused private-cutover evidence root",
    },
    .{
        .path = "testing/cases/mulh_private_test_root.zig",
        .why = "focused private-cutover evidence root",
    },
    .{
        .path = "testing/cases/div_private_test_root.zig",
        .why = "focused private-cutover evidence root",
    },
    .{
        .path = "testing/focused_test_hash_component_prepared_0.zig",
        .why = "focused prepared hash-component evidence root",
    },
    .{
        .path = "rv32/focused_test_lookup_source_ingest_0.zig",
        .why = "focused lookup source-ingest evidence root",
    },
    .{
        .path = "testing/focused_test_lookup_source_ingest_0.zig",
        .why = "focused lookup source-ingest evidence root",
    },
    .{
        .path = "rv32/focused_test_lookup_table_framework_export_0.zig",
        .why = "focused lookup-table interaction evidence root",
    },
    .{
        .path = "focused_test_lookup_table_framework_export_0.zig",
        .why = "focused lookup-table interaction evidence root",
    },
    .{
        .path = "rv32/focused_test_lookup_table_interaction_0.zig",
        .why = "focused lookup-table interaction evidence root",
    },
    .{
        .path = "focused_test_lookup_table_interaction_0.zig",
        .why = "focused lookup-table interaction evidence root",
    },
    .{
        .path = "rv32/focused_test_opcode_interaction_0.zig",
        .why = "focused opcode-interaction evidence root",
    },
    .{
        .path = "testing/focused_test_opcode_interaction_0.zig",
        .why = "focused opcode-interaction evidence root",
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

        var inventory = inventories[0];
        for (inventories[1..]) |candidate| {
            if (std.mem.startsWith(u8, entry.path, candidate.prefix) and
                entry.path.len > candidate.prefix.len and entry.path[candidate.prefix.len] == '/')
            {
                inventory = candidate;
                break;
            }
        }
        const relative = if (inventory.prefix.len == 0) entry.path else entry.path[inventory.prefix.len + 1 ..];
        if (inventory.prefix.len != 0 and (std.mem.eql(u8, relative, "mod.zig") or std.mem.eql(u8, relative, "tests/root.zig"))) continue;
        const quoted = try std.fmt.allocPrint(allocator, "\"{s}{s}\"", .{ if (inventory.prefix.len == 0 or std.mem.startsWith(u8, relative, "tests/")) "" else "../", if (inventory.prefix.len != 0 and std.mem.startsWith(u8, relative, "tests/")) relative[6..] else relative });
        defer allocator.free(quoted);
        if (std.mem.indexOf(u8, inventory.source, quoted) != null) {
            named += 1;
            continue;
        }
        if (inventory.prefix.len != 0 and std.mem.startsWith(u8, relative, "focused") and
            std.fs.path.dirname(relative) == null and try @import("test_inventory_collector.zig").coveredCollector(allocator, source, inventory.source)) continue;
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
    for (inventories) |inventory| {
        if (inventory.prefix.len != 0) {
            const parent_link = try std.fmt.allocPrint(allocator, "_ = @import(\"{s}\");", .{inventory.module});
            defer allocator.free(parent_link);
            try std.testing.expect(std.mem.indexOf(u8, inventories[0].source, parent_link) != null);
            const module_path = try std.fmt.allocPrint(allocator, "{s}/mod.zig", .{inventory.prefix});
            defer allocator.free(module_path);
            const module_source = try root.readFileAlloc(allocator, module_path, 1 << 21);
            defer allocator.free(module_source);
            try std.testing.expect(std.mem.indexOf(u8, module_source, "_ = @import(\"tests/root.zig\");") != null);
        }
        var lines = std.mem.tokenizeAny(u8, inventory.source, "\r\n");
        while (lines.next()) |line| {
            const code = std.mem.trimLeft(u8, line, " \t");
            if (std.mem.startsWith(u8, code, "//")) continue;
            const needle = "_ = @import(\"";
            const hit = std.mem.indexOf(u8, code, needle) orelse continue;
            const start = hit + needle.len;
            const end = std.mem.indexOfScalarPos(u8, code, start, '"') orelse
                return error.UnterminatedInventoryPath;
            const literal = code[start..end];
            if (!std.mem.endsWith(u8, literal, ".zig")) {
                var admitted = false;
                for (inventories[1..]) |candidate| admitted = admitted or std.mem.eql(u8, literal, candidate.module);
                try std.testing.expect(inventory.prefix.len == 0 and admitted);
                continue;
            }
            const path = if (inventory.prefix.len == 0) try allocator.dupe(u8, literal) else try std.fmt.allocPrint(allocator, "{s}/tests/{s}", .{ inventory.prefix, literal });
            defer allocator.free(path);
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
    }
    try std.testing.expect(listed > 100);
}
