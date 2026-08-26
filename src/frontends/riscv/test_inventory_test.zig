//! The gate on `test_inventory.zig`: a test-bearing file this package forgets to
//! name there is compiled into nothing, and nothing else would say so.
//!
//! The inventory is a hand-written list because Zig's test collection needs a
//! literal `@import`, and a hand-written list of 115 paths drifts. This walks
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
