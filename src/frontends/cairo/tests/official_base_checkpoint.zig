//! Official Stwo-Cairo base-trace checkpoint admission.

const std = @import("std");
const cairo = @import("cairo_frontend");
const direct_trace = cairo.conformance.direct_trace;
const recorded_trace = cairo.conformance.recorded_trace;
const receipt = cairo.conformance.receipt;
const registry = cairo.claim_registry;
const witness_bundle = cairo.witness.bundle;

const Case = struct {
    input_path: []const u8,
    checkpoint_path: []const u8,
    component_count: usize,
    column_count: usize,
    first_component: []const u8,
    final_component: []const u8,
    final_accumulator_hex: []const u8,
};

const cases = [_]Case{
    .{
        .input_path = "vectors/cairo/official/all_opcodes.prover_input.json",
        .checkpoint_path = "vectors/cairo/official/all_opcodes.base_trace_checkpoint.json",
        .component_count = 46,
        .column_count = 1464,
        .first_component = "add_opcode",
        .final_component = "verify_bitwise_xor_9",
        .final_accumulator_hex = "45acd12a96745ee0e9fbc32b5509de84c65676eb4d2a9d2bdb5822b696fd38d6",
    },
    .{
        .input_path = "vectors/cairo/official/all_builtins.prover_input.json",
        .checkpoint_path = "vectors/cairo/official/all_builtins.base_trace_checkpoint.json",
        .component_count = 48,
        .column_count = 3332,
        .first_component = "add_opcode_small",
        .final_component = "verify_bitwise_xor_9",
        .final_accumulator_hex = "d7a654ae5c3017c1c742fe9186a38f625722adf22ce47896840c83817e1818f8",
    },
};

fn inputDigest(allocator: std.mem.Allocator, path: []const u8) ![32]u8 {
    const encoded = try std.fs.cwd().readFileAlloc(allocator, path, 2 * 1024 * 1024);
    defer allocator.free(encoded);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &digest, .{});
    return digest;
}

test "official Cairo base checkpoints authenticate the complete fixture layouts" {
    for (cases) |case| {
        var loaded = try receipt.readFile(std.testing.allocator, case.checkpoint_path, .{
            .input_sha256 = try inputDigest(std.testing.allocator, case.input_path),
            .authority = .{
                .stwo_cairo_revision = registry.source_revision.stwo_cairo,
                .stwo_revision = registry.source_revision.stwo,
            },
        });
        defer loaded.deinit();

        try std.testing.expectEqual(case.component_count, loaded.components.len);
        var column_count: usize = 0;
        for (loaded.components) |component| column_count += component.columns.len;
        try std.testing.expectEqual(case.column_count, column_count);
        try std.testing.expectEqualStrings(case.first_component, loaded.components[0].label);
        try std.testing.expectEqualStrings(
            case.final_component,
            loaded.components[loaded.components.len - 1].label,
        );
        const final_hex = std.fmt.bytesToHex(loaded.final_accumulator, .lower);
        try std.testing.expectEqualStrings(case.final_accumulator_hex, &final_hex);
    }
}

test "official Cairo witness recordings match every covered all-opcodes column" {
    try expectWitnessMatches(cases[0], 42, 21, 21);
}

test "official Cairo witness recordings match every covered all-builtins column" {
    try expectWitnessMatches(cases[1], 45, 18, 27);
}

test "official Cairo recorded graph matches the complete all-opcodes Blake chain" {
    try expectRecordedGraphMatches(cases[0], 24, 22);
}

test "official Cairo recorded graph matches supported builtin dependencies" {
    try expectRecordedGraphMatches(cases[1], 25, 23);
}

fn expectRecordedGraphMatches(
    case: Case,
    expected_matches: usize,
    expected_skipped: usize,
) !void {
    var input = try cairo.adapter.official_input.readFile(std.testing.allocator, case.input_path);
    defer input.deinit(std.testing.allocator);
    var bundle = try witness_bundle.Bundle.readFile(
        std.testing.allocator,
        "vectors/cairo/official/witness_programs_v1.bin",
    );
    defer bundle.deinit();
    var expected = try receipt.readFile(std.testing.allocator, case.checkpoint_path, .{
        .input_sha256 = try inputDigest(std.testing.allocator, case.input_path),
        .authority = .{
            .stwo_cairo_revision = registry.source_revision.stwo_cairo,
            .stwo_revision = registry.source_revision.stwo,
        },
    });
    defer expected.deinit();

    var report = try recorded_trace.compare(
        std.testing.allocator,
        &input,
        &bundle,
        expected.components,
    );
    defer report.deinit();
    if (report.mismatch) |mismatch| {
        std.debug.print(
            "recorded graph mismatch component={s} ordinal={} column={?}\n",
            .{ mismatch.component_label, mismatch.component_ordinal, mismatch.column_ordinal },
        );
    }
    try std.testing.expect(report.mismatch == null);
    if (report.matches.len != expected_matches) {
        std.debug.print("recorded graph matched:", .{});
        for (report.matches) |match| std.debug.print(" {s}", .{match.label});
        std.debug.print("\n", .{});
    }
    try std.testing.expectEqual(expected_matches, report.matches.len);
    try std.testing.expectEqual(expected_skipped, report.skipped_components);
}

fn expectWitnessMatches(
    case: Case,
    expected_covered: usize,
    expected_matches: usize,
    expected_skipped: usize,
) !void {
    var input = try cairo.adapter.official_input.readFile(std.testing.allocator, case.input_path);
    defer input.deinit(std.testing.allocator);
    var bundle = try witness_bundle.Bundle.readFile(
        std.testing.allocator,
        "vectors/cairo/official/witness_programs_v1.bin",
    );
    defer bundle.deinit();
    var expected = try receipt.readFile(std.testing.allocator, case.checkpoint_path, .{
        .input_sha256 = try inputDigest(std.testing.allocator, case.input_path),
        .authority = .{
            .stwo_cairo_revision = registry.source_revision.stwo_cairo,
            .stwo_revision = registry.source_revision.stwo,
        },
    });
    defer expected.deinit();

    var covered = std.ArrayList(cairo.conformance.checkpoint.Component).empty;
    defer covered.deinit(std.testing.allocator);
    for (expected.components) |component| {
        if (bundle.find(component.label) != null)
            try covered.append(std.testing.allocator, component);
    }
    var report = try direct_trace.compare(
        std.testing.allocator,
        &input,
        &bundle,
        covered.items,
    );
    defer report.deinit();
    try std.testing.expect(report.mismatch == null);
    try std.testing.expectEqual(expected_covered, covered.items.len);
    try std.testing.expectEqual(expected_skipped, report.skipped_components);
    try std.testing.expectEqual(expected_matches, report.matches.len);
}
