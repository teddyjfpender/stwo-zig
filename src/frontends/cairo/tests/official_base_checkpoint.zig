//! Official Stwo-Cairo base-trace checkpoint admission.

const std = @import("std");
const cairo = @import("cairo_frontend");
const receipt = cairo.conformance.receipt;
const registry = cairo.claim_registry;

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
