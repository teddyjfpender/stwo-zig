//! Live Cairo witness geometry checked against, but never sourced from, Rust.

const std = @import("std");
const cairo = @import("cairo_frontend");

const Case = struct {
    input_path: []const u8,
    checkpoint_path: []const u8,
    variant: cairo.claim_generator.PreprocessedVariant,
    generated_components: usize,
};

test "official all-opcodes geometry and generated columns derive from live input" {
    try expectLiveCase(.{
        .input_path = "vectors/cairo/official/all_opcodes.prover_input.json",
        .checkpoint_path = "vectors/cairo/official/all_opcodes.base_trace_checkpoint.json",
        .variant = .canonical_small,
        .generated_components = 24,
    });
}

test "official all-builtins geometry and generated columns derive from live input" {
    try expectLiveCase(.{
        .input_path = "vectors/cairo/official/all_builtins.prover_input.json",
        .checkpoint_path = "vectors/cairo/official/all_builtins.base_trace_checkpoint.json",
        .variant = .canonical,
        .generated_components = 26,
    });
}

fn expectLiveCase(case: Case) !void {
    var input = try cairo.adapter.official_input.readFile(
        std.testing.allocator,
        case.input_path,
    );
    defer input.deinit(std.testing.allocator);
    var programs = try cairo.witness.bundle.Bundle.readFile(
        std.testing.allocator,
        "vectors/cairo/official/witness_programs_v1.bin",
    );
    defer programs.deinit();
    var expected = try cairo.conformance.receipt.readFile(
        std.testing.allocator,
        case.checkpoint_path,
        .{
            .input_sha256 = try inputDigest(std.testing.allocator, case.input_path),
            .authority = .{
                .stwo_cairo_revision = cairo.claim_registry.source_revision.stwo_cairo,
                .stwo_revision = cairo.claim_registry.source_revision.stwo,
            },
        },
    );
    defer expected.deinit();

    var geometry = try cairo.claim_generator.deriveFromProverInput(
        std.testing.allocator,
        &input,
        .{ .preprocessed_variant = case.variant },
    );
    defer geometry.deinit();
    var observer = Observer{ .expected = expected.components };
    var execution = try cairo.witness.live_graph.execute(
        std.testing.allocator,
        &input,
        &programs,
        &geometry,
        .{
            .context = &observer,
            .visit = Observer.visit,
        },
        null,
        null,
    );
    defer execution.deinit();

    try std.testing.expectEqual(case.generated_components, execution.components.len);
    try std.testing.expectEqual(case.generated_components, observer.visited);
    try std.testing.expectEqual(expected.components.len, geometry.components.len);
    for (geometry.components, expected.components) |component, oracle| {
        try expectIdentity(component, oracle.label);
        const log_size = switch (component.log_size) {
            .known => |value| value,
            .deferred => return error.UnresolvedLiveGeometry,
        };
        try std.testing.expectEqual(
            oracle.columns[0].row_count,
            @as(u64, 1) << @intCast(log_size),
        );
    }
}

const Observer = struct {
    expected: []const cairo.conformance.checkpoint.Component,
    visited: usize = 0,

    fn visit(
        raw_context: *anyopaque,
        layout: cairo.witness.component_layout.ComponentLayout,
        execution: *const cairo.witness.component_executor.Execution,
    ) !void {
        const self: *Observer = @ptrCast(@alignCast(raw_context));
        if (layout.ordinal >= self.expected.len) return error.InvalidLiveOrdinal;
        const oracle = self.expected[layout.ordinal];
        if (!std.mem.eql(u8, layout.label, oracle.label) or
            layout.row_count != oracle.columns[0].row_count or
            layout.column_count != oracle.columns.len)
            return error.LiveGeometryMismatch;
        if (try cairo.conformance.base_execution.compare(oracle, execution.*) != null)
            return error.LiveColumnMismatch;
        self.visited += 1;
    }
};

fn expectIdentity(
    component: cairo.claim_generator.ComponentGeometry,
    oracle_label: []const u8,
) !void {
    if (!std.mem.eql(u8, component.name, "memory_id_to_big"))
        return std.testing.expectEqualStrings(component.name, oracle_label);
    var buffer: [64]u8 = undefined;
    const label = try std.fmt.bufPrint(
        &buffer,
        "memory_id_to_big[{}]",
        .{component.instance},
    );
    try std.testing.expectEqualStrings(label, oracle_label);
}

fn inputDigest(allocator: std.mem.Allocator, path: []const u8) ![32]u8 {
    const encoded = try std.fs.cwd().readFileAlloc(allocator, path, 2 * 1024 * 1024);
    defer allocator.free(encoded);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &digest, .{});
    return digest;
}
