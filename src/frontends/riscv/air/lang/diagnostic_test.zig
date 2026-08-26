const std = @import("std");
const degree = @import("degree.zig");
const diagnostic = @import("diagnostic.zig");
const ir = @import("ir.zig");
const source = @import("source.zig");
const test_support = @import("test_support.zig");
const types = @import("types.zig");

test "diagnostic renderer pins component, source, path, type, and degree" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var analysis = try degree.analyze(std.testing.allocator, &fixture.arena);
    defer analysis.deinit();
    const constraint_id = try types.idFromIndex(types.ConstraintId, 0);
    const constraint_degree = analysis.constraint(constraint_id).?;

    const rendered = try diagnostic.renderAlloc(
        std.testing.allocator,
        &fixture.arena,
        &analysis,
        .{
            .code = .degree_exceeded,
            .component = "riscv.lui",
            .message = "constraint exceeds the backend budget",
            .source_span = fixture.arena.constraints.items[0].source_span,
            .value_path = &.{ fixture.lhs, fixture.sum },
            .type_context = .{
                .expected = .felt,
                .actual = .word32,
            },
            .degree_context = .{
                .expression = constraint_degree.expression,
                .gate = constraint_degree.gate,
                .total = constraint_degree.total,
                .limit = 1,
            },
        },
    );
    defer std.testing.allocator.free(rendered);

    const expected =
        \\error[AIR0003 degree_exceeded] component="riscv.lui" source="fixture/primary.zig":1:1@0-1:5@4
        \\  message="constraint exceeds the backend budget"
        \\  value_path=%0:felt@degree=1 -> %4:felt@degree=1
        \\  type=expected:felt actual:word32
        \\  degree=expression:1 gate:1 total:2 limit:1
        \\
    ;
    try std.testing.expectEqualStrings(expected, rendered);
}

test "diagnostic renderer escapes text and survives unavailable values" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const unknown = try types.idFromIndex(types.ValueId, 999);
    const rendered = try diagnostic.renderAlloc(
        std.testing.allocator,
        &arena,
        null,
        .{
            .severity = .warning,
            .code = .type_mismatch,
            .component = "component\"\n",
            .message = "tab\t slash\\ byte\x01",
            .source_span = source.SourceSpan.generated(),
            .value_path = &.{unknown},
            .type_context = .{
                .expected = try types.Type.boundedLimbs(32, 8, 4),
                .actual = try types.Type.staticArray(.byte, 16),
            },
        },
    );
    defer std.testing.allocator.free(rendered);

    const expected =
        \\warning[AIR0002 type_mismatch] component="component\"\n" source=<generated>
        \\  message="tab\t slash\\ byte\x01"
        \\  value_path=%999:<invalid>@degree=?
        \\  type=expected:bounded_uint(bits=32,representation=little_endian_limbs(limb_bits=8,limb_count=4)) actual:array(element=byte,len=16)
        \\  degree=<none>
        \\
    ;
    try std.testing.expectEqualStrings(expected, rendered);
}

test "diagnostic codes have stable machine identities" {
    try std.testing.expectEqualStrings("AIR0001", diagnostic.codeId(.validation_failed));
    try std.testing.expectEqualStrings("AIR0002", diagnostic.codeId(.type_mismatch));
    try std.testing.expectEqualStrings("AIR0003", diagnostic.codeId(.degree_exceeded));
    try std.testing.expectEqualStrings("AIR0004", diagnostic.codeId(.unbound_hint_output));
    try std.testing.expectEqualStrings("AIR0005", diagnostic.codeId(.invalid_relation_event));
    try std.testing.expectEqualStrings("AIR0006", diagnostic.codeId(.lowering_failed));
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var arena = ir.Arena.init(allocator);
    defer arena.deinit();
    const rendered = try diagnostic.renderAlloc(allocator, &arena, null, .{
        .code = .validation_failed,
        .component = "allocation",
        .message = "render",
    });
    defer allocator.free(rendered);
}

test "diagnostic renderer releases every partial allocation" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}
