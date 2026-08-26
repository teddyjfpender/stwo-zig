const std = @import("std");
const artifacts = @import("typed_air_artifacts");
const protocol_report = @import("protocol_report.zig");

test "protocol report emits deterministic machine and human views" {
    const report = try protocol_report.collect(std.testing.allocator);
    try report.validate();

    var machine: std.ArrayList(u8) = .empty;
    defer machine.deinit(std.testing.allocator);
    try protocol_report.writeMachine(
        machine.writer(std.testing.allocator),
        &report,
    );
    var markdown: std.ArrayList(u8) = .empty;
    defer markdown.deinit(std.testing.allocator);
    try protocol_report.writeMarkdown(
        markdown.writer(std.testing.allocator),
        &report,
    );
    try std.testing.expectEqualStrings(
        artifacts.m2_production_shadow_machine,
        machine.items,
    );
    try std.testing.expectEqualStrings(
        artifacts.m2_production_shadow_markdown,
        markdown.items,
    );
}

test "protocol report writers survive every allocation failure" {
    const report = try protocol_report.collect(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        writeFailureCase,
        .{&report},
    );
}

test "protocol report rejects corrupt structural summaries" {
    const report = try protocol_report.collect(std.testing.allocator);

    var corrupted = report;
    corrupted.families[0].family = .div;
    try std.testing.expectError(error.InvalidReport, corrupted.validate());

    corrupted = report;
    corrupted.families[0].typed_nodes += 1;
    try std.testing.expectError(error.InvalidReport, corrupted.validate());

    corrupted = report;
    corrupted.families[0].batch_size = 0;
    try std.testing.expectError(error.InvalidReport, corrupted.validate());

    corrupted = report;
    corrupted.families[0].interaction_columns += 1;
    try std.testing.expectError(error.InvalidReport, corrupted.validate());

    corrupted = report;
    corrupted.families[0].role_counts[0] += 1;
    try std.testing.expectError(error.InvalidReport, corrupted.validate());

    corrupted = report;
    corrupted.families[0].dependency_counts[0] += 1;
    try std.testing.expectError(error.InvalidReport, corrupted.validate());

    corrupted = report;
    corrupted.families[0].direct_expansion_bits += 1;
    try std.testing.expectError(error.InvalidReport, corrupted.validate());

    corrupted = report;
    corrupted.families[0].lookups = std.math.maxInt(u32);
    try std.testing.expectError(error.InvalidReport, corrupted.validate());
}

fn writeFailureCase(
    allocator: std.mem.Allocator,
    report: *const protocol_report.Report,
) !void {
    var machine: std.ArrayList(u8) = .empty;
    defer machine.deinit(allocator);
    try protocol_report.writeMachine(machine.writer(allocator), report);

    var markdown: std.ArrayList(u8) = .empty;
    defer markdown.deinit(allocator);
    try protocol_report.writeMarkdown(markdown.writer(allocator), report);
}
