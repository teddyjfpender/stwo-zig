const std = @import("std");
const artifacts = @import("typed_air_artifacts");
const trace = @import("../../runner/trace.zig");
const compat_manifest = @import("compat_manifest.zig");

test "all 17 compat-v1 manifests and their AIR IR exports are byte exact" {
    try std.testing.expectEqual(
        trace.N_FAMILIES,
        artifacts.m3_compat_v1_manifests.len,
    );
    var summaries: [trace.N_FAMILIES]compat_manifest.Summary = undefined;
    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        var generated = try compat_manifest.generate(std.testing.allocator, family);
        defer generated.deinit();
        try std.testing.expectEqualSlices(
            u8,
            artifacts.m3_compat_v1_manifests[family_index],
            generated.bytes,
        );
        try std.testing.expect(std.mem.startsWith(
            u8,
            generated.bytes,
            compat_manifest.magic,
        ));
        summaries[family_index] = generated.summary;
    }

    var index: std.ArrayList(u8) = .empty;
    defer index.deinit(std.testing.allocator);
    try compat_manifest.writeIndex(index.writer(std.testing.allocator), &summaries);
    try std.testing.expectEqualStrings(artifacts.m3_compat_v1_index, index.items);
}

test "compat-v1 family artifact generation is deterministic" {
    var first = try compat_manifest.generate(std.testing.allocator, .div);
    defer first.deinit();
    var second = try compat_manifest.generate(std.testing.allocator, .div);
    defer second.deinit();
    try std.testing.expectEqualSlices(u8, first.bytes, second.bytes);
    try std.testing.expect(std.meta.eql(first.summary, second.summary));
}

test "compat-v1 index rejects duplicate or reordered families" {
    var generated = try compat_manifest.generate(std.testing.allocator, .lui);
    defer generated.deinit();
    const invalid = [_]compat_manifest.Summary{generated.summary} ** trace.N_FAMILIES;
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try std.testing.expectError(
        error.InvalidFamilyOrder,
        compat_manifest.writeIndex(bytes.writer(std.testing.allocator), &invalid),
    );
}

test "compat-v1 artifact generation releases every partial allocation" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        generationFailureCase,
        .{},
    );
}

fn generationFailureCase(allocator: std.mem.Allocator) !void {
    var generated = try compat_manifest.generateWithScratch(
        allocator,
        std.testing.allocator,
        .lui,
    );
    defer generated.deinit();
}
