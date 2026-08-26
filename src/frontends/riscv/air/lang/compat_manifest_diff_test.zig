const std = @import("std");
const artifacts = @import("typed_air_artifacts");
const diff = @import("compat_manifest_diff.zig");

const fixture = artifacts.m3_compat_v1_manifests[8]; // LUI.

test "compat manifest diff accepts an equal canonical artifact without allocation" {
    for (artifacts.m3_compat_v1_manifests) |manifest|
        try std.testing.expectEqual(diff.Result.equal, diff.compare(manifest, manifest));
}

test "compat manifest diff names physical and logical layout changes" {
    const physical = try copyFixture();
    defer std.testing.allocator.free(physical);
    replaceUniqueByte(physical, "rd_nonzero", 0, 'x');
    const physical_result = diff.compare(fixture, physical);
    try expectDifferencePath(physical_result, "layout.main[16].physical_name");
    try std.testing.expectEqualStrings(
        "difference at layout.main[16].physical_name " ++
            "(column logical=\"destination_nonzero\", physical=\"rd_nonzero\"): " ++
            "expected/generated \"rd_nonzero\", actual/on-disk \"xd_nonzero\"",
        try render(physical_result),
    );

    const logical = try copyFixture();
    defer std.testing.allocator.free(logical);
    replaceUniqueByte(logical, "destination_nonzero", 0, 'x');
    try expectDifferencePath(
        diff.compare(fixture, logical),
        "layout.main[16].logical_name",
    );
}

test "compat manifest diff identifies a moved column with both names" {
    const changed = try copyFixture();
    defer std.testing.allocator.free(changed);
    const logical = uniqueOffset(changed, "destination_nonzero");
    const index_offset = logical - 12;
    changed[index_offset] +%= 1;
    const result = diff.compare(fixture, changed);
    try expectDifferencePath(result, "layout.main[16].reference.local_index");
    const rendered = try render(result);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "logical=\"destination_nonzero\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "physical=\"rd_nonzero\"") != null);
}

test "compat manifest diff identifies runtime node and named direct root changes" {
    const node = try copyFixture();
    defer std.testing.allocator.free(node);
    const direct = sectionPayload(node, 2);
    const runtime_start = direct.start + 32 + 4;
    node[runtime_start + 16 + 9] +%= 1;
    try expectDifferencePath(
        diff.compare(fixture, node),
        "direct.runtime.nodes[0].value",
    );

    const root = try copyFixture();
    defer std.testing.allocator.free(root);
    const name = uniqueOffset(root, "compat.riscv.lui.direct.0");
    root[name + "compat.riscv.lui.direct.0".len + 8] +%= 1;
    const result = diff.compare(fixture, root);
    try expectDifferencePath(result, "direct.constraints[0].lowered_root");
    try std.testing.expect(std.mem.indexOf(u8, try render(result), "name=\"compat.riscv.lui.direct.0\"") != null);
}

test "compat manifest diff identifies lookup schema role event and batch changes" {
    const schema_name = "stwo.riscv.program_access";
    const schema = try copyFixture();
    defer std.testing.allocator.free(schema);
    const schema_offset = uniqueOffset(schema, schema_name);
    schema[schema_offset - 9] +%= 1;
    try expectDifferencePath(diff.compare(fixture, schema), "lookup.events[0].schema_id");

    const role = try copyFixture();
    defer std.testing.allocator.free(role);
    role[uniqueOffset(role, schema_name) + schema_name.len] = 1;
    const role_result = diff.compare(fixture, role);
    try expectDifferencePath(role_result, "lookup.events[0].role");
    try std.testing.expect(std.mem.indexOf(u8, try render(role_result), "request (0)") != null);
    try std.testing.expect(std.mem.indexOf(u8, try render(role_result), "consume (1)") != null);

    const event = try copyFixture();
    defer std.testing.allocator.free(event);
    event[uniqueOffset(event, schema_name) + schema_name.len + 5] +%= 1;
    try expectDifferencePath(diff.compare(fixture, event), "lookup.events[0].numerator");

    const batch = try copyFixture();
    defer std.testing.allocator.free(batch);
    batch[firstBatchOffset(batch) + 4] = 1;
    try expectDifferencePath(diff.compare(fixture, batch), "lookup.batches[0].event_count");
}

test "compat manifest diff identifies degree and formal identity changes" {
    const degree = try copyFixture();
    defer std.testing.allocator.free(degree);
    degree[sectionPayload(degree, 4).start + 4] +%= 1;
    try expectDifferencePath(
        diff.compare(fixture, degree),
        "degree.maximum_direct_degree",
    );

    const formal = try copyFixture();
    defer std.testing.allocator.free(formal);
    const mnemonic = std.mem.lastIndexOf(u8, formal, "lui").?;
    formal[mnemonic + 3 + 4] ^= 0x80;
    try expectDifferencePath(diff.compare(fixture, formal), "formal.exports[0].sha256");
}

test "compat manifest diff fails closed on malformed framing" {
    try expectInvalid(
        diff.compare(fixture[0..7], fixture[0..11]),
        .expected,
        .truncated,
        "header.magic",
    );

    const truncated = diff.compare(fixture, fixture[0..11]);
    try expectInvalid(truncated, .actual, .truncated, "header.section_count");
    try std.testing.expectEqualStrings(
        "invalid actual/on-disk manifest at header.section_count (byte 11): truncated field",
        try render(truncated),
    );

    const reordered = try copyFixture();
    defer std.testing.allocator.free(reordered);
    reordered[12] = 2;
    try expectInvalid(
        diff.compare(fixture, reordered),
        .actual,
        .unexpected_section,
        "sections[0].id",
    );

    const trailing = try std.testing.allocator.alloc(u8, fixture.len + 1);
    defer std.testing.allocator.free(trailing);
    @memcpy(trailing[0..fixture.len], fixture);
    trailing[fixture.len] = 0;
    try expectInvalid(diff.compare(fixture, trailing), .actual, .trailing_bytes, "manifest");

    const section_trailing = try insertSectionByte(fixture, 5);
    defer std.testing.allocator.free(section_trailing);
    try expectInvalid(
        diff.compare(fixture, section_trailing),
        .actual,
        .section_trailing_bytes,
        "hints",
    );
}

test "compat manifest diff rejects malformed nested values deterministically" {
    const utf8 = try copyFixture();
    defer std.testing.allocator.free(utf8);
    utf8[uniqueOffset(utf8, "rd_nonzero")] = 0xff;
    try expectInvalid(
        diff.compare(fixture, utf8),
        .actual,
        .invalid_utf8,
        "layout.main[16].physical_name",
    );

    const optional = try copyFixture();
    defer std.testing.allocator.free(optional);
    const event_name = "stwo.riscv.program_access";
    const presence = uniqueOffset(optional, event_name) + event_name.len + 10;
    optional[presence] = 2;
    try expectInvalid(
        diff.compare(fixture, optional),
        .actual,
        .invalid_optional,
        "lookup.events[0].access_ordinal",
    );

    const runtime = try copyFixture();
    defer std.testing.allocator.free(runtime);
    runtime[sectionPayload(runtime, 2).start + 32 + 4] = 'X';
    try expectInvalid(
        diff.compare(fixture, runtime),
        .actual,
        .invalid_runtime_magic,
        "direct.runtime.magic",
    );
}

fn copyFixture() ![]u8 {
    return std.testing.allocator.dupe(u8, fixture);
}

fn uniqueOffset(bytes: []const u8, needle: []const u8) usize {
    const first = std.mem.indexOf(u8, bytes, needle).?;
    std.debug.assert(std.mem.indexOfPos(u8, bytes, first + 1, needle) == null);
    return first;
}

fn replaceUniqueByte(bytes: []u8, needle: []const u8, relative: usize, value: u8) void {
    bytes[uniqueOffset(bytes, needle) + relative] = value;
}

const Span = struct { start: usize, len: usize };

fn sectionPayload(bytes: []const u8, wanted: usize) Span {
    var pos: usize = 12;
    for (0..7) |index| {
        pos += 1;
        const len = std.mem.readInt(u32, bytes[pos..][0..4], .little);
        pos += 4;
        if (index == wanted) return .{ .start = pos, .len = len };
        pos += len;
    }
    unreachable;
}

fn insertSectionByte(bytes: []const u8, wanted: usize) ![]u8 {
    const section = sectionPayload(bytes, wanted);
    const end = section.start + section.len;
    const result = try std.testing.allocator.alloc(u8, bytes.len + 1);
    @memcpy(result[0..end], bytes[0..end]);
    result[end] = 0;
    @memcpy(result[end + 1 ..], bytes[end..]);
    std.mem.writeInt(u32, result[section.start - 4 ..][0..4], @intCast(section.len + 1), .little);
    return result;
}

fn firstBatchOffset(bytes: []const u8) usize {
    const lookup = sectionPayload(bytes, 3);
    var pos = lookup.start + 32;
    const runtime_len = std.mem.readInt(u32, bytes[pos..][0..4], .little);
    pos += 4 + runtime_len;
    const event_count = std.mem.readInt(u32, bytes[pos..][0..4], .little);
    pos += 4;
    for (0..event_count) |_| {
        pos += 2 + 1 + 2;
        const name_len = std.mem.readInt(u32, bytes[pos..][0..4], .little);
        pos += 4 + name_len;
        pos += 1 + 4 + 4;
        const arity = bytes[pos];
        pos += 1;
        const present = bytes[pos];
        pos += 1 + (if (present == 1) @as(usize, 1) else 0);
        pos += @as(usize, arity) * 4;
    }
    pos += 4; // Batch count.
    return pos;
}

fn expectDifferencePath(result: diff.Result, expected: []const u8) !void {
    switch (result) {
        .difference => |item| try std.testing.expectEqualStrings(expected, item.path.slice()),
        else => return error.ExpectedDifference,
    }
}

fn expectInvalid(
    result: diff.Result,
    side: diff.Side,
    kind: diff.InvalidKind,
    expected_path: []const u8,
) !void {
    switch (result) {
        .invalid => |item| {
            try std.testing.expectEqual(side, item.side);
            try std.testing.expectEqual(kind, item.kind);
            try std.testing.expectEqualStrings(expected_path, item.path.slice());
        },
        else => return error.ExpectedInvalid,
    }
}

var render_buffer: [1024]u8 = undefined;

fn render(result: diff.Result) ![]const u8 {
    var writer = std.Io.Writer.fixed(&render_buffer);
    try diff.writeResult(&writer, result);
    return writer.buffered();
}
