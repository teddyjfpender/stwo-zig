//! Machine-readable RISC-V proof opcode manifest surface.

const std = @import("std");
const manifest = @import("stwo").frontends.riscv.opcode_manifest;

const usage = "usage: riscv-opcode-manifest <dump|check>\n";

const ManifestJson = struct {
    pub fn jsonStringify(_: ManifestJson, writer: anytype) !void {
        try writer.beginObject();
        try writer.objectField("schema_version");
        try writer.write(manifest.schema_version);
        try writer.objectField("semantic_authority_revision");
        try writer.write(manifest.semantic_authority_revision);
        try writer.objectField("legacy_layout_revision");
        try writer.write(manifest.legacy_layout_revision);
        try writer.objectField("supported");
        try writer.beginArray();
        for (manifest.entries) |entry| {
            try writer.beginObject();
            try writer.objectField("protocol_id");
            try writer.write(entry.opcode.protocolId());
            try writer.objectField("mnemonic");
            try writer.write(entry.mnemonic);
            try writer.objectField("family");
            try writer.write(@tagName(entry.family));
            try writer.objectField("program_shape");
            try writer.write(@tagName(entry.program_shape));
            try writer.objectField("encoding_class");
            try writer.write(@tagName(entry.encoding_class));
            try writer.objectField("witness_schema");
            try writer.write(@tagName(entry.witness_schema));
            try writer.objectField("semantic_component");
            try writer.write(@tagName(entry.semantic_component));
            try writer.objectField("relation_domains");
            try writer.beginArray();
            inline for (@typeInfo(manifest.RelationDomain).@"enum".fields) |field| {
                const domain: manifest.RelationDomain = @enumFromInt(field.value);
                if (entry.relation_domains.contains(domain)) try writer.write(field.name);
            }
            try writer.endArray();
            try writer.objectField("execution_supported");
            try writer.write(entry.execution_supported);
            try writer.objectField("proof_eligibility");
            try writer.write(@tagName(entry.proof_eligibility));
            try writer.endObject();
        }
        try writer.endArray();
        try writer.objectField("unsupported");
        try writer.beginArray();
        for (manifest.unsupported_entries) |entry| {
            try writer.beginObject();
            try writer.objectField("mnemonic");
            try writer.write(entry.mnemonic);
            try writer.objectField("class");
            try writer.write(@tagName(entry.class));
            try writer.objectField("execution_supported");
            try writer.write(entry.execution_supported);
            try writer.objectField("proof_supported");
            try writer.write(false);
            try writer.endObject();
        }
        try writer.endArray();
        try writer.endObject();
    }
};

pub fn main() void {
    run() catch |err| {
        std.debug.print("riscv-opcode-manifest failed: {s}\n", .{@errorName(err)});
        std.process.exit(2);
    };
}

fn run() !void {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len != 2) {
        std.debug.print("{s}", .{usage});
        return error.InvalidArguments;
    }

    try manifest.validate();
    var buffer: [32 * 1024]u8 = undefined;
    var output = std.fs.File.stdout().writer(&buffer);
    const writer = &output.interface;
    if (std.mem.eql(u8, args[1], "dump")) {
        try std.json.Stringify.value(ManifestJson{}, .{ .whitespace = .indent_2 }, writer);
    } else if (std.mem.eql(u8, args[1], "check")) {
        try std.json.Stringify.value(.{
            .schema_version = manifest.schema_version,
            .status = "ok",
            .supported_count = manifest.entries.len,
            .unsupported_count = manifest.unsupported_entries.len,
        }, .{}, writer);
    } else {
        std.debug.print("{s}", .{usage});
        return error.InvalidArguments;
    }
    try writer.writeByte('\n');
    try writer.flush();
}

test "machine-readable view contains proof and host-control policy" {
    var encoded: [32 * 1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&encoded);
    try std.json.Stringify.value(ManifestJson{}, .{}, &writer);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, writer.buffered(), .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 46), parsed.value.object.get("supported").?.array.items.len);
    try std.testing.expectEqual(@as(usize, 2), parsed.value.object.get("unsupported").?.array.items.len);
    const first = parsed.value.object.get("supported").?.array.items[0].object;
    try std.testing.expectEqualStrings("r_type", first.get("encoding_class").?.string);
    try std.testing.expect(first.get("relation_domains").?.array.items.len >= 4);
}
