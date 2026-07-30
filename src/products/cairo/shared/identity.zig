//! Machine-readable identity rendering shared by Cairo products.

pub fn Value(comptime Generated: type, comptime Registry: type) type {
    return struct {
        pub fn jsonStringify(_: @This(), writer: anytype) !void {
            try writer.beginObject();
            try field(writer, "schema_version", Generated.schema_version);
            try field(writer, "name", Generated.product);
            try field(writer, "frontend", Generated.frontend);
            try field(writer, "backend", Generated.backend);
            try field(writer, "role", Generated.role);
            try field(writer, "protocol_features", Generated.protocol_features);
            try field(
                writer,
                "protocol_manifest_sha256",
                Generated.protocol_manifest_sha256,
            );
            try field(writer, "identity_sha256", Generated.identity_sha256);
            try writer.objectField("source");
            try writer.beginObject();
            try field(writer, "repository", Generated.implementation_repository);
            try field(writer, "commit", Generated.implementation_commit);
            try writer.objectField("tree");
            try writer.write(if (Generated.implementation_tree_available)
                Generated.implementation_tree
            else
                null);
            try field(writer, "dirty", Generated.implementation_dirty);
            try writer.objectField("dirty_content_sha256");
            try writer.write(if (Generated.dirty_content_sha256_available)
                Generated.dirty_content_sha256
            else
                null);
            try writer.endObject();
            try field(writer, "zig_version", Generated.zig_version);
            try writer.objectField("target");
            try writer.beginObject();
            try field(writer, "arch", Generated.target_arch);
            try field(writer, "os", Generated.target_os);
            try field(writer, "abi", Generated.target_abi);
            try field(writer, "cpu_model", Generated.cpu_model);
            try field(
                writer,
                "cpu_features_sha256",
                Generated.cpu_features_sha256,
            );
            try writer.endObject();
            try field(writer, "optimize", Generated.optimize);
            try writer.objectField("runtime");
            try writer.beginObject();
            try field(writer, "manifest", Generated.runtime_manifest);
            try field(writer, "sdk", Generated.sdk_manifest);
            try field(writer, "aot", Generated.aot_manifest);
            try writer.endObject();
            try writer.objectField("upstream");
            try writer.beginObject();
            try field(
                writer,
                "stwo_cairo_revision",
                Registry.source_revision.stwo_cairo,
            );
            try field(writer, "stwo_revision", Registry.source_revision.stwo);
            try field(writer, "cairo_language_version", "2.20.0");
            try field(writer, "cairo_vm_version", "3.2.0");
            try writer.endObject();
            try writer.endObject();
        }
    };
}

pub fn value(comptime Generated: type, comptime Registry: type) Value(
    Generated,
    Registry,
) {
    return .{};
}

pub fn write(
    comptime Generated: type,
    comptime Registry: type,
    writer: anytype,
) !void {
    const std = @import("std");
    try std.json.Stringify.value(value(Generated, Registry), .{}, writer);
}

fn field(writer: anytype, name: []const u8, value_: anytype) !void {
    try writer.objectField(name);
    try writer.write(value_);
}
