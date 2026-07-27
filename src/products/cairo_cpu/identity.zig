//! Machine-readable identity for the Cairo CPU/SIMD product.

const std = @import("std");
const generated = @import("product_identity");
const stwo = @import("stwo_cairo_cpu");

const registry = stwo.frontends.cairo.claim_registry;

pub const Value = struct {
    pub fn jsonStringify(_: Value, writer: anytype) !void {
        try writer.beginObject();
        try field(writer, "schema_version", generated.schema_version);
        try field(writer, "name", generated.product);
        try field(writer, "frontend", generated.frontend);
        try field(writer, "backend", generated.backend);
        try field(writer, "role", generated.role);
        try field(writer, "protocol_features", generated.protocol_features);
        try field(
            writer,
            "protocol_manifest_sha256",
            generated.protocol_manifest_sha256,
        );
        try field(writer, "identity_sha256", generated.identity_sha256);
        try writer.objectField("source");
        try writer.beginObject();
        try field(writer, "repository", generated.implementation_repository);
        try field(writer, "commit", generated.implementation_commit);
        try writer.objectField("tree");
        try writer.write(if (generated.implementation_tree_available)
            generated.implementation_tree
        else
            null);
        try field(writer, "dirty", generated.implementation_dirty);
        try writer.objectField("dirty_content_sha256");
        try writer.write(if (generated.dirty_content_sha256_available)
            generated.dirty_content_sha256
        else
            null);
        try writer.endObject();
        try field(writer, "zig_version", generated.zig_version);
        try writer.objectField("target");
        try writer.beginObject();
        try field(writer, "arch", generated.target_arch);
        try field(writer, "os", generated.target_os);
        try field(writer, "abi", generated.target_abi);
        try field(writer, "cpu_model", generated.cpu_model);
        try field(
            writer,
            "cpu_features_sha256",
            generated.cpu_features_sha256,
        );
        try writer.endObject();
        try field(writer, "optimize", generated.optimize);
        try writer.objectField("runtime");
        try writer.beginObject();
        try field(writer, "manifest", generated.runtime_manifest);
        try field(writer, "sdk", generated.sdk_manifest);
        try field(writer, "aot", generated.aot_manifest);
        try writer.endObject();
        try writer.objectField("upstream");
        try writer.beginObject();
        try field(
            writer,
            "stwo_cairo_revision",
            registry.source_revision.stwo_cairo,
        );
        try field(writer, "stwo_revision", registry.source_revision.stwo);
        try field(writer, "cairo_language_version", "2.20.0");
        try field(writer, "cairo_vm_version", "3.2.0");
        try writer.endObject();
        try writer.endObject();
    }
};

pub fn value() Value {
    return .{};
}

pub fn write(writer: anytype) !void {
    try std.json.Stringify.value(value(), .{}, writer);
}

fn field(writer: anytype, name: []const u8, value_: anytype) !void {
    try writer.objectField(name);
    try writer.write(value_);
}
