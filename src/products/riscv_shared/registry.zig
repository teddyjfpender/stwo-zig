//! Shared machine-readable capability surface for focused RISC-V products.
//!
//! Each product binds this generic with its own injected capabilities and
//! product-identity modules plus a single-key `backend_availability` object
//! (for example `.{ .cpu = true }`). The backend list is always a parameter
//! supplied by the product binding — never a literal in this file — so one
//! product's registry can never name another product's backend.

const std = @import("std");

pub fn Registry(
    comptime capabilities: type,
    comptime identity: type,
    comptime availability: anytype,
) type {
    return struct {
        pub fn write(writer: anytype) !void {
            try std.json.Stringify.value(.{
                .schema_version = @as(u32, 1),
                .product = .{
                    .schema_version = identity.schema_version,
                    .name = identity.product,
                    .frontend = identity.frontend,
                    .backend = identity.backend,
                    .role = identity.role,
                    .protocol_features = identity.protocol_features,
                    .protocol_manifest_sha256 = identity.protocol_manifest_sha256,
                    .identity_sha256 = identity.identity_sha256,
                    .source = .{
                        .repository = identity.implementation_repository,
                        .commit = identity.implementation_commit,
                        .tree = if (identity.implementation_tree_available)
                            identity.implementation_tree
                        else
                            null,
                        .dirty = identity.implementation_dirty,
                        .dirty_content_sha256 = if (identity.dirty_content_sha256_available)
                            identity.dirty_content_sha256
                        else
                            null,
                    },
                    .zig_version = identity.zig_version,
                    .target = .{
                        .arch = identity.target_arch,
                        .os = identity.target_os,
                        .abi = identity.target_abi,
                        .cpu_model = identity.cpu_model,
                        .cpu_features_sha256 = identity.cpu_features_sha256,
                    },
                    .optimize = identity.optimize,
                    .runtime = .{
                        .manifest = identity.runtime_manifest,
                        .sdk = identity.sdk_manifest,
                        .aot = identity.aot_manifest,
                    },
                },
                .backend_availability = availability,
                .applications = if (capabilities.adapter_release_gated)
                    &[_]Application{Application.releaseGated()}
                else
                    &[_]Application{},
                .deferred_adapters = if (capabilities.adapter_release_gated)
                    &[_]Application{}
                else
                    &[_]Application{Application.deferred()},
            }, .{}, writer);
        }

        const Application = struct {
            adapter: []const u8 = capabilities.adapter,
            air: []const u8 = capabilities.air,
            status: []const u8,
            isa: []const u8 = capabilities.isa,
            backends: []const []const u8 = &.{capabilities.backend},
            reason: ?[]const u8 = null,

            pub fn jsonStringify(self: Application, writer: anytype) !void {
                try writer.beginObject();
                try writer.objectField("adapter");
                try writer.write(self.adapter);
                try writer.objectField("air");
                try writer.write(self.air);
                try writer.objectField("status");
                try writer.write(self.status);
                try writer.objectField("isa");
                try writer.write(self.isa);
                try writer.objectField("backends");
                try writer.write(self.backends);
                if (self.reason) |reason| {
                    try writer.objectField("reason");
                    try writer.write(reason);
                }
                try writer.endObject();
            }

            fn releaseGated() Application {
                return .{ .status = "release_gated" };
            }

            fn deferred() Application {
                return .{
                    .status = "not_release_gated",
                    .reason = capabilities.deferred_reason,
                };
            }
        };
    };
}
