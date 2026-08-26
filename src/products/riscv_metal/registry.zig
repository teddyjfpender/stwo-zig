//! Machine-readable capability surface for the focused RISC-V Metal product.
//!
//! Thin binding of the shared focused-product registry
//! (`src/products/riscv_shared/registry.zig`). The Metal product supplies its own
//! capabilities and identity modules and the single-key `backend_availability`
//! object, so the backend set below is the only backend this registry can ever
//! report — this CLI cannot advertise the CPU product's lane.
//!
//! `capabilities.zig` is reached through an injected module name rather than as
//! a sibling file because it is also the root of the capabilities module handed
//! to the shared proof adapter, and a Zig file may belong to exactly one module.
//! `build_support/products/riscv_metal.zig` therefore creates ONE module from
//! `src/products/riscv_metal/capabilities.zig` and adds it to this product's root
//! module as `riscv_capabilities` (used here) and to the adapter module as
//! `riscv_cpu_capabilities`, the name the shared adapter hard-codes. Pointing
//! either name at the CPU product's capability file fails this file's test as
//! well as the Metal product's source-closure gate.

const std = @import("std");
const capabilities = @import("riscv_capabilities");
const identity = @import("product_identity");

pub fn write(writer: anytype) !void {
    try std.json.Stringify.value(.{
        .schema_version = @as(u32, 2),
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
        .backend_availability = .{ .metal = true },
        .applications = if (capabilities.adapter_release_gated)
            &[_]Application{Application.releaseGated()}
        else
            &[_]Application{},
        .deferred_adapters = if (capabilities.adapter_release_gated)
            &[_]Application{}
        else
            &[_]Application{Application.deferred()},
        .guest_profiles = &[_]GuestProfile{GuestProfile.canonical()},
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

const GuestProfile = struct {
    profile: []const u8,
    version: u16,
    capability: []const u8,
    manifest_sha256: []const u8,
    status: []const u8,
    caller_component: []const u8,
    provider_component: []const u8,
    execution_placement: []const u8,
    runtime_requirement: []const u8,
    pcs_policies: []const []const u8,
    prove_command: []const u8,
    verify_command: []const u8,
    backend_fallback_allowed: bool,
    verification_requires_metal_device: bool,

    fn canonical() GuestProfile {
        const profile = capabilities.guest_poseidon2;
        return .{
            .profile = profile.profile,
            .version = profile.version,
            .capability = profile.capability,
            .manifest_sha256 = profile.manifest_sha256,
            .status = "parity_gated",
            .caller_component = profile.caller_component,
            .provider_component = profile.provider_component,
            .execution_placement = profile.execution_placement,
            .runtime_requirement = profile.runtime_requirement,
            .pcs_policies = &.{ "secure", "functional-development" },
            .prove_command = profile.prove_command,
            .verify_command = profile.verify_command,
            .backend_fallback_allowed = profile.backend_fallback_allowed,
            .verification_requires_metal_device = false,
        };
    }
};

test "registry exposes the base RISC-V Metal lane and exact guest profile" {
    var storage: [8192]u8 = undefined;
    var output = std.Io.Writer.fixed(&storage);
    try write(&output);
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        output.buffered(),
        .{},
    );
    defer parsed.deinit();

    const root = parsed.value.object;
    const product = root.get("product").?.object;
    try std.testing.expectEqualStrings("metal", product.get("backend").?.string);
    try std.testing.expectEqual(@as(usize, 1), root.get("backend_availability").?.object.count());
    try std.testing.expect(root.get("backend_availability").?.object.get("metal").?.bool);
    const guest_profiles = root.get("guest_profiles").?.array;
    try std.testing.expectEqual(@as(usize, 1), guest_profiles.items.len);
    const guest = guest_profiles.items[0].object;
    try std.testing.expectEqualStrings(
        "rv32im-zkvm-poseidon2-v1",
        guest.get("profile").?.string,
    );
    try std.testing.expectEqual(@as(i64, 1), guest.get("version").?.integer);
    try std.testing.expectEqualStrings(
        "reviewed_generic_direct_plus_logup_v1",
        guest.get("execution_placement").?.string,
    );
    try std.testing.expect(!guest.get("backend_fallback_allowed").?.bool);
    try std.testing.expect(!guest.get("verification_requires_metal_device").?.bool);
    if (capabilities.adapter_release_gated) {
        const applications = root.get("applications").?.array;
        try std.testing.expectEqual(@as(usize, 1), applications.items.len);
        const backends = applications.items[0].object.get("backends").?.array;
        try std.testing.expectEqual(@as(usize, 1), backends.items.len);
        try std.testing.expectEqualStrings("metal", backends.items[0].string);
        try std.testing.expect(applications.items[0].object.get("reason") == null);
    }
    const encoded = output.buffered();
    // The bare token `cpu` legitimately appears in identity keys such as
    // `cpu_model`; what must never appear is a quoted `cpu` value, which is how
    // a backend token would be encoded.
    try std.testing.expect(std.mem.indexOf(u8, encoded, "\"cpu\"") == null);
    inline for (.{ "cuda", "cairo", "wide_fibonacci", "generic_guest" }) |forbidden| {
        try std.testing.expect(std.mem.indexOf(u8, encoded, forbidden) == null);
    }
}
