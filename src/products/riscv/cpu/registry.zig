//! Machine-readable capability surface for the focused RISC-V CPU product.
//!
//! Thin binding of the shared focused-product registry. The CPU product
//! supplies its own capabilities and identity modules and the single-key
//! `backend_availability` object, so the backend set below is the only
//! backend this registry can ever report.

const std = @import("std");
const builtin = @import("builtin");
const capabilities = @import("riscv_cpu_capabilities");
const identity = @import("product_identity");
const shared_registry = @import("riscv_shared_registry");

const impl = shared_registry.Registry(capabilities, identity, .{ .cpu = true });

pub const write = impl.write;

test "registry exposes exactly the RISC-V CPU capability" {
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
    try std.testing.expectEqual(@as(i64, 2), product.get("schema_version").?.integer);
    try std.testing.expectEqualStrings(builtin.zig_version_string, product.get("zig_version").?.string);
    try std.testing.expectEqualStrings(
        "https://github.com/teddyjfpender/stwo-zig",
        product.get("source").?.object.get("repository").?.string,
    );
    try std.testing.expectEqual(@as(usize, 1), root.get("backend_availability").?.object.count());
    try std.testing.expect(root.get("backend_availability").?.object.get("cpu").?.bool);
    if (capabilities.adapter_release_gated) {
        const applications = root.get("applications").?.array;
        try std.testing.expectEqual(@as(usize, 1), applications.items.len);
        try std.testing.expect(applications.items[0].object.get("reason") == null);
    }
    const guest_profiles = root.get("guest_profiles").?.array;
    try std.testing.expectEqual(@as(usize, 1), guest_profiles.items.len);
    const guest = guest_profiles.items[0].object;
    try std.testing.expectEqualStrings(
        capabilities.guest_poseidon2.profile,
        guest.get("profile").?.string,
    );
    try std.testing.expectEqualStrings(
        "cpu_scalar_simd_generic_direct_plus_logup_v1",
        guest.get("execution_placement").?.string,
    );
    try std.testing.expect(!guest.get("backend_fallback_allowed").?.bool);
    const encoded = output.buffered();
    inline for (.{ "metal", "cuda", "cairo", "wide_fibonacci" }) |forbidden| {
        try std.testing.expect(std.mem.indexOf(u8, encoded, forbidden) == null);
    }
    try std.testing.expect(std.mem.indexOf(u8, encoded, "rv32im-zkvm-poseidon2-v1") != null);
}
