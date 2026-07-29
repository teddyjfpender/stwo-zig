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
//! The build graph must therefore create ONE module from
//! `src/products/riscv_metal/capabilities.zig` and add it to this product's root
//! module as `riscv_metal_capabilities` and to the adapter module under the name
//! the adapter imports (`riscv_cpu_capabilities` today). Pointing either name at
//! the CPU product's capabilities file fails this file's test and the Metal
//! product's source-closure gate.

const std = @import("std");
const capabilities = @import("riscv_metal_capabilities");
const identity = @import("product_identity");
const shared_registry = @import("riscv_shared_registry");

const impl = shared_registry.Registry(capabilities, identity, .{ .metal = true });

pub const write = impl.write;

test "registry exposes exactly the RISC-V Metal capability" {
    var storage: [4096]u8 = undefined;
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
    inline for (.{ "cuda", "cairo", "wide_fibonacci", "poseidon" }) |forbidden| {
        try std.testing.expect(std.mem.indexOf(u8, encoded, forbidden) == null);
    }
}
