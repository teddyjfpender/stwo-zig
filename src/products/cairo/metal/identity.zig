//! Machine-readable identity for the Cairo Metal product.

const std = @import("std");
const generated = @import("product_identity");
const package = @import("stwo_cairo_metal");
const shared = @import("cairo_product").identity;

const registry = package.frontends.cairo.claim_registry;

pub const Value = shared.Value(generated, registry);

pub fn value() Value {
    return shared.value(generated, registry);
}

pub fn write(writer: anytype) !void {
    try shared.write(generated, registry, writer);
}

test "Cairo Metal identity binds the composition eval-domain AOT" {
    const digest = "06435e82fcae331f952e2eab66dfd58ecb4166b1197b554b336c033f845bacfb";
    try std.testing.expect(std.mem.indexOf(u8, generated.runtime_manifest, digest) != null);
    try std.testing.expect(std.mem.indexOf(u8, generated.aot_manifest, digest) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        generated.aot_manifest,
        "air_template_composition_eval_domain_v1",
    ) != null);
}
