//! Machine-readable identity for the Cairo CPU/SIMD product.

const generated = @import("product_identity");
const package = @import("stwo_cairo_cpu");
const shared = @import("cairo_product").identity;

const registry = package.frontends.cairo.claim_registry;

pub const Value = shared.Value(generated, registry);

pub fn value() Value {
    return shared.value(generated, registry);
}

pub fn write(writer: anytype) !void {
    try shared.write(generated, registry, writer);
}
