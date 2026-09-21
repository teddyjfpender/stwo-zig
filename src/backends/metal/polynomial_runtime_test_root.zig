//! Focused codegen/quotient tests for the resident polynomial runtime.

test {
    _ = @import("runtime/base_polynomial_codegen.zig");
    _ = @import("runtime/lookup_polynomial_codegen.zig");
    _ = @import("runtime/lookup_polynomial_v2_codegen.zig");
    _ = @import("runtime/polynomial_quotient_geometry.zig");
}
