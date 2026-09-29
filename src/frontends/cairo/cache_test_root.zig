//! Explicit discovery of the public cache tests without AIR code generation.
comptime {
    @import("std").testing.refAllDeclsRecursive(@import("codegen/field_shapes_test.zig"));
    @import("std").testing.refAllDeclsRecursive(@import("preprocessed/prepared_columns_cache_test.zig"));
    @import("std").testing.refAllDeclsRecursive(@import("preprocessed/tree_digest_cache.zig"));
    @import("std").testing.refAllDeclsRecursive(@import("preprocessed/product_cache.zig"));
}
