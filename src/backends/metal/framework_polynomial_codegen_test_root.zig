//! Device-free gate for recursive framework polynomial source generation.
test {
    _ = @import("runtime/framework_polynomial_codegen.zig");
    _ = @import("runtime/framework_polynomial_jobs.zig");
    _ = @import("runtime/framework_polynomial_codegen_test.zig");
}
