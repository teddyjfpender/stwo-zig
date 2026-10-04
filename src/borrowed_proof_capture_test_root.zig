//! No STARK proof, native callback, driver or segment is invoked.
test {
    _ = @import("core/tests/borrowed_proof_capture_test.zig");
    _ = @import("core/tests/borrowed_pcs_capture_success_test.zig");
}
