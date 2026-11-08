//! No STARK proof, native callback, driver or segment is invoked.
test {
    _ = @import("tests/borrowed_proof_capture_test.zig");
    _ = @import("tests/borrowed_pcs_capture_success_test.zig");
}
