//! No STARK proof, native callback, driver or segment is invoked.
test "borrowed proof capture root collects retained fixtures" {
    _ = @import("borrowed_proof_capture_test.zig");
    _ = @import("borrowed_pcs_capture_success_test.zig");
}
