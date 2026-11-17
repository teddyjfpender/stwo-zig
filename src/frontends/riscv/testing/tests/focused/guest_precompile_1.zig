//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("cases/air/guest_precompile/tests/main_trace_test.zig");
    _ = @import("cases/air/guest_precompile/tests/lookup_registration_test.zig");
    _ = @import("cases/air/guest_precompile/tests/proof_admission_test.zig");
    _ = @import("cases/air/guest_precompile/tests/proof_transcript_test.zig");
    _ = @import("cases/air/guest_precompile/tests/proof_transcript_security_test.zig");
    _ = @import("cases/air/guest_precompile/tests/program_commitment_test.zig");
}
