//! Backend-neutral proof execution descriptions.

pub const proof_program = @import("stwo_backend_contracts").proof_program;
pub const request_service = @import("request_service.zig");

pub const ProofProgram = proof_program.ProofProgram;

test {
    _ = proof_program;
    _ = request_service;
    _ = @import("request_service_test.zig");
}
