//! Backend-neutral proof execution descriptions.

pub const proof_program = @import("stwo_backend_contracts").proof_program;

pub const ProofProgram = proof_program.ProofProgram;

test {
    _ = proof_program;
}
