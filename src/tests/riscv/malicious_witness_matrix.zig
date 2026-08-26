//! Reusable mutation/rejection accounting for the CP-12 verifier matrix.

const std = @import("std");
const riscv_cpu = @import("stwo_riscv_cpu_integration");
const prover = @import("stwo_riscv_frontend").prover_mod;
const postcard = @import("interop_postcard");
const transcript = @import("stwo_riscv_frontend").air.transcript;
const pcs_core = @import("stwo_core").pcs;

/// One prove, many verify attempts: every attempt decodes a fresh proof from
/// the shared wire bytes because `verifyRiscV` consumes the proof it is given.
pub const RejectionMatrix = struct {
    allocator: std.mem.Allocator,
    config: pcs_core.PcsConfig,
    proof_bytes: []const u8,
    tree0_root: prover.Hasher.Hash,
    tree1_root: prover.Hasher.Hash,
    statement: prover.RiscVStatement,
    claim: prover.RiscVInteractionClaim,
    rejected: usize = 0,
    pow_rejected: usize = 0,
    logup_rejected: usize = 0,
    bound_pow_classified: usize = 0,
    bound_logup_classified: usize = 0,

    pub fn cloneProof(self: *const RejectionMatrix) !prover.Proof {
        var stream = std.io.fixedBufferStream(self.proof_bytes);
        return postcard.deserializeProof(prover.Hasher, self.allocator, stream.reader());
    }

    /// Classify the exact verifier boundary reached by a statement mutation.
    pub fn expectedBoundRejection(
        self: *RejectionMatrix,
        statement: prover.RiscVStatement,
    ) anyerror {
        var channel = riscv_cpu.CpuProverEngine.Channel{};
        self.config.mixInto(&channel);
        statement.public_data.mixInto(&channel);
        riscv_cpu.CpuProverEngine.MerkleChannel.mixRoot(&channel, self.tree0_root);
        riscv_cpu.CpuProverEngine.MerkleChannel.mixRoot(&channel, self.tree1_root);
        const main_claim = statement.canonicalMainClaim();
        main_claim.mixInto(&channel);
        statement.mixShardManifest(&channel);
        if (channel.verifyPowNonce(transcript.INTERACTION_POW_BITS, self.claim.interaction_pow)) {
            self.bound_logup_classified += 1;
            return error.LogupSumNonZero;
        }
        self.bound_pow_classified += 1;
        return error.InvalidInteractionProofOfWork;
    }

    fn expectRejected(
        self: *RejectionMatrix,
        label: []const u8,
        index: usize,
        sub: usize,
        expected_error: anyerror,
        statement: prover.RiscVStatement,
        claim: prover.RiscVInteractionClaim,
    ) !void {
        const proof = try self.cloneProof();
        const result = riscv_cpu.verifyRiscV(
            self.allocator,
            self.config,
            statement,
            proof,
            &claim,
        );
        if (result) |_| {
            std.debug.print("forged {s}[{d}][{d}] was accepted\n", .{
                label,
                index,
                sub,
            });
            return error.ForgedWitnessAccepted;
        } else |actual_error| {
            if (actual_error != expected_error) {
                std.debug.print(
                    "forged {s}[{d}][{d}] rejected as {s}, expected {s}\n",
                    .{
                        label,
                        index,
                        sub,
                        @errorName(actual_error),
                        @errorName(expected_error),
                    },
                );
                return error.UnexpectedRejectionClass;
            }
            switch (actual_error) {
                error.InvalidInteractionProofOfWork => self.pow_rejected += 1,
                error.LogupSumNonZero => self.logup_rejected += 1,
                else => {},
            }
        }
        self.rejected += 1;
    }

    pub fn expectClaimRejected(
        self: *RejectionMatrix,
        label: []const u8,
        index: usize,
        sub: usize,
        expected_error: anyerror,
        claim: prover.RiscVInteractionClaim,
    ) !void {
        try self.expectRejected(
            label,
            index,
            sub,
            expected_error,
            self.statement,
            claim,
        );
    }

    pub fn expectStatementRejected(
        self: *RejectionMatrix,
        label: []const u8,
        index: usize,
        expected_error: anyerror,
        statement: prover.RiscVStatement,
    ) !void {
        try self.expectRejected(
            label,
            index,
            0,
            expected_error,
            statement,
            self.claim,
        );
    }
};
