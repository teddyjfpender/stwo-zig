//! RISC-V frontend binding for the resident CUDA architecture.
//!
//! This package owns the formal frontend/backend seam. It compiles an RV32IM
//! `ProofProgram` into a provider-bound CUDA plan and binds the independent AIR
//! satisfaction and Lean refinement identities into the admission receipt.
//! Device execution remains fail closed until the RISC-V AOT catalogue and
//! end-to-end parity gate are complete.

const std = @import("std");
const backend = @import("stwo_cuda_backend");
const proof_ir = @import("stwo_backend_contracts").proof_program;

pub const frontend = @import("stwo_riscv_frontend");
pub const production_ready = false;
pub const execution_blocker =
    "RISC-V CUDA constraint AOT and end-to-end proof parity are incomplete";

pub const FormalEvidence = struct {
    air_satisfaction: proof_ir.Digest,
    lean_refinement: proof_ir.Digest,

    pub fn validate(self: FormalEvidence) !void {
        if (empty(self.air_satisfaction) or empty(self.lean_refinement))
            return error.FormalEvidenceAbsent;
    }

    pub fn identity(self: FormalEvidence) proof_ir.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig/riscv-cuda-formal-evidence/v1\x00");
        hash.update(&self.air_satisfaction);
        hash.update(&self.lean_refinement);
        var digest: proof_ir.Digest = undefined;
        hash.final(&digest);
        return digest;
    }
};

pub const Prepared = struct {
    program: proof_ir.ProofProgram,
    plan: backend.runtime.execution_plan.CudaPlan,
    receipt: backend.frontend_contract.Receipt,
    formal_evidence: FormalEvidence,

    pub fn deinit(self: *Prepared, allocator: std.mem.Allocator) void {
        self.plan.deinit(allocator);
        self.program.deinit(allocator);
        self.* = undefined;
    }
};

pub fn compile(
    allocator: std.mem.Allocator,
    program: *proof_ir.ProofProgram,
    target: backend.runtime.execution_plan.CompileOptions,
    evidence: FormalEvidence,
) !Prepared {
    if (program.identity.frontend != .riscv)
        return error.FrontendMismatch;
    try evidence.validate();
    var plan = try backend.runtime.execution_plan.CudaPlan.compile(
        allocator,
        program.*,
        target,
    );
    errdefer plan.deinit(allocator);
    const receipt = try backend.frontend_contract.admit(
        program.*,
        plan,
        .{
            .frontend = .riscv,
            .level = .structural,
            .evidence = .{
                .aot = target.kernel_pack_identity,
                .parity = evidence.identity(),
                .provider = target.runtime_build_identity,
                .aot_complete = false,
                .parity_complete = false,
                .provider_complete = false,
            },
        },
    );
    const owned_program = program.*;
    program.* = undefined;
    return .{
        .program = owned_program,
        .plan = plan,
        .receipt = receipt,
        .formal_evidence = evidence,
    };
}

pub fn requireExecution(_: *const Prepared) error{RiscVCudaExecutionUnavailable}!void {
    return error.RiscVCudaExecutionUnavailable;
}

fn empty(value: proof_ir.Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}

test "RISC-V binds formal evidence to NVIDIA and CuMetal plan identities" {
    const allocator = std.testing.allocator;
    const evidence = FormalEvidence{
        .air_satisfaction = proof_ir.identityDigest("air-satisfaction"),
        .lean_refinement = proof_ir.identityDigest("fv1-fv2"),
    };
    inline for (.{
        backend.runtime.provider.Kind.nvidia_cuda,
        backend.runtime.provider.Kind.cumetal,
    }) |provider| {
        var program = try backend.runtime.execution_plan.testing.program(
            allocator,
            .riscv,
        );
        var prepared = try compile(
            allocator,
            &program,
            backend.runtime.execution_plan.testing.target(provider),
            evidence,
        );
        defer prepared.deinit(allocator);
        try std.testing.expectEqual(provider, prepared.receipt.provider);
        try std.testing.expectEqual(
            proof_ir.Frontend.riscv,
            prepared.receipt.frontend,
        );
        try std.testing.expectError(
            error.RiscVCudaExecutionUnavailable,
            requireExecution(&prepared),
        );
    }
}

test "RISC-V structural admission rejects missing formal evidence" {
    const allocator = std.testing.allocator;
    var program = try backend.runtime.execution_plan.testing.program(
        allocator,
        .riscv,
    );
    defer program.deinit(allocator);
    try std.testing.expectError(error.FormalEvidenceAbsent, compile(
        allocator,
        &program,
        backend.runtime.execution_plan.testing.target(.cumetal),
        .{
            .air_satisfaction = [_]u8{0} ** 32,
            .lean_refinement = proof_ir.identityDigest("fv1-fv2"),
        },
    ));
}
