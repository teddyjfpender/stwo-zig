//! Shared frontend admission boundary for resident CUDA execution providers.

const std = @import("std");
const execution_plan = @import("runtime/execution_plan.zig");
const provider = @import("runtime/provider.zig");
const proof_ir = @import("stwo_backend_contracts").proof_program;

pub const Level = enum(u8) {
    structural = 1,
    development_execution = 2,
    production_execution = 3,
};

pub const Evidence = struct {
    /// Identity of the authenticated frontend-specific AOT selection.
    aot: proof_ir.Digest,
    /// Independent semantic/parity evidence for this frontend/backend pair.
    parity: proof_ir.Digest,
    /// Provider-specific translation or device-acceptance evidence.
    provider: proof_ir.Digest,
    aot_complete: bool,
    parity_complete: bool,
    provider_complete: bool,
};

pub const Request = struct {
    frontend: proof_ir.Frontend,
    level: Level,
    evidence: Evidence,
};

pub const Receipt = struct {
    frontend: proof_ir.Frontend,
    provider: provider.Kind,
    evidence_class: provider.EvidenceClass,
    level: Level,
    statement: proof_ir.Digest,
    semantic_program: proof_ir.Digest,
    complete_program: proof_ir.Digest,
    plan: proof_ir.Digest,
    aot: proof_ir.Digest,
    parity: proof_ir.Digest,
    provider_evidence: proof_ir.Digest,

    pub fn validate(self: Receipt) Error!void {
        if (empty(self.statement) or
            empty(self.semantic_program) or
            empty(self.complete_program) or
            empty(self.plan) or
            empty(self.aot) or
            empty(self.parity) or
            empty(self.provider_evidence) or
            self.evidence_class != provider.evidenceClass(self.provider))
        {
            return error.InvalidFrontendReceipt;
        }
    }

    /// Admits this structural plan only to the runtime provider that was part
    /// of its cache key. This is required even before execution evidence is
    /// promoted beyond the structural level.
    pub fn requireProvider(
        self: Receipt,
        runtime_provider: provider.Kind,
    ) Error!void {
        try self.validate();
        if (self.provider != runtime_provider)
            return error.RuntimeProviderMismatch;
    }

    /// Stronger admission for callers that claim an execution-qualified
    /// frontend/backend pairing. Structural receipts deliberately fail here.
    pub fn requireExecution(
        self: Receipt,
        runtime_provider: provider.Kind,
    ) Error!void {
        try self.requireProvider(runtime_provider);
        if (self.level == .structural)
            return error.ExecutionEvidenceIncomplete;
    }
};

pub const Error = error{
    AotIncomplete,
    FrontendMismatch,
    InvalidFrontendReceipt,
    ParityIncomplete,
    ProviderEvidenceIncomplete,
    RuntimeProviderMismatch,
    ExecutionEvidenceIncomplete,
};

pub fn admit(
    program: proof_ir.ProofProgram,
    plan: execution_plan.CudaPlan,
    request: Request,
) Error!Receipt {
    if (program.identity.frontend != request.frontend)
        return error.FrontendMismatch;
    if (request.level != .structural) {
        if (!request.evidence.aot_complete) return error.AotIncomplete;
        if (!request.evidence.parity_complete) return error.ParityIncomplete;
        if (!request.evidence.provider_complete)
            return error.ProviderEvidenceIncomplete;
    }
    const receipt = Receipt{
        .frontend = request.frontend,
        .provider = plan.target.provider,
        .evidence_class = provider.evidenceClass(plan.target.provider),
        .level = request.level,
        .statement = program.identity.statement,
        .semantic_program = program.semantic_digest,
        .complete_program = program.program_digest,
        .plan = plan.cache_key,
        .aot = request.evidence.aot,
        .parity = request.evidence.parity,
        .provider_evidence = request.evidence.provider,
    };
    try receipt.validate();
    return receipt;
}

/// Binds a frontend program to a provider-specific plan without claiming that
/// execution, parity, or production acceptance is complete.
pub fn admitStructural(
    program: proof_ir.ProofProgram,
    plan: execution_plan.CudaPlan,
) Error!Receipt {
    return admit(program, plan, .{
        .frontend = program.identity.frontend,
        .level = .structural,
        .evidence = .{
            .aot = plan.target.kernel_pack_identity,
            .parity = program.semantic_digest,
            .provider = plan.target.runtime_build_identity,
            .aot_complete = false,
            .parity_complete = false,
            .provider_complete = false,
        },
    });
}

fn empty(value: proof_ir.Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}

test "execution admission requires all three independent evidence classes" {
    const testing = @import("runtime/execution_plan.zig").testing;
    const allocator = std.testing.allocator;
    var program = try testing.program(allocator, .native);
    defer program.deinit(allocator);
    var plan = try execution_plan.CudaPlan.compile(
        allocator,
        program,
        testing.target(.cumetal),
    );
    defer plan.deinit(allocator);
    const identity = proof_ir.identityDigest("complete");
    const base = Request{
        .frontend = .native,
        .level = .production_execution,
        .evidence = .{
            .aot = identity,
            .parity = identity,
            .provider = identity,
            .aot_complete = true,
            .parity_complete = true,
            .provider_complete = false,
        },
    };
    try std.testing.expectError(
        error.ProviderEvidenceIncomplete,
        admit(program, plan, base),
    );
    var complete = base;
    complete.evidence.provider_complete = true;
    const receipt = try admit(program, plan, complete);
    try std.testing.expectEqual(provider.Kind.cumetal, receipt.provider);
    try std.testing.expectEqual(
        provider.EvidenceClass.apple_gpu_translation,
        receipt.evidence_class,
    );
    try receipt.requireExecution(.cumetal);
    try std.testing.expectError(
        error.RuntimeProviderMismatch,
        receipt.requireExecution(.nvidia_cuda),
    );
}

test "structural admission binds a provider but cannot claim execution" {
    const testing = @import("runtime/execution_plan.zig").testing;
    const allocator = std.testing.allocator;
    var program = try testing.program(allocator, .native);
    defer program.deinit(allocator);
    var plan = try execution_plan.CudaPlan.compile(
        allocator,
        program,
        testing.target(.cumetal),
    );
    defer plan.deinit(allocator);
    const receipt = try admitStructural(program, plan);
    try receipt.requireProvider(.cumetal);
    try std.testing.expectError(
        error.ExecutionEvidenceIncomplete,
        receipt.requireExecution(.cumetal),
    );
}
