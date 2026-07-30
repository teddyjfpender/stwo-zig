//! Fail-closed receipt for one compiled Cairo CUDA request.

const std = @import("std");

pub const Blocker = enum(u8) {
    proof_derived_semantic_authority,
    component_aot_lowerings,
    resident_stage_hooks,
    terminal_proof_assembly,
};

const all_blockers_mask = blockerBit(.proof_derived_semantic_authority) |
    blockerBit(.component_aot_lowerings) |
    blockerBit(.resident_stage_hooks) |
    blockerBit(.terminal_proof_assembly);

pub const Receipt = struct {
    adapted_input_sha256: [32]u8,
    statement: [32]u8,
    semantic_program: [32]u8,
    complete_program: [32]u8,
    cuda_plan_cache_key: [32]u8,
    aot_lowering_identity: [32]u8,
    resident_plan_identity: [32]u8,
    missing_lowering_digest: [32]u8,
    component_count: u32,
    missing_lowering_count: u32,
    blocker_mask: u8,
    execution_admissible: bool = false,
    production_eligible: bool = false,

    pub fn hasBlocker(self: Receipt, blocker: Blocker) bool {
        return self.blocker_mask & blockerBit(blocker) != 0;
    }

    pub fn validate(self: Receipt) !void {
        if (self.component_count == 0 or
            digestEmpty(self.adapted_input_sha256) or
            digestEmpty(self.statement) or
            digestEmpty(self.semantic_program) or
            digestEmpty(self.complete_program) or
            digestEmpty(self.cuda_plan_cache_key) or
            digestEmpty(self.aot_lowering_identity) or
            digestEmpty(self.resident_plan_identity) or
            digestEmpty(self.missing_lowering_digest) or
            self.execution_admissible or self.production_eligible or
            self.blocker_mask != blockerMask(self.missing_lowering_count))
        {
            return error.InvalidCairoCudaAdmissionReceipt;
        }
    }
};

pub fn blockerMask(missing_lowering_count: u32) u8 {
    if (missing_lowering_count == 0)
        return all_blockers_mask & ~blockerBit(.component_aot_lowerings);
    return all_blockers_mask;
}

fn blockerBit(blocker: Blocker) u8 {
    return @as(u8, 1) << @intCast(@intFromEnum(blocker));
}

fn digestEmpty(value: [32]u8) bool {
    return std.mem.allEqual(u8, &value, 0);
}

test "receipt closes lowering inventory without opening execution" {
    const receipt = Receipt{
        .adapted_input_sha256 = [_]u8{1} ** 32,
        .statement = [_]u8{2} ** 32,
        .semantic_program = [_]u8{3} ** 32,
        .complete_program = [_]u8{4} ** 32,
        .cuda_plan_cache_key = [_]u8{5} ** 32,
        .aot_lowering_identity = [_]u8{7} ** 32,
        .resident_plan_identity = [_]u8{8} ** 32,
        .missing_lowering_digest = [_]u8{6} ** 32,
        .component_count = 58,
        .missing_lowering_count = 174,
        .blocker_mask = blockerMask(174),
    };
    try receipt.validate();
    try std.testing.expect(receipt.hasBlocker(.component_aot_lowerings));

    var forged = receipt;
    forged.execution_admissible = true;
    try std.testing.expectError(
        error.InvalidCairoCudaAdmissionReceipt,
        forged.validate(),
    );

    var lowered = receipt;
    lowered.missing_lowering_count = 0;
    lowered.blocker_mask = blockerMask(0);
    try lowered.validate();
    try std.testing.expect(!lowered.hasBlocker(.component_aot_lowerings));
    try std.testing.expect(lowered.hasBlocker(
        .proof_derived_semantic_authority,
    ));
    try std.testing.expect(lowered.hasBlocker(.resident_stage_hooks));
    try std.testing.expect(lowered.hasBlocker(.terminal_proof_assembly));
    try std.testing.expect(!lowered.execution_admissible);
    try std.testing.expect(!lowered.production_eligible);
}
