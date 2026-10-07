//! Verifier-owned ProgramV2 instruction list without any leaf identity bytes.
//! The native plan, PCS profile, wire length and descriptor mix are explicit
//! template inputs. This is a schedule commitment, not a native AIR owner.
const std = @import("std");
const schedule = @import("air/verifier_schedule.zig");
const transcript = @import("transcript_program_v2_contract.zig");
const statement = @import("../air/statement.zig");
const lookup = @import("../air/lang/lookup_physical_manifest_v2.zig");
const security = @import("segment_v3_production_security_policy.zig");

pub const DOMAIN = "stwo-zig/riscv-native-instruction-template/v6\x00";
pub const PRODUCTION_PROOF_ACTIVATION = false;

pub const InstructionTemplateV6 = struct {
    native_plan_id: [8]u32,
    wire_word_count: u32,
    lookup_enabled: bool,
    instruction_count: u32,
    canonical_program_word_count: u32,
    schedule_id: [32]u8,

    pub fn build(
        allocator: std.mem.Allocator,
        plan: *const schedule.Plan,
        wire_word_count: u32,
        component_descs: []const statement.FamilyComponentDesc,
        infra_descs: []const statement.InfraComponentDesc,
        lookup_enabled: bool,
    ) !InstructionTemplateV6 {
        const owned = try compileInstructions(allocator, plan, wire_word_count, component_descs, infra_descs, lookup_enabled);
        defer allocator.free(owned);
        const instructions = owned;
        const canonical_count = try std.math.add(usize, 43 + if (lookup_enabled) @as(usize, 112) else 0, try std.math.mul(usize, 13, instructions.len));
        if (canonical_count > std.math.maxInt(u32)) return error.InvalidInstructionTemplateV6;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(DOMAIN);
        for (plan.authority_digest) |word| hashInt(&hash, u32, word);
        hashInt(&hash, u32, wire_word_count);
        hashInt(&hash, u8, @intFromBool(lookup_enabled));
        hashInt(&hash, u32, @intCast(instructions.len));
        for (instructions) |instruction| {
            hashInt(&hash, u8, @intFromEnum(instruction.kind));
            hashInt(&hash, u32, instruction.verifier_sequence);
            hashInt(&hash, u32, instruction.sub_index);
            for (instruction.args) |arg| hashInt(&hash, u32, arg);
        }
        return .{
            .native_plan_id = plan.authority_digest,
            .wire_word_count = wire_word_count,
            .lookup_enabled = lookup_enabled,
            .instruction_count = @intCast(instructions.len),
            .canonical_program_word_count = @intCast(canonical_count),
            .schedule_id = hash.finalResult(),
        };
    }
};

/// Rebuilds descriptor words from admitted geometry; no leaf proof or
/// ProgramV2 object is accepted as a source of fixed preprocessing.
pub fn compileInstructions(
    allocator: std.mem.Allocator,
    plan: *const schedule.Plan,
    wire_word_count: u32,
    component_descs: []const statement.FamilyComponentDesc,
    infra_descs: []const statement.InfraComponentDesc,
    lookup_enabled: bool,
) ![]transcript.Instruction {
    try plan.validate();
    try transcript.validatePlanPrefix(plan);
    try transcript.validatePcsAgainstPlan(security.REQUIRED_PCS_CONFIG, plan);
    var interaction_pow_steps: usize = 0;
    for (plan.steps) |step| switch (step) {
        .verify_and_absorb_interaction_pow => |pow| {
            if (pow.bits != security.REQUIRED_INTERACTION_POW_BITS)
                return error.InsecureInstructionTemplateV6;
            interaction_pow_steps += 1;
        },
        else => {},
    };
    if (interaction_pow_steps != 1) return error.InsecureInstructionTemplateV6;
    if (wire_word_count == 0 or
        component_descs.len > statement.MAX_COMPONENTS or
        infra_descs.len > statement.MAX_INFRA_COMPONENTS)
        return error.InvalidInstructionTemplateV6;
    var manifest = lookup.Manifest.native();
    const activation = if (lookup_enabled) blk: {
        var core: statement.RiscVStatement = undefined;
        core.n_components = @intCast(component_descs.len);
        @memcpy(core.component_descs[0..component_descs.len], component_descs);
        break :blk try lookup.AuthenticatedStatement.init(&core, &manifest);
    } else null;
    var instructions: std.ArrayList(transcript.Instruction) = .empty;
    errdefer instructions.deinit(allocator);
    try transcript.buildInstructions(
        allocator,
        &instructions,
        plan,
        security.REQUIRED_PCS_CONFIG,
        wire_word_count,
        component_descs,
        infra_descs,
        activation,
        if (lookup_enabled) &manifest else null,
    );
    if (instructions.items.len == 0 or instructions.items.len > std.math.maxInt(u32))
        return error.InvalidInstructionTemplateV6;
    return instructions.toOwnedSlice(allocator);
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}
