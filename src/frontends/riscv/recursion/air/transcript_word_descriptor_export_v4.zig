//! Dormant row4 variant: export the instruction kind and args from the same
//! native transcript-word preprocessing that consumes row5 payload tuples.
//! Only a selected payload row can export. Tag offset, canonical indices and
//! u16 limbs are preprocessing; the AIR enforces recomposition and uses the
//! actual native row4 tag/args, while the detached verifier must independently
//! recompile those preprocessing values from an admitted ProgramV2 identity.
//! This does not source verifier_sequence, sub_index, or zero-payload draws.
const std = @import("std");
const core = @import("stwo_core");
const word = @import("transcript_word.zig");
const lang = @import("../../air/lang/definition.zig");
const relation_effect = @import("relation_effect.zig");
const bridge = @import("transcript_program_v2_field_bridge_v5.zig");

const M31 = core.fields.m31.M31;
const Id = lang.types.ValueId;
const Span = lang.source.SourceSpan;

pub const STABLE_NAME = "recursion.transcript_word.instruction_export.v4";
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const COMPLETE_INSTRUCTION_EXPORT_AVAILABLE = false;
pub const EXTRA_PREPROCESSED_COLUMN_COUNT: usize = 11;
pub const LOGICAL_INPUT_COUNT: usize = word.LOGICAL_INPUT_COUNT + EXTRA_PREPROCESSED_COLUMN_COUNT;
pub const EXTRA_CONSTRAINT_COUNT: usize = 7;
pub const EXTRA_EVENT_COUNT: usize = 9;
pub const TOTAL_EVENT_COUNT: usize = word.RELATION_EVENT_COUNT + EXTRA_EVENT_COUNT;
pub const SEMANTIC_DIGEST_HEX = "e6f72e046c27ffe99d3fb7bfe186fccda192b6df2228b415efadac9c897df182";
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, SEMANTIC_DIGEST_HEX) catch
        @compileError("invalid row4 instruction export digest");
    break :blk result;
};

pub const ExtraRow = [EXTRA_PREPROCESSED_COLUMN_COUNT]M31;
pub const Row = [LOGICAL_INPUT_COUNT]M31;

pub const Definition = struct {
    base: word.Definition,
    roots: [EXTRA_CONSTRAINT_COUNT]Id,
    events: [EXTRA_EVENT_COUNT]lang.types.EffectId,

    pub fn deinit(self: *Definition) void {
        self.base.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.base.arena);
        if (self.base.arena.constraintsView().len != word.DIRECT_CONSTRAINT_COUNT + EXTRA_CONSTRAINT_COUNT or
            self.base.arena.effectsView().len != TOTAL_EVENT_COUNT)
            return error.InvalidInstructionExportDefinition;
        const actual = (try lang.digest.computeIdentity(&self.base.arena)).bytes;
        if (!std.mem.eql(u8, &actual, &SEMANTIC_DIGEST))
            return error.InvalidInstructionExportDefinition;
        for (self.roots, 0..) |root, index| {
            const constraint = self.base.arena.constraintsView()[word.DIRECT_CONSTRAINT_COUNT + index];
            if (constraint.root != root or constraint.gate != null or constraint.category != .semantic)
                return error.InvalidInstructionExportDefinition;
        }
        for (self.events, 0..) |event, index|
            if (lang.types.idIndex(event) != word.RELATION_EVENT_COUNT + index)
                return error.InvalidInstructionExportDefinition;
    }
};

pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = try buildRaw(allocator);
    errdefer result.deinit();
    try result.validate();
    return result;
}

pub fn computeSemanticDigest(allocator: std.mem.Allocator) ![32]u8 {
    var result = try buildRaw(allocator);
    defer result.deinit();
    return (try lang.digest.computeIdentity(&result.base.arena)).bytes;
}

fn buildRaw(allocator: std.mem.Allocator) !Definition {
    var base = try word.build(allocator);
    errdefer base.deinit();
    const arena = &base.arena;
    const span = Span.generated();
    const selected = try arena.input("row4_descriptor.selected", .selector, span);
    const tag_offset = try arena.input("row4_descriptor.tag_offset", .felt, span);
    const canonical_base = try arena.input("row4_descriptor.canonical_base", .felt, span);
    var limbs: [8]Id = undefined;
    for (&limbs, 0..) |*limb, index| {
        var name: [64]u8 = undefined;
        limb.* = try arena.input(try std.fmt.bufPrint(&name, "row4_descriptor.arg_limb_{d}", .{index}), .felt, span);
    }
    const one = try arena.constantField(1, span);
    const power16 = try arena.constantField(65536, span);
    const active = try arena.mul(base.active, selected, span);
    var roots: [EXTRA_CONSTRAINT_COUNT]Id = undefined;
    roots[0] = try arena.mul(selected, try arena.sub(selected, one, span), span);
    roots[1] = try arena.mul(selected, try arena.sub(one, base.preprocessed.is_payload, span), span);
    roots[2] = try arena.mul(selected, try arena.sub(one, base.preprocessed.row_mask, span), span);
    for (0..4) |arg| {
        const recomposed = try arena.add(limbs[2 * arg], try arena.mul(power16, limbs[2 * arg + 1], span), span);
        roots[3 + arg] = try arena.mul(selected, try arena.sub(recomposed, base.preprocessed.args[arg], span), span);
    }
    for (roots, 0..) |root, index| {
        var name: [64]u8 = undefined;
        _ = try arena.assertZero(try std.fmt.bufPrint(&name, "row4_descriptor.constraint_{d}", .{index}), root, null, .semantic, span);
    }
    const scope = try arena.constantField(bridge.NATIVE_EXPORT_SCOPE, span);
    const raw_kind = try arena.sub(base.preprocessed.tag, tag_offset, span);
    const payloads = [_]Id{raw_kind} ++ limbs;
    const canonical_offsets = [_]u32{ 0, 5, 6, 7, 8, 9, 10, 11, 12 };
    var tuples: [EXTRA_EVENT_COUNT][3]Id = undefined;
    var specs: [EXTRA_EVENT_COUNT]relation_effect.EventSpec = undefined;
    for (&tuples, &specs, payloads, canonical_offsets) |*tuple, *spec, payload, offset| {
        tuple.* = .{ scope, try arena.add(canonical_base, try arena.constantField(offset, span), span), payload };
        spec.* = .{ .domain = .recursion_vm_public_claim_word, .role = .emit, .values = tuple, .weight = active };
    }
    const events = try relation_effect.appendGroup(EXTRA_EVENT_COUNT, arena, specs, span);
    return .{ .base = base, .roots = roots, .events = events };
}
