//! Required native row3 descriptor owner for all ProgramV2 instructions.
//!
//! Row4 can export kind/args only for instructions with a payload word. Row3
//! has a call even for zero-payload draws and its sequence is consumed by the
//! native `recursion_step` relation. It lacks instruction ordinal, raw kind,
//! raw args and sub-index. A future fixed-key row3 variant must add those
//! columns and the equations below; copying ProgramV2 into separate main rows
//! would not prove that the native verifier executed that program.
const std = @import("std");
const transcript = @import("transcript_program_v2.zig");
const schedule = @import("air/verifier_schedule.zig");

pub const VERSION: u16 = 1;
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const COMPLETE_NATIVE_OWNER_AVAILABLE = false;

/// These are mandatory before a direct wrapper may source instruction words.
pub const RequiredEquation = enum {
    /// One row3 first-call selector per ProgramV2 instruction, including
    /// adjacent instructions with the same verifier sequence.
    distinct_instruction_first_call,
    /// The selected row is the actual native call: its call/hash IDs, step 0,
    /// and first-call bit are constrained by the row3 hash-call relations.
    selected_call_native_relation_join,
    /// Canonical sequence limbs recompose to row3's existing sequence, which
    /// is consumed through `recursion_step` against the native plan.
    sequence_u16_recomposition,
    /// The key owns canonical raw kind, sub-index and argument limbs, and is
    /// independently recompiled from the admitted ProgramV2/plan identity.
    descriptor_key_recompilation,
    /// Raw kind/args and sub-index must select the same native instruction
    /// operation that produced this first call; a host label is insufficient.
    operation_descriptor_equivalence,
    /// Every canonical word is emitted once under its assigned NPV2 index;
    /// absent and duplicate instruction owners fail the relation closure.
    exact_npv2_instruction_closure,
};

pub const REQUIRED_EQUATIONS = [_]RequiredEquation{
    .distinct_instruction_first_call,
    .selected_call_native_relation_join,
    .sequence_u16_recomposition,
    .descriptor_key_recompilation,
    .operation_descriptor_equivalence,
    .exact_npv2_instruction_closure,
};

pub const Anchor = struct {
    instruction_index: u32,
    row3_call_index: usize,
    first_hash_id: u32,
    verifier_sequence: u32,
};

/// Diagnostic only. This checks where a future row3 descriptor selector would
/// attach to the *already written* native trace; it emits no NPV2 relations.
pub const AnchorAudit = struct {
    allocator: std.mem.Allocator,
    anchors: []Anchor,

    pub fn init(
        allocator: std.mem.Allocator,
        program: *const transcript.Program,
        plan: *const schedule.Plan,
        operations: []const transcript.Operation,
        row3: anytype,
    ) !AnchorAudit {
        if (operations.len != program.instructions.len) return error.NativeOperationCountMismatch;
        const anchors = try allocator.alloc(Anchor, operations.len);
        errdefer allocator.free(anchors);
        for (program.instructions, operations, anchors, 0..) |instruction, operation, *anchor, index| {
            if (operation.instruction_index != index or operation.call_count == 0 or
                operation.hash_count == 0 or operation.first_call_id >= row3.len or
                instruction.verifier_sequence >= plan.steps.len)
                return error.InvalidNativeInstructionAnchor;
            const preprocessed = row3[operation.first_call_id].preprocessing;
            const encoded = plan.steps[instruction.verifier_sequence].encode();
            if (preprocessed.row_mask != 1 or preprocessed.segment_mask != 1 or
                preprocessed.binary_mask != 0 or preprocessed.verifier_id != 0 or
                preprocessed.call_id != operation.first_call_id or
                preprocessed.hash_id != operation.first_hash_id or
                preprocessed.hash_step != 0 or preprocessed.is_first != 1 or
                preprocessed.sequence != instruction.verifier_sequence or
                preprocessed.tag != encoded.tag or
                !std.meta.eql(preprocessed.args, encoded.args))
                return error.InvalidNativeInstructionAnchor;
            anchor.* = .{
                .instruction_index = @intCast(index),
                .row3_call_index = operation.first_call_id,
                .first_hash_id = operation.first_hash_id,
                .verifier_sequence = instruction.verifier_sequence,
            };
        }
        return .{ .allocator = allocator, .anchors = anchors };
    }

    pub fn deinit(self: *AnchorAudit) void {
        self.allocator.free(self.anchors);
        self.* = undefined;
    }

    pub fn requireProofVisibleOwner(self: *const AnchorAudit) !void {
        _ = self;
        return error.MissingProofVisibleInstructionOwner;
    }
};
