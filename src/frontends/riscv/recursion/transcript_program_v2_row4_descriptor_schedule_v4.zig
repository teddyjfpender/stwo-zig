//! Fixed native-row4 selection for the dormant instruction descriptor export.
//! It selects one existing payload word per instruction, never invents a row.
//! The selected preprocessing must be independently rebuilt into the native
//! Tree0 root; this host schedule alone is not proof authority.
const std = @import("std");
const core = @import("stwo_core");
const transcript = @import("transcript_program_v2.zig");
const origins = @import("transcript_program_v2_word_origins_v4.zig");
const native = @import("segment_transcript_outer_source_v2_contract.zig");
const export_air = @import("air/transcript_word_descriptor_export_v4.zig");
const native_word = @import("air/transcript_word.zig");

const M31 = core.fields.m31.M31;

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const Entry = struct {
    row_index: ?usize = null,
    canonical_base: u32,
    tag_offset: u32,
    args: [4]u32,
};

pub const Coverage = struct {
    total_instructions: usize,
    selected_kind_arg_sources: usize,
    missing_row4_payload: usize,
    missing_verifier_sequence_source: usize,
    missing_sub_index_source: usize,

    pub fn requireComplete(self: Coverage) !void {
        if (self.missing_row4_payload != 0 or
            self.missing_verifier_sequence_source != 0 or
            self.missing_sub_index_source != 0)
            return error.IncompleteInstructionDescriptorSource;
    }
};

pub const Schedule = struct {
    allocator: std.mem.Allocator,
    entries: []Entry,

    pub fn init(allocator: std.mem.Allocator, program: *const transcript.Program, rows: anytype) !Schedule {
        var map = try origins.Map.init(allocator, program);
        defer map.deinit();
        const entries = try allocator.alloc(Entry, program.instructions.len);
        errdefer allocator.free(entries);
        for (program.instructions, entries, 0..) |instruction, *entry, instruction_index| {
            const canonical_base = for (map.origins, 0..) |origin, index| {
                if (origin.kind == .instruction_kind and origin.ordinal == instruction_index)
                    break std.math.cast(u32, index) orelse return error.DescriptorIndexOverflow;
            } else return error.MissingCanonicalInstructionIndex;
            const tag = native.typedTag(instruction.kind);
            const kind: u32 = @intFromEnum(instruction.kind);
            const offset = if (tag >= kind) tag - kind else core.fields.m31.Modulus - (kind - tag);
            entry.* = .{
                .canonical_base = canonical_base,
                .tag_offset = offset,
                .args = instruction.args,
            };
        }
        for (rows, 0..) |row, row_index| {
            const pp = row.preprocessing;
            if (pp.row_mask == 0 or pp.is_payload == 0 or pp.payload_index != 0) continue;
            if (pp.is_payload != 1 or pp.word_index != native_word.RATE or
                pp.segment_mask != 1 or pp.binary_mask != 0 or pp.verifier_id != 0 or
                pp.sequence >= entries.len)
                return error.InvalidNativeInstructionPayloadRow;
            const entry = &entries[pp.sequence];
            const instruction = program.instructions[pp.sequence];
            if (entry.row_index != null) return error.DuplicateNativeInstructionPayloadOrigin;
            if (pp.tag != native.typedTag(instruction.kind) or
                !std.meta.eql(pp.args, instruction.args))
                return error.NativeInstructionDescriptorMismatch;
            entry.row_index = row_index;
        }
        return .{ .allocator = allocator, .entries = entries };
    }

    pub fn deinit(self: *Schedule) void {
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn coverage(self: *const Schedule) Coverage {
        var selected: usize = 0;
        for (self.entries) |entry| selected += @intFromBool(entry.row_index != null);
        return .{
            .total_instructions = self.entries.len,
            .selected_kind_arg_sources = selected,
            .missing_row4_payload = self.entries.len - selected,
            // Neither field exists in the native row4 descriptor. A future
            // versioned row0-9 descriptor owner must supply both.
            .missing_verifier_sequence_source = self.entries.len,
            .missing_sub_index_source = self.entries.len,
        };
    }

    pub fn extraRow(self: *const Schedule, row_index: usize) export_air.ExtraRow {
        for (self.entries) |entry| {
            if (entry.row_index != row_index) continue;
            var result = [_]M31{M31.zero()} ** export_air.EXTRA_PREPROCESSED_COLUMN_COUNT;
            result[0] = M31.one();
            result[1] = M31.fromCanonical(entry.tag_offset);
            result[2] = M31.fromCanonical(entry.canonical_base);
            for (entry.args, 0..) |arg, index| {
                result[3 + 2 * index] = M31.fromCanonical(arg & 0xffff);
                result[4 + 2 * index] = M31.fromCanonical(arg >> 16);
            }
            return result;
        }
        return [_]M31{M31.zero()} ** export_air.EXTRA_PREPROCESSED_COLUMN_COUNT;
    }

    /// The detached verifier must compare the full rebuilt preprocessing
    /// against the committed Tree0 root. This check is a local prerequisite,
    /// not an alternative to that independent root recomputation.
    pub fn validateExtraRow(self: *const Schedule, row_index: usize, candidate: export_air.ExtraRow) !void {
        const expected = self.extraRow(row_index);
        for (candidate, expected) |actual, reference|
            if (!actual.eql(reference)) return error.IncorrectNativeDescriptorPreprocessing;
    }
};
