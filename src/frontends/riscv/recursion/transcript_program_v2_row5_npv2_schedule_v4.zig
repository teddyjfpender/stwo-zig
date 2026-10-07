//! Exact dormant masks for native row-5 ProgramV2 word export.
//!
//! A future direct cohort calls this on its freshly written native transcript
//! payload rows. It cannot authorize a proof by itself: the versioned row-5
//! AIR must be committed, and all other NPV2 words must close separately.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const transcript = @import("transcript_program_v2.zig");
const mixed_program = @import("transcript_program_v2_program.zig");
const source = @import("segment_transcript_outer_source_v2.zig");
const air = @import("air/transcript_payload.zig");
const protocol = @import("segment_leaf_wrapper_protocol_direct_v4.zig");

pub const PRODUCTION_ACTIVATION = false;
pub const Entry = struct {
    wire_mask: u32 = 0,
    pcs_mask: u32 = 0,
    pcs_canonical_index: u32 = 0,
};

pub const Schedule = struct {
    allocator: std.mem.Allocator,
    entries: []Entry,

    pub fn init(allocator: std.mem.Allocator, program: *const transcript.Program, rows: anytype) !Schedule {
        if (!std.meta.eql(program.pcs_config, protocol.PCS_CONFIG))
            return error.UnexpectedNpv2PcsProfile;
        const entries = try allocator.alloc(Entry, rows.len);
        errdefer allocator.free(entries);
        @memset(entries, .{});
        var wire_seen = [_]bool{false} ** air.NPV2_WIRE_WORD_COUNT;
        var pcs_seen = [_]bool{false} ** air.NPV2_PCS_CANONICAL_INDICES.len;
        var mixed: [8]M31 = undefined;
        mixed_program.writePcsFelts(&mixed, program.pcs_config);
        for (rows, entries) |row, *entry| {
            if (row.source_kind == source.PayloadSourceKindV2.statement and row.item_index == 1) {
                if (row.limb_index >= wire_seen.len or wire_seen[row.limb_index] or
                    row.constant_mask != 0 or row.input_use_count != 1 or
                    row.value.toU32() != program.wire_id[row.limb_index])
                    return error.InvalidNpv2Row5WireSource;
                wire_seen[row.limb_index] = true;
                entry.wire_mask = 1;
            } else if (row.source_kind == source.PayloadSourceKindV2.pcs_parameters and row.item_index == 0 and row.limb_index < pcs_seen.len) {
                if (pcs_seen[row.limb_index] or row.constant_mask != 1 or
                    row.input_use_count != 0 or !row.value.eql(mixed[row.limb_index]))
                    return error.InvalidNpv2Row5PcsSource;
                pcs_seen[row.limb_index] = true;
                entry.pcs_mask = 1;
                entry.pcs_canonical_index = air.NPV2_PCS_CANONICAL_INDICES[row.limb_index];
            }
        }
        for (wire_seen) |seen| if (!seen) return error.IncompleteNpv2Row5WireSource;
        for (pcs_seen) |seen| if (!seen) return error.IncompleteNpv2Row5PcsSource;
        return .{ .allocator = allocator, .entries = entries };
    }

    pub fn deinit(self: *Schedule) void {
        self.allocator.free(self.entries);
        self.* = undefined;
    }
};
