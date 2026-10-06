//! Exact index map for the canonical ProgramV2 field preimage.
//!
//! Origins identify what must be joined to native verifier AIR. They are not
//! a witness and do not emit lookup tuples. Only the separately versioned
//! row-5 profile currently proves the wire-ID slice.
const std = @import("std");
const program_mod = @import("transcript_program_v2.zig");
const field = @import("transcript_program_v2_field_authority_v1.zig");
const profile = @import("segment_leaf_wrapper_protocol_direct_v4.zig");
const base_source = @import("segment_transcript_outer_source_v2_contract.zig");

pub const PRODUCTION_ACTIVATION = false;
pub const Kind = enum {
    format,
    schema,
    plan_id,
    wire_id,
    statement_authority_id,
    wire_word_count,
    pcs_parameter,
    lookup_activation,
    instruction_count,
    instruction_kind,
    instruction_sequence,
    instruction_sub_index,
    instruction_arg,
};

pub const Origin = struct {
    kind: Kind,
    /// Digest limb, low/high u16 limb, or instruction ordinal as appropriate.
    ordinal: u32,
    /// Index within that instruction's kind/sequence/sub-index/arg field.
    part: u8 = 0,
};

/// A route is an obligation, not a witness capability. `fixed_row42_required`
/// needs a versioned mode/equality AIR at row42 before any wrapper can close.
pub const Route = enum { row5_native, fixed_row42_required, unlinked };

pub fn route(origin: Origin) Route {
    return switch (origin.kind) {
        .wire_id => .row5_native,
        .format, .schema => .fixed_row42_required,
        .pcs_parameter => switch (origin.ordinal) {
            0, 2, 4, 6, 8, 11 => .row5_native,
            else => .fixed_row42_required,
        },
        else => .unlinked,
    };
}

pub const Coverage = struct {
    native_row5: usize = 0,
    fixed_row42_required: usize = 0,
    unlinked: usize = 0,

    pub fn complete(self: Coverage) bool {
        return self.unlinked == 0 and self.fixed_row42_required == 0;
    }

    /// The active direct cohort must call this before any authorization. Even
    /// with a versioned fixed-word bridge, unlinked instruction/identity words
    /// keep the entire ProgramV2 producer unqualified.
    pub fn requireComplete(self: Coverage) !void {
        if (self.fixed_row42_required != 0 or self.unlinked != 0)
            return error.IncompleteNpv2ProgramCoverage;
    }
};

pub const Map = struct {
    allocator: std.mem.Allocator,
    origins: []Origin,

    pub fn init(allocator: std.mem.Allocator, program: *const program_mod.Program) !Map {
        if (!std.meta.eql(program.pcs_config, profile.PCS_CONFIG))
            return error.UnexpectedNpv2PcsProfile;
        const canonical = try field.canonicalWords(allocator, program);
        defer allocator.free(canonical);
        const lookup_count = if (program.lookup_activation) |activation| blk: {
            const bytes = try std.math.add(usize, activation.manifest_identity.len, try std.math.add(usize, activation.statement_identity.len, activation.activation_identity.len));
            break :blk try std.math.add(usize, 16, bytes);
        } else 0;
        const expected_count = try std.math.add(usize, 43, try std.math.add(usize, lookup_count, try std.math.mul(usize, 13, program.instructions.len)));
        if (canonical.len != expected_count) return error.ProgramOriginCoverageMismatch;
        const origins = try allocator.alloc(Origin, canonical.len);
        errdefer allocator.free(origins);
        var cursor: usize = 0;
        put(origins, &cursor, .format, 0, 0);
        put(origins, &cursor, .schema, 0, 0);
        for (0..8) |limb| put(origins, &cursor, .plan_id, @intCast(limb), 0);
        for (0..8) |limb| put(origins, &cursor, .wire_id, @intCast(limb), 0);
        for (0..8) |limb| put(origins, &cursor, .statement_authority_id, @intCast(limb), 0);
        for (0..2) |limb| put(origins, &cursor, .wire_word_count, 0, @intCast(limb));
        for (0..13) |part| put(origins, &cursor, .pcs_parameter, @intCast(part), 0);
        if (program.lookup_activation != null) {
            // Two schema words, then three length-prefixed byte arrays,
            // then four split-u32 geometry values.
            for (0..lookup_count) |part| put(origins, &cursor, .lookup_activation, @intCast(part), 0);
        }
        for (0..2) |limb| put(origins, &cursor, .instruction_count, 0, @intCast(limb));
        for (program.instructions, 0..) |_, instruction| {
            const ordinal = std.math.cast(u32, instruction) orelse return error.ProgramOriginOverflow;
            put(origins, &cursor, .instruction_kind, ordinal, 0);
            for (0..2) |limb| put(origins, &cursor, .instruction_sequence, ordinal, @intCast(limb));
            for (0..2) |limb| put(origins, &cursor, .instruction_sub_index, ordinal, @intCast(limb));
            for (0..8) |part| put(origins, &cursor, .instruction_arg, ordinal, @intCast(part));
        }
        if (cursor != origins.len) return error.ProgramOriginCoverageMismatch;
        return .{ .allocator = allocator, .origins = origins };
    }

    pub fn deinit(self: *Map) void {
        self.allocator.free(self.origins);
        self.* = undefined;
    }

    pub fn count(self: *const Map, kind: Kind) usize {
        var result: usize = 0;
        for (self.origins) |origin| result += @intFromBool(origin.kind == kind);
        return result;
    }

    pub fn coverage(self: *const Map) Coverage {
        var result = Coverage{};
        for (self.origins) |origin| switch (route(origin)) {
            .row5_native => result.native_row5 += 1,
            .fixed_row42_required => result.fixed_row42_required += 1,
            .unlinked => result.unlinked += 1,
        };
        return result;
    }
};

/// Records whether the native row-4 transcript-word table contains each
/// instruction's *actual* kind/args descriptor. Presence is only a necessary
/// condition: row4 does not hold sub-index or split-u16 fields and some
/// instructions have no row4 word at all. No NPV2 emitter is authorized here.
pub const Row4Audit = struct {
    allocator: std.mem.Allocator,
    present: []bool,

    pub fn init(allocator: std.mem.Allocator, program: *const program_mod.Program, rows: anytype) !Row4Audit {
        const present = try allocator.alloc(bool, program.instructions.len);
        errdefer allocator.free(present);
        @memset(present, false);
        for (rows) |row| {
            const pp = row.preprocessing;
            if (pp.row_mask == 0) continue;
            if (pp.verifier_id != 0 or pp.segment_mask != 1 or
                pp.sequence >= program.instructions.len)
                return error.InvalidNpv2Row4Descriptor;
            const instruction = program.instructions[pp.sequence];
            if (pp.tag != base_source.typedTag(instruction.kind) or
                !std.meta.eql(pp.args, instruction.args))
                return error.InvalidNpv2Row4Descriptor;
            present[pp.sequence] = true;
        }
        return .{ .allocator = allocator, .present = present };
    }

    pub fn requireAllPresent(self: *const Row4Audit) !void {
        for (self.present) |item| if (!item)
            return error.MissingNpv2Row4Instruction;
    }

    pub fn deinit(self: *Row4Audit) void {
        self.allocator.free(self.present);
        self.* = undefined;
    }
};

fn put(items: []Origin, cursor: *usize, kind: Kind, ordinal: u32, part: u8) void {
    std.debug.assert(cursor.* < items.len);
    items[cursor.*] = .{ .kind = kind, .ordinal = ordinal, .part = part };
    cursor.* += 1;
}
