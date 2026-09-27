//! Six shared-table partitions at fresh family11 PCS roots.
//! This projection is admitted only against a fresh caller arithmetic proof.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
const Profile = @import("blake3_ethereum_sha_profile.zig");
const source = @import("block_v5_precompile_lookup_source_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const schema = @import("../air/lookups/tables/schema.zig");
const framework = @import("../recursion/air/framework_interaction.zig");
pub const TAG: u32 = 0x42354354; // B5CT

pub const Slot = source.Slot;
pub const Claim = struct { sum: Q, row_count: u64 };
pub const Generated = struct { columns: [4][]M, claim: Q };
pub fn generate(a: std.mem.Allocator, fixed: []const Column, main: []const Column, slot: Slot, relations: *const Profile.Relations, source_owner: *const source.Owner) !Generated {
    const size: usize = @as(usize, 1) << @intCast(slot.log_size);
    var columns: [4][]M = undefined;
    var initialized: usize = 0;
    errdefer for (columns[0..initialized]) |values| a.free(values);
    for (&columns) |*values| {
        values.* = try a.alloc(M, size);
        initialized += 1;
    }
    const terms = try a.alloc(Q, size);
    defer a.free(terms);
    const width = slot.width;
    for (0..size) |logical| {
        var row: [source.MAX_MAIN]Q = undefined;
        const physical = framework.committedRow(logical, slot.log_size);
        for (row[0..width], main[slot.main_offset..][0..width]) |*value, column| value.* = Q.fromBase(column.values[physical]);
        var fixed_row: [source.MAX_FIXED]Q = undefined;
        for (fixed_row[0..slot.fixed_width], fixed[slot.fixed_offset..][0..slot.fixed_width]) |*value, column| value.* = Q.fromBase(column.values[physical]);
        const request = try source_owner.pair(slot, fixed_row[0..slot.fixed_width], row[0..width], relations);
        terms[logical] = request.n1.mul(request.d2).add(request.n2.mul(request.d1)).mul(try request.d1.mul(request.d2).inv());
    }
    var claim = Q.zero();
    for (terms) |term| claim = claim.add(term);
    const shift = try claim.divM31(M.fromCanonical(@intCast(size)));
    var running = Q.zero();
    for (terms, 0..) |term, logical| {
        running = running.add(term).sub(shift);
        const limbs = running.toM31Array();
        const physical = framework.committedRow(logical, slot.log_size);
        for (&columns, limbs) |*values, limb| values.*[physical] = limb;
    }
    return .{ .columns = columns, .claim = claim };
}
pub fn validateSlots(slots: []const Slot, main: []const Column) !void {
    if (slots.len == 0) return error.EmptyV5LookupRequestRoster;
    for (slots) |slot| {
        const width = slot.width;
        if (slot.log_size == 0 or slot.log_size > 24 or slot.n_rows > (@as(u32, 1) << @intCast(slot.log_size)) or
            slot.main_offset + width > main.len) return error.InvalidV5LookupRequestRoster;
        for (main[slot.main_offset..][0..width]) |column| if (column.log_size != slot.log_size or
            column.values.len != (@as(usize, 1) << @intCast(slot.log_size))) return error.InvalidV5LookupRequestRoster;
    }
}
pub fn logs(a: std.mem.Allocator, columns: []const Column) ![]u32 {
    const result = try a.alloc(u32, columns.len);
    for (columns, result) |column, *log| log.* = column.log_size;
    return result;
}
pub fn openMask(a: std.mem.Allocator, len: usize, slots: []const Slot) ![]bool {
    const result = try a.alloc(bool, len);
    errdefer a.free(result);
    @memset(result, false);
    for (slots) |slot| {
        const width = slot.width;
        if (slot.main_offset + width > len) return error.InvalidV5LookupRequestRoster;
        @memset(result[slot.main_offset..][0..width], true);
    }
    return result;
}
pub fn firstChannel(native_key_id: [32]u8, native_instance_id: [32]u8, index: u32, slots: []const Slot) suite.Channel {
    var channel = suite.Channel{};
    channel.mixU32s(&.{ TAG, 1, index, @intCast(slots.len) });
    channel.mixRoot(native_key_id);
    channel.mixRoot(native_instance_id);
    for (slots) |slot| mixSlot(&channel, slot);
    return channel;
}
pub fn mixClaims(channel: anytype, native_key_id: [32]u8, native_instance_id: [32]u8, index: u32, slots: []const Slot, claims: []const Claim) void {
    channel.mixU32s(&.{ TAG, 2, index, @intCast(claims.len) });
    channel.mixRoot(native_key_id);
    channel.mixRoot(native_instance_id);
    for (slots, claims) |slot, claim| {
        mixSlot(channel, slot);
        channel.mixU64(claim.row_count);
        channel.mixFelts(&.{claim.sum});
    }
}

pub fn mixSlot(channel: anytype, slot: Slot) void {
    channel.mixU32s(&.{ @intFromEnum(slot.source), @intFromEnum(slot.table), slot.entries[0], slot.entries[1], slot.entry_count, slot.degree, slot.log_size, slot.n_rows, @intCast(slot.fixed_offset), @intCast(slot.fixed_width), @intCast(slot.main_offset), @intCast(slot.width) });
}
pub fn proofChannel(sealed: Seal.Sealed) suite.Channel {
    var channel = suite.Channel{};
    channel.mixU32s(&.{ TAG, 1 });
    channel.mixRoot(sealed.digest);
    return channel;
}

/// PCS composition chunks use one split for every component in this proof.
/// The maximum is derived from the independently reconstructed slot degrees.
pub fn compositionSplit(slots: []const Slot) u32 {
    var split: u32 = 1;
    for (slots) |slot| split = @max(split, std.math.log2_int_ceil(u32, slot.degree));
    return split;
}

pub fn fixedMask(a: std.mem.Allocator, len: usize, slots: []const Slot) ![]bool {
    const out = try a.alloc(bool, len);
    errdefer a.free(out);
    @memset(out, false);
    for (slots) |slot| {
        if (slot.fixed_offset + slot.fixed_width > len) return error.InvalidV5CallerLookupSlot;
        @memset(out[slot.fixed_offset..][0..slot.fixed_width], true);
    }
    return out;
}
