//! Non-production register-read alias candidates for SLT/SLTU and multiply.
//!
//! Each family below commits two read-only register accesses as both
//! `previous` and `next` bytes, then constrains those byte arrays equal.  The
//! candidate commits only `previous`, substitutes it for `next` in the frozen
//! family evaluator and lookup program, and removes exactly the eight equality
//! roots.  Sharing is limited to this mechanical projection; every family has
//! a distinct verifier-program identity bound to its canonical authority.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const entry = @import("../lookups/entry.zig");
const lt_reg = @import("typed_lt_reg_authority.zig");
const mul = @import("typed_mul_authority.zig");
const mulh = @import("typed_mulh_authority.zig");

pub const production_active = false;
pub const schema_version: u16 = 1;
pub const alias_count: usize = 8;
pub const raw_m31_bytes: u64 = @sizeOf(u32);
pub const Digest = [32]u8;

pub const Family = enum(u8) {
    lt_reg = 0,
    mul = 1,
    mulh = 2,
};

pub const Alias = struct {
    omitted_column: u8,
    source_column: u8,
};

const access_at_12_aliases = [alias_count]Alias{
    .{ .omitted_column = 18, .source_column = 13 },
    .{ .omitted_column = 19, .source_column = 14 },
    .{ .omitted_column = 20, .source_column = 15 },
    .{ .omitted_column = 21, .source_column = 16 },
    .{ .omitted_column = 28, .source_column = 23 },
    .{ .omitted_column = 29, .source_column = 24 },
    .{ .omitted_column = 30, .source_column = 25 },
    .{ .omitted_column = 31, .source_column = 26 },
};

const access_at_13_aliases = [alias_count]Alias{
    .{ .omitted_column = 19, .source_column = 14 },
    .{ .omitted_column = 20, .source_column = 15 },
    .{ .omitted_column = 21, .source_column = 16 },
    .{ .omitted_column = 22, .source_column = 17 },
    .{ .omitted_column = 29, .source_column = 24 },
    .{ .omitted_column = 30, .source_column = 25 },
    .{ .omitted_column = 31, .source_column = 26 },
    .{ .omitted_column = 32, .source_column = 27 },
};

const lt_removed_roots = [alias_count]u8{ 27, 28, 29, 30, 31, 32, 33, 34 };
const mul_removed_roots = [alias_count]u8{ 8, 9, 10, 11, 12, 13, 14, 15 };
const mulh_removed_roots = [alias_count]u8{ 15, 16, 17, 18, 19, 20, 21, 22 };

pub const ProfileV1 = struct {
    family: Family,
    canonical_authority_identity: Digest,
    canonical_main_column_count: u8,
    main_column_count: u8,
    canonical_direct_constraint_count: u8,
    direct_constraint_count: u8,
    lookup_count: u8,
    lookup_batch_size: u8,
    aliases: [alias_count]Alias,
    removed_direct_roots: [alias_count]u8,
    verifier_program_identity: Digest,

    pub fn validate(self: *const ProfileV1) !void {
        if (!std.meta.eql(self.*, trustedProfile(self.family)))
            return error.InvalidTwoReadRegisterAliasProfile;
    }
};

pub const RetainedPaddedRows = struct {
    lt_reg: u64,
    mul: u64,
    mulh: u64,
};

pub const CostProjection = struct {
    lt_reg_padded_rows: u64,
    mul_padded_rows: u64,
    mulh_padded_rows: u64,
    lt_reg_saved_cells: u64,
    mul_saved_cells: u64,
    mulh_saved_cells: u64,
    saved_main_cells: u64,
    saved_raw_bytes: u64,
};

pub fn profile(family: Family) ProfileV1 {
    return trustedProfile(family);
}

pub fn CanonicalRow(comptime family: Family, comptime S: type) type {
    return [canonicalMainColumnCount(family)]S;
}

pub fn CandidateRow(comptime family: Family, comptime S: type) type {
    return [canonicalMainColumnCount(family) - alias_count]S;
}

pub fn CandidateDirect(comptime family: Family, comptime S: type) type {
    return [canonicalDirectConstraintCount(family) - alias_count]S;
}

pub fn project(
    comptime family: Family,
    canonical: CanonicalRow(family, M31),
) !CandidateRow(family, M31) {
    for (aliases(family)) |alias| {
        if (canonical[alias.omitted_column].toU32() !=
            canonical[alias.source_column].toU32())
        {
            return error.RegisterReadAliasMismatch;
        }
    }
    var result: CandidateRow(family, M31) = undefined;
    var destination: usize = 0;
    for (canonical, 0..) |value, column| {
        if (aliasSource(family, column) != null) continue;
        result[destination] = value;
        destination += 1;
    }
    std.debug.assert(destination == result.len);
    return result;
}

pub fn expand(
    comptime family: Family,
    comptime S: type,
    candidate: CandidateRow(family, S),
) CanonicalRow(family, S) {
    var result: CanonicalRow(family, S) = undefined;
    var source_index: usize = 0;
    for (&result, 0..) |*value, column| {
        value.* = if (aliasSource(family, column)) |source_column|
            result[source_column]
        else blk: {
            const committed = candidate[source_index];
            source_index += 1;
            break :blk committed;
        };
    }
    std.debug.assert(source_index == candidate.len);
    return result;
}

pub fn filterCanonicalDirect(
    comptime family: Family,
    comptime S: type,
    canonical: [canonicalDirectConstraintCount(family)]S,
) CandidateDirect(family, S) {
    var result: CandidateDirect(family, S) = undefined;
    var destination: usize = 0;
    for (canonical, 0..) |value, root| {
        if (isRemovedRoot(family, root)) continue;
        result[destination] = value;
        destination += 1;
    }
    std.debug.assert(destination == result.len);
    return result;
}

pub fn ltRegDirect(
    comptime S: type,
    candidate: CandidateRow(.lt_reg, S),
    is_active: S,
) !CandidateDirect(.lt_reg, S) {
    const canonical = expand(.lt_reg, S, candidate);
    const direct = try lt_reg.Evaluator(S).direct(&canonical, is_active);
    return filterCanonicalDirect(.lt_reg, S, direct.values);
}

pub fn ltRegLookups(
    comptime S: type,
    candidate: CandidateRow(.lt_reg, S),
) !entry.Builder(S).List {
    const canonical = expand(.lt_reg, S, candidate);
    return lt_reg.Evaluator(S).lookups(&canonical);
}

pub fn mulDirect(
    comptime S: type,
    candidate: CandidateRow(.mul, S),
    is_active: S,
) !CandidateDirect(.mul, S) {
    const canonical = expand(.mul, S, candidate);
    const direct = try mul.Evaluator(S).direct(&canonical, is_active);
    return filterCanonicalDirect(.mul, S, direct.values);
}

pub fn mulLookups(
    comptime S: type,
    candidate: CandidateRow(.mul, S),
) !entry.Builder(S).List {
    const canonical = expand(.mul, S, candidate);
    return mul.Evaluator(S).lookups(&canonical);
}

pub fn mulhDirect(
    comptime S: type,
    candidate: CandidateRow(.mulh, S),
    is_active: S,
) !CandidateDirect(.mulh, S) {
    const canonical = expand(.mulh, S, candidate);
    const direct = try mulh.Evaluator(S).direct(&canonical, is_active);
    return filterCanonicalDirect(.mulh, S, direct.values);
}

pub fn mulhLookups(
    comptime S: type,
    candidate: CandidateRow(.mulh, S),
) !entry.Builder(S).List {
    const canonical = expand(.mulh, S, candidate);
    return mulh.Evaluator(S).lookups(&canonical);
}

pub fn projectRetainedCost(rows: RetainedPaddedRows) !CostProjection {
    const lt_saved = try mulCost(rows.lt_reg, alias_count);
    const mul_saved = try mulCost(rows.mul, alias_count);
    const mulh_saved = try mulCost(rows.mulh, alias_count);
    const total = try add(try add(lt_saved, mul_saved), mulh_saved);
    return .{
        .lt_reg_padded_rows = rows.lt_reg,
        .mul_padded_rows = rows.mul,
        .mulh_padded_rows = rows.mulh,
        .lt_reg_saved_cells = lt_saved,
        .mul_saved_cells = mul_saved,
        .mulh_saved_cells = mulh_saved,
        .saved_main_cells = total,
        .saved_raw_bytes = try mulCost(total, raw_m31_bytes),
    };
}

fn trustedProfile(family: Family) ProfileV1 {
    var result: ProfileV1 = switch (family) {
        .lt_reg => .{
            .family = family,
            .canonical_authority_identity = lt_reg.AUTHORITY_BINDING_DIGEST,
            .canonical_main_column_count = 44,
            .main_column_count = 36,
            .canonical_direct_constraint_count = 36,
            .direct_constraint_count = 28,
            .lookup_count = 14,
            .lookup_batch_size = 2,
            .aliases = access_at_12_aliases,
            .removed_direct_roots = lt_removed_roots,
            .verifier_program_identity = undefined,
        },
        .mul => .{
            .family = family,
            .canonical_authority_identity = mul.AUTHORITY_BINDING_DIGEST,
            .canonical_main_column_count = 39,
            .main_column_count = 31,
            .canonical_direct_constraint_count = 17,
            .direct_constraint_count = 9,
            .lookup_count = 16,
            .lookup_batch_size = 1,
            .aliases = access_at_13_aliases,
            .removed_direct_roots = mul_removed_roots,
            .verifier_program_identity = undefined,
        },
        .mulh => .{
            .family = family,
            .canonical_authority_identity = mulh.AUTHORITY_BINDING_DIGEST,
            .canonical_main_column_count = 47,
            .main_column_count = 39,
            .canonical_direct_constraint_count = 24,
            .direct_constraint_count = 16,
            .lookup_count = 22,
            .lookup_batch_size = 1,
            .aliases = access_at_12_aliases,
            .removed_direct_roots = mulh_removed_roots,
            .verifier_program_identity = undefined,
        },
    };
    result.verifier_program_identity = programIdentity(&result);
    return result;
}

fn programIdentity(value: *const ProfileV1) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.two-read-register-alias-verifier-program.v1\x00");
    hashInt(&hash, schema_version);
    hashInt(&hash, @intFromEnum(value.family));
    hash.update(&value.canonical_authority_identity);
    hashInt(&hash, value.canonical_main_column_count);
    hashInt(&hash, value.main_column_count);
    hashInt(&hash, value.canonical_direct_constraint_count);
    hashInt(&hash, value.direct_constraint_count);
    hashInt(&hash, value.lookup_count);
    hashInt(&hash, value.lookup_batch_size);
    for (value.aliases) |alias| {
        hashInt(&hash, alias.omitted_column);
        hashInt(&hash, alias.source_column);
    }
    for (value.removed_direct_roots) |root| hashInt(&hash, root);
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}

fn canonicalMainColumnCount(comptime family: Family) usize {
    return switch (family) {
        .lt_reg => 44,
        .mul => 39,
        .mulh => 47,
    };
}

fn canonicalDirectConstraintCount(comptime family: Family) usize {
    return switch (family) {
        .lt_reg => 36,
        .mul => 17,
        .mulh => 24,
    };
}

fn aliases(comptime family: Family) *const [alias_count]Alias {
    return switch (family) {
        .lt_reg, .mulh => &access_at_12_aliases,
        .mul => &access_at_13_aliases,
    };
}

fn removedRoots(comptime family: Family) *const [alias_count]u8 {
    return switch (family) {
        .lt_reg => &lt_removed_roots,
        .mul => &mul_removed_roots,
        .mulh => &mulh_removed_roots,
    };
}

fn aliasSource(comptime family: Family, column: usize) ?usize {
    for (aliases(family)) |alias| {
        if (alias.omitted_column == column) return alias.source_column;
    }
    return null;
}

fn isRemovedRoot(comptime family: Family, root: usize) bool {
    for (removedRoots(family)) |removed| if (removed == root) return true;
    return false;
}

fn add(lhs: u64, rhs: u64) !u64 {
    return std.math.add(u64, lhs, rhs) catch error.ArithmeticOverflow;
}

fn mulCost(lhs: u64, rhs: anytype) !u64 {
    return std.math.mul(u64, lhs, @intCast(rhs)) catch error.ArithmeticOverflow;
}

fn hashInt(hash: anytype, value: anytype) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (lt_reg.MAIN_COLUMN_COUNT != 44 or
        lt_reg.DIRECT_CONSTRAINT_COUNT != 36 or
        mul.MAIN_COLUMN_COUNT != 39 or
        mul.DIRECT_CONSTRAINT_COUNT != 17 or
        mulh.MAIN_COLUMN_COUNT != 47 or
        mulh.DIRECT_CONSTRAINT_COUNT != 24 or
        production_active)
    {
        @compileError("two-read register alias candidate geometry drifted");
    }
}
