//! Non-production register-read alias candidates for three RV32 families.
//!
//! A read-only register access consumes `previous` and emits `next`.  The
//! shipped AIR commits both four-byte values and constrains them equal.  These
//! candidates commit only `previous`, substitute it for `next` in the frozen
//! family evaluator and ordered relation program, and remove exactly those
//! equality roots.  The common machinery owns only this physical rewrite;
//! every family keeps a distinct verifier-program identity bound to its
//! canonical fixed authority.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const entry = @import("../lookups/entry.zig");
const base_alu_imm = @import("typed_base_alu_imm_authority.zig");
const branch_eq = @import("typed_branch_eq_authority.zig");
const branch_lt = @import("typed_branch_lt_authority.zig");

pub const production_active = false;
pub const schema_version: u16 = 1;
pub const maximum_aliases: usize = 8;
pub const raw_m31_bytes: u64 = @sizeOf(u32);
pub const Digest = [32]u8;

pub const Family = enum(u8) {
    base_alu_imm = 0,
    branch_eq = 1,
    branch_lt = 2,
};

pub const Alias = struct {
    omitted_column: u8,
    source_column: u8,
};

const base_aliases = [4]Alias{
    .{ .omitted_column = 18, .source_column = 13 },
    .{ .omitted_column = 19, .source_column = 14 },
    .{ .omitted_column = 20, .source_column = 15 },
    .{ .omitted_column = 21, .source_column = 16 },
};
const two_read_aliases = [8]Alias{
    .{ .omitted_column = 8, .source_column = 3 },
    .{ .omitted_column = 9, .source_column = 4 },
    .{ .omitted_column = 10, .source_column = 5 },
    .{ .omitted_column = 11, .source_column = 6 },
    .{ .omitted_column = 18, .source_column = 13 },
    .{ .omitted_column = 19, .source_column = 14 },
    .{ .omitted_column = 20, .source_column = 15 },
    .{ .omitted_column = 21, .source_column = 16 },
};
const base_removed_roots = [4]u8{ 17, 18, 19, 20 };
const eq_removed_roots = [8]u8{ 9, 10, 11, 12, 13, 14, 15, 16 };
const lt_removed_roots = [8]u8{ 24, 25, 26, 27, 28, 29, 30, 31 };

pub const ProfileV1 = struct {
    family: Family,
    canonical_authority_identity: Digest,
    canonical_main_column_count: u8,
    main_column_count: u8,
    canonical_direct_constraint_count: u8,
    direct_constraint_count: u8,
    lookup_count: u8,
    lookup_batch_size: u8,
    alias_count: u8,
    aliases: [maximum_aliases]Alias,
    removed_root_count: u8,
    removed_direct_roots: [maximum_aliases]u8,
    verifier_program_identity: Digest,

    pub fn validate(self: *const ProfileV1) !void {
        const expected = trustedProfile(self.family);
        if (!std.meta.eql(self.*, expected))
            return error.InvalidRegisterReadAliasProfile;
    }
};

pub const CostProjection = struct {
    base_alu_imm_padded_rows: u64,
    branch_eq_padded_rows: u64,
    branch_lt_padded_rows: u64,
    base_alu_imm_saved_cells: u64,
    branch_eq_saved_cells: u64,
    branch_lt_saved_cells: u64,
    saved_main_cells: u64,
    saved_raw_bytes: u64,
};

pub const RetainedPaddedRows = struct {
    base_alu_imm: u64,
    branch_eq: u64,
    branch_lt: u64,
};

pub fn profile(family: Family) ProfileV1 {
    return trustedProfile(family);
}

pub fn CanonicalRow(comptime family: Family, comptime S: type) type {
    return [canonicalMainColumnCount(family)]S;
}

pub fn CandidateRow(comptime family: Family, comptime S: type) type {
    return [candidateMainColumnCount(family)]S;
}

pub fn CandidateDirect(comptime family: Family, comptime S: type) type {
    return [candidateDirectConstraintCount(family)]S;
}

pub fn project(
    comptime family: Family,
    canonical: CanonicalRow(family, M31),
) !CandidateRow(family, M31) {
    const authority = trustedProfile(family);
    for (authority.aliases[0..authority.alias_count]) |alias| {
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

pub fn baseAluImmDirect(
    comptime S: type,
    candidate: CandidateRow(.base_alu_imm, S),
    is_active: S,
) !CandidateDirect(.base_alu_imm, S) {
    const canonical = expand(.base_alu_imm, S, candidate);
    const direct = try base_alu_imm.Evaluator(S).direct(&canonical, is_active);
    return filterCanonicalDirect(.base_alu_imm, S, direct.values);
}

pub fn baseAluImmLookups(
    comptime S: type,
    candidate: CandidateRow(.base_alu_imm, S),
) !entry.Builder(S).List {
    const canonical = expand(.base_alu_imm, S, candidate);
    return base_alu_imm.Evaluator(S).lookups(&canonical);
}

pub fn branchEqDirect(
    comptime S: type,
    candidate: CandidateRow(.branch_eq, S),
    is_active: S,
) !CandidateDirect(.branch_eq, S) {
    const canonical = expand(.branch_eq, S, candidate);
    const direct = try branch_eq.Evaluator(S).direct(&canonical, is_active);
    return filterCanonicalDirect(.branch_eq, S, direct.values);
}

pub fn branchEqLookups(
    comptime S: type,
    candidate: CandidateRow(.branch_eq, S),
) !entry.Builder(S).List {
    const canonical = expand(.branch_eq, S, candidate);
    return branch_eq.Evaluator(S).lookups(&canonical);
}

pub fn branchLtDirect(
    comptime S: type,
    candidate: CandidateRow(.branch_lt, S),
    pc_polynomial: S,
    branch_target_polynomial: S,
    is_active: S,
) !CandidateDirect(.branch_lt, S) {
    const canonical = expand(.branch_lt, S, candidate);
    const direct = try branch_lt.Evaluator(S).direct(
        &canonical,
        pc_polynomial,
        branch_target_polynomial,
        is_active,
    );
    return filterCanonicalDirect(.branch_lt, S, direct.values);
}

pub fn branchLtLookups(
    comptime S: type,
    candidate: CandidateRow(.branch_lt, S),
) !entry.Builder(S).List {
    const canonical = expand(.branch_lt, S, candidate);
    return branch_lt.Evaluator(S).lookups(&canonical);
}

pub fn projectRetainedCost(rows: RetainedPaddedRows) !CostProjection {
    const base_saved = try mul(rows.base_alu_imm, aliasCount(.base_alu_imm));
    const eq_saved = try mul(rows.branch_eq, aliasCount(.branch_eq));
    const lt_saved = try mul(rows.branch_lt, aliasCount(.branch_lt));
    const total = try add(try add(base_saved, eq_saved), lt_saved);
    return .{
        .base_alu_imm_padded_rows = rows.base_alu_imm,
        .branch_eq_padded_rows = rows.branch_eq,
        .branch_lt_padded_rows = rows.branch_lt,
        .base_alu_imm_saved_cells = base_saved,
        .branch_eq_saved_cells = eq_saved,
        .branch_lt_saved_cells = lt_saved,
        .saved_main_cells = total,
        .saved_raw_bytes = try mul(total, raw_m31_bytes),
    };
}

fn trustedProfile(family: Family) ProfileV1 {
    var aliases = [_]Alias{.{ .omitted_column = 0, .source_column = 0 }} **
        maximum_aliases;
    var removed = [_]u8{0} ** maximum_aliases;
    var result: ProfileV1 = switch (family) {
        .base_alu_imm => blk: {
            aliases[0..base_aliases.len].* = base_aliases;
            removed[0..base_removed_roots.len].* = base_removed_roots;
            break :blk .{
                .family = family,
                .canonical_authority_identity = base_alu_imm.AUTHORITY_BINDING_DIGEST,
                .canonical_main_column_count = 35,
                .main_column_count = 31,
                .canonical_direct_constraint_count = 22,
                .direct_constraint_count = 18,
                .lookup_count = 16,
                .lookup_batch_size = 2,
                .alias_count = 4,
                .aliases = aliases,
                .removed_root_count = 4,
                .removed_direct_roots = removed,
                .verifier_program_identity = undefined,
            };
        },
        .branch_eq => blk: {
            aliases = two_read_aliases;
            removed = eq_removed_roots;
            break :blk .{
                .family = family,
                .canonical_authority_identity = branch_eq.AUTHORITY_BINDING_DIGEST,
                .canonical_main_column_count = 30,
                .main_column_count = 22,
                .canonical_direct_constraint_count = 18,
                .direct_constraint_count = 10,
                .lookup_count = 9,
                .lookup_batch_size = 2,
                .alias_count = 8,
                .aliases = aliases,
                .removed_root_count = 8,
                .removed_direct_roots = removed,
                .verifier_program_identity = undefined,
            };
        },
        .branch_lt => blk: {
            aliases = two_read_aliases;
            removed = lt_removed_roots;
            break :blk .{
                .family = family,
                .canonical_authority_identity = branch_lt.AUTHORITY_BINDING_DIGEST,
                .canonical_main_column_count = 37,
                .main_column_count = 29,
                .canonical_direct_constraint_count = 33,
                .direct_constraint_count = 25,
                .lookup_count = 11,
                .lookup_batch_size = 2,
                .alias_count = 8,
                .aliases = aliases,
                .removed_root_count = 8,
                .removed_direct_roots = removed,
                .verifier_program_identity = undefined,
            };
        },
    };
    result.verifier_program_identity = programIdentity(&result);
    return result;
}

fn programIdentity(value: *const ProfileV1) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.register-read-alias-verifier-program.v1\x00");
    hashInt(&hash, schema_version);
    hashInt(&hash, @intFromEnum(value.family));
    hash.update(&value.canonical_authority_identity);
    hashInt(&hash, value.canonical_main_column_count);
    hashInt(&hash, value.main_column_count);
    hashInt(&hash, value.canonical_direct_constraint_count);
    hashInt(&hash, value.direct_constraint_count);
    hashInt(&hash, value.lookup_count);
    hashInt(&hash, value.lookup_batch_size);
    hashInt(&hash, value.alias_count);
    for (value.aliases[0..value.alias_count]) |alias| {
        hashInt(&hash, alias.omitted_column);
        hashInt(&hash, alias.source_column);
    }
    hashInt(&hash, value.removed_root_count);
    for (value.removed_direct_roots[0..value.removed_root_count]) |root|
        hashInt(&hash, root);
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}

fn canonicalMainColumnCount(comptime family: Family) usize {
    return switch (family) {
        .base_alu_imm => 35,
        .branch_eq => 30,
        .branch_lt => 37,
    };
}

fn candidateMainColumnCount(comptime family: Family) usize {
    return canonicalMainColumnCount(family) - aliasCount(family);
}

fn canonicalDirectConstraintCount(comptime family: Family) usize {
    return switch (family) {
        .base_alu_imm => 22,
        .branch_eq => 18,
        .branch_lt => 33,
    };
}

fn candidateDirectConstraintCount(comptime family: Family) usize {
    return canonicalDirectConstraintCount(family) - aliasCount(family);
}

fn aliasCount(comptime family: Family) usize {
    return switch (family) {
        .base_alu_imm => 4,
        .branch_eq, .branch_lt => 8,
    };
}

fn aliasSource(comptime family: Family, column: usize) ?usize {
    const aliases: []const Alias = switch (family) {
        .base_alu_imm => &base_aliases,
        .branch_eq, .branch_lt => &two_read_aliases,
    };
    for (aliases) |alias| {
        if (alias.omitted_column == column) return alias.source_column;
    }
    return null;
}

fn isRemovedRoot(comptime family: Family, root: usize) bool {
    const removed_roots: []const u8 = switch (family) {
        .base_alu_imm => &base_removed_roots,
        .branch_eq => &eq_removed_roots,
        .branch_lt => &lt_removed_roots,
    };
    for (removed_roots) |removed| {
        if (removed == root) return true;
    }
    return false;
}

fn add(lhs: u64, rhs: u64) !u64 {
    return std.math.add(u64, lhs, rhs) catch error.ArithmeticOverflow;
}

fn mul(lhs: u64, rhs: anytype) !u64 {
    return std.math.mul(u64, lhs, @intCast(rhs)) catch error.ArithmeticOverflow;
}

fn hashInt(hash: anytype, value: anytype) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (base_alu_imm.MAIN_COLUMN_COUNT != 35 or
        base_alu_imm.DIRECT_CONSTRAINT_COUNT != 22 or
        branch_eq.MAIN_COLUMN_COUNT != 30 or
        branch_eq.DIRECT_CONSTRAINT_COUNT != 18 or
        branch_lt.MAIN_COLUMN_COUNT != 37 or
        branch_lt.DIRECT_CONSTRAINT_COUNT != 33 or
        production_active)
    {
        @compileError("register-read alias candidate geometry drifted");
    }
}
