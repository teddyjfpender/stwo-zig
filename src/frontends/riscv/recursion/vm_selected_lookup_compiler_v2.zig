//! Cold compiler authority for ProfileV2's selected opcode lookup programs.
//!
//! The physical manifest is a compact retained commitment. This module
//! independently lowers every typed family program, checks the exact V2
//! program/layout/partition identities, and exposes only the authenticated
//! contiguous batch ranges to the row-18 symbolic recorder.

const std = @import("std");
const prover_component = @import("stwo_prover_engine").air.component_prover;
const logup = @import("../air/logup.zig");
const entry_mod = @import("../air/lookups/entry.zig");
const opcode_entries = @import("../air/lookups/opcode_entries.zig");
const lookup_batch = @import("../air/lang/lookup_batch_execution.zig");
const lookup_lowering = @import("../air/lang/lookup_polynomial_program_v2.zig");
const lookup_manifest = @import("../air/lang/lookup_physical_manifest_v2.zig");
const statement_mod = @import("../air/statement.zig");
const trace = @import("../runner/trace.zig");
const profile_mod = @import("vm_air_profile_v2.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const FAMILY_COUNT: usize = lookup_manifest.FAMILY_COUNT;
pub const IDENTITY_DOMAIN =
    "stwo-zig/riscv/recursion/vm-selected-lookup-compiler/v2\x00";
const BATCH_DOMAIN =
    "stwo-zig/riscv/recursion/vm-selected-lookup-batches/v2\x00";

pub const Error = error{
    InvalidBatchIndex,
    InvalidCompilerIdentity,
    InvalidCompilerVersion,
    InvalidFamilyAuthority,
    InvalidProfileEntry,
    InvalidSelectedBatch,
};

pub const FamilyProgramV2 = struct {
    family: trace.OpcodeFamily,
    authority: prover_component.LookupPolynomialAuthorityV2,
    batch_count: u32,
    batches_sha256: [32]u8,

    pub fn validate(
        self: FamilyProgramV2,
        physical: *const lookup_manifest.FamilyEntry,
    ) !void {
        try self.authority.validate();
        if (self.family != physical.family or
            !std.meta.eql(self.authority, physical.lookup_authority) or
            self.batch_count != physical.activeBatches().len or
            !std.mem.eql(
                u8,
                &self.batches_sha256,
                &batchIdentity(physical),
            ))
        {
            return error.InvalidFamilyAuthority;
        }
    }
};

pub const CompilerV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    profile_identity: [32]u8,
    manifest_identity: [32]u8,
    authenticated_statement_identity: [32]u8,
    activation_identity: [32]u8,
    families: [FAMILY_COUNT]FamilyProgramV2,
    identity_sha256: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        statement: *const statement_mod.RiscVStatement,
        manifest: *const lookup_manifest.Manifest,
        authenticated: *const lookup_manifest.AuthenticatedStatement,
        profile: *const profile_mod.ProfileV2,
    ) !CompilerV2 {
        try profile.validateAuthority(
            allocator,
            statement,
            manifest,
            authenticated,
        );
        var result = CompilerV2{
            .profile_identity = profile.identity_digest,
            .manifest_identity = manifest.identity,
            .authenticated_statement_identity = authenticated.statement_identity,
            .activation_identity = authenticated.activation_identity,
            .families = undefined,
            .identity_sha256 = undefined,
        };
        for (&result.families, 0..) |*destination, index| {
            const selected_family: trace.OpcodeFamily = @enumFromInt(index);
            const physical = manifest.entryForFamily(selected_family);
            var plan = try lookup_batch.FamilyPlan.initNativeV1(
                allocator,
                selected_family,
            );
            defer plan.deinit();
            var lowered = try lookup_lowering.lowerSelected(allocator, &plan);
            defer lowered.deinit();
            try lowered.validateAgainst(&physical.lookup_authority);
            destination.* = .{
                .family = selected_family,
                .authority = try lowered.authority(),
                .batch_count = @intCast(physical.activeBatches().len),
                .batches_sha256 = batchIdentity(physical),
            };
            try destination.validate(physical);
        }
        result.identity_sha256 = result.computeIdentity();
        try result.validateAgainstManifest(manifest);
        return result;
    }

    pub fn validateAgainstManifest(
        self: *const CompilerV2,
        manifest: *const lookup_manifest.Manifest,
    ) !void {
        try manifest.validate();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION)
        {
            return error.InvalidCompilerVersion;
        }
        if (!std.mem.eql(
            u8,
            &self.manifest_identity,
            &manifest.identity,
        ) or allZero(self.profile_identity) or
            allZero(self.authenticated_statement_identity) or
            allZero(self.activation_identity))
        {
            return error.InvalidFamilyAuthority;
        }
        for (self.families, 0..) |program, index| {
            const expected: trace.OpcodeFamily = @enumFromInt(index);
            if (program.family != expected) return error.InvalidFamilyAuthority;
            try program.validate(manifest.entryForFamily(expected));
        }
        const actual = self.computeIdentity();
        if (!std.mem.eql(u8, &actual, &self.identity_sha256))
            return error.InvalidCompilerIdentity;
    }

    pub fn validateAuthority(
        self: *const CompilerV2,
        allocator: std.mem.Allocator,
        statement: *const statement_mod.RiscVStatement,
        manifest: *const lookup_manifest.Manifest,
        authenticated: *const lookup_manifest.AuthenticatedStatement,
        profile: *const profile_mod.ProfileV2,
    ) !void {
        try self.validateAgainstManifest(manifest);
        const expected = try init(
            allocator,
            statement,
            manifest,
            authenticated,
            profile,
        );
        if (!std.meta.eql(self.*, expected))
            return error.InvalidCompilerIdentity;
    }

    pub fn programForFamily(
        self: *const CompilerV2,
        selected: trace.OpcodeFamily,
    ) *const FamilyProgramV2 {
        return &self.families[@intFromEnum(selected)];
    }

    fn computeIdentity(self: *const CompilerV2) [32]u8 {
        var hash = Sha256.init(.{});
        hash.update(IDENTITY_DOMAIN);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.schema_version);
        hash.update(&self.profile_identity);
        hash.update(&self.manifest_identity);
        hash.update(&self.authenticated_statement_identity);
        hash.update(&self.activation_identity);
        for (self.families) |program| {
            hashInt(&hash, u8, @intFromEnum(program.family));
            hashAuthority(&hash, program.authority);
            hashInt(&hash, u32, program.batch_count);
            hash.update(&program.batches_sha256);
        }
        return hash.finalResult();
    }
};

/// Symbolic selected-batch execution. The entry sequence is rebuilt by
/// `opcode_entries.Entries(S)` from the production typed evaluator; only the
/// manifest-authenticated contiguous partition is applied here.
pub fn rowPairForProfileEntry(
    comptime S: type,
    compiler: *const CompilerV2,
    profile_entry: profile_mod.EntryV2,
    manifest: *const lookup_manifest.Manifest,
    list: *const entry_mod.Builder(S).List,
    batch_index: usize,
    relations: anytype,
) !logup.RowPairFor(S) {
    try compiler.validateAgainstManifest(manifest);
    const key = switch (profile_entry.registry) {
        .opcode_lookup => |value| value,
        else => return error.InvalidProfileEntry,
    };
    const physical = manifest.entryForFamily(key.family);
    const family_program = compiler.programForFamily(key.family);
    try family_program.validate(physical);
    if (list.len != physical.lookup_authority.entry_count or
        batch_index >= physical.activeBatches().len or
        profile_entry.interaction_batch_count !=
            physical.lookup_authority.batch_count or
        !std.mem.eql(
            u8,
            &key.component_identity,
            &physical.lookup_authority.component_identity,
        ) or !std.mem.eql(
        u8,
        &key.partition_identity,
        &physical.lookup_authority.partition_identity,
    ) or !std.mem.eql(
        u8,
        &key.layout_identity,
        &physical.lookup_authority.layout_identity,
    ) or !std.mem.eql(
        u8,
        &key.program_identity,
        &physical.lookup_authority.program_identity,
    )) {
        return error.InvalidProfileEntry;
    }
    const batch = physical.activeBatches()[batch_index];
    return rowPairFromRange(
        S,
        list,
        batch.first_entry,
        batch.entry_count,
        relations,
    );
}

pub fn buildTypedEntries(
    comptime S: type,
    family: trace.OpcodeFamily,
    main: []const S,
) !entry_mod.Builder(S).List {
    return opcode_entries.Entries(S).fromMain(family, main);
}

fn rowPairFromRange(
    comptime S: type,
    list: *const entry_mod.Builder(S).List,
    first_entry: u32,
    entry_count: u8,
    relations: anytype,
) !logup.RowPairFor(S) {
    if (entry_count == 0 or entry_count > 2 or first_entry >= list.len)
        return error.InvalidSelectedBatch;
    const first_index: usize = first_entry;
    const end = std.math.add(usize, first_index, entry_count) catch
        return error.InvalidSelectedBatch;
    if (end > list.len) return error.InvalidSelectedBatch;
    const first = &list.entries[first_index];
    if (entry_count == 1) return logup.RowPairFor(S).single(
        first.numerator,
        try first.denominatorWith(relations),
    );
    const second = &list.entries[first_index + 1];
    return .{
        .n1 = first.numerator,
        .d1 = try first.denominatorWith(relations),
        .n2 = second.numerator,
        .d2 = try second.denominatorWith(relations),
    };
}

fn batchIdentity(entry: *const lookup_manifest.FamilyEntry) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(BATCH_DOMAIN);
    hashInt(&hash, u8, @intFromEnum(entry.family));
    hashInt(&hash, u32, entry.lookup_authority.entry_count);
    hashInt(&hash, u32, entry.activeBatches().len);
    for (entry.activeBatches()) |batch| {
        hashInt(&hash, u32, batch.first_entry);
        hashInt(&hash, u8, batch.entry_count);
        hashInt(&hash, u32, batch.interaction_degree);
    }
    return hash.finalResult();
}

fn hashAuthority(
    hash: *Sha256,
    authority: prover_component.LookupPolynomialAuthorityV2,
) void {
    hashInt(hash, u16, authority.format_version);
    hash.update(&authority.component_identity);
    hash.update(&authority.partition_identity);
    hash.update(&authority.layout_identity);
    hash.update(&authority.program_identity);
    hashInt(hash, u32, authority.entry_count);
    hashInt(hash, u32, authority.batch_count);
    hashInt(hash, u32, authority.interaction_column_count);
    hashInt(hash, u32, authority.maximum_interaction_degree);
}

fn allZero(value: [32]u8) bool {
    return std.mem.allEqual(u8, &value, 0);
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

pub const testing = struct {
    pub fn reseal(value: *CompilerV2) void {
        value.identity_sha256 = value.computeIdentity();
    }
};

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        FAMILY_COUNT != trace.N_FAMILIES)
    {
        @compileError("VM selected lookup compiler V2 contract drifted");
    }
}
