//! Role-aware public compensation for Ethereum incremental-memory V4 leaves.
//!
//! SegmentV2 remains the authority for CPU/register/root state and retains its
//! original completion wire.  A nonfinal leaf has no SegmentV2 completion, so
//! this version requires one separately ELF-derived, unretired program fetch
//! and adds its Ethereum-profile program-access compensation exactly once.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const execution_profile = @import("../isa/execution_profile.zig");
const public_data = @import("public_data.zig");
const public_data_v2 = @import("public_data_v2.zig");
const public_logup = @import("public_logup.zig");
const public_logup_v2 = @import("public_logup_v2.zig");
const incremental_v3 = @import("incremental_public_logup_v3.zig");
const relation_challenges = @import("relation_challenges.zig");
const statement_v2 = @import("statement_v2.zig");

pub const PRODUCTION_ACTIVE = false;
pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const PROFILE = execution_profile.ExecutionProfile.rv32im_zkvm_ethereum_v1;
pub const Sums = public_logup_v2.Sums;
pub const Digest = [32]u8;

const BOUNDARY_IDENTITY_DOMAIN =
    "stwo.riscv.incremental-public-boundary.v4\x00";
const SUMS_IDENTITY_DOMAIN =
    "stwo.riscv.incremental-public-sums.v4\x00";

pub const ReplacementAuditV4 = struct {
    native_v2: Sums,
    removed_sparse_rw: QM31,
    removed_sparse_continuation_tree: QM31,
    added_role_aware_io: QM31,
    added_role_program_fetch: QM31,
    result: Sums,
};

pub const VerifiedPublicSumsV4 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    execution_profile: execution_profile.ExecutionProfile = PROFILE,
    native_wire_id: public_data_v2.Digest,
    public_boundary_identity_sha256: Digest,
    sums: Sums,
    total: QM31,
    identity_sha256: Digest,

    pub fn init(
        native: *const public_data_v2.PublicDataV2,
        role_aware: *const public_data.PublicData,
        relations: *const relation_challenges.Relations,
    ) !VerifiedPublicSumsV4 {
        const value = try relationSums(native, role_aware, relations);
        var result = VerifiedPublicSumsV4{
            .native_wire_id = native.wireId(),
            .public_boundary_identity_sha256 = publicBoundaryIdentity(
                native,
                role_aware,
            ),
            .sums = value,
            .total = value.total(),
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = sumsIdentity(&result);
        return result;
    }

    pub fn validateAgainst(
        self: *const VerifiedPublicSumsV4,
        native: *const public_data_v2.PublicDataV2,
        role_aware: *const public_data.PublicData,
        relations: *const relation_challenges.Relations,
    ) !void {
        const expected = try VerifiedPublicSumsV4.init(
            native,
            role_aware,
            relations,
        );
        if (!std.meta.eql(self.*, expected))
            return error.InvalidIncrementalPublicSumsV4;
    }
};

pub const OwnedPublicDataV4 = struct {
    allocator: std.mem.Allocator,
    input_words: []u32,
    output_words: []public_data.OutputWord,
    value: public_data.PublicData,
    public_boundary_identity_sha256: Digest,

    pub fn initVerified(
        allocator: std.mem.Allocator,
        native: *const public_data_v2.PublicDataV2,
        source: *const public_data.PublicData,
    ) !OwnedPublicDataV4 {
        try validateSharedAuthority(native, source);
        const input_words = try allocator.dupe(
            u32,
            source.io_entries.input_words,
        );
        errdefer allocator.free(input_words);
        const output_words = try allocator.dupe(
            public_data.OutputWord,
            source.io_entries.output_words,
        );
        errdefer allocator.free(output_words);
        var value = source.*;
        value.io_entries.input_words = input_words;
        value.io_entries.output_words = output_words;
        const result = OwnedPublicDataV4{
            .allocator = allocator,
            .input_words = input_words,
            .output_words = output_words,
            .value = value,
            .public_boundary_identity_sha256 = publicBoundaryIdentity(
                native,
                &value,
            ),
        };
        try result.validateAgainst(native);
        return result;
    }

    pub fn deinit(self: *OwnedPublicDataV4) void {
        self.allocator.free(self.output_words);
        self.allocator.free(self.input_words);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const OwnedPublicDataV4,
        native: *const public_data_v2.PublicDataV2,
    ) !void {
        if (self.value.io_entries.input_words.ptr != self.input_words.ptr or
            self.value.io_entries.input_words.len != self.input_words.len or
            self.value.io_entries.output_words.ptr != self.output_words.ptr or
            self.value.io_entries.output_words.len != self.output_words.len or
            !std.mem.eql(
                u8,
                &self.public_boundary_identity_sha256,
                &publicBoundaryIdentity(native, &self.value),
            ))
        {
            return error.IncrementalPublicAuthorityMismatchV4;
        }
        try validateSharedAuthority(native, &self.value);
    }
};

pub fn validateSharedAuthority(
    native: *const public_data_v2.PublicDataV2,
    role_aware: *const public_data.PublicData,
) !void {
    try role_aware.validate();
    const expected = try statement_v2.canonicalCorePublicData(native);
    const metadata = try native.metadata();
    if (role_aware.initial_pc != expected.initial_pc or
        role_aware.final_pc != expected.final_pc or
        role_aware.clock != expected.clock or
        !std.mem.eql(u32, &role_aware.initial_regs, &expected.initial_regs) or
        !std.mem.eql(u32, &role_aware.final_regs, &expected.final_regs) or
        !std.mem.eql(u32, &role_aware.reg_last_clock, &expected.reg_last_clock) or
        !std.meta.eql(role_aware.program_root, expected.program_root) or
        !std.meta.eql(role_aware.initial_rw_root, expected.initial_rw_root) or
        !std.meta.eql(role_aware.final_rw_root, expected.final_rw_root) or
        (!metadata.is_first and
            (role_aware.io_entries.input_len != 0 or
                role_aware.io_entries.input_words.len != 0)) or
        (!metadata.is_final and
            (role_aware.io_entries.output_len != 0 or
                role_aware.io_entries.output_words.len != 0)))
    {
        return error.IncrementalPublicAuthorityMismatchV4;
    }

    if (expected.completion) |retained| {
        if (!std.meta.eql(
            role_aware.completion,
            @as(?public_data.Completion, retained),
        )) return error.IncrementalPublicCompletionMismatchV4;
    } else {
        const completion = role_aware.completion orelse
            return error.MissingCompletion;
        if (metadata.is_final or
            completion.kind != .unretired_program_fetch or
            completion.address != role_aware.final_pc or
            completion.clock != 0)
        {
            return error.IncrementalPublicCompletionMismatchV4;
        }
    }
}

pub fn publicBoundaryIdentity(
    native: *const public_data_v2.PublicDataV2,
    value: *const public_data.PublicData,
) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(BOUNDARY_IDENTITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u16, @intFromEnum(PROFILE));
    for (native.wireId()) |word| hashInt(&hash, u32, word);
    hash.update(&incremental_v3.publicIoIdentity(value));
    if (value.completion) |completion| {
        hashInt(&hash, u8, 1);
        hashInt(&hash, u32, @intFromEnum(completion.kind));
        hashInt(&hash, u32, completion.address);
        hashInt(&hash, u32, completion.value);
        hashInt(&hash, u32, completion.clock);
    } else {
        hashInt(&hash, u8, 0);
    }
    return hash.finalResult();
}

pub fn relationSums(
    native: *const public_data_v2.PublicDataV2,
    role_aware: *const public_data.PublicData,
    relations: *const relation_challenges.Relations,
) !Sums {
    return (try audit(native, role_aware, relations)).result;
}

pub fn sum(
    native: *const public_data_v2.PublicDataV2,
    role_aware: *const public_data.PublicData,
    relations: *const relation_challenges.Relations,
) !QM31 {
    return (try relationSums(native, role_aware, relations)).total();
}

pub fn audit(
    native: *const public_data_v2.PublicDataV2,
    role_aware: *const public_data.PublicData,
    relations: *const relation_challenges.Relations,
) !ReplacementAuditV4 {
    try validateSharedAuthority(native, role_aware);
    const native_v2 = try statement_v2.nativeRelationSums(native, relations);
    const removed_sparse_rw = try public_logup_v2.rwMemoryAccessSum(
        native,
        relations,
    );
    const removed_sparse_continuation_tree =
        try statement_v2.sparseContinuationTreeCompensation(
            native,
            relations,
        );
    const added_role_aware_io = try public_logup.publicIoMemoryAccessSum(
        role_aware,
        relations,
    );
    const metadata = try native.metadata();
    const added_role_program_fetch = if (metadata.completion == null)
        try public_logup.programAccessSumForProfile(
            PROFILE,
            role_aware,
            relations,
        )
    else
        QM31.zero();
    var result = native_v2;
    result.memory_access = result.memory_access
        .sub(removed_sparse_rw)
        .add(added_role_aware_io);
    result.merkle = result.merkle.sub(removed_sparse_continuation_tree);
    result.program_access = result.program_access.add(added_role_program_fetch);
    return .{
        .native_v2 = native_v2,
        .removed_sparse_rw = removed_sparse_rw,
        .removed_sparse_continuation_tree = removed_sparse_continuation_tree,
        .added_role_aware_io = added_role_aware_io,
        .added_role_program_fetch = added_role_program_fetch,
        .result = result,
    };
}

fn sumsIdentity(value: *const VerifiedPublicSumsV4) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(SUMS_IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u16, @intFromEnum(value.execution_profile));
    for (value.native_wire_id) |word| hashInt(&hash, u32, word);
    hash.update(&value.public_boundary_identity_sha256);
    hashQm31(&hash, value.sums.registers_state);
    hashQm31(&hash, value.sums.merkle);
    hashQm31(&hash, value.sums.memory_access);
    hashQm31(&hash, value.sums.program_access);
    hashQm31(&hash, value.total);
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn hashQm31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |limb| hashInt(hash, u32, limb.toU32());
}

test "incremental public V4 adds one actual nonfinal program fetch" {
    const support = @import("public_data_v2_test_support.zig");
    var fixture = try support.Fixture.init();
    const source = fixture.leftSource();
    const words = try support.encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(words);
    const native = try public_data_v2.PublicDataV2.authenticate(words);
    var role = try statement_v2.canonicalCorePublicData(&native);
    role.completion = public_data.Completion.unretiredProgramFetch(
        role.final_pc,
        0x0010_0093,
    );
    try validateSharedAuthority(&native, &role);

    const relations = relation_challenges.Relations.dummy();
    const result = try audit(&native, &role, &relations);
    try std.testing.expect(result.native_v2.program_access.isZero());
    try std.testing.expect(!result.added_role_program_fetch.isZero());
    try std.testing.expect(result.result.program_access.eql(
        result.added_role_program_fetch,
    ));

    const identity_before = publicBoundaryIdentity(&native, &role);
    role.completion.?.value ^= 4;
    const identity_after = publicBoundaryIdentity(&native, &role);
    try std.testing.expect(!std.mem.eql(
        u8,
        &identity_before,
        &identity_after,
    ));
    role.completion = public_data.Completion.canonicalSelfLoop(role.final_pc);
    try std.testing.expectError(
        error.IncrementalPublicCompletionMismatchV4,
        validateSharedAuthority(&native, &role),
    );
}

test "incremental public V4 decodes boundary CUSTOM-0 under Ethereum profile" {
    const support = @import("public_data_v2_test_support.zig");
    const custom0 = @import("../isa/custom0.zig");
    var fixture = try support.Fixture.init();
    const source = fixture.leftSource();
    const words = try support.encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(words);
    const native = try public_data_v2.PublicDataV2.authenticate(words);
    var role = try statement_v2.canonicalCorePublicData(&native);
    role.completion = public_data.Completion.unretiredProgramFetch(
        role.final_pc,
        custom0.encodeKeccakf(5),
    );
    try validateSharedAuthority(&native, &role);
    const relations = relation_challenges.Relations.dummy();
    try std.testing.expect(!(try public_logup.programAccessSumForProfile(
        PROFILE,
        &role,
        &relations,
    )).isZero());
    try std.testing.expectError(
        error.InvalidCompletionValue,
        public_logup.programAccessSumForProfile(
            .rv32im_zkvm_v1,
            &role,
            &relations,
        ),
    );

    const final_source = fixture.rightSource();
    const final_words = try support.encode(std.testing.allocator, &final_source);
    defer std.testing.allocator.free(final_words);
    const final_native = try public_data_v2.PublicDataV2.authenticate(final_words);
    var final_role = try statement_v2.canonicalCorePublicData(&final_native);
    final_role.completion = role.completion;
    // A final SegmentV2 leaf owns its runner completion and cannot substitute
    // the role-only nonfinal fetch. Structural completion validation rejects
    // this cross-coordinate value before the later shared-authority check.
    try std.testing.expectError(
        error.InvalidCompletionAddress,
        validateSharedAuthority(&final_native, &final_role),
    );

    try std.testing.expectEqual(
        @as(u32, 1),
        @intFromEnum(public_data.CompletionKind.halt_flag),
    );
    try std.testing.expectEqual(
        @as(u32, 2),
        @intFromEnum(public_data.CompletionKind.unretired_self_loop),
    );
    try std.testing.expectEqual(
        @as(u32, 3),
        @intFromEnum(public_data.CompletionKind.unretired_program_fetch),
    );
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 1 or PRODUCTION_ACTIVE)
        @compileError("incremental public LogUp V4 activated or drifted");
}
