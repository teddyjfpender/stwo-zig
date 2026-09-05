//! Split public compensation for full-state incremental-memory V3 leaves.
//!
//! The authenticated V2 statement remains the authority for CPU state,
//! register endpoints, program/continuation roots, and resumed clocks. Its
//! sparse RW transition is not a public-I/O authority, however: zero-valued,
//! never-accessed input words are absent from both sparse snapshots. The V3
//! full-state boundary commits every ordinary RW endpoint and continuation
//! leaf, so this adapter removes both V2 sparse-only compensations while
//! retaining the public root anchors, then inserts only the exact role-derived
//! V1 input/output/completion tuples.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const public_data = @import("public_data.zig");
const public_data_v2 = @import("public_data_v2.zig");
const public_logup = @import("public_logup.zig");
const public_logup_v2 = @import("public_logup_v2.zig");
const relation_challenges = @import("relation_challenges.zig");
const statement_v2 = @import("statement_v2.zig");
const boundary = @import("memory_commitment/boundary.zig");
const boundary_interaction = @import("memory_commitment/interaction.zig");
const memory_logup = @import("memory_logup.zig");

pub const PRODUCTION_ACTIVE = false;
pub const FORMAT_VERSION: u16 = 3;
pub const Sums = public_logup_v2.Sums;
pub const Digest = [32]u8;

const IO_IDENTITY_DOMAIN =
    "stwo.riscv.incremental-public-io.v3\x00";
const SUMS_IDENTITY_DOMAIN =
    "stwo.riscv.incremental-public-sums.v3\x00";

pub const ReplacementAuditV3 = struct {
    native_v2: Sums,
    removed_sparse_rw: QM31,
    removed_sparse_continuation_tree: QM31,
    added_role_aware_io: QM31,
    result: Sums,
};

/// Pointer-free public compensation sealed only after the authenticated V2
/// wire and the role-aware V1 public boundary agree. This is durable evidence
/// for a fresh verifier capture; it is not a substitute for proof admission.
pub const VerifiedPublicSumsV3 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = 1,
    native_wire_id: public_data_v2.Digest,
    public_io_identity_sha256: Digest,
    sums: Sums,
    total: QM31,
    identity_sha256: Digest,

    pub fn init(
        native: *const public_data_v2.PublicDataV2,
        role_aware: *const public_data.PublicData,
        relations: *const relation_challenges.Relations,
    ) !VerifiedPublicSumsV3 {
        const value = try relationSums(native, role_aware, relations);
        var result = VerifiedPublicSumsV3{
            .native_wire_id = native.wireId(),
            .public_io_identity_sha256 = publicIoIdentity(role_aware),
            .sums = value,
            .total = value.total(),
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = sumsIdentity(&result);
        return result;
    }

    pub fn validateAgainst(
        self: *const VerifiedPublicSumsV3,
        native: *const public_data_v2.PublicDataV2,
        role_aware: *const public_data.PublicData,
        relations: *const relation_challenges.Relations,
    ) !void {
        const expected = try VerifiedPublicSumsV3.init(
            native,
            role_aware,
            relations,
        );
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != 1 or
            !std.meta.eql(self.*, expected))
        {
            return error.InvalidIncrementalPublicSums;
        }
    }
};

/// Fresh-verifier-owned copy of the exact role-aware public boundary. The
/// scalar CPU/root fields are retained as a complete `PublicData` value while
/// both dynamic IO slices point exclusively into this owner.
pub const OwnedPublicDataV3 = struct {
    allocator: std.mem.Allocator,
    input_words: []u32,
    output_words: []public_data.OutputWord,
    value: public_data.PublicData,
    public_io_identity_sha256: Digest,

    pub fn initVerified(
        allocator: std.mem.Allocator,
        native: *const public_data_v2.PublicDataV2,
        source: *const public_data.PublicData,
    ) !OwnedPublicDataV3 {
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
        const result = OwnedPublicDataV3{
            .allocator = allocator,
            .input_words = input_words,
            .output_words = output_words,
            .value = value,
            .public_io_identity_sha256 = publicIoIdentity(&value),
        };
        try result.validateAgainst(native);
        return result;
    }

    pub fn deinit(self: *OwnedPublicDataV3) void {
        self.allocator.free(self.output_words);
        self.allocator.free(self.input_words);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const OwnedPublicDataV3,
        native: *const public_data_v2.PublicDataV2,
    ) !void {
        if (self.value.io_entries.input_words.ptr != self.input_words.ptr or
            self.value.io_entries.input_words.len != self.input_words.len or
            self.value.io_entries.output_words.ptr != self.output_words.ptr or
            self.value.io_entries.output_words.len != self.output_words.len or
            !std.mem.eql(
                u8,
                &self.public_io_identity_sha256,
                &publicIoIdentity(&self.value),
            ))
        {
            return error.IncrementalPublicAuthorityMismatch;
        }
        try validateSharedAuthority(native, &self.value);
    }
};

pub fn publicIoIdentity(value: *const public_data.PublicData) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(IO_IDENTITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, 1);
    hashInt(&hash, u32, value.io_entries.input_start);
    hashInt(&hash, u32, value.io_entries.input_len);
    hashInt(&hash, u64, value.io_entries.input_words.len);
    for (value.io_entries.input_words) |word| hashInt(&hash, u32, word);
    hashInt(&hash, u32, value.io_entries.output_len);
    hashInt(&hash, u32, value.io_entries.output_len_addr);
    hashInt(&hash, u32, value.io_entries.output_data_addr);
    hashInt(&hash, u64, value.io_entries.output_words.len);
    for (value.io_entries.output_words) |word| {
        hashInt(&hash, u32, word.addr);
        hashInt(&hash, u32, word.value);
        hashInt(&hash, u32, word.clock);
    }
    return hash.finalResult();
}

fn sumsIdentity(value: *const VerifiedPublicSumsV3) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(SUMS_IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    for (value.native_wire_id) |word| hashInt(&hash, u32, word);
    hash.update(&value.public_io_identity_sha256);
    hashQm31(&hash, value.sums.registers_state);
    hashQm31(&hash, value.sums.merkle);
    hashQm31(&hash, value.sums.memory_access);
    hashQm31(&hash, value.sums.program_access);
    hashQm31(&hash, value.total);
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

/// Exposes the exact replacement decomposition for cold-verifier diagnostics.
/// The individual members are evidence only; callers must use `result` (or
/// `sum`) as the global public compensation.
pub fn audit(
    native: *const public_data_v2.PublicDataV2,
    role_aware: *const public_data.PublicData,
    relations: *const relation_challenges.Relations,
) !ReplacementAuditV3 {
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
    var result = native_v2;
    result.memory_access = result.memory_access
        .sub(removed_sparse_rw)
        .add(added_role_aware_io);
    result.merkle = result.merkle.sub(removed_sparse_continuation_tree);
    return .{
        .native_v2 = native_v2,
        .removed_sparse_rw = removed_sparse_rw,
        .removed_sparse_continuation_tree = removed_sparse_continuation_tree,
        .added_role_aware_io = added_role_aware_io,
        .result = result,
    };
}

/// The integration owner separately cold-validates layout, public roles, and
/// the retained transition artifact. This frontend guard pins every shared
/// V1/V2 field so the role-aware IO value cannot smuggle a second CPU, root,
/// program, or completion statement into the proof.
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
        !completionMatches(role_aware.completion, expected.completion) or
        (!metadata.is_first and
            (role_aware.io_entries.input_len != 0 or
                role_aware.io_entries.input_words.len != 0)) or
        (!metadata.is_final and
            (role_aware.io_entries.output_len != 0 or
                role_aware.io_entries.output_words.len != 0)))
    {
        return error.IncrementalPublicAuthorityMismatch;
    }
}

fn completionMatches(
    actual: ?public_data.Completion,
    expected: ?public_data.Completion,
) bool {
    if (expected) |value| return std.meta.eql(actual, @as(?public_data.Completion, value));
    return if (actual) |value|
        value.kind == .unretired_self_loop and value.clock == 0
    else
        false;
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn hashQm31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |limb| hashInt(hash, u32, limb.toU32());
}

fn testPublicData(input_words: []const u32) public_data.PublicData {
    return .{
        .initial_pc = 0,
        .final_pc = 0,
        .clock = 1,
        .initial_regs = .{0} ** 32,
        .final_regs = .{0} ** 32,
        .reg_last_clock = .{0} ** 32,
        .program_root = 0,
        .initial_rw_root = 7,
        .final_rw_root = 7,
        .completion = public_data.Completion.canonicalSelfLoop(0),
        .io_entries = .{
            .input_start = 0x1000,
            .input_len = @intCast(input_words.len * 4),
            .input_words = input_words,
            .output_len = 0,
            .output_len_addr = 0x2000,
            .output_data_addr = 0x2004,
            .output_words = &.{},
        },
    };
}

fn accessWitness(
    address: u32,
    previous_clock: u32,
    previous_word: u32,
    next_clock: u32,
    next_word: u32,
) memory_logup.AccessWitness {
    return .{
        .addr_space = secure(1),
        .addr = secure(address),
        .previous_clock = secure(previous_clock),
        .previous = limbs(previous_word),
        .clock = secure(next_clock),
        .next = limbs(next_word),
        .enabler = QM31.one(),
    };
}

fn secure(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@as(u64, value)));
}

fn limbs(value: u32) [4]QM31 {
    return .{
        secure(@as(u8, @truncate(value))),
        secure(@as(u8, @truncate(value >> 8))),
        secure(@as(u8, @truncate(value >> 16))),
        secure(@as(u8, @truncate(value >> 24))),
    };
}

test "incremental public V3 closes an untouched zero input through its exit row" {
    const relations = relation_challenges.Relations.dummy();
    const input_words = [_]u32{0};
    const public = testPublicData(&input_words);
    const public_io = try public_logup.publicIoMemoryAccessSum(
        &public,
        &relations,
    );
    const exit = boundary.Row{
        .addr = 0x1000,
        .clock = 0,
        .value = .{ 0, 0, 0, 0 },
        .multiplicity = M31.one().neg(),
        .root = 7,
    };
    const exit_claim = try boundary_interaction.diagnosticSum(
        &.{exit},
        .memory_access,
        &relations,
    );
    try std.testing.expect(public_io.add(exit_claim).isZero());

    var suppressed = exit;
    suppressed.multiplicity = M31.zero();
    const missing = try boundary_interaction.diagnosticSum(
        &.{suppressed},
        .memory_access,
        &relations,
    );
    try std.testing.expect(!public_io.add(missing).isZero());
}

test "incremental public V3 does not double count an ordinary RW transition" {
    const allocator = std.testing.allocator;
    const relations = relation_challenges.Relations.dummy();
    const entry = boundary.Row{
        .addr = 0x3000,
        .clock = 0,
        .value = .{ 7, 0, 0, 0 },
        .multiplicity = M31.one(),
        .root = 11,
    };
    const exit = boundary.Row{
        .addr = 0x3000,
        .clock = 1,
        .value = .{ 9, 0, 0, 0 },
        .multiplicity = M31.one().neg(),
        .root = 13,
    };
    const boundary_claim = try boundary_interaction.diagnosticSum(
        &.{ entry, exit },
        .memory_access,
        &relations,
    );
    var access = try memory_logup.generate(
        allocator,
        &.{accessWitness(0x3000, 0, 7, 1, 9)},
        0,
        &relations.memory_access,
    );
    defer access.deinit(allocator);
    try std.testing.expect(boundary_claim.add(access.claimed).isZero());

    // V2 sparse-RW compensation is the same entry-minus-exit endpoint pair.
    // Retaining it here would double the already committed V3 boundary.
    try std.testing.expect(!boundary_claim
        .add(access.claimed)
        .add(boundary_claim)
        .isZero());
}

test "incremental public V3 retains roots but removes sparse tree leaves" {
    const support = @import("public_data_v2_test_support.zig");
    var fixture = try support.Fixture.init();
    const source = fixture.rightSource();
    const words = try support.encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(words);
    const native = try public_data_v2.PublicDataV2.authenticate(words);
    const role_aware = try statement_v2.canonicalCorePublicData(&native);
    const relations = relation_challenges.Relations.dummy();

    const audit_result = try audit(&native, &role_aware, &relations);
    const root_anchors = try public_logup_v2.relationSums(
        &native,
        &relations,
    );
    try std.testing.expect(!audit_result
        .removed_sparse_continuation_tree.isZero());
    try std.testing.expect(audit_result.result.merkle.eql(root_anchors.merkle));
    try std.testing.expect(!audit_result.native_v2.merkle.eql(
        root_anchors.merkle,
    ));

    const retained_sparse_tree = audit_result.result.merkle.add(
        audit_result.removed_sparse_continuation_tree,
    );
    try std.testing.expect(retained_sparse_tree.eql(
        audit_result.native_v2.merkle,
    ));
}

comptime {
    if (PRODUCTION_ACTIVE or FORMAT_VERSION != 3)
        @compileError("incremental public LogUp V3 activation drifted");
}
