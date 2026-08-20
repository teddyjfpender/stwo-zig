//! Exact logical-work authority for the PCS transcript shell.
//!
//! The ordinary RISC-V product uses Blake2s for both Fiat--Shamir and lifted
//! Merkle hashing. Those algorithms execute no field operations, but zero is
//! still an observation that needs an exhaustive producer boundary: absence
//! cannot be interpreted as zero. A profiled proof therefore accumulates one
//! cold phase audit and publishes this receipt only after the PCS proof and
//! auxiliary decommitment object have both been assembled successfully.
//!
//! Field-native transcript or Merkle suites are intentionally not assigned the
//! Blake2s zero formula. They fail closed until their own permutation receipt
//! is connected; this prevents a new Poseidon-backed engine from inheriting a
//! zero contribution through a generic `anytype` call path.

const std = @import("std");
const builtin = @import("builtin");
const channel_blake2s = @import("stwo_core").channel.blake2s;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const SCHEMA_VERSION: u16 = 1;
pub const DIGEST_DOMAIN = "stwo-zig/prover/pcs-shell-work/v1\x00";
pub const PREOPENING_DOMAIN = "stwo-zig/prover/pcs-shell-preopening/v1\x00";
pub const FRI_ROOT_MIX_DOMAIN = "stwo-zig/prover/fri-root-mix-work/v1\x00";
pub const Digest = [Sha256.digest_length]u8;

pub const Error = error{
    CountOverflow,
    DuplicatePhase,
    IncompletePhases,
    InvalidReceipt,
    UnsupportedSuite,
};

/// Frozen counter boundary. Proof-object construction is inside the native
/// prover; postcard/JSON encoding and all external serialization are outside.
/// Moving that boundary requires a new enum value and receipt schema.
pub const CounterPartition = enum(u8) {
    native_prover_external_serialization_excluded = 1,
};

pub const COUNTER_PARTITION: CounterPartition =
    .native_prover_external_serialization_excluded;

pub const TranscriptSuite = enum(u8) {
    blake2s_bytes = 1,
    blake2s_m31 = 2,
};

pub const MerkleSuite = enum(u8) {
    blake2s_prefixed_bytes = 1,
    blake2s_prefixed_m31 = 2,
    blake2s_plain_bytes = 3,
    blake2s_plain_m31 = 4,
};

pub const Suite = struct {
    transcript: TranscriptSuite,
    merkle: MerkleSuite,
};

const Phase = enum(u4) {
    preopening_roots_mixed,
    sampled_values_mixed,
    coefficient_drawn,
    fri_roots_and_terminal_mixed,
    proof_of_work_mixed,
    fri_decommitted,
    trace_decommitted,
    commitment_roots_materialized,
    proof_assembled,
};

const PHASE_COUNT = @typeInfo(Phase).@"enum".fields.len;
const ALL_PHASES: u16 = (@as(u16, 1) << PHASE_COUNT) - 1;

pub const PreOpeningReceipt = struct {
    root_mix_count: u32,
    authority_digest: Digest,
};

/// Scheme-owned, allocation-free custody for every trace/composition root
/// mixed before sampled values enter the opening transcript.
pub const PreOpeningAudit = struct {
    active: bool = false,
    complete: bool = true,
    root_mix_count: u32 = 0,
    authority_digest: Digest = [_]u8{0} ** Sha256.digest_length,

    pub fn begin(
        self: *PreOpeningAudit,
        committed_tree_count: usize,
        has_pending_tree: bool,
    ) void {
        if (self.active) return;
        self.active = true;
        self.complete = committed_tree_count == 0 and !has_pending_tree;
        var hash = Sha256.init(.{});
        hash.update(PREOPENING_DOMAIN);
        hashInt(&hash, u16, SCHEMA_VERSION);
        hashInt(&hash, u8, @intFromEnum(COUNTER_PARTITION));
        self.authority_digest = hash.finalResult();
    }

    /// Must be called immediately after `MC.mixRoot` succeeds. The ordinal is
    /// the commitment-tree index in transcript order.
    pub fn observeRootMixed(
        self: *PreOpeningAudit,
        ordinal: usize,
        root: []const u8,
    ) void {
        if (!self.active) return;
        const encoded_ordinal = std.math.cast(u32, ordinal) orelse {
            self.complete = false;
            return;
        };
        if (!self.complete or encoded_ordinal != self.root_mix_count or root.len == 0) {
            self.complete = false;
            return;
        }
        var hash = Sha256.init(.{});
        hash.update(PREOPENING_DOMAIN);
        hash.update(&self.authority_digest);
        hashInt(&hash, u32, encoded_ordinal);
        hashInt(&hash, u32, std.math.cast(u32, root.len) orelse {
            self.complete = false;
            return;
        });
        hash.update(root);
        self.authority_digest = hash.finalResult();
        self.root_mix_count = std.math.add(u32, self.root_mix_count, 1) catch {
            self.complete = false;
            return;
        };
    }

    pub fn finish(self: *const PreOpeningAudit, expected_count: usize) Error!PreOpeningReceipt {
        const expected = try cast(u32, expected_count);
        if (!self.active or !self.complete or self.root_mix_count != expected or
            expected == 0 or digestIsZero(self.authority_digest))
        {
            return error.IncompletePhases;
        }
        return .{
            .root_mix_count = self.root_mix_count,
            .authority_digest = self.authority_digest,
        };
    }
};

/// Receipt from the FRI producer. The path counts are observed only after the
/// corresponding generic/lazy mix or receipt-bearing fused transaction has
/// succeeded; `authority_digest` additionally binds the returned roots.
pub const FriRootMixReceipt = struct {
    root_mix_count: u32,
    generic_count: u32,
    lazy_count: u32,
    fused_count: u32,
    authority_digest: Digest,
    receipt_digest: Digest,

    pub fn init(
        root_mix_count: usize,
        generic_count: usize,
        lazy_count: usize,
        fused_count: usize,
        authority_digest: Digest,
    ) Error!FriRootMixReceipt {
        var result = FriRootMixReceipt{
            .root_mix_count = try cast(u32, root_mix_count),
            .generic_count = try cast(u32, generic_count),
            .lazy_count = try cast(u32, lazy_count),
            .fused_count = try cast(u32, fused_count),
            .authority_digest = authority_digest,
            .receipt_digest = undefined,
        };
        result.receipt_digest = friRootMixReceiptDigest(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const FriRootMixReceipt) Error!void {
        const total = std.math.add(
            u32,
            self.generic_count,
            self.lazy_count,
        ) catch return error.CountOverflow;
        const all = std.math.add(u32, total, self.fused_count) catch
            return error.CountOverflow;
        if (self.root_mix_count == 0 or all != self.root_mix_count or
            digestIsZero(self.authority_digest) or
            !std.mem.eql(u8, &self.receipt_digest, &friRootMixReceiptDigest(self)))
        {
            return error.InvalidReceipt;
        }
    }
};

pub const FriRootMixCapture = struct {
    receipt: ?FriRootMixReceipt = null,

    pub fn publish(self: *FriRootMixCapture, receipt: FriRootMixReceipt) Error!void {
        try receipt.validate();
        if (self.receipt != null) return error.DuplicatePhase;
        self.receipt = receipt;
    }
};

/// Pointer-free, digest-bound evidence for the included-with-zero Blake2s
/// shell. Merkle parent counts remain owned by the existing commitment/FRI
/// sites and are deliberately not duplicated here.
pub const Receipt = struct {
    schema_version: u16 = SCHEMA_VERSION,
    counter_partition: CounterPartition = COUNTER_PARTITION,
    suite: Suite,
    sampled_tree_count: u32,
    sampled_column_count: u32,
    sampled_value_count: u64,
    pow_bits: u32,
    pow_nonce: u64,
    fri_raw_query_count: u32,
    fri_unique_query_count: u32,
    fri_layer_count: u32,
    trace_decommitment_count: u32,
    commitment_count: u32,
    preopening_root_mix_count: u32,
    preopening_authority_digest: Digest,
    fri_root_mix_count: u32,
    fri_root_mix_authority_digest: Digest,
    phase_mask: u16,
    receipt_digest: Digest,

    pub fn validate(self: *const Receipt) Error!void {
        if (self.schema_version != SCHEMA_VERSION or
            self.counter_partition != COUNTER_PARTITION or
            self.sampled_tree_count == 0 or
            self.sampled_column_count == 0 or
            self.fri_raw_query_count == 0 or
            self.fri_unique_query_count == 0 or
            self.fri_unique_query_count > self.fri_raw_query_count or
            self.fri_layer_count == 0 or
            self.trace_decommitment_count != self.sampled_tree_count or
            self.commitment_count != self.sampled_tree_count or
            self.preopening_root_mix_count != self.commitment_count or
            self.fri_root_mix_count != self.fri_layer_count or
            digestIsZero(self.preopening_authority_digest) or
            digestIsZero(self.fri_root_mix_authority_digest) or
            self.phase_mask != ALL_PHASES or
            !std.mem.eql(u8, &self.receipt_digest, &receiptDigest(self)))
        {
            return error.InvalidReceipt;
        }
    }
};

/// Cold request-local phase ledger. Every observation happens after the
/// corresponding operation succeeds; duplicate or missing observations make
/// publication impossible instead of producing a partial receipt.
pub const Audit = struct {
    suite: ?Suite,
    preopening: PreOpeningReceipt,
    sampled_tree_count: u32,
    sampled_column_count: u32,
    sampled_value_count: u64,
    pow_bits: u32 = 0,
    pow_nonce: u64 = 0,
    fri_raw_query_count: u32 = 0,
    fri_unique_query_count: u32 = 0,
    fri_layer_count: u32 = 0,
    trace_decommitment_count: u32 = 0,
    fri_root_mix: ?FriRootMixReceipt = null,
    commitment_count: u32 = 0,
    phase_mask: u16 = 0,

    pub fn init(
        comptime Channel: type,
        comptime H: type,
        comptime MC: type,
        sampled_tree_count: usize,
        sampled_column_count: usize,
        sampled_value_count: usize,
        preopening: *const PreOpeningAudit,
    ) Error!Audit {
        const tree_count = try cast(u32, sampled_tree_count);
        const preopening_receipt = try preopening.finish(sampled_tree_count);
        return .{
            .suite = classifySuite(Channel, H, MC),
            .preopening = preopening_receipt,
            .sampled_tree_count = tree_count,
            .sampled_column_count = try cast(u32, sampled_column_count),
            .sampled_value_count = try cast(u64, sampled_value_count),
            .phase_mask = phaseBit(.preopening_roots_mixed),
        };
    }

    pub fn observeSampledValuesMixed(self: *Audit) Error!void {
        try self.observe(.sampled_values_mixed);
    }

    pub fn observeCoefficientDrawn(self: *Audit) Error!void {
        try self.observe(.coefficient_drawn);
    }

    pub fn observeFriCommitted(
        self: *Audit,
        layer_count: usize,
        root_mix: FriRootMixReceipt,
    ) Error!void {
        const count = try cast(u32, layer_count);
        try root_mix.validate();
        if (count == 0 or root_mix.root_mix_count != count)
            return error.IncompletePhases;
        try self.observe(.fri_roots_and_terminal_mixed);
        self.fri_layer_count = count;
        self.fri_root_mix = root_mix;
    }

    pub fn observeProofOfWorkMixed(
        self: *Audit,
        pow_bits: u32,
        nonce: u64,
    ) Error!void {
        try self.observe(.proof_of_work_mixed);
        self.pow_bits = pow_bits;
        self.pow_nonce = nonce;
    }

    pub fn observeFriDecommitted(
        self: *Audit,
        raw_query_count: usize,
        unique_query_count: usize,
    ) Error!void {
        const raw = try cast(u32, raw_query_count);
        const unique = try cast(u32, unique_query_count);
        if (raw == 0 or unique == 0 or unique > raw)
            return error.IncompletePhases;
        try self.observe(.fri_decommitted);
        self.fri_raw_query_count = raw;
        self.fri_unique_query_count = unique;
    }

    pub fn observeTraceDecommitted(self: *Audit, count: usize) Error!void {
        const encoded = try cast(u32, count);
        if (encoded != self.sampled_tree_count)
            return error.IncompletePhases;
        try self.observe(.trace_decommitted);
        self.trace_decommitment_count = encoded;
    }

    pub fn observeCommitmentRootsMaterialized(self: *Audit, count: usize) Error!void {
        const encoded = try cast(u32, count);
        if (encoded != self.sampled_tree_count)
            return error.IncompletePhases;
        try self.observe(.commitment_roots_materialized);
        self.commitment_count = encoded;
    }

    pub fn finish(self: *Audit, commitment_count: usize) Error!Receipt {
        const commitments = try cast(u32, commitment_count);
        if (commitments != self.sampled_tree_count or commitments != self.commitment_count)
            return error.IncompletePhases;
        try self.observe(.proof_assembled);
        if (self.phase_mask != ALL_PHASES) return error.IncompletePhases;
        const suite = self.suite orelse return error.UnsupportedSuite;
        const fri_root_mix = self.fri_root_mix orelse return error.IncompletePhases;
        var result = Receipt{
            .counter_partition = COUNTER_PARTITION,
            .suite = suite,
            .sampled_tree_count = self.sampled_tree_count,
            .sampled_column_count = self.sampled_column_count,
            .sampled_value_count = self.sampled_value_count,
            .pow_bits = self.pow_bits,
            .pow_nonce = self.pow_nonce,
            .fri_raw_query_count = self.fri_raw_query_count,
            .fri_unique_query_count = self.fri_unique_query_count,
            .fri_layer_count = self.fri_layer_count,
            .trace_decommitment_count = self.trace_decommitment_count,
            .commitment_count = commitments,
            .preopening_root_mix_count = self.preopening.root_mix_count,
            .preopening_authority_digest = self.preopening.authority_digest,
            .fri_root_mix_count = fri_root_mix.root_mix_count,
            .fri_root_mix_authority_digest = fri_root_mix.authority_digest,
            .phase_mask = self.phase_mask,
            .receipt_digest = undefined,
        };
        result.receipt_digest = receiptDigest(&result);
        try result.validate();
        return result;
    }

    fn observe(self: *Audit, phase: Phase) Error!void {
        const bit = phaseBit(phase);
        if (self.phase_mask & bit != 0) return error.DuplicatePhase;
        self.phase_mask |= bit;
    }
};

/// Closed recognition of suites whose complete shell executes zero field
/// operations. An unlisted wrapper or future hash implementation is not
/// structurally guessed to be Blake2s.
pub fn classifySuite(
    comptime Channel: type,
    comptime H: type,
    comptime MC: type,
) ?Suite {
    const transcript: TranscriptSuite = if (Channel == channel_blake2s.Blake2sChannel)
        .blake2s_bytes
    else if (Channel == channel_blake2s.Blake2sM31Channel)
        .blake2s_m31
    else
        return null;

    if (MC != blake2_merkle.Blake2sMerkleChannel and
        MC != blake2_merkle.Blake2sM31MerkleChannel)
    {
        return null;
    }

    const merkle: MerkleSuite = if (H == blake2_merkle.Blake2sMerkleHasher)
        .blake2s_prefixed_bytes
    else if (H == blake2_merkle.Blake2sM31MerkleHasher)
        .blake2s_prefixed_m31
    else if (H == blake2_merkle.Blake2sPlainMerkleHasher)
        .blake2s_plain_bytes
    else if (H == blake2_merkle.Blake2sPlainM31MerkleHasher)
        .blake2s_plain_m31
    else
        return null;
    return .{ .transcript = transcript, .merkle = merkle };
}

const TestReceiptAuditState = struct {
    receipt: ?Receipt = null,
    observation_count: usize = 0,

    fn observe(self: *TestReceiptAuditState, receipt: Receipt) void {
        self.observation_count += 1;
        if (self.receipt == null) self.receipt = receipt;
    }

    pub fn snapshot(self: *const TestReceiptAuditState) TestReceiptAuditSnapshot {
        return .{
            .receipt = self.receipt,
            .observation_count = self.observation_count,
        };
    }
};

const TestReceiptAuditSnapshot = struct {
    receipt: ?Receipt,
    observation_count: usize,
};

const TestReceiptAuditThread = if (builtin.is_test) struct {
    threadlocal var active: ?*TestReceiptAuditState = null;
} else struct {};

const TestReceiptAuditBindingState = struct {
    audit: *TestReceiptAuditState,
    active: bool = true,

    pub fn init(audit: *TestReceiptAuditState) !TestReceiptAuditBindingState {
        if (comptime !builtin.is_test) return error.TestOnly;
        if (TestReceiptAuditThread.active != null)
            return error.TestReceiptAuditAlreadyBound;
        TestReceiptAuditThread.active = audit;
        return .{ .audit = audit };
    }

    pub fn deinit(self: *TestReceiptAuditBindingState) void {
        if (comptime !builtin.is_test) unreachable;
        std.debug.assert(self.active);
        std.debug.assert(TestReceiptAuditThread.active == self.audit);
        TestReceiptAuditThread.active = null;
        self.active = false;
    }
};

inline fn observeAcceptedReceiptForTest(receipt: Receipt) void {
    if (comptime !builtin.is_test) return;
    const audit = TestReceiptAuditThread.active orelse return;
    audit.observe(receipt);
}

/// Narrow receipt observation seam for owned integration tests. Production
/// builds erase the call and expose an empty namespace.
pub const testing = if (builtin.is_test) struct {
    pub const ReceiptAudit = TestReceiptAuditState;
    pub const ReceiptAuditBinding = TestReceiptAuditBindingState;
    pub const ReceiptAuditSnapshot = TestReceiptAuditSnapshot;

    pub inline fn observeAcceptedReceipt(receipt: Receipt) void {
        observeAcceptedReceiptForTest(receipt);
    }
} else struct {};

fn receiptDigest(receipt: *const Receipt) Digest {
    var hash = Sha256.init(.{});
    hash.update(DIGEST_DOMAIN);
    hashInt(&hash, u16, receipt.schema_version);
    hashInt(&hash, u8, @intFromEnum(receipt.counter_partition));
    hashInt(&hash, u8, @intFromEnum(receipt.suite.transcript));
    hashInt(&hash, u8, @intFromEnum(receipt.suite.merkle));
    hashInt(&hash, u32, receipt.sampled_tree_count);
    hashInt(&hash, u32, receipt.sampled_column_count);
    hashInt(&hash, u64, receipt.sampled_value_count);
    hashInt(&hash, u32, receipt.pow_bits);
    hashInt(&hash, u64, receipt.pow_nonce);
    hashInt(&hash, u32, receipt.fri_raw_query_count);
    hashInt(&hash, u32, receipt.fri_unique_query_count);
    hashInt(&hash, u32, receipt.fri_layer_count);
    hashInt(&hash, u32, receipt.trace_decommitment_count);
    hashInt(&hash, u32, receipt.commitment_count);
    hashInt(&hash, u32, receipt.preopening_root_mix_count);
    hash.update(&receipt.preopening_authority_digest);
    hashInt(&hash, u32, receipt.fri_root_mix_count);
    hash.update(&receipt.fri_root_mix_authority_digest);
    hashInt(&hash, u16, receipt.phase_mask);
    return hash.finalResult();
}

fn friRootMixReceiptDigest(receipt: *const FriRootMixReceipt) Digest {
    var hash = Sha256.init(.{});
    hash.update(FRI_ROOT_MIX_DOMAIN);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u32, receipt.root_mix_count);
    hashInt(&hash, u32, receipt.generic_count);
    hashInt(&hash, u32, receipt.lazy_count);
    hashInt(&hash, u32, receipt.fused_count);
    hash.update(&receipt.authority_digest);
    return hash.finalResult();
}

fn phaseBit(phase: Phase) u16 {
    return @as(u16, 1) << @intFromEnum(phase);
}

fn digestIsZero(value: Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

fn cast(comptime T: type, value: anytype) Error!T {
    return std.math.cast(T, value) orelse error.CountOverflow;
}

fn preopeningFixture(count: usize) PreOpeningAudit {
    var audit = PreOpeningAudit{};
    audit.begin(0, false);
    for (0..count) |ordinal| {
        const root = [_]u8{@intCast(ordinal + 1)} ** 32;
        audit.observeRootMixed(ordinal, &root);
    }
    return audit;
}

fn friRootMixFixture(count: usize) !FriRootMixReceipt {
    var hash = Sha256.init(.{});
    hash.update(FRI_ROOT_MIX_DOMAIN);
    hashInt(&hash, u32, @intCast(count));
    return FriRootMixReceipt.init(count, count, 0, 0, hash.finalResult());
}

fn completeFixture(audit: *Audit) !Receipt {
    try audit.observeSampledValuesMixed();
    try audit.observeCoefficientDrawn();
    try audit.observeFriCommitted(4, try friRootMixFixture(4));
    try audit.observeProofOfWorkMixed(10, 37);
    try audit.observeFriDecommitted(70, 67);
    try audit.observeTraceDecommitted(3);
    try audit.observeCommitmentRootsMaterialized(3);
    return audit.finish(3);
}

test "PCS shell receipt closes every Blake2s phase exactly once" {
    const preopening = preopeningFixture(3);
    var audit = try Audit.init(
        channel_blake2s.Blake2sChannel,
        blake2_merkle.Blake2sMerkleHasher,
        blake2_merkle.Blake2sMerkleChannel,
        3,
        11,
        29,
        &preopening,
    );
    const receipt = try completeFixture(&audit);
    try receipt.validate();
    try std.testing.expectEqual(ALL_PHASES, receipt.phase_mask);
    try std.testing.expectEqual(@as(u32, 70), receipt.fri_raw_query_count);
    try std.testing.expectEqual(@as(u32, 67), receipt.fri_unique_query_count);
}

test "PCS shell receipt rejects omissions duplicates and mutations" {
    const preopening = preopeningFixture(3);
    var missing = try Audit.init(
        channel_blake2s.Blake2sChannel,
        blake2_merkle.Blake2sMerkleHasher,
        blake2_merkle.Blake2sMerkleChannel,
        3,
        11,
        29,
        &preopening,
    );
    try missing.observeSampledValuesMixed();
    try std.testing.expectError(error.IncompletePhases, missing.finish(3));

    var duplicate = try Audit.init(
        channel_blake2s.Blake2sChannel,
        blake2_merkle.Blake2sMerkleHasher,
        blake2_merkle.Blake2sMerkleChannel,
        3,
        11,
        29,
        &preopening,
    );
    try duplicate.observeCoefficientDrawn();
    try std.testing.expectError(
        error.DuplicatePhase,
        duplicate.observeCoefficientDrawn(),
    );

    var valid = try Audit.init(
        channel_blake2s.Blake2sChannel,
        blake2_merkle.Blake2sMerkleHasher,
        blake2_merkle.Blake2sMerkleChannel,
        3,
        11,
        29,
        &preopening,
    );
    var receipt = try completeFixture(&valid);
    receipt.fri_unique_query_count -= 1;
    try std.testing.expectError(error.InvalidReceipt, receipt.validate());
}

test "PCS shell never assigns Blake2s zero work to an unknown suite" {
    const UnknownChannel = struct {};
    const UnknownHasher = struct {};
    const UnknownMerkleChannel = struct {};
    try std.testing.expect(
        classifySuite(UnknownChannel, UnknownHasher, UnknownMerkleChannel) == null,
    );
    const preopening = preopeningFixture(3);
    var audit = try Audit.init(
        UnknownChannel,
        UnknownHasher,
        UnknownMerkleChannel,
        3,
        11,
        29,
        &preopening,
    );
    try std.testing.expectError(error.UnsupportedSuite, completeFixture(&audit));
}

test "PCS shell accepted-receipt audit is scoped and preserves first receipt" {
    var receipt_audit: testing.ReceiptAudit = .{};
    var binding = try testing.ReceiptAuditBinding.init(&receipt_audit);
    defer binding.deinit();

    const preopening = preopeningFixture(3);
    var first_audit = try Audit.init(
        channel_blake2s.Blake2sChannel,
        blake2_merkle.Blake2sMerkleHasher,
        blake2_merkle.Blake2sMerkleChannel,
        3,
        11,
        29,
        &preopening,
    );
    const first = try completeFixture(&first_audit);
    testing.observeAcceptedReceipt(first);

    var second_audit = try Audit.init(
        channel_blake2s.Blake2sChannel,
        blake2_merkle.Blake2sMerkleHasher,
        blake2_merkle.Blake2sMerkleChannel,
        3,
        11,
        29,
        &preopening,
    );
    var second = try completeFixture(&second_audit);
    second.pow_nonce += 1;
    second.receipt_digest = receiptDigest(&second);
    testing.observeAcceptedReceipt(second);

    const snapshot = receipt_audit.snapshot();
    try std.testing.expectEqual(@as(usize, 2), snapshot.observation_count);
    try std.testing.expectEqualDeep(first, snapshot.receipt.?);
    try std.testing.expectError(
        error.TestReceiptAuditAlreadyBound,
        testing.ReceiptAuditBinding.init(&receipt_audit),
    );
}
