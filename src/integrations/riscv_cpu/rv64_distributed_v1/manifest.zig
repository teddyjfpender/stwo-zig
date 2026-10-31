//! INACTIVE complete-manifest commitment/challenge API. There is deliberately
//! no accepting aggregate receiver: root matching is not STARK verification.
const std = @import("std");
const air = @import("stwo_riscv_frontend").rv64_air;
pub const T = @import("types.zig");
pub const FunctionChallenges = air.word16_v1.function_bus.Challenges;
pub const Challenges = struct { alu: FunctionChallenges, binary: FunctionChallenges, shift: FunctionChallenges };
pub const Expected = struct { context: T.Context, specs: []const T.Spec };
pub const Manifest = struct {
    allocator: std.mem.Allocator,
    context: T.Context,
    specs: []T.Spec,
    receipts: []T.Receipt,
    digest: T.Digest,
    positive_capacity: u64,

    /// Full exact inventory is admitted BEFORE allocation or challenge draws.
    /// Both expected descriptors and received roots are copied; no borrows live
    /// beyond success. Failure preserves every caller-owned object.
    pub fn init(a: std.mem.Allocator, expected: Expected, receipts: []const T.Receipt) !Manifest {
        const mass = try validateInputs(expected, receipts);
        const specs = try a.alloc(T.Spec, expected.specs.len);
        errdefer a.free(specs);
        var initialized: usize = 0;
        errdefer for (specs[0..initialized]) |spec| a.free(spec.column_logs);
        for (specs, expected.specs) |*copy, source| {
            copy.* = source;
            copy.column_logs = try a.dupe(u32, source.column_logs);
            initialized += 1;
        }
        const roots = try a.dupe(T.Receipt, receipts);
        errdefer a.free(roots);
        const result = Manifest{ .allocator = a, .context = expected.context, .specs = specs, .receipts = roots, .digest = computeDigest(expected, receipts), .positive_capacity = mass };
        return result;
    }
    pub fn deinit(self: *Manifest) void {
        for (self.specs) |spec| self.allocator.free(spec.column_logs);
        self.allocator.free(self.specs);
        self.allocator.free(self.receipts);
        self.* = undefined;
    }
    pub fn validateExpected(self: *const Manifest, expected: Expected) !void {
        if (!std.meta.eql(self.context, expected.context) or self.specs.len != expected.specs.len) return error.DistributedContextMismatch;
        for (self.specs, expected.specs) |actual, wanted| if (!std.mem.eql(u8, &T.specDigest(actual), &T.specDigest(wanted))) return error.DistributedInventoryMismatch;
        try self.validateUnchanged();
    }
    pub fn validateUnchanged(self: *const Manifest) !void {
        const expected = Expected{ .context = self.context, .specs = self.specs };
        const mass = try validateInputs(expected, self.receipts);
        if (mass != self.positive_capacity or !std.mem.eql(u8, &self.digest, &computeDigest(expected, self.receipts))) return error.DistributedManifestChanged;
    }
    /// Callers provide a COMPLETE manifest, not an authoritative alpha. Typed
    /// family challenges are independently tagged and derived from this seal.
    pub fn derive(self: *const Manifest) !Challenges {
        try self.validateUnchanged();
        var channel = T.P.Channel{};
        channel.mixU32s(&.{ 0x52563634, 0x44534841, 1 });
        T.mixDigest(&channel, self.digest);
        return .{ .alu = drawFamily(&channel, 1), .binary = drawFamily(&channel, 2), .shift = drawFamily(&channel, 3) };
    }
    /// Worker-local transcript resumes after its ACTUAL stage1 commits. This
    /// digest precedes later interaction claims/constraint coefficient draws.
    /// The final verifier must reproduce this order with its observed roots.
    fn mixStage2(self: *const Manifest, ordinal: usize, channel: *T.P.Channel) !Challenges {
        try self.validateUnchanged();
        if (ordinal >= self.specs.len) return error.DistributedInventoryMismatch;
        const expected_channel = try stage1Channel(self.context, self.specs[ordinal], self.receipts[ordinal]);
        if (channel.n_draws != 0 or !std.mem.eql(u8, &channel.digestBytes(), &expected_channel.digestBytes())) return error.Stage1TranscriptMismatch;
        channel.mixU32s(&.{ 0x52563634, 0x44535432, 1, @intCast(ordinal) });
        T.mixDigest(channel, self.digest);
        T.mixDigest(channel, self.receipts[ordinal].shared.value);
        return self.derive();
    }
    pub fn resumeWorker(self: *const Manifest, a: std.mem.Allocator, ordinal: usize, scheme: *T.Scheme, channel: *T.P.Channel) !Challenges {
        try self.validateUnchanged();
        if (ordinal >= self.specs.len) return error.DistributedInventoryMismatch;
        const actual = try T.fromCommitted(a, scheme, self.specs[ordinal]);
        if (!std.meta.eql(actual, self.receipts[ordinal])) return error.Stage1ProofRootMismatch;
        return self.mixStage2(ordinal, channel);
    }
    /// Returns transcript inputs only, never an acceptance certificate. The
    /// caller still MUST run the concrete physical proof verifier afterwards.
    pub fn resumeReceiver(self: *const Manifest, ordinal: usize, proof: *const T.P.Proof, channel: *T.P.Channel) !Challenges {
        try self.checkObservedRoots(ordinal, proof);
        return self.mixStage2(ordinal, channel);
    }
    /// Binding check ONLY. This reads actual proof commitments, rather than a
    /// caller's claimed root. It neither verifies FRI/AIR nor accepts execution.
    /// A future aggregate receiver must additionally fresh-verify each concrete
    /// component under derive(), transcript-bind all physical claims BEFORE
    /// constraint coefficients, and close every typed relation/endpoint.
    pub fn checkObservedRoots(self: *const Manifest, ordinal: usize, proof: *const T.P.Proof) !void {
        try self.validateUnchanged();
        if (ordinal >= self.specs.len) return error.DistributedInventoryMismatch;
        const spec = self.specs[ordinal];
        const receipt = self.receipts[ordinal];
        const pcs = &proof.commitment_scheme_proof;
        if (!std.meta.eql(pcs.config, T.P.config()) or pcs.revision_config != null) return error.DistributedSuiteMismatch;
        if (spec.fixed_tree >= pcs.commitments.items.len or spec.shared_tree >= pcs.commitments.items.len) return error.MissingStage1Commitment;
        if (!std.mem.eql(u8, &pcs.commitments.items[spec.fixed_tree], &spec.expected_fixed.value) or !std.mem.eql(u8, &pcs.commitments.items[spec.shared_tree], &receipt.shared.value)) return error.Stage1ProofRootMismatch;
    }
};

pub fn validateInputs(expected: Expected, receipts: []const T.Receipt) !u64 {
    const positive = try validateInventory(expected);
    if (receipts.len != expected.specs.len) return error.IncompleteDistributedManifest;
    for (expected.specs, receipts, 0..) |spec, receipt, i| {
        if (spec.ordinal != i or receipt.ordinal != i or !std.mem.eql(u8, &receipt.spec_digest, &T.specDigest(spec)) or !std.mem.eql(u8, &receipt.fixed.value, &spec.expected_fixed.value)) return error.DistributedInventoryMismatch;
    }
    return positive;
}
pub fn validateInventory(expected: Expected) !u64 {
    const context = expected.context;
    try validateContext(context);
    if (expected.specs.len == 0 or expected.specs.len > T.MAX_ROOTS) return error.IncompleteDistributedManifest;
    var bytes: usize = 312;
    var positive: u64 = 0;
    var cpus: usize = 0;
    for (expected.specs, 0..) |spec, i| {
        try T.validateSpec(spec);
        if (spec.role != .cpu and spec.role != .alu and spec.role != .binary and spec.role != .shift and spec.role != .public_consumer) return error.UnsupportedDistributedRamProfile;
        bytes = try std.math.add(usize, bytes, try std.math.add(usize, 268, try std.math.mul(usize, spec.column_logs.len, 4)));
        if (bytes > T.MAX_MANIFEST_BYTES) return error.DistributedResourceLimit;
        if (spec.ordinal != i) return error.DistributedInventoryMismatch;
        if (spec.role == .cpu or spec.role == .public_consumer) {
            cpus += 1;
            var log: u32 = 0;
            for (spec.column_logs) |column_log| log = @max(log, column_log);
            // Both positive schemas permit at most one query per row: CPU family
            // flags or the public-consumer Boolean weight. Count PADDING too.
            positive = std.math.add(u64, positive, @as(u64, 1) << @intCast(log)) catch return error.DistributedMassOverflow;
        }
    }
    if (cpus == 0) return error.IncompleteDistributedManifest;
    if (positive > context.positive_limit) return error.DistributedMassOverflow;
    _ = try air.word16_v1.function_bus.admitPositiveMass(&.{positive});
    return positive;
}
pub fn validateContext(context: T.Context) !void {
    if (context.protocol != .functional13_v1) return error.UnsupportedDistributedRamProfile;
    if (context.local_register_clock_bits != 24 or context.relation_epoch == 0 or context.positive_limit == 0 or context.positive_limit >= 0x7fff_ffff or !std.mem.eql(u8, &context.opcode_map, &T.opcodeMapIdentity())) return error.InvalidDistributedContext;
}
pub fn beginStage1(context: T.Context, spec: T.Spec, channel: *T.P.Channel) !void {
    try validateContext(context);
    try T.validateSpec(spec);
    if (channel.n_draws != 0 or !std.mem.allEqual(u8, &channel.digestBytes(), 0)) return error.Stage1TranscriptMismatch;
    channel.mixU32s(&.{ 0x52563634, 0x44535431, 1, @intFromEnum(context.protocol), 13 });
    T.P.config().mixInto(channel);
    mixContext(channel, context);
    T.mixSpec(channel, spec);
}
pub fn stage1Channel(context: T.Context, spec: T.Spec, receipt: T.Receipt) !T.P.Channel {
    var channel = T.P.Channel{};
    try beginStage1(context, spec, &channel);
    T.P.MerkleChannel.mixRoot(&channel, receipt.fixed.value);
    T.P.MerkleChannel.mixRoot(&channel, receipt.shared.value);
    return channel;
}
pub fn computeDigest(expected: Expected, receipts: []const T.Receipt) T.Digest {
    var channel = T.P.Channel{};
    channel.mixU32s(&.{ 0x52563634, 0x44534d46, 1, @intFromEnum(expected.context.protocol), 13 });
    T.P.config().mixInto(&channel);
    mixContext(&channel, expected.context);
    channel.mixU64(expected.specs.len);
    for (expected.specs, receipts) |spec, receipt| {
        T.mixSpec(&channel, spec);
        channel.mixU32s(&.{receipt.ordinal});
        T.mixDigest(&channel, receipt.spec_digest);
        T.mixDigest(&channel, receipt.fixed.value);
        T.mixDigest(&channel, receipt.shared.value);
    }
    return channel.digestBytes();
}
fn mixContext(channel: *T.P.Channel, c: T.Context) void {
    channel.mixU64(c.request_id);
    channel.mixU64(c.relation_epoch);
    channel.mixU64(c.positive_limit);
    channel.mixU32s(&.{c.local_register_clock_bits});
    for ([_]T.Digest{ c.request_digest, c.instance, c.program_key, c.input, c.policy, c.terminal, c.opcode_map }) |digest| T.mixDigest(channel, digest);
}
fn drawFamily(channel: *T.P.Channel, family: u32) FunctionChallenges {
    channel.mixU32s(&.{ 0x46554e43, 1, family, 13 });
    var result: FunctionChallenges = undefined;
    result.offset = channel.drawSecureFelt();
    for (&result.coefficients) |*coefficient| coefficient.* = channel.drawSecureFelt();
    return result;
}
