//! Independent durable PAGE policy. Pinned bytes choose no verification result;
//! original PAGE/RAM/range proofs must still close every source equation.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Files = @import("block_v5_artifact_files_v1.zig");
const Global = @import("block_v5_capacity_global_receiver_v1.zig");
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Batch = @import("block_v5_memory_source_batch_protocol_v1.zig");
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const Raw = @import("block_v5_memory_source_batch_raw_schema_v1.zig");
const RawStage = @import("block_v5_memory_source_packed_sha_replay_v1.zig");
const FoldStore = @import("block_v5_memory_source_fold_operand_store_v1.zig");
const Protocol = @import("block_v5_memory_source_unified_page_protocol_v1.zig");
const Page = @import("block_v5_memory_source_unified_page_proof_v1.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Algebra = @import("../recursion/block_v5_memory_source_page_forest_algebra_v1.zig");
const Codec = @import("block_v5_memory_source_unified_page_codec_v1.zig");
pub const FILE = "source-page-policy-v1.json";
pub const FORMAT = "stwo-zig/block-v5/source-PAGE-policy";
pub const VERSION: u32 = 2;
pub const LEGACY_VERSION: u32 = 1;
pub const Artifact = struct { byte_len: u64, sha256: [32]u8 };
pub const RawRecord = struct { pin: RawStage.Pin, artifact: Artifact, expected_claims: ?Semantic.Claims = null };
pub const FoldRecord = struct { pin: Protocol.FoldPin, operands: FoldStore.Pin, artifact: Artifact, expected_claims: ?Semantic.Claims = null };
pub const Pin = struct {
    byte_len: u64,
    sha256: [32]u8,
    pub fn require(self: Pin, limits: Limits) !void {
        try limits.validate();
        if (self.byte_len == 0 or self.byte_len > limits.max_file_bytes or std.mem.allEqual(u8, &self.sha256, 0)) return error.UntrustedSourcePagePolicyPin;
    }
};
pub const Wire = struct {
    format: []const u8 = FORMAT,
    version: u32 = VERSION,
    page_abi: [32]u8 = blk: {
        @setEvalBranchQuota(1_000_000);
        break :blk Protocol.abiId();
    },
    config: core.pcs.PcsConfig,
    raw_plan: Raw.Protocol.Plan,
    fold_plan: Protocol.FoldPlan,
    raw: []const RawRecord,
    fold: []const FoldRecord,
    sealed: Protocol.Sealed,
};
pub const Limits = struct {
    max_file_bytes: usize = 256 << 20,
    max_owned_bytes: usize = 512 << 20,
    max_metadata_bytes: usize = 256 << 20,
    max_pages: usize = 524288,
    max_artifact_bytes: u64 = 512 << 30,
    max_operand_bytes: u64 = 512 << 30,
    source: Source.Limits = .{},
    fold: Fold.Limits = .{},
    pages: Page.Limits = .{},
    codec: Codec.Limits = .{},
    pub fn validate(self: Limits) !void {
        if (self.max_file_bytes == 0 or self.max_owned_bytes < self.max_file_bytes or self.max_metadata_bytes == 0 or self.max_pages == 0 or
            self.max_artifact_bytes == 0 or self.max_operand_bytes == 0 or self.pages.max_receiver_heap_bytes == 0 or
            self.codec.max_proof_bytes == 0 or self.codec.max_artifact_bytes < @max(Codec.ForKind(.raw).HEADER_BYTES, Codec.ForKind(.fold).HEADER_BYTES) or
            self.codec.max_proof_bytes > self.codec.max_artifact_bytes - @max(Codec.ForKind(.raw).HEADER_BYTES, Codec.ForKind(.fold).HEADER_BYTES) or
            !std.meta.eql(self.pages.raw, self.pages.protocol.raw) or !std.meta.eql(self.pages.fold.protocol, self.pages.protocol)) return error.InvalidSourcePagePolicyLimits;
    }
};
pub fn metadataBytes(raw_count: usize, fold_count: usize) !usize {
    // Wire owns records; Context duplicates normative rosters. Temporary pins
    // during reconstruction are also charged to the same owned heap cap.
    return std.math.add(usize, try std.math.mul(usize, raw_count, @sizeOf(RawRecord) + 2 * @sizeOf(RawStage.Pin)), try std.math.mul(usize, fold_count, @sizeOf(FoldRecord) + 2 * @sizeOf(Protocol.FoldPin)));
}
fn artifactRequire(artifact: Artifact, maximum: usize, total: *u64) !void {
    if (artifact.byte_len == 0 or artifact.byte_len > maximum or std.mem.allEqual(u8, &artifact.sha256, 0)) return error.UntrustedSourcePagePolicyArtifact;
    total.* = try std.math.add(u64, total.*, artifact.byte_len);
}
/// Strict normative reconstruction; neither returned Context nor file hash is
/// a proof receipt. Config and source authority come from original Globals.
pub fn reconstruct(a: std.mem.Allocator, globals: Global.Pins, wire: Wire, limits: Limits) !Page.Context {
    try limits.validate();
    if (!std.mem.eql(u8, wire.format, FORMAT) or (wire.version != VERSION and wire.version != LEGACY_VERSION) or !std.meta.eql(wire.page_abi, Protocol.abiId())) return error.UnsupportedSourcePagePolicy;
    const count = try std.math.add(usize, wire.raw.len, wire.fold.len);
    if (count > limits.max_pages or try metadataBytes(wire.raw.len, wire.fold.len) > limits.max_metadata_bytes) return error.SourcePagePolicyResourceLimit;
    try requireClaimVersion(wire);
    const base = try globals.validate();
    if (base.register_custody_mode != 1 or !std.meta.eql(wire.config, globals.tables.seal.config) or
        !std.meta.eql(wire.raw_plan.config, wire.config) or !std.meta.eql(wire.fold_plan.config, wire.config)) return error.UntrustedSourcePagePolicyIdentity;
    const source = try Source.admit(globals.memory.memory.source(), globals.tables.seal, globals.tables.roster, base, limits.source);
    const admitted = try Batch.Admission.init(source, limits.fold);
    if (!std.meta.eql(wire.raw_plan, try Raw.Protocol.init(&source, wire.config, limits.pages.raw.first)) or
        !std.meta.eql(wire.fold_plan, try Protocol.FoldPlan.init(&admitted, wire.fold_plan.census, wire.config, limits.pages.protocol)) or
        wire.raw.len != wire.raw_plan.pages or wire.fold.len != wire.fold_plan.pages) return error.UntrustedSourcePagePolicyPlan;
    var artifact_bytes: u64 = 0;
    var operand_bytes: u64 = 0;
    for (wire.raw) |record| try artifactRequire(record.artifact, limits.codec.max_artifact_bytes, &artifact_bytes);
    for (wire.fold) |record| {
        try artifactRequire(record.artifact, limits.codec.max_artifact_bytes, &artifact_bytes);
        const expected_bytes = try std.math.add(u64, FoldStore.HEADER_BYTES, try std.math.mul(u64, record.pin.page.count, FoldStore.RECORD_BYTES));
        if (record.operands.byte_len != expected_bytes or expected_bytes > limits.pages.fold.stored.max_file_bytes or record.pin.page.count > limits.pages.fold.stored.max_operations or
            std.mem.allEqual(u8, &record.operands.sha256, 0) or std.mem.allEqual(u8, &record.operands.page_identity, 0)) return error.UntrustedSourcePagePolicyInventory;
        operand_bytes = try std.math.add(u64, operand_bytes, expected_bytes);
    }
    if (artifact_bytes > limits.max_artifact_bytes or operand_bytes > limits.max_operand_bytes) return error.SourcePagePolicyResourceLimit;
    const raws = try a.alloc(RawStage.Pin, wire.raw.len);
    defer a.free(raws);
    const folds = try a.alloc(Protocol.FoldPin, wire.fold.len);
    defer a.free(folds);
    for (raws, wire.raw) |*pin, record| pin.* = record.pin;
    for (folds, wire.fold) |*pin, record| pin.* = record.pin;
    // Original complete census/order/nonzero roots/first circuit/epoch checks.
    return Page.Context.init(a, admitted, wire.raw_plan, wire.fold_plan, raws, folds, wire.sealed, wire.sealed.digest, base, limits.pages);
}
/// Version 1 is read-only compatibility. It never nominates expected
/// recursive setup constants. Version 2 pins the original pre-proof proposal;
/// proof verification, not this policy, establishes those claims' correctness.
pub fn expectedClaims(comptime kind: Semantic.Kind, proposed: ?Semantic.Claims) !Semantic.Claims {
    const claims = proposed orelse return error.MissingIndependentPageSemanticClaims;
    try Algebra.canonical(Algebra.flatten(claims));
    if (kind == .raw) {
        if (!std.meta.eql(claims.fold, Semantic.Claims.zero().fold)) return error.UntrustedPagePolicySemanticClaims;
    } else if (!std.meta.eql(claims.source, Semantic.Claims.zero().source) or !claims.indexed.eql(@import("stwo_core").fields.qm31.QM31.zero())) return error.UntrustedPagePolicySemanticClaims;
    return claims;
}
pub fn requireClaimVersion(wire: Wire) !void {
    if (wire.version == VERSION) {
        for (wire.raw) |record| _ = try expectedClaims(.raw, record.expected_claims);
        for (wire.fold) |record| _ = try expectedClaims(.fold, record.expected_claims);
    } else if (wire.version == LEGACY_VERSION) {
        for (wire.raw) |record| if (record.expected_claims != null) return error.UnsupportedSourcePagePolicy;
        for (wire.fold) |record| if (record.expected_claims != null) return error.UnsupportedSourcePagePolicy;
    } else return error.UnsupportedSourcePagePolicy;
}
pub const Owned = struct {
    budget: *Budget,
    parsed: std.json.Parsed(Wire),
    context: Page.Context,
    pin: Pin,
    limits: Limits,
    pub fn allocator(self: *Owned) std.mem.Allocator {
        return self.budget.allocator();
    }
    pub fn deinit(self: *Owned) void {
        const budget = self.budget;
        self.context.deinit();
        self.parsed.deinit();
        budget.allocator().destroy(self);
        budget.destroy();
    }
};
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, globals: Global.Pins, wire: Wire, limits: Limits) !Pin {
    try limits.validate();
    if (wire.version != VERSION) return error.UnsupportedSourcePagePolicy;
    try requireClaimVersion(wire);
    const budget = try Budget.createRetainingParent(a, limits.max_owned_bytes);
    defer budget.destroy();
    const bounded = budget.allocator();
    var context = try reconstruct(bounded, globals, wire, limits);
    defer context.deinit();
    var counter = @import("block_v5_cpu_counting_writer_v1.zig").Counting.init(limits.max_file_bytes);
    std.json.Stringify.value(wire, .{}, &counter.writer) catch |failure| {
        if (counter.exceeded) return error.SourcePagePolicyResourceLimit;
        return failure;
    };
    const raw = try bounded.alloc(u8, counter.count);
    defer bounded.free(raw);
    var output = std.Io.Writer.fixed(raw);
    try std.json.Stringify.value(wire, .{}, &output);
    const bytes = output.buffered();
    if (bytes.len != counter.count) return error.ChangedSourcePagePolicySerialization;
    try Files.publish(dir, FILE, bytes);
    return .{ .byte_len = bytes.len, .sha256 = Files.hash(bytes) };
}
pub fn read(a: std.mem.Allocator, dir: std.fs.Dir, expected: Pin, globals: Global.Pins, limits: Limits) !*Owned {
    try expected.require(limits);
    const budget = try Budget.createRetainingParent(a, limits.max_owned_bytes);
    errdefer budget.destroy();
    const bounded = budget.allocator();
    const raw = try Files.readPinned(bounded, dir, FILE, expected.byte_len, expected.sha256, limits.max_file_bytes);
    defer bounded.free(raw);
    var parsed = try std.json.parseFromSlice(Wire, bounded, raw, .{ .allocate = .alloc_always, .ignore_unknown_fields = false, .max_value_len = limits.max_file_bytes });
    errdefer parsed.deinit();
    var context = try reconstruct(bounded, globals, parsed.value, limits);
    errdefer context.deinit();
    const self = try bounded.create(Owned);
    self.* = .{ .budget = budget, .parsed = parsed, .context = context, .pin = expected, .limits = limits };
    return self;
}
