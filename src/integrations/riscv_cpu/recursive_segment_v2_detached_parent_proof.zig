//! The ordinary proof engine consumes the detached parent cohort. Returning a
//! serialized candidate is not acceptance; callers destroy the producer and
//! child owners before invoking the standalone verifier with independent inputs.
const std = @import("std");
const recursion = @import("stwo_riscv_frontend").recursion;
const postcard = @import("interop_postcard");
const cohort = @import("recursive_segment_v2_detached_parent_cohort.zig");
const protocol = @import("recursive_segment_v2_detached_parent_protocol.zig");
const verifier = @import("recursive_segment_v2_detached_parent_verifier.zig");
const storage = @import("recursive_segment_v2_outer_engine_storage.zig");
const Engine = @import("recursive_segment_v2_outer_engine.zig").Engine;
const TreeStorage = storage.TreeStorageForManifest(Engine, cohort.manifest_mod);
pub const Candidate = struct {
    allocator: std.mem.Allocator,
    key_json: []u8,
    proof_bytes: []u8,
    claims: protocol.ClaimsV1,
    circuit_identity: [32]u8,
    prepare_ns: u64,
    prove_ns: u64,
    pub fn deinit(self: *Candidate) void {
        self.allocator.free(self.key_json);
        self.allocator.free(self.proof_bytes);
        self.* = undefined;
    }
};

pub fn produce(allocator: std.mem.Allocator, prepared: *cohort.PreparedV1, expected: *const protocol.ExpectedV1, child_key_sha256: [2][32]u8, admitted_key: ?*const protocol.KeyV1) !Candidate {
    try protocol.validateExpected(expected);
    var timer = try std.time.Timer.start();
    const manifest = prepared.manifest();
    var scheme = try Engine.init(allocator, protocol.PCS_CONFIG);
    scheme.setCoefficientRetentionPolicy(.never);
    var scheme_moved = false;
    defer if (!scheme_moved) Engine.deinit(&scheme, allocator);
    var channel = Engine.Channel{};
    var preprocessed = try TreeStorage.init(allocator, manifest, 0);
    defer preprocessed.deinit();
    try prepared.fillPreprocessedInto(preprocessed.columns);
    try preprocessed.commit(&scheme, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 1) return error.DetachedParentPreprocessedCommitmentMismatch;
    const candidate_key = protocol.KeyV1{
        .manifest = manifest.*,
        .parameters = prepared.parameters(),
        .preprocessed_root = roots.items[0],
        .child_key_sha256 = child_key_sha256,
    };
    const identity = try candidate_key.identity();
    const key = admitted_key orelse &candidate_key;
    if (!std.meta.eql(identity, try key.identity())) return error.DetachedParentFixedCircuitMismatch;
    const key_json = try std.json.Stringify.valueAlloc(allocator, key.*, .{});
    errdefer allocator.free(key_json);
    const prepare_ns = timer.lap();
    var main = try TreeStorage.init(allocator, manifest, 1);
    defer main.deinit();
    try prepared.fillMainInto(main.columns);
    _ = try prepared.auditExactTupleClosure(expected, main.columns);
    try main.commit(&scheme, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    try protocol.mixAdmission(&channel, key, expected);
    const relations = try cohort.Relations.draw(allocator, &channel);
    var interaction = try TreeStorage.init(allocator, manifest, 2);
    defer interaction.deinit();
    const claims = try prepared.fillInteractionInto(&relations, interaction.columns);
    try protocol.mixClaimsAndBoundary(&channel, key, expected, claims, &relations);
    try interaction.commit(&scheme, &channel);
    const components = try cohort.OwnedComponentsV1.init(allocator, manifest, key.parameters, &relations, claims);
    defer components.deinit();
    var gate = try cohort.manifest_mod.ProofGate.init(manifest);
    try components.appendToGate(manifest, &gate);
    try gate.sealGate(manifest);
    scheme_moved = true;
    var extended = try Engine.prove(allocator, try gate.proverSlice(), &channel, scheme, .{});
    defer extended.deinit(allocator);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try postcard.serializeProof(recursion.engine.Hasher, encoded.writer(allocator), extended.proof);
    if (encoded.items.len == 0 or encoded.items.len > verifier.MAX_PROOF_BYTES) return error.DetachedParentProofSizeMismatch;
    return .{ .allocator = allocator, .key_json = key_json, .proof_bytes = try encoded.toOwnedSlice(allocator), .claims = claims, .circuit_identity = identity, .prepare_ns = prepare_ns, .prove_ns = timer.read() };
}
