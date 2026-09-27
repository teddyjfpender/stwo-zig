//! Distinct simultaneous-fold equation ABI. Admissions and candidate sums are
//! metadata only; no source/root authority exists before actual fresh proofs.
const std = @import("std");
const core = @import("stwo_core");
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const Relation = @import("../air/relation_challenges.zig").RelationElements;
const G = @import("../recursion/air/blake3_g_call.zig");
const Xor = @import("../recursion/air/blake3_xor_call.zig");
pub const TAG: u32 = 0x42355346; // B5SF, cannot relabel old B5SA per-edit chunks
pub const VERSION: u32 = 1;
pub const ROUTE_WIDTH = 67; // height, 2 index limbs, 32 before+32 after bytes
pub const INDEXED_WIDTH = 13; // stream, ordinal4, address2, value2, clock4
pub const HASH_WIDTH = 97; // frame tag, 64 payload bytes, 32 digest bytes
pub fn abiId() [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("stwo-zig/block-v5/sorted-source-fold/v1\x00depth30;strict-ram;full-image;paired-before;untouched-retained;authenticated-initial-input;full-u64-clocks;postorder-coordinate-routing;one-root;original-blake3-tree-v2;no-proof-authority\x00");
    h.update(&G.SEMANTIC_DIGEST);
    h.update(&Xor.SEMANTIC_DIGEST);
    return h.finalResult();
}
pub const Admission = struct {
    source: Source.Admitted,
    limits: Fold.Limits,
    identity: [32]u8,
    pub fn init(source: Source.Admitted, limits: Fold.Limits) !Admission {
        try source.require();
        if (limits.max_leaves == 0 or limits.max_operations == 0 or limits.max_compressions == 0 or limits.max_operations >= core.fields.m31.Modulus or limits.max_compressions >= core.fields.m31.Modulus) return error.InvalidSourceFoldLimits;
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(&abiId());
        h.update(&source.identity);
        var raw: [24]u8 = undefined;
        std.mem.writeInt(u64, raw[0..8], limits.max_leaves, .little);
        std.mem.writeInt(u64, raw[8..16], limits.max_operations, .little);
        std.mem.writeInt(u64, raw[16..24], limits.max_compressions, .little);
        h.update(&raw);
        return .{ .source = source, .limits = limits, .identity = h.finalResult() };
    }
    pub fn require(self: *const Admission) !void {
        const rebuilt = try init(self.source, self.limits);
        if (!std.mem.eql(u8, &self.identity, &rebuilt.identity)) return error.InvalidSourceFoldAdmission;
    }
};
pub const Challenges = struct {
    /// These three *new* buses must be drawn only after original source, fold
    /// routing/digests and packed core inputs/output main roots are committed.
    /// Source9 itself follows source roots and precedes arithmetic generation.
    source: Source.Challenges,
    route: Relation(ROUTE_WIDTH),
    indexed: Relation(INDEXED_WIDTH),
    hash: Relation(HASH_WIDTH),
};
pub const Sums = struct {
    indexed: core.fields.qm31.QM31 = .zero(),
    insertion: core.fields.qm31.QM31 = .zero(),
    before: core.fields.qm31.QM31 = .zero(),
    after: core.fields.qm31.QM31 = .zero(),
    route: core.fields.qm31.QM31 = .zero(),
    hash: core.fields.qm31.QM31 = .zero(),
};
/// Independently admitted source counts, not private proposed stream counters.
/// All five source byte/SHA/input/order chains still require genuine proofs.
pub const Required = struct {
    input: u64,
    rw: u64,
    touches: u64,
    roots: u64 = 1,
    pub fn fromAdmission(admitted: *const Admission) !Required {
        try admitted.require();
        return .{ .input = admitted.source.records(.input_words), .rw = admitted.source.records(.rw_words), .touches = admitted.source.records(.endpoints) };
    }
};
