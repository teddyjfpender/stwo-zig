//! Versioned raw+fold PAGE commitment epochs. This is transcript/admission
//! metadata, never a source receipt. PAGE verification must prove original
//! core/table/capture/input/arithmetic closure, then an aggregate must join
//! both exact rosters and the independently fresh sorted-RAM endpoints.
const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const Q = core.fields.qm31.QM31;
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Batch = @import("block_v5_memory_source_batch_protocol_v1.zig");
const Word = @import("block_v5_word_memory_protocol_v1.zig");
const RawSchema = @import("block_v5_memory_source_batch_raw_schema_v1.zig");
const RawOperand = @import("block_v5_memory_source_packed_sha_replay_v1.zig");
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const Blake = @import("block_v5_memory_source_packed_blake_columns_v1.zig");
const Universal = @import("../recursion/air/universal_challenges.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
pub const TAG: u32 = 0x42355047; // B5PG, never B5SC/B5SK
pub const VERSION: u32 = 1;
pub const PREMIX_TREES = 6;
pub const SEMANTIC_TREES = 2;
pub const TREE_COUNT = 9; // six premix, semantic fixed/main, interaction
pub const PROOF_COMMITMENTS = TREE_COUNT + 1; // composition
pub const Kind = Semantic.Kind;
/// Disjoint namespaces even when raw/fold proofs share the same dedicated
/// wire relation. This exact namespace belongs to independent page admission.
pub fn semanticCircuitId(admitted: *const Batch.Admission, fold_plan: FoldPlan, kind: Kind, page_index: u32, limits: Limits) !u32 {
    try fold_plan.require(admitted, limits);
    const raw = try @import("block_v5_memory_source_batch_raw_v1.zig").census(&admitted.source);
    const page_count = if (kind == .raw) (try RawSchema.Protocol.init(&admitted.source, fold_plan.config, limits.raw.first)).pages else fold_plan.pages;
    if (page_index >= page_count) return error.InvalidSourceUnifiedPage;
    const base = try std.math.add(u64, @max(raw.compressions, fold_plan.census.compressions), 1);
    // Each PAGE has the original segment/binary lowering lanes. Only segment
    // rows are committed, but both circuit IDs remain distinct and admitted.
    const index = try std.math.add(u64, try std.math.mul(u64, page_index, 4), 2 * @as(u64, @intFromEnum(kind)));
    const id = try std.math.add(u64, base, index);
    if (id == 0 or id >= core.fields.m31.Modulus - 1) return error.SourceUnifiedPageResourceLimit;
    return @intCast(id);
}
pub const Limits = struct {
    raw: RawOperand.Limits = .{},
    fold_cores: Blake.Limits = .{},
    page_row_log: u32 = 12,
    max_fold_pages: u32 = 262144,
    max_roster_bytes: usize = 128 << 20,
};
pub const FoldPlan = struct {
    admission_id: [32]u8,
    census: Fold.Census,
    pages: u32,
    row_log: u32,
    config: core.pcs.PcsConfig,
    identity: [32]u8,
    pub fn init(admitted: *const Batch.Admission, census: Fold.Census, config: core.pcs.PcsConfig, limits: Limits) !FoldPlan {
        try admitted.require();
        try census.require(&admitted.source, admitted.limits);
        try @import("blake3_execution_protocol.zig").validateConfig(config);
        if (limits.page_row_log < 1 or limits.page_row_log > 12 or limits.max_fold_pages == 0 or limits.max_fold_pages > 262144 or limits.max_roster_bytes == 0)
            return error.SourceUnifiedPageResourceLimit;
        const fri = config.fri_config;
        if (limits.page_row_log + fri.log_blowup_factor >= core.circle.M31_CIRCLE_LOG_ORDER or limits.page_row_log < fri.fold_step or
            limits.page_row_log - fri.fold_step < fri.log_last_layer_degree_bound) return error.InvalidSourceUnifiedPageGeometry;
        const rows: u64 = @as(u64, 1) << @intCast(limits.page_row_log);
        const operations = try census.operations();
        const pages = (try std.math.add(u64, operations, rows - 1)) / rows;
        if (pages == 0 or pages > limits.max_fold_pages or try std.math.mul(usize, @intCast(pages), @sizeOf(FoldPin)) > limits.max_roster_bytes)
            return error.SourceUnifiedPageResourceLimit;
        var channel = suite.Channel{};
        channel.mixRoot(abiId());
        channel.mixRoot(admitted.identity);
        channel.mixU32s(&.{ TAG, VERSION, 0x464f4c44, @intCast(pages), limits.page_row_log });
        mixCensus(&channel, census);
        config.mixInto(&channel);
        return .{ .admission_id = admitted.identity, .census = census, .pages = @intCast(pages), .row_log = limits.page_row_log, .config = config, .identity = channel.digestBytes() };
    }
    pub fn require(self: FoldPlan, admitted: *const Batch.Admission, limits: Limits) !void {
        if (!std.meta.eql(self, try init(admitted, self.census, self.config, limits))) return error.UntrustedSourceUnifiedFoldPlan;
    }
    pub fn page(self: FoldPlan, index: u32) !Page {
        if (self.row_log < 1 or self.row_log > 12 or index >= self.pages) return error.InvalidSourceUnifiedPage;
        const total = try self.census.operations();
        const capacity: u64 = @as(u64, 1) << @intCast(self.row_log);
        if (self.pages != (total + capacity - 1) / capacity) return error.InvalidSourceUnifiedPage;
        const first = @as(u64, index) * capacity;
        return .{ .index = index, .first = first, .count = @intCast(@min(capacity, total - first)), .row_log = self.row_log };
    }
};
pub const Page = struct { index: u32, first: u64, count: u32, row_log: u32 };
pub const FoldPin = struct {
    page: Page,
    plan_id: [32]u8,
    /// Full kind/height/recipe inventory. The receiver rebuilds all fixed
    /// columns from this independently admitted, bounded public inventory.
    inventory_id: [32]u8,
    geometry: Blake.Geometry,
    roots: [PREMIX_TREES][32]u8,
    pub fn require(self: FoldPin, admitted: *const Batch.Admission, plan: FoldPlan, limits: Limits) !void {
        try plan.require(admitted, limits);
        if (!std.meta.eql(self.page, try plan.page(self.page.index)) or !std.meta.eql(self.plan_id, plan.identity) or
            self.geometry.operations != self.page.count or self.geometry.first_ordinal != self.page.first or
            self.geometry.first_circuit == 0 or self.geometry.compressions > limits.fold_cores.max_compressions or
            self.geometry.frames > 2 * @as(u64, self.page.count) or self.geometry.cells > limits.fold_cores.max_cells or
            std.mem.allEqual(u8, &self.inventory_id, 0)) return error.UntrustedSourceUnifiedFoldPin;
        for (self.geometry.logs) |log| if (log == 0 or log >= core.circle.M31_CIRCLE_LOG_ORDER) return error.InvalidSourceUnifiedPageGeometry;
        if (self.geometry.capture_log == 0 or self.geometry.capture_log >= core.circle.M31_CIRCLE_LOG_ORDER or
            self.geometry.compressions > (@as(u64, 1) << @intCast(self.geometry.capture_log))) return error.InvalidSourceUnifiedPageGeometry;
        for (self.roots) |root| if (std.mem.allEqual(u8, &root, 0)) return error.UntrustedSourceUnifiedFoldPin;
    }
    pub fn identity(self: FoldPin, admitted: *const Batch.Admission, plan: FoldPlan, limits: Limits) ![32]u8 {
        try self.require(admitted, plan, limits);
        var channel = foldFirstChannel(plan, self);
        for (self.roots) |root| channel.mixRoot(root);
        return channel.digestBytes();
    }
};
fn mixCensus(channel: *suite.Channel, census: Fold.Census) void {
    inline for (std.meta.fields(Fold.Census)) |field| channel.mixU64(@field(census, field.name));
}
pub fn abiId() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/source-unified-PAGE/v1\x00");
    hash.update(&RawSchema.abiId());
    hash.update(&Batch.abiId());
    inline for (Blake.Airs) |Air| hash.update(&Air.SEMANTIC_DIGEST);
    hash.update(&Universal.registryOrderDigest());
    hash.update("raw+fold;no-sibling-stream;all-six-premix-roots-before-Source9/indexed13/route67/hash97;original-word-prefix;semantic-fixed-main-before-page-universal;one-interaction/composition/FRI;exact-input-mapping;segment-binary-four-id-namespace;ten-proof-commitments;source-authority-only-after-full-aggregate/sorted-join\x00");
    return hash.finalResult();
}
pub fn foldFirstChannel(plan: FoldPlan, pin: FoldPin) suite.Channel {
    var channel = suite.Channel{};
    mixFoldFirst(&channel, plan, pin);
    return channel;
}
pub fn mixFoldFirst(channel: anytype, plan: FoldPlan, pin: FoldPin) void {
    channel.mixRoot(abiId());
    channel.mixRoot(plan.identity);
    channel.mixRoot(pin.inventory_id);
    channel.mixU32s(&.{ TAG, VERSION, 0x46525354, pin.page.index, pin.page.count, pin.page.row_log, pin.geometry.first_circuit, pin.geometry.compressions, pin.geometry.frames, pin.geometry.capture_log });
    channel.mixU64(pin.page.first);
    channel.mixU32s(&pin.geometry.logs);
    channel.mixU64(@intCast(pin.geometry.cells));
    plan.config.mixInto(channel);
}
pub const Sealed = struct {
    digest: [32]u8,
    admission_id: [32]u8,
    raw_plan_id: [32]u8,
    fold_plan_id: [32]u8,
    raw_pages: u32,
    fold_pages: u32,
};
pub fn seal(admitted: *const Batch.Admission, raw_plan: RawSchema.Protocol.Plan, fold_plan: FoldPlan, raw: []const RawOperand.Pin, fold: []const FoldPin, limits: Limits) !Sealed {
    try admitted.require();
    try raw_plan.require(&admitted.source, limits.raw.first);
    try fold_plan.require(admitted, limits);
    if (!std.meta.eql(raw_plan.config, fold_plan.config) or raw.len != raw_plan.pages or fold.len != fold_plan.pages or
        try std.math.add(usize, try std.math.mul(usize, raw.len, @sizeOf(RawOperand.Pin)), try std.math.mul(usize, fold.len, @sizeOf(FoldPin))) > limits.max_roster_bytes)
        return error.UntrustedSourceUnifiedRoster;
    var channel = suite.Channel{};
    channel.mixRoot(abiId());
    channel.mixRoot(admitted.identity);
    channel.mixRoot(admitted.source.sealed_digest);
    channel.mixRoot(raw_plan.identity);
    channel.mixRoot(fold_plan.identity);
    channel.mixU32s(&.{ TAG, VERSION, 0x5345414c, @intCast(raw.len), @intCast(fold.len) });
    for (raw, 0..) |pin, index| {
        if (pin.raw.page.index != index) return error.UntrustedSourceUnifiedRoster;
        channel.mixRoot(try pin.identity(&admitted.source, raw_plan, limits.raw));
    }
    var compressions: u64 = 0;
    for (fold, 0..) |pin, index| {
        if (pin.page.index != index or pin.geometry.first_circuit != 1 + compressions) return error.UntrustedSourceUnifiedRoster;
        channel.mixRoot(try pin.identity(admitted, fold_plan, limits));
        compressions = try std.math.add(u64, compressions, pin.geometry.compressions);
    }
    if (compressions != fold_plan.census.compressions or compressions + 1 >= core.fields.m31.Modulus) return error.UntrustedSourceUnifiedRoster;
    return .{ .digest = channel.digestBytes(), .admission_id = admitted.identity, .raw_plan_id = raw_plan.identity, .fold_plan_id = fold_plan.identity, .raw_pages = @intCast(raw.len), .fold_pages = @intCast(fold.len) };
}
pub const SourceEpoch = struct { challenges: Batch.Challenges, after_draw_digest: [32]u8, seal_digest: [32]u8 };
pub fn draw(a: std.mem.Allocator, admitted: *const Batch.Admission, raw_plan: RawSchema.Protocol.Plan, fold_plan: FoldPlan, raw: []const RawOperand.Pin, fold: []const FoldPin, expected_sealed: Sealed, independent_digest: [32]u8, base_sealed: anytype, limits: Limits) !SourceEpoch {
    const rebuilt = try seal(admitted, raw_plan, fold_plan, raw, fold, limits);
    if (!std.meta.eql(rebuilt, expected_sealed) or !std.meta.eql(rebuilt.digest, independent_digest) or
        !std.meta.eql(base_sealed.digest, admitted.source.sealed_digest) or base_sealed.register_custody_mode != 1 or
        !std.meta.eql(base_sealed.initial_source_plan_digest, try admitted.source.pins.initial.digest()) or
        !std.meta.eql(base_sealed.rw_endpoint_plan_digest, try admitted.source.pins.digest()) or
        !std.meta.eql(base_sealed.expected_final_rw_root, admitted.source.pins.expected_final_rw_root)) return error.UntrustedSourceUnifiedSeal;
    var channel = base_sealed.sharedChannel();
    // Preserve the original sorted-RAM challenges before adding PAGE roots.
    const word = try Word.Challenges.drawFromChannel(a, &channel);
    channel.mixU32s(&.{ TAG, VERSION, 0x534f5552, 6, 4, 5, 4, 8, 71, 36, 7, 37 });
    channel.mixRoot(abiId());
    channel.mixRoot(rebuilt.digest);
    const source = try channel.drawSecureFelts(a, 18);
    defer a.free(source);
    channel.mixU32s(&.{ TAG, VERSION, 0x464f4c44, Batch.ROUTE_WIDTH, Batch.INDEXED_WIDTH, Batch.HASH_WIDTH });
    const extra = try channel.drawSecureFelts(a, 6);
    defer a.free(extra);
    return .{ .seal_digest = rebuilt.digest, .after_draw_digest = channel.digestBytes(), .challenges = .{
        .source = .{ .word = word, .bytes = .init(source[0], source[1]), .input = .init(source[2], source[3]), .insertion = .init(source[4], source[5]), .before = .init(source[6], source[7]), .after = .init(source[8], source[9]), .route = .init(source[10], source[11]), .roots = .init(source[12], source[13]), .ordering = .init(source[14], source[15]), .sha_chain = .init(source[16], source[17]) },
        .route = .init(extra[0], extra[1]),
        .indexed = .init(extra[2], extra[3]),
        .hash = .init(extra[4], extra[5]),
    } };
}
pub const SemanticPin = struct {
    premix_identity: [32]u8,
    source_epoch: [32]u8,
    graph_identity: [32]u8,
    circuit_id: u32,
    input_requests: u64,
    claims: Semantic.Claims,
    roots: [SEMANTIC_TREES][32]u8,
};
/// Apply to the ACTUAL page commitment channel, after its six real roots and
/// before committing arithmetic fixed/main. No wire challenge is drawn here.
pub fn beginSemantic(channel: anytype, kind: Kind, premix_identity: [32]u8, epoch: SourceEpoch, graph: *const Semantic.Prepared, claims: Semantic.Claims) !void {
    if (graph.kind != kind or graph.circuit == null or graph.circuit_id == 0 or graph.input_requests >= core.fields.m31.Modulus or
        std.mem.allEqual(u8, &premix_identity, 0) or std.mem.allEqual(u8, &epoch.seal_digest, 0)) return error.InvalidSourceUnifiedSemanticEpoch;
    channel.mixU32s(&.{ TAG, VERSION, 0x53454d41, @intFromEnum(kind), graph.circuit_id });
    channel.mixRoot(abiId());
    channel.mixRoot(premix_identity);
    channel.mixRoot(epoch.seal_digest);
    channel.mixRoot(epoch.after_draw_digest);
    channel.mixRoot(graph.identity);
    channel.mixU64(graph.input_requests);
    mixClaims(channel, claims);
}
pub fn mixClaims(channel: anytype, claims: Semantic.Claims) void {
    inline for (std.meta.fields(@TypeOf(claims.source))) |field| channel.mixFelts(&.{@field(claims.source, field.name)});
    channel.mixFelts(&.{claims.indexed});
    inline for (std.meta.fields(@TypeOf(claims.fold))) |field| channel.mixFelts(&.{@field(claims.fold, field.name)});
}
/// Both wire sides are now committed: original source/core/captures and all
/// requesting semantic main cells. The caller must require roots from actual
/// PCS tree inventory6/7; supplying this metadata alone grants no authority.
pub fn drawPageRelations(a: std.mem.Allocator, channel: anytype, pin: SemanticPin, expected: SemanticPin) !Universal.UniversalRelations {
    if (!std.meta.eql(pin, expected) or pin.circuit_id == 0 or pin.input_requests >= core.fields.m31.Modulus) return error.UntrustedSourceUnifiedSemanticPin;
    for (pin.roots) |root| if (std.mem.allEqual(u8, &root, 0)) return error.UntrustedSourceUnifiedSemanticPin;
    mixPageRelationsPrelude(channel);
    return Universal.UniversalRelations.draw(a, channel);
}

/// The original fixed wire-domain framing only. This draws no challenge and
/// does not replace the independent SemanticPin checks in drawPageRelations.
pub fn mixPageRelationsPrelude(channel: anytype) void {
    channel.mixU32s(&.{ TAG, VERSION, 0x57495245, TREE_COUNT });
    channel.mixRoot(abiId());
}
