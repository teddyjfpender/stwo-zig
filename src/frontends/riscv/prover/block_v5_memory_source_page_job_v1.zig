//! One bounded source-PAGE job. Collection owns one page at a time and retains
//! only premix/file pins. Publication replays all six roots, invokes the genuine
//! unified producer, decodes its strict artifact, freshly verifies, then writes.
//! Completion here means PAGE publication only: complete source/RAM/global and
//! recursive closure are separate obligations, never flags granted by this owner.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Budget = engine.host_budget_allocator.SharedHostBudget;
const Batch = @import("block_v5_memory_source_batch_protocol_v1.zig");
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Schema = @import("block_v5_memory_source_batch_raw_schema_v1.zig");
const Raw = @import("block_v5_memory_source_batch_raw_v1.zig");
const RawStage = @import("block_v5_memory_source_packed_sha_replay_v1.zig");
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const FoldStage = @import("block_v5_memory_source_fold_premix_v1.zig");
const FoldStore = @import("block_v5_memory_source_fold_operand_store_v1.zig");
const Draft = @import("block_v5_memory_source_fold_draft_pages_v1.zig");
const DraftCollection = @import("block_v5_memory_source_fold_draft_collection_v1.zig").Collection;
const SHA = @import("block_v5_memory_source_packed_sha_columns_v1.zig");
const Blake = @import("block_v5_memory_source_packed_blake_columns_v1.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Protocol = @import("block_v5_memory_source_unified_page_protocol_v1.zig");
const Page = @import("block_v5_memory_source_unified_page_proof_v1.zig");
const Components = @import("block_v5_memory_source_unified_page_components_v1.zig");
const Codec = @import("block_v5_memory_source_unified_page_codec_v1.zig");
const Claims = @import("block_v5_memory_source_page_claim_proposal_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const Place = @import("../air/block/memory_component_trace.zig");
pub const RawPage = Page.ForKind(.raw);
pub const FoldPage = Page.ForKind(.fold);
pub const ArtifactPin = struct {
    kind: Semantic.Kind,
    index: u32,
    source_seal: [32]u8,
    premix_identity: [32]u8,
    graph_identity: [32]u8,
    byte_len: u64,
    sha256: [32]u8,
};
pub const RawRecord = struct { pin: RawStage.Pin, stored: Schema.Store.Pin, artifact: ?ArtifactPin = null, expected_claims: ?Semantic.Claims = null, verified: ?RawPage.VerifiedPage = null };
pub const FoldRecord = struct { pin: Protocol.FoldPin, stored: FoldStore.Pin, artifact: ?ArtifactPin = null, expected_claims: ?Semantic.Claims = null, verified: ?FoldPage.VerifiedPage = null };
/// Observational publication callbacks only. An independent complete source
/// receiver takes actual proofs and freshly verifies; it never accepts these
/// transported/plain metadata values as a substitute for verification.
pub const Sink = struct {
    context: *anyopaque,
    raw: *const fn (*anyopaque, *const RawPage.VerifiedPage, ArtifactPin) anyerror!void,
    fold: *const fn (*anyopaque, *const FoldPage.VerifiedPage, ArtifactPin) anyerror!void,
};
pub const Limits = struct {
    proof: Page.Limits = .{},
    artifact: Codec.Limits = .{},
    max_job_heap_bytes: usize = 8 << 30,
    max_metadata_bytes: usize = 256 << 20,
    max_operand_bytes: u64 = 512 << 30,
    max_artifact_bytes: u64 = 512 << 30,
};
pub const FilesBudget = struct {
    operands: u64 = 0,
    artifacts: u64 = 0,
    pub fn requireNext(current: u64, bytes: u64, maximum: u64) !u64 {
        if (maximum == 0 or bytes == 0) return error.InvalidSourcePageJobLimits;
        const total = try std.math.add(u64, current, bytes);
        if (total > maximum) return error.SourcePageJobFileResourceLimit;
        return total;
    }
};
pub const Phase = enum { collecting, sealed, publishing, published, failed };
/// Private witness stream, never a source receipt. Metadata must agree with
/// independent admission/plan before collection; PAGE proofs establish values.
pub const OperationSource = struct {
    context: *anyopaque,
    admission_id: [32]u8,
    census: Fold.Census,
    stored_bytes: u64 = 0,
    next: *const fn (*anyopaque) anyerror!?Fold.Operation,
    require_finished: *const fn (*anyopaque) anyerror!void,
};
pub fn metadataBytes(raw_count: usize, fold_count: usize) !usize {
    // Context owns one roster copy and sealing uses a temporary flat copy.
    const raws = try std.math.mul(usize, raw_count, @sizeOf(RawRecord) + 2 * @sizeOf(RawStage.Pin));
    const folds = try std.math.mul(usize, fold_count, @sizeOf(FoldRecord) + 2 * @sizeOf(Protocol.FoldPin));
    return std.math.add(usize, raws, folds);
}
pub fn requireLimits(limits: Limits) !void {
    const header = @max(Codec.ForKind(.raw).HEADER_BYTES, Codec.ForKind(.fold).HEADER_BYTES);
    if (limits.max_job_heap_bytes == 0 or limits.max_metadata_bytes == 0 or limits.max_operand_bytes == 0 or limits.max_artifact_bytes == 0 or
        limits.artifact.max_proof_bytes == 0 or limits.artifact.max_artifact_bytes < header or
        limits.artifact.max_proof_bytes > limits.artifact.max_artifact_bytes - header or limits.proof.max_receiver_heap_bytes == 0)
        return error.InvalidSourcePageJobLimits;
}
pub fn validateInput(admitted: *const Batch.Admission, raw_plan: Schema.Protocol.Plan, fold_plan: Protocol.FoldPlan, base: Seal.Sealed, limits: Limits) !void {
    try requireLimits(limits);
    try admitted.require();
    try raw_plan.require(&admitted.source, limits.proof.raw.first);
    try fold_plan.require(admitted, limits.proof.protocol);
    if (!std.meta.eql(limits.proof.raw, limits.proof.protocol.raw) or !std.meta.eql(limits.proof.fold.protocol, limits.proof.protocol) or
        !std.meta.eql(raw_plan.config, fold_plan.config) or
        base.register_custody_mode != 1 or !std.meta.eql(base.digest, admitted.source.sealed_digest) or
        !std.meta.eql(base.initial_source_plan_digest, try admitted.source.pins.initial.digest()) or
        !std.meta.eql(base.rw_endpoint_plan_digest, try admitted.source.pins.digest()) or
        !std.meta.eql(base.expected_final_rw_root, admitted.source.pins.expected_final_rw_root)) return error.InvalidSourcePageJobLimits;
    if (try metadataBytes(raw_plan.pages, fold_plan.pages) > limits.max_metadata_bytes) return error.SourcePageJobMetadataResourceLimit;
}
pub fn name(buffer: []u8, kind: Semantic.Kind, index: u32, artifact: bool) ![]const u8 {
    return std.fmt.bufPrint(buffer, "source-page-{s}-{d}.{s}", .{ @tagName(kind), index, if (artifact) "b5pg" else "operands" });
}
fn rawOperandBytes(admitted: *const Source.Admitted, page: Schema.Protocol.Page) !u64 {
    var bytes: u64 = 64; // released compact raw file header
    for (0..page.chunks) |i| bytes = try std.math.add(u64, bytes, try Schema.CompactCodec.size((try Raw.kindAt(admitted, page.first_chunk + i)).original()));
    return bytes;
}
/// Bounded public fixed inventory only. Private source/core matrices and the
/// producer proof are released before the independent CPU verification pass.
pub const FoldInventory = struct {
    a: std.mem.Allocator,
    rows: []Semantic.FoldRow,
    recipes: []@import("block_v5_memory_source_blake_semantics_v1.zig").Recipe,
    pub fn deinit(self: *FoldInventory) void {
        self.a.free(self.recipes);
        self.a.free(self.rows);
        self.* = undefined;
    }
    pub fn copy(a: std.mem.Allocator, original: []const Semantic.FoldRow, max_bytes: usize) !FoldInventory {
        if (original.len == 0 or original.len > 4096) return error.InvalidSourcePageJobInventory;
        var count: usize = 0;
        for (original) |row| {
            if (row.recipes.len > 2) return error.InvalidSourcePageJobInventory;
            count = try std.math.add(usize, count, row.recipes.len);
        }
        const Recipe = @import("block_v5_memory_source_blake_semantics_v1.zig").Recipe;
        const bytes = try std.math.add(usize, try std.math.mul(usize, original.len, @sizeOf(Semantic.FoldRow)), try std.math.mul(usize, count, @sizeOf(Recipe)));
        if (bytes > max_bytes) return error.SourcePageJobMetadataResourceLimit;
        const rows = try a.alloc(Semantic.FoldRow, original.len);
        errdefer a.free(rows);
        const recipes = try a.alloc(Recipe, count);
        var next: usize = 0;
        for (rows, original) |*row, source| {
            row.* = source;
            @memcpy(recipes[next..][0..source.recipes.len], source.recipes);
            row.recipes = recipes[next..][0..source.recipes.len];
            next += source.recipes.len;
        }
        return .{ .a = a, .rows = rows, .recipes = recipes };
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const RawOwner = RawStage.ForBackend(Backend);
        const FoldOwner = FoldStage.ForBackend(Backend);
        const RawProducer = RawPage.ForBackend(Backend);
        const FoldProducer = FoldPage.ForBackend(Backend);
        pub const Job = struct {
            child: std.mem.Allocator,
            budget: *Budget,
            parent_owner: ?*Budget,
            control: Budget.ExternalReservation,
            /// Borrowed directory capability; caller owns its lifetime. No
            /// source-file reader or public-input whole-image slice is retained.
            dir: std.fs.Dir,
            limits: Limits,
            admitted: Batch.Admission,
            raw_plan: Schema.Protocol.Plan,
            fold_plan: Protocol.FoldPlan,
            base: Seal.Sealed,
            phase: Phase = .collecting,
            active: bool = false,
            sha_setup: ?*const SHA.Setup = null,
            blake_setup: ?*const Blake.Setup = null,
            arithmetic_setup: ?*const Components.ArithmeticSetup = null,
            raws: []RawRecord = &.{},
            folds: []FoldRecord = &.{},
            context: ?Page.Context = null,
            files: FilesBudget = .{},
            next_raw: u32 = 0,
            next_fold: u32 = 0,
            pub fn allocator(self: *Job) std.mem.Allocator {
                return self.budget.allocator();
            }
            pub fn deinit(self: *Job) !void {
                if (self.active) return error.SourcePageJobPageLive;
                if (self.sha_setup) |setup| if (setup.references.load(.acquire) != 1) return error.SourcePageJobSetupLeaseLive;
                if (self.blake_setup) |setup| if (setup.references.load(.acquire) != 1) return error.SourcePageJobSetupLeaseLive;
                if (self.arithmetic_setup) |setup| if (setup.references.load(.acquire) != 1) return error.SourcePageJobSetupLeaseLive;
                if (self.context) |*context| context.deinit();
                self.allocator().free(self.folds);
                self.allocator().free(self.raws);
                if (self.arithmetic_setup) |setup| setup.release();
                if (self.blake_setup) |setup| setup.release();
                if (self.sha_setup) |setup| setup.release();
                const usage = self.budget.snapshot();
                if (usage.host_live_bytes != 0 or usage.external_live_bytes != self.control.bytes) @panic("source PAGE job ownership invariant");
                const child = self.child;
                const budget = self.budget;
                const parent = self.parent_owner;
                var control = self.control.take();
                child.destroy(self);
                control.deinit();
                budget.destroy();
                if (parent) |retained| retained.destroy();
            }
            /// Actual common constructor. This admits plans and owns setup,
            /// but remains in collecting phase until every real root exists.
            pub fn init(a: std.mem.Allocator, dir: std.fs.Dir, admitted: Batch.Admission, raw_plan: Schema.Protocol.Plan, fold_plan: Protocol.FoldPlan, base: Seal.Sealed, limits: Limits) !*Job {
                try validateInput(&admitted, raw_plan, fold_plan, base, limits);
                const parent = if (Budget.fromAllocator(a)) |retained| retained.retain() else null;
                var owns_parent = true;
                errdefer if (owns_parent) if (parent) |retained| retained.destroy();
                const budget = try Budget.create(a, limits.max_job_heap_bytes);
                var owns_budget = true;
                errdefer if (owns_budget) budget.destroy();
                // These two stable control allocations come from the parent
                // allocator; charge them explicitly inside the same job cap.
                var control = try budget.reserveExternal(@sizeOf(Job) + @sizeOf(Budget));
                defer control.deinit();
                const self = try a.create(Job);
                self.* = .{ .child = a, .budget = budget, .parent_owner = parent, .control = control.take(), .dir = dir, .limits = limits, .admitted = admitted, .raw_plan = raw_plan, .fold_plan = fold_plan, .base = base };
                owns_parent = false;
                owns_budget = false;
                errdefer self.deinit() catch @panic("source PAGE setup rollback lifetime");
                const bounded = self.allocator();
                self.sha_setup = try SHA.Setup.create(bounded);
                self.blake_setup = try Blake.Setup.create(bounded);
                self.arithmetic_setup = try Components.ArithmeticSetup.create(bounded);
                self.raws = try bounded.alloc(RawRecord, raw_plan.pages);
                self.folds = try bounded.alloc(FoldRecord, fold_plan.pages);
                return self;
            }
            /// Plans/census are independently admitted proposals, not proofs.
            /// The real fold traversal must match the exact planned census.
            pub fn collect(a: std.mem.Allocator, dir: std.fs.Dir, admitted: Batch.Admission, raw_plan: Schema.Protocol.Plan, fold_plan: Protocol.FoldPlan, reader: Fold.Reader, base: Seal.Sealed, limits: Limits) !*Job {
                return collectInternal(a, dir, admitted, raw_plan, fold_plan, reader, null, null, base, limits);
            }
            /// Commit already-generated canonical operands. A durable spool
            /// provider finishes its full footer/hash checks before publication.
            /// Default collect remains the original independent cold traversal.
            pub fn collectWithOperations(a: std.mem.Allocator, dir: std.fs.Dir, admitted: Batch.Admission, raw_plan: Schema.Protocol.Plan, fold_plan: Protocol.FoldPlan, reader: Fold.Reader, operations_source: OperationSource, base: Seal.Sealed, limits: Limits) !*Job {
                try requireLimits(limits);
                if (!std.meta.eql(operations_source.admission_id, admitted.identity) or !std.meta.eql(operations_source.census, fold_plan.census)) return error.InvalidSourcePageJobCollection;
                try operations_source.census.require(&admitted.source, admitted.limits);
                if (operations_source.stored_bytes > limits.max_operand_bytes) return error.SourcePageJobFileResourceLimit;
                return collectInternal(a, dir, admitted, raw_plan, fold_plan, reader, operations_source, null, base, limits);
            }
            /// Canonical staged transport: the original genuine collect loop
            /// commits every PAGE, then promotes its already-written payload.
            /// Draft proposals never replace original source/pin admission.
            pub fn collectWithDrafts(a: std.mem.Allocator, dir: std.fs.Dir, admitted: Batch.Admission, raw_plan: Schema.Protocol.Plan, fold_plan: Protocol.FoldPlan, reader: Fold.Reader, drafts: *Draft.Owner, base: Seal.Sealed, limits: Limits) !*Job {
                try validateInput(&admitted, raw_plan, fold_plan, base, limits);
                try drafts.require(&admitted, fold_plan, limits.proof.protocol);
                if (drafts.total_bytes > limits.max_operand_bytes or !std.meta.eql(drafts.limits.stored, limits.proof.fold.stored) or drafts.dir.fd != dir.fd or
                    drafts.a.ptr != a.ptr or drafts.a.vtable != a.vtable)
                    return error.InvalidSourcePageJobDrafts;
                // Retained draft metadata and the original Job roster copies
                // share the caller's aggregate budget and this metadata cap.
                const draft_metadata = try std.math.add(usize, @sizeOf(Draft.Owner), try std.math.mul(usize, drafts.capacity, @sizeOf(Draft.Pin)));
                if (try std.math.add(usize, draft_metadata, try metadataBytes(raw_plan.pages, fold_plan.pages)) > limits.max_metadata_bytes)
                    return error.SourcePageJobMetadataResourceLimit;
                var collection = try DraftCollection.init(drafts, &admitted, fold_plan, limits.proof.protocol, raw_plan.pages);
                defer collection.deinit();
                const self = try collectInternal(a, dir, admitted, raw_plan, fold_plan, reader, .{
                    .context = &collection,
                    .admission_id = admitted.identity,
                    .census = fold_plan.census,
                    // Final PAGE bytes are charged once in the original loop.
                    // No separate spool remains or consumes another disk cap.
                    .stored_bytes = 0,
                    .next = draftNext,
                    .require_finished = draftFinished,
                }, &collection, base, limits);
                errdefer self.deinit() catch @panic("source PAGE draft collection rollback lifetime");
                try collection.commit();
                return self;
            }
            fn draftNext(context: *anyopaque) !?Fold.Operation {
                const collection: *DraftCollection = @ptrCast(@alignCast(context));
                return collection.next();
            }
            fn draftFinished(context: *anyopaque) !void {
                const collection: *DraftCollection = @ptrCast(@alignCast(context));
                return collection.requireFinished();
            }
            fn collectInternal(a: std.mem.Allocator, dir: std.fs.Dir, admitted: Batch.Admission, raw_plan: Schema.Protocol.Plan, fold_plan: Protocol.FoldPlan, reader: Fold.Reader, operations_source: ?OperationSource, draft_collection: ?*DraftCollection, base: Seal.Sealed, limits: Limits) !*Job {
                const self = try init(a, dir, admitted, raw_plan, fold_plan, base, limits);
                errdefer self.deinit() catch @panic("source PAGE collection rollback lifetime");
                if (operations_source) |provided| if (provided.stored_bytes != 0) {
                    self.files.operands = try FilesBudget.requireNext(0, provided.stored_bytes, limits.max_operand_bytes);
                };
                const bounded = self.allocator();
                var raw_collector = try Schema.Round.Collector.init(admitted.source, reader, raw_plan, limits.proof.raw.first);
                for (self.raws, 0..) |*record, i| {
                    const page = try raw_plan.page(@intCast(i));
                    const bytes = try rawOperandBytes(&admitted.source, page);
                    const total = try FilesBudget.requireNext(self.files.operands, bytes, limits.max_operand_bytes);
                    const owner = try RawOwner.collectWithSetup(bounded, &raw_collector, limits.proof.raw, self.sha_setup.?);
                    defer owner.deinit() catch @panic("source PAGE collected raw lease invariant");
                    const pin = owner.pin orelse return error.InvalidSourcePageJobCollection;
                    var path: [96]u8 = undefined;
                    const stored = try RawOwner.persist(dir, try name(&path, .raw, @intCast(i), false), owner, &admitted.source, raw_plan, pin, limits.proof.raw);
                    if (draft_collection) |collection| collection.recordRaw(@intCast(i));
                    if (stored.bytes != bytes) return error.InvalidSourcePageJobCollection;
                    record.* = .{ .pin = pin, .stored = stored };
                    self.files.operands = total;
                }
                try raw_collector.requireFinished();
                var cursor: ?Fold.Cursor = if (operations_source == null) try Fold.Cursor.init(admitted.source, reader, admitted.limits) else null;
                const operations = try bounded.alloc(Fold.Operation, @as(usize, 1) << @intCast(fold_plan.row_log));
                defer bounded.free(operations);
                var first_circuit: u32 = 1;
                for (self.folds, 0..) |*record, i| {
                    const page = try fold_plan.page(@intCast(i));
                    const bytes = try std.math.add(u64, FoldStore.HEADER_BYTES, try std.math.mul(u64, page.count, FoldStore.RECORD_BYTES));
                    const total = try FilesBudget.requireNext(self.files.operands, bytes, limits.max_operand_bytes);
                    for (operations[0..page.count]) |*operation| {
                        operation.* = (if (operations_source) |provided| try provided.next(provided.context) else try cursor.?.next()) orelse return error.InvalidSourcePageJobCollection;
                    }
                    const owner = try FoldOwner.collect(bounded, &admitted, fold_plan, @intCast(i), operations[0..page.count], first_circuit, self.blake_setup.?, limits.proof.fold);
                    defer owner.deinit() catch @panic("source PAGE collected fold lease invariant");
                    const pin = owner.pin orelse return error.InvalidSourcePageJobCollection;
                    var path: [96]u8 = undefined;
                    const stored = if (draft_collection) |collection| blk: {
                        // Exactly the original FoldOwner.persist custody check;
                        // only the payload publication mechanism is replaced.
                        try owner.require(&admitted, fold_plan, pin, limits.proof.fold);
                        break :blk try collection.promote(@intCast(i), try pin.identity(&admitted, fold_plan, limits.proof.fold.protocol));
                    } else try FoldOwner.persist(dir, try name(&path, .fold, @intCast(i), false), owner, &admitted, fold_plan, pin, limits.proof.fold);
                    if (stored.byte_len != bytes) return error.InvalidSourcePageJobCollection;
                    record.* = .{ .pin = pin, .stored = stored };
                    self.files.operands = total;
                    first_circuit = try std.math.add(u32, first_circuit, pin.geometry.compressions);
                }
                if (operations_source) |provided| {
                    if (try provided.next(provided.context) != null) return error.InvalidSourcePageJobCollection;
                    try provided.require_finished(provided.context);
                } else if (try cursor.?.next() != null or !std.meta.eql(cursor.?.census, fold_plan.census)) return error.InvalidSourcePageJobCollection;
                const raw_pins = try bounded.alloc(RawStage.Pin, self.raws.len);
                defer bounded.free(raw_pins);
                const fold_pins = try bounded.alloc(Protocol.FoldPin, self.folds.len);
                defer bounded.free(fold_pins);
                for (raw_pins, self.raws) |*pin, record| pin.* = record.pin;
                for (fold_pins, self.folds) |*pin, record| pin.* = record.pin;
                const sealed = try Protocol.seal(&admitted, raw_plan, fold_plan, raw_pins, fold_pins, limits.proof.protocol);
                self.context = try Page.Context.init(bounded, admitted, raw_plan, fold_plan, raw_pins, fold_pins, sealed, sealed.digest, base, limits.proof);
                self.phase = .sealed;
                return self;
            }
            fn readRaw(raw: *anyopaque, group: Semantic.Group, logical: u32, column: u32) !M {
                const owner: *RawOwner.Owner = @ptrCast(@alignCast(raw));
                const matrix: struct { values: []const M, log: u32 } = switch (group) {
                    .source => blk: {
                        const source = &owner.raw.?.columns.?;
                        if (column >= Schema.MAIN_COUNT) return error.InvalidSourcePageCell;
                        break :blk .{ .values = source.mainColumn(column), .log = source.page.row_log };
                    },
                    .capture => blk: {
                        if (column >= owner.cores.?.captures.columns.len) return error.InvalidSourcePageCell;
                        const capture = owner.cores.?.captures.columns[column];
                        break :blk .{ .values = capture.values, .log = capture.log_size };
                    },
                };
                if (logical >= matrix.values.len) return error.InvalidSourcePageCell;
                return matrix.values[Place.committedRow(logical, matrix.log)];
            }
            fn artifactPin(comptime kind: Semantic.Kind, verified: Page.ForKind(kind).VerifiedPage, bytes: []const u8) ArtifactPin {
                return .{ .kind = kind, .index = verified.page_index, .source_seal = verified.source_seal, .premix_identity = verified.premix_identity, .graph_identity = verified.graph_identity, .byte_len = bytes.len, .sha256 = Files.hash(bytes) };
            }
            /// Exactly one resident page. A partial prove/decode/verify/write or
            /// callback failure poisons this session; no skipped retry or flag
            /// can turn a partial job into successful publication.
            pub fn publishNext(self: *Job, sink: Sink) !bool {
                if (self.active or (self.phase != .sealed and self.phase != .publishing)) return error.InvalidSourcePageJobPhase;
                if (self.next_raw == self.raws.len and self.next_fold == self.folds.len) {
                    self.phase = .published;
                    return false;
                }
                self.active = true;
                defer self.active = false;
                self.phase = .publishing;
                errdefer self.phase = .failed;
                const a = self.allocator();
                const context = &self.context.?;
                try context.require(a, self.limits.proof);
                if (self.next_raw < self.raws.len) {
                    const record = &self.raws[self.next_raw];
                    var operand_path: [96]u8 = undefined;
                    const bytes = produced: {
                        const owner = try RawOwner.replayWithSetup(a, self.dir, try name(&operand_path, .raw, self.next_raw, false), &self.admitted.source, self.raw_plan, record.pin, record.stored, self.limits.proof.raw, self.sha_setup.?);
                        defer owner.deinit() catch @panic("source PAGE raw publication lifetime");
                        const proposed = try Claims.raw(&self.admitted, record.pin.raw.page, .{ .context = owner, .read = readRaw }, context.epoch.challenges);
                        record.expected_claims = proposed;
                        var proved = try RawProducer.prove(owner, context, record.pin, proposed, self.sha_setup.?, self.arithmetic_setup.?, self.limits.proof);
                        defer proved.deinit();
                        break :produced try Codec.ForKind(.raw).encode(a, &proved.proof, context, record.pin, &.{}, self.limits.proof, self.limits.artifact);
                    }; // Both producer proof and original PCS owner are gone.
                    defer a.free(bytes);
                    const total = try FilesBudget.requireNext(self.files.artifacts, bytes.len, self.limits.max_artifact_bytes);
                    const received = try Codec.ForKind(.raw).decode(a, bytes, context, record.pin, &.{}, self.limits.proof, self.limits.artifact);
                    const verified = try RawPage.verifyOwned(a, received, context, record.pin, &.{}, self.sha_setup.?, self.arithmetic_setup.?, self.limits.proof);
                    if (!std.meta.eql(record.expected_claims.?, verified.claims)) return error.UntrustedSourcePageJobSemanticClaims;
                    const pin = artifactPin(.raw, verified, bytes);
                    var artifact_path: [96]u8 = undefined;
                    try Files.publish(self.dir, try name(&artifact_path, .raw, self.next_raw, true), bytes);
                    self.files.artifacts = total;
                    record.artifact = pin;
                    record.verified = verified;
                    try sink.raw(sink.context, &verified, pin);
                    self.next_raw += 1;
                } else {
                    const record = &self.folds[self.next_fold];
                    var operand_path: [96]u8 = undefined;
                    var encoded = produced: {
                        const owner = try FoldOwner.replay(a, self.dir, try name(&operand_path, .fold, self.next_fold, false), &self.admitted, self.fold_plan, record.pin, record.stored, self.blake_setup.?, self.limits.proof.fold);
                        defer owner.deinit() catch @panic("source PAGE fold publication lifetime");
                        const proposed = try Claims.fold(&self.admitted, owner.descriptors, owner.semanticReader(), context.epoch.challenges);
                        record.expected_claims = proposed;
                        var proved = try FoldProducer.prove(owner, context, record.pin, proposed, self.blake_setup.?, self.arithmetic_setup.?, self.limits.proof);
                        defer proved.deinit();
                        var inventory = try FoldInventory.copy(a, owner.descriptors, self.limits.max_metadata_bytes -| try metadataBytes(self.raws.len, self.folds.len));
                        errdefer inventory.deinit();
                        const bytes = try Codec.ForKind(.fold).encode(a, &proved.proof, context, record.pin, owner.descriptors, self.limits.proof, self.limits.artifact);
                        break :produced .{ .bytes = bytes, .inventory = inventory };
                    }; // Retain only bounded public inventory and owned bytes.
                    const bytes = encoded.bytes;
                    defer a.free(bytes);
                    defer encoded.inventory.deinit();
                    const total = try FilesBudget.requireNext(self.files.artifacts, bytes.len, self.limits.max_artifact_bytes);
                    const received = try Codec.ForKind(.fold).decode(a, bytes, context, record.pin, encoded.inventory.rows, self.limits.proof, self.limits.artifact);
                    const verified = try FoldPage.verifyOwned(a, received, context, record.pin, encoded.inventory.rows, self.blake_setup.?, self.arithmetic_setup.?, self.limits.proof);
                    if (!std.meta.eql(record.expected_claims.?, verified.claims)) return error.UntrustedSourcePageJobSemanticClaims;
                    const pin = artifactPin(.fold, verified, bytes);
                    var artifact_path: [96]u8 = undefined;
                    try Files.publish(self.dir, try name(&artifact_path, .fold, self.next_fold, true), bytes);
                    self.files.artifacts = total;
                    record.artifact = pin;
                    record.verified = verified;
                    try sink.fold(sink.context, &verified, pin);
                    self.next_fold += 1;
                }
                return true;
            }
            fn Publisher(comptime kind: Semantic.Kind) type {
                return struct {
                    job: *Job,
                    sink: Sink,
                    const Owner = if (kind == .raw) RawOwner.Owner else FoldOwner.Owner;
                    const KindPage = Page.ForKind(kind);
                    const Prepared = struct {
                        owner: ?*Owner,
                        claims: Semantic.Claims,
                        rows: []const Semantic.FoldRow,
                        inventory: ?FoldInventory,
                        pub fn releaseProducer(self: *@This()) void {
                            if (self.owner) |owner| {
                                owner.deinit() catch @panic("source PAGE roster publication lifetime");
                                self.owner = null;
                            }
                        }
                        pub fn deinit(self: *@This()) void {
                            self.releaseProducer();
                            if (self.inventory) |*inventory| inventory.deinit();
                            self.* = undefined;
                        }
                    };
                    pub fn prepare(self: *@This(), a: std.mem.Allocator, ordinal: u32) !Prepared {
                        const job = self.job;
                        const next = if (kind == .raw) job.next_raw else job.next_fold;
                        if (!job.active or job.phase != .publishing or ordinal != next) return error.InvalidSourcePageJobPhase;
                        var operand_path: [96]u8 = undefined;
                        if (kind == .raw) {
                            const record = job.raws[ordinal];
                            const owner = try RawOwner.replayWithSetup(a, job.dir, try name(&operand_path, .raw, ordinal, false), &job.admitted.source, job.raw_plan, record.pin, record.stored, job.limits.proof.raw, job.sha_setup.?);
                            errdefer owner.deinit() catch @panic("source PAGE raw replay rollback");
                            const claims = try Claims.raw(&job.admitted, record.pin.raw.page, .{ .context = owner, .read = readRaw }, job.context.?.epoch.challenges);
                            job.raws[ordinal].expected_claims = claims;
                            return .{ .owner = owner, .claims = claims, .rows = &.{}, .inventory = null };
                        } else {
                            const record = job.folds[ordinal];
                            const owner = try FoldOwner.replay(a, job.dir, try name(&operand_path, .fold, ordinal, false), &job.admitted, job.fold_plan, record.pin, record.stored, job.blake_setup.?, job.limits.proof.fold);
                            errdefer owner.deinit() catch @panic("source PAGE fold replay rollback");
                            const claims = try Claims.fold(&job.admitted, owner.descriptors, owner.semanticReader(), job.context.?.epoch.challenges);
                            job.folds[ordinal].expected_claims = claims;
                            const inventory = try FoldInventory.copy(a, owner.descriptors, job.limits.max_metadata_bytes -| try metadataBytes(job.raws.len, job.folds.len));
                            return .{ .owner = owner, .claims = claims, .rows = inventory.rows, .inventory = inventory };
                        }
                    }
                    pub fn accept(self: *@This(), ordinal: u32, verified: KindPage.VerifiedPage, bytes: []const u8) !void {
                        const job = self.job;
                        const next = if (kind == .raw) job.next_raw else job.next_fold;
                        if (!job.active or job.phase != .publishing or ordinal != next or verified.page_index != ordinal or verified.kind != kind)
                            return error.InvalidSourcePageJobPhase;
                        const record = if (kind == .raw) &job.raws[ordinal] else &job.folds[ordinal];
                        const expected_claims = record.expected_claims orelse return error.MissingIndependentPageSemanticClaims;
                        if (!std.meta.eql(expected_claims, verified.claims)) return error.UntrustedSourcePageJobSemanticClaims;
                        const total = try FilesBudget.requireNext(job.files.artifacts, bytes.len, job.limits.max_artifact_bytes);
                        const pin = artifactPin(kind, verified, bytes);
                        var artifact_path: [96]u8 = undefined;
                        try Files.publish(job.dir, try name(&artifact_path, kind, ordinal, true), bytes);
                        job.files.artifacts = total;
                        record.artifact = pin;
                        record.verified = verified;
                        if (kind == .raw) {
                            try self.sink.raw(self.sink.context, &verified, pin);
                            job.next_raw += 1;
                        } else {
                            try self.sink.fold(self.sink.context, &verified, pin);
                            job.next_fold += 1;
                        }
                    }
                };
            }
            /// Canonical opted-in publisher: one exact synchronous raw roster,
            /// then one fold roster. Four full-context checks total, independent
            /// of page count. Every PAGE retains its original recommit, framing,
            /// arithmetic/core/table masks, interaction and fresh CPU FRI checks.
            /// Files and callback observations are provisional until success;
            /// any error poisons the session and prevents requirePublished.
            pub fn publishAll(self: *Job, sink: Sink) !void {
                if (self.active or self.phase != .sealed or self.next_raw != 0 or self.next_fold != 0) return error.InvalidSourcePageJobPhase;
                self.active = true;
                defer self.active = false;
                self.phase = .publishing;
                errdefer self.phase = .failed;
                var raws = Publisher(.raw){ .job = self, .sink = sink };
                try RawProducer.publishRoster(self.allocator(), &self.context.?, self.sha_setup.?, self.arithmetic_setup.?, self.limits.proof, self.limits.artifact, &raws);
                var folds = Publisher(.fold){ .job = self, .sink = sink };
                try FoldProducer.publishRoster(self.allocator(), &self.context.?, self.blake_setup.?, self.arithmetic_setup.?, self.limits.proof, self.limits.artifact, &folds);
                if (self.next_raw != self.raws.len or self.next_fold != self.folds.len) return error.IncompleteSourcePageJobPublication;
                self.phase = .published;
            }
            pub fn requirePublished(self: *const Job) !void {
                if (self.active or self.phase != .published or self.next_raw != self.raws.len or self.next_fold != self.folds.len) return error.IncompleteSourcePageJobPublication;
                for (self.raws) |record| if (record.artifact == null or record.verified == null or record.expected_claims == null) return error.IncompleteSourcePageJobPublication;
                for (self.folds) |record| if (record.artifact == null or record.verified == null or record.expected_claims == null) return error.IncompleteSourcePageJobPublication;
            }
        };
    };
}
