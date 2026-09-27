//! Genuine combined PAGE PCS/composition/FRI route. A fresh VerifiedPage proves
//! one independently admitted page only. It cannot close the full source or
//! sorted-RAM buses until the separate exact-roster aggregate consumes it.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const M = core.fields.m31.M31;
const Column = engine.pcs.ColumnEvaluation;
const Batch = @import("block_v5_memory_source_batch_protocol_v1.zig");
const SourceSeal = @import("block_v5_source_seal_v1.zig");
const Protocol = @import("block_v5_memory_source_unified_page_protocol_v1.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Components = @import("block_v5_memory_source_unified_page_components_v1.zig");
const Arithmetic = @import("block_v5_memory_source_page_arithmetic_columns_v1.zig");
const Interaction = @import("block_v5_memory_source_page_interaction_v1.zig");
const Composition = @import("block_v5_memory_source_page_composition_v1.zig");
const RawSchema = @import("block_v5_memory_source_batch_raw_schema_v1.zig");
const Raw = @import("block_v5_memory_source_batch_raw_v1.zig");
const RawStage = @import("block_v5_memory_source_packed_sha_replay_v1.zig");
const RawKernel = @import("block_v5_memory_source_packed_sha_proof_v1.zig");
const FoldStage = @import("block_v5_memory_source_fold_premix_v1.zig");
const FoldFixed = @import("block_v5_memory_source_fold_fixed_columns_v1.zig");
const CaptureFrame = @import("block_v5_memory_source_page_capture_frame_v1.zig");
const Place = @import("../air/block/memory_component_trace.zig");
const BlakeAir = @import("block_v5_memory_source_blake_capture_air_v1.zig");
pub const Limits = struct {
    protocol: Protocol.Limits = .{},
    raw: RawStage.Limits = .{},
    fold: FoldStage.Limits = .{},
    semantic: Semantic.Limits = .{},
    arithmetic: Arithmetic.Limits = .{},
    interaction: Interaction.Limits = .{},
    composition: Composition.Limits = .{},
    max_receiver_heap_bytes: usize = 4 << 30,
};
/// Owned complete first-root roster. Single-page boundaries recheck the real
/// SOURCE/Word epoch; consuming roster batches check it on entry and exit.
/// A copied digest alone never substitutes for this roster.
pub const Context = struct {
    a: std.mem.Allocator,
    admitted: Batch.Admission,
    raw_plan: RawSchema.Protocol.Plan,
    fold_plan: Protocol.FoldPlan,
    raw: []RawStage.Pin,
    fold: []Protocol.FoldPin,
    sealed: Protocol.Sealed,
    independent_digest: [32]u8,
    base: SourceSeal.Sealed,
    epoch: Protocol.SourceEpoch,
    pub fn init(a: std.mem.Allocator, admitted: Batch.Admission, raw_plan: RawSchema.Protocol.Plan, fold_plan: Protocol.FoldPlan, raw: []const RawStage.Pin, fold: []const Protocol.FoldPin, sealed: Protocol.Sealed, independent_digest: [32]u8, base: SourceSeal.Sealed, limits: Limits) !Context {
        const epoch = try Protocol.draw(a, &admitted, raw_plan, fold_plan, raw, fold, sealed, independent_digest, base, limits.protocol);
        const owned_raw = try a.dupe(RawStage.Pin, raw);
        errdefer a.free(owned_raw);
        const owned_fold = try a.dupe(Protocol.FoldPin, fold);
        return .{ .a = a, .admitted = admitted, .raw_plan = raw_plan, .fold_plan = fold_plan, .raw = owned_raw, .fold = owned_fold, .sealed = sealed, .independent_digest = independent_digest, .base = base, .epoch = epoch };
    }
    pub fn deinit(self: *Context) void {
        self.a.free(self.fold);
        self.a.free(self.raw);
        self.* = undefined;
    }
    pub fn require(self: *const Context, a: std.mem.Allocator, limits: Limits) !void {
        const epoch = try Protocol.draw(a, &self.admitted, self.raw_plan, self.fold_plan, self.raw, self.fold, self.sealed, self.independent_digest, self.base, limits.protocol);
        if (!std.meta.eql(epoch, self.epoch)) return error.UntrustedSourcePageEpoch;
    }
};
pub fn ForKind(comptime kind: Semantic.Kind) type {
    return struct {
        const C = Components.ForKind(kind);
        const A = Arithmetic.ForKind(kind);
        const I = Interaction.ForKind(kind);
        pub const Pin = if (kind == .raw) RawStage.Pin else Protocol.FoldPin;
        pub const Proof = struct {
            abi: [32]u8,
            pin: Pin,
            semantic: Protocol.SemanticPin,
            claims: C.Claims,
            stark: suite.Proof,
            pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
                self.stark.deinit(a);
                self.* = undefined;
            }
        };
        pub const VerifiedPage = struct {
            admission_id: [32]u8,
            source_seal: [32]u8,
            premix_identity: [32]u8,
            graph_identity: [32]u8,
            page_index: u32,
            kind: Semantic.Kind = kind,
            input_requests: u64,
            claims: Semantic.Claims,
            final_channel: [32]u8,
        };
        pub const Captured = CaptureFrame.Capture(kind, Pin, VerifiedPage);
        pub const Admission = struct {
            graph: *Semantic.Prepared,
            fixed: A.Fixed,
            pub fn deinit(self: *Admission) void {
                self.fixed.deinit();
                self.graph.deinit();
                self.* = undefined;
            }
            /// Complete public graph/fixed inventory, not proof authority.
            pub fn init(a: std.mem.Allocator, context: *const Context, expected: Pin, independently_admitted_fold_rows: []const Semantic.FoldRow, claims: Semantic.Claims, limits: Limits) !Admission {
                try requirePin(context, expected, limits);
                const rows = try descriptors(a, context, expected, independently_admitted_fold_rows, limits);
                defer a.free(rows);
                const graph = try prepare(a, context, expected, independently_admitted_fold_rows, claims, limits);
                errdefer graph.deinit();
                const source_log = if (kind == .raw) expected.raw.page.row_log else expected.page.row_log;
                const capture_log = if (kind == .raw) expected.geometry.connector_log else expected.geometry.capture_log;
                const fixed = try A.Fixed.init(a, graph, rows, source_log, capture_log, limits.arithmetic);
                return .{ .graph = graph, .fixed = fixed };
            }
        };
        pub fn abiId() [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update("stwo-zig/block-v5/source-unified-PAGE-proof/v1\x00");
            hash.update(&Protocol.abiId());
            hash.update(&.{@intFromEnum(kind)});
            inline for (C.CoreAirs) |Air| hash.update(&Air.SEMANTIC_DIGEST);
            inline for (@import("../recursion/air/arithmetic_fusion_fixed_columns_v1.zig").Airs) |Air| hash.update(&Air.SEMANTIC_DIGEST);
            hash.update("nine-trees;original-main-aliases;complete-independent-fixed;two-mode-fusion;exact-mask-union;post-both-main-wire;separate-kernel-and-semantic-closure;one-interaction-composition-FRI;page-only\x00");
            return hash.finalResult();
        }
        fn index(pin: Pin) u32 {
            return if (kind == .raw) pin.raw.page.index else pin.page.index;
        }
        fn requirePin(context: *const Context, pin: Pin, limits: Limits) !void {
            const roster = if (kind == .raw) context.raw else context.fold;
            const position = index(pin);
            if (position >= roster.len or !std.meta.eql(roster[position], pin)) return error.UntrustedSourcePageRoster;
            if (kind == .raw) try pin.require(&context.admitted.source, context.raw_plan, limits.raw) else try pin.require(&context.admitted, context.fold_plan, limits.protocol);
        }
        pub fn identity(context: *const Context, pin: Pin, limits: Limits) ![32]u8 {
            return if (kind == .raw) pin.identity(&context.admitted.source, context.raw_plan, limits.raw) else pin.identity(&context.admitted, context.fold_plan, limits.protocol);
        }
        fn descriptors(a: std.mem.Allocator, context: *const Context, pin: Pin, fold_rows: []const Semantic.FoldRow, limits: Limits) ![]A.Descriptor {
            if (kind == .raw) {
                if (fold_rows.len != 0) return error.InvalidSourcePageInventory;
                const rows = try a.alloc(A.Descriptor, pin.raw.page.chunks);
                errdefer a.free(rows);
                for (rows, 0..) |*row, ordinal| row.* = try Raw.kindAt(&context.admitted.source, pin.raw.page.first_chunk + ordinal);
                return rows;
            }
            if (!std.meta.eql(pin.geometry, try FoldFixed.geometry(pin.page, pin.geometry.first_circuit, fold_rows, limits.protocol.fold_cores)) or
                !std.meta.eql(pin.inventory_id, try FoldStage.inventoryId(pin.page, pin.geometry.first_circuit, fold_rows))) return error.InvalidSourcePageInventory;
            const rows = try a.alloc(A.Descriptor, fold_rows.len);
            for (rows, fold_rows) |*row, original| row.* = original.descriptor;
            return rows;
        }
        fn prepare(a: std.mem.Allocator, context: *const Context, pin: Pin, fold_rows: []const Semantic.FoldRow, claims: Semantic.Claims, limits: Limits) !*Semantic.Prepared {
            try requirePin(context, pin, limits);
            const id = try Protocol.semanticCircuitId(&context.admitted, context.fold_plan, kind, index(pin), limits.protocol);
            return if (kind == .raw)
                Semantic.prepareRaw(a, &context.admitted, context.raw_plan, pin.raw, context.epoch.challenges, claims, id, limits.raw.first, limits.semantic)
            else
                Semantic.prepareFold(a, &context.admitted, fold_rows, try identity(context, pin, limits), context.epoch.challenges, claims, id, limits.semantic);
        }
        fn geometry(pin: Pin, fixed: *const A.Fixed) C.Geometry {
            return .{
                .source_log = if (kind == .raw) pin.raw.page.row_log else pin.page.row_log,
                .capture_log = if (kind == .raw) pin.geometry.connector_log else pin.geometry.capture_log,
                .core_logs = pin.geometry.logs,
                .arithmetic_logs = fixed.arithmetic.logs,
                .capture_requests = @as(u64, pin.geometry.compressions) * if (kind == .raw) 32 else BlakeAir.requestMass(),
            };
        }
        fn semanticPin(context: *const Context, pin: Pin, graph: *const Semantic.Prepared, claims: Semantic.Claims, roots: [2][32]u8, limits: Limits) !Protocol.SemanticPin {
            return .{ .premix_identity = try identity(context, pin, limits), .source_epoch = context.epoch.seal_digest, .graph_identity = graph.identity, .circuit_id = graph.circuit_id, .input_requests = graph.input_requests, .claims = claims, .roots = roots };
        }
        const ClaimValues = struct {
            values: C.Claims,
            pub fn core(self: @This(), channel: anytype) void {
                channel.mixFelts(&self.values.core);
            }
            pub fn capture(self: @This(), channel: anytype) void {
                channel.mixFelts(&self.values.capture.sums);
            }
            pub fn captureRequests(self: @This(), channel: anytype) void {
                channel.mixU64(self.values.capture.wire_requests);
            }
            pub fn sourceInputs(self: @This(), channel: anytype) void {
                channel.mixFelts(&self.values.source_inputs.sums);
            }
            pub fn sourceRequests(self: @This(), channel: anytype) void {
                channel.mixU64(self.values.source_inputs.requests);
            }
            pub fn captureInputs(self: @This(), channel: anytype) void {
                channel.mixFelts(&self.values.capture_inputs.sums);
            }
            pub fn captureInputRequests(self: @This(), channel: anytype) void {
                channel.mixU64(self.values.capture_inputs.requests);
            }
            pub fn arithmetic(self: @This(), channel: anytype) void {
                channel.mixFelts(&self.values.arithmetic);
            }
        };
        pub fn mixClaims(channel: anytype, claims: C.Claims) void {
            mixClaimsFrom(channel, ClaimValues{ .values = claims });
        }
        /// One original framing/order body for actual claims and fixed-only
        /// normative lengths. A length provider produces no claim or receipt.
        pub fn mixClaimsFrom(channel: anytype, payload: anytype) void {
            channel.mixU32s(&.{ Protocol.TAG, Protocol.VERSION, 0x434c414d, @intFromEnum(kind) });
            channel.mixRoot(abiId());
            payload.core(channel);
            payload.capture(channel);
            payload.captureRequests(channel);
            payload.sourceInputs(channel);
            payload.sourceRequests(channel);
            payload.captureInputs(channel);
            payload.captureInputRequests(channel);
            payload.arithmetic(channel);
        }
        /// Proposal admission only. Fresh verification reconstructs all graph
        /// routing/use counts/fixed roots and closes original AIR equations.
        pub fn admit(proof: *const Proof, context: *const Context, expected: Pin, limits: Limits) !void {
            try requirePin(context, expected, limits);
            const commitments = proof.stark.commitment_scheme_proof.commitments.items;
            if (!std.meta.eql(proof.abi, abiId()) or !std.meta.eql(proof.pin, expected) or commitments.len != Protocol.PROOF_COMMITMENTS or
                !std.meta.eql(proof.stark.commitment_scheme_proof.config, context.fold_plan.config) or !std.meta.eql(commitments[0..6].*, expected.roots) or
                !std.meta.eql(commitments[6..8].*, proof.semantic.roots) or !std.meta.eql(proof.semantic.premix_identity, try identity(context, expected, limits)) or
                !std.meta.eql(proof.semantic.source_epoch, context.sealed.digest) or std.mem.allEqual(u8, &proof.semantic.graph_identity, 0) or
                proof.semantic.circuit_id != try Protocol.semanticCircuitId(&context.admitted, context.fold_plan, kind, index(expected), limits.protocol) or
                proof.semantic.input_requests >= core.fields.m31.Modulus or proof.claims.source_inputs.requests >= core.fields.m31.Modulus or
                proof.claims.capture_inputs.requests >= core.fields.m31.Modulus or
                try std.math.add(u64, proof.claims.source_inputs.requests, proof.claims.capture_inputs.requests) != proof.semantic.input_requests or
                proof.claims.capture.wire_requests != @as(u64, expected.geometry.compressions) * if (kind == .raw) 32 else BlakeAir.requestMass())
                return error.UntrustedSourceUnifiedPageProof;
            for (proof.semantic.roots) |root| if (std.mem.allEqual(u8, &root, 0)) return error.UntrustedSourceUnifiedSemanticPin;
        }
        pub fn ForBackend(comptime Backend: type) type {
            return struct {
                const Stage = if (kind == .raw) RawStage.ForBackend(Backend) else FoldStage.ForBackend(Backend);
                pub const Proved = struct {
                    owner: *Stage.Owner,
                    proof: Proof,
                    pub fn deinit(self: *Proved) void {
                        self.proof.deinit(self.owner.allocator());
                        std.debug.assert(self.owner.active_leases != 0);
                        self.owner.active_leases -= 1;
                        self.* = undefined;
                    }
                };
                /// Own the entire synchronous kind roster. The coordinator
                /// supplies replayed owners and owns only proposal bytes/fixed
                /// inventories; fresh authority is produced here by the same
                /// private verifier as the public single-page operation.
                /// Publications remain provisional until the exit guard passes.
                pub fn publishRoster(a: std.mem.Allocator, context: *const Context, core_setup: *const C.CoreColumns.Setup, arithmetic_setup: *const Components.ArithmeticSetup, limits: Limits, codec_limits: @import("block_v5_memory_source_unified_page_codec_v1.zig").Limits, publisher: anytype) !void {
                    const Codec = @import("block_v5_memory_source_unified_page_codec_v1.zig").ForKind(kind);
                    if (limits.max_receiver_heap_bytes == 0) return error.SourcePageReceiverResourceLimit;
                    try context.require(a, limits);
                    const roster = if (kind == .raw) context.raw else context.fold;
                    for (roster, 0..) |expected, ordinal| {
                        var prepared = try publisher.prepare(a, @intCast(ordinal));
                        defer prepared.deinit();
                        const bytes = encoded: {
                            var proved = try proveAfterContext(prepared.owner.?, context, expected, prepared.claims, core_setup, arithmetic_setup, limits);
                            defer proved.deinit();
                            break :encoded try Codec.encodeProposal(a, &proved.proof, context, expected, prepared.rows, limits, codec_limits);
                        };
                        defer a.free(bytes);
                        // No producer PCS or producer proof overlaps nested
                        // decoding and independent fresh CPU verification.
                        prepared.releaseProducer();
                        const received = try Codec.decodeProposal(a, bytes, context, expected, prepared.rows, limits, codec_limits);
                        const fresh = try verifyOwnedAfterContext(a, received, context, expected, prepared.rows, core_setup, arithmetic_setup, limits);
                        try publisher.accept(@intCast(ordinal), fresh, bytes);
                    }
                    try context.require(a, limits);
                }
                fn readRaw(raw: *anyopaque, group: Semantic.Group, logical: u32, column: u32) !M {
                    const owner: *Stage.Owner = @ptrCast(@alignCast(raw));
                    if (kind != .raw) return error.InvalidSourcePageReader;
                    if (column >= if (group == .source) C.SOURCE_MAIN else C.CAPTURE_MAIN) return error.InvalidSourcePageCell;
                    const values = switch (group) {
                        .source => owner.raw.?.columns.?.mainColumn(column),
                        .capture => owner.cores.?.captures.columns[column].values,
                    };
                    if (logical >= values.len) return error.InvalidSourcePageCell;
                    return values[Place.committedRow(logical, owner.pin.?.raw.page.row_log)];
                }
                /// Never invokes a legacy standalone SHA kernel or bit-graph
                /// source proof. All original equations enter one real proof.
                pub fn prove(owner: *Stage.Owner, context: *const Context, pin: Pin, claims: Semantic.Claims, core_setup: *const C.CoreColumns.Setup, arithmetic_setup: *const Components.ArithmeticSetup, limits: Limits) !Proved {
                    if (owner.active_leases >= std.math.maxInt(usize) - 1) return error.SourcePageProofLeaseLimit;
                    try context.require(owner.allocator(), limits);
                    return proveAfterContext(owner, context, pin, claims, core_setup, arithmetic_setup, limits);
                }
                fn proveAfterContext(owner: *Stage.Owner, context: *const Context, pin: Pin, claims: Semantic.Claims, core_setup: *const C.CoreColumns.Setup, arithmetic_setup: *const Components.ArithmeticSetup, limits: Limits) !Proved {
                    const a = owner.allocator();
                    if (owner.active_leases >= std.math.maxInt(usize) - 1) return error.SourcePageProofLeaseLimit;
                    try requirePin(context, pin, limits);
                    if (kind == .raw) try owner.require(&context.admitted.source, context.raw_plan, pin, limits.raw) else try owner.require(&context.admitted, context.fold_plan, pin, limits.fold);
                    const fold_rows: []const Semantic.FoldRow = if (kind == .raw) &.{} else owner.descriptors;
                    const expected_descriptors = try descriptors(a, context, pin, fold_rows, limits);
                    defer a.free(expected_descriptors);
                    const graph = try prepare(a, context, pin, fold_rows, claims, limits);
                    defer graph.deinit();
                    const reader: Semantic.Reader = if (kind == .raw) .{ .context = owner, .read = readRaw } else owner.semanticReader();
                    try graph.readAndMaterialize(reader, limits.semantic);
                    const source_log = if (kind == .raw) pin.raw.page.row_log else pin.page.row_log;
                    const capture_log = if (kind == .raw) pin.geometry.connector_log else pin.geometry.capture_log;
                    var fixed = try A.Fixed.init(a, graph, expected_descriptors, source_log, capture_log, limits.arithmetic);
                    defer fixed.deinit();
                    var main = try A.Main.init(a, graph, &fixed, limits.arithmetic);
                    defer main.deinit();
                    var channel: suite.Channel = undefined;
                    var lease = if (kind == .raw)
                        try Stage.lease(owner, &context.admitted.source, context.raw_plan, pin, limits.raw, &channel)
                    else
                        try Stage.lease(owner, &context.admitted, context.fold_plan, pin, limits.fold, &channel);
                    defer lease.deinit();
                    channel.mixRoot(abiId());
                    try Protocol.beginSemantic(&channel, kind, try identity(context, pin, limits), context.epoch, graph, claims);
                    try lease.scheme.commitBorrowedStreaming(a, fixed.columns, 16, &channel);
                    try lease.scheme.commitBorrowedStreaming(a, main.columns, 16, &channel);
                    var roots = try lease.scheme.roots(a);
                    defer roots.deinit(a);
                    if (roots.items.len != 8 or !std.meta.eql(roots.items[0..6].*, pin.roots)) return error.UntrustedSourcePageCommittedRoots;
                    const semantic = try semanticPin(context, pin, graph, claims, roots.items[6..8].*, limits);
                    const relations = try Protocol.drawPageRelations(a, &channel, semantic, semantic);
                    var source_columns: [C.SOURCE_MAIN]Column = undefined;
                    if (kind == .raw) {
                        for (&source_columns, 0..) |*column, i| {
                            column.* = .{ .log_size = source_log, .values = owner.raw.?.columns.?.mainColumn(i) };
                        }
                    } else {
                        @memcpy(&source_columns, owner.source_main.?.columns);
                    }
                    const cores = if (kind == .raw) &owner.cores.? else owner.cores.?;
                    const capture_fixed = if (kind == .raw) cores.connector_fixed.columns else cores.capture_fixed.?.columns;
                    const capture_main = if (kind == .raw) cores.captures.columns else cores.capture_main.?.columns;
                    var generated = try I.generate(a, .{ .cores = cores, .source_main = &source_columns, .capture_fixed = capture_fixed, .capture_main = capture_main, .source_log = source_log, .capture_log = capture_log, .logical_source_rows = if (kind == .raw) pin.raw.page.chunks else pin.page.count, .compressions = pin.geometry.compressions, .first_circuit = if (kind == .raw) 1 else pin.geometry.first_circuit }, &fixed, &main, &relations, arithmetic_setup, limits.interaction);
                    defer generated.deinit();
                    const component_owner = try C.Owner.init(a, graph, &fixed.plan, &fixed.arithmetic, &fixed.source_inputs, &fixed.capture_inputs, geometry(pin, &fixed), relations, generated.claims, core_setup, arithmetic_setup, limits.composition);
                    defer component_owner.deinit();
                    mixClaims(&channel, generated.claims);
                    try lease.scheme.commitBorrowedStreaming(a, generated.columns, 16, &channel);
                    const components = [_]engine.air.component_prover.ComponentProver{component_owner.asProverComponent()};
                    const scheme = try lease.takeScheme();
                    const stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, &components, &channel, scheme);
                    owner.active_leases += 1; // storage lease survives warm tree lease.
                    return .{ .owner = owner, .proof = .{ .abi = abiId(), .pin = pin, .semantic = semantic, .claims = generated.claims, .stark = stark } };
                }
            };
        }
        /// Fresh CPU receiver consumes its proof vectors on every path. The
        /// caller's allocation policy must bound decoded proof storage; all
        /// graph, fixed recipe and component work uses this separate heap cap.
        pub fn verifyOwned(a: std.mem.Allocator, proof: Proof, context: *const Context, expected: Pin, independently_admitted_fold_rows: []const Semantic.FoldRow, core_setup: *const C.CoreColumns.Setup, arithmetic_setup: *const Components.ArithmeticSetup, limits: Limits) !VerifiedPage {
            context.require(a, limits) catch |failure| {
                var rejected = proof;
                rejected.deinit(a);
                return failure;
            };
            return verifyOwnedAfterContext(a, proof, context, expected, independently_admitted_fold_rows, core_setup, arithmetic_setup, limits);
        }
        /// Original immutable proof bytes stay live only until this call returns.
        /// All capture vectors and frame log arrays are independently owned.
        pub fn verifyCaptureBorrowed(a: std.mem.Allocator, proof: *const Proof, context: *const Context, expected: Pin, independently_admitted_fold_rows: []const Semantic.FoldRow, core_setup: *const C.CoreColumns.Setup, arithmetic_setup: *const Components.ArithmeticSetup, limits: Limits) !Captured {
            try context.require(a, limits);
            var result: Captured = undefined;
            _ = try verifyInternal(false, a, proof, context, expected, independently_admitted_fold_rows, core_setup, arithmetic_setup, limits, &result);
            return result;
        }
        /// Consume original PAGE vectors on every path, while publishing only
        /// independently owned material from the same full fresh verifier.
        pub fn verifyCaptureOwned(a: std.mem.Allocator, proof: Proof, context: *const Context, expected: Pin, independently_admitted_fold_rows: []const Semantic.FoldRow, core_setup: *const C.CoreColumns.Setup, arithmetic_setup: *const Components.ArithmeticSetup, limits: Limits) !Captured {
            var received = proof;
            defer received.deinit(a);
            return verifyCaptureBorrowed(a, &received, context, expected, independently_admitted_fold_rows, core_setup, arithmetic_setup, limits);
        }
        /// Consume the exact independently admitted kind roster. The loader
        /// supplies original proof bytes, never verified scalar proposals.
        /// `accept` is provisional until this call's final epoch check succeeds.
        /// Keeping the unchecked kernel private prevents a caller from skipping
        /// admission or reusing an epoch token for a different roster.
        pub fn verifyRosterOwned(a: std.mem.Allocator, context: *const Context, core_setup: *const C.CoreColumns.Setup, arithmetic_setup: *const Components.ArithmeticSetup, limits: Limits, loader: anytype) !void {
            if (limits.max_receiver_heap_bytes == 0) return error.SourcePageReceiverResourceLimit;
            try context.require(a, limits);
            const roster = if (kind == .raw) context.raw else context.fold;
            for (roster, 0..) |expected, ordinal| {
                const rows: []const Semantic.FoldRow = if (kind == .raw) &.{} else try loader.rows(a, @intCast(ordinal), expected.page.count);
                // Durable inventories may own nested recipe slices. Their
                // exact owner must release them before this live allocator
                // is destroyed; old flat/borrowed-recipe fixtures stay valid.
                defer if (kind == .fold) {
                    if (@hasDecl(@TypeOf(loader.*), "releaseRows")) loader.releaseRows(a, rows) else a.free(rows);
                };
                if (kind == .fold and rows.len != expected.page.count) return error.InvalidSourcePageInventory;
                const proof = try loader.take(a, @intCast(ordinal));
                const fresh = try verifyOwnedAfterContext(a, proof, context, expected, rows, core_setup, arithmetic_setup, limits);
                try loader.accept(fresh);
            }
            try context.require(a, limits);
        }
        fn verifyOwnedAfterContext(a: std.mem.Allocator, proof: Proof, context: *const Context, expected: Pin, independently_admitted_fold_rows: []const Semantic.FoldRow, core_setup: *const C.CoreColumns.Setup, arithmetic_setup: *const Components.ArithmeticSetup, limits: Limits) !VerifiedPage {
            return verifyInternal(true, a, &proof, context, expected, independently_admitted_fold_rows, core_setup, arithmetic_setup, limits, null);
        }
        // One original verifier body. Capture mode changes only immutable
        // proof ownership and transactional publication after full verification.
        fn verifyInternal(comptime take: bool, a: std.mem.Allocator, proof: *const Proof, context: *const Context, expected: Pin, independently_admitted_fold_rows: []const Semantic.FoldRow, core_setup: *const C.CoreColumns.Setup, arithmetic_setup: *const Components.ArithmeticSetup, limits: Limits, capture_out: ?*Captured) !VerifiedPage {
            var owned = proof.*;
            var owns_proof = take;
            defer if (owns_proof) owned.deinit(a);
            try admit(&owned, context, expected, limits);
            const commitments = owned.stark.commitment_scheme_proof.commitments.items;
            if (limits.max_receiver_heap_bytes == 0 or !std.meta.eql(owned.abi, abiId()) or !std.meta.eql(owned.pin, expected) or
                !std.meta.eql(owned.stark.commitment_scheme_proof.config, context.fold_plan.config) or commitments.len != Protocol.PROOF_COMMITMENTS or
                !std.meta.eql(commitments[0..6].*, expected.roots) or !std.meta.eql(commitments[6..8].*, owned.semantic.roots)) return error.UntrustedSourceUnifiedPageProof;
            var budget = engine.host_budget_allocator.HostBudgetAllocator.init(a, limits.max_receiver_heap_bytes);
            const bounded = budget.allocator();
            const expected_descriptors = try descriptors(bounded, context, expected, independently_admitted_fold_rows, limits);
            defer bounded.free(expected_descriptors);
            const graph = try prepare(bounded, context, expected, independently_admitted_fold_rows, owned.semantic.claims, limits);
            defer graph.deinit();
            const source_log = if (kind == .raw) expected.raw.page.row_log else expected.page.row_log;
            const capture_log = if (kind == .raw) expected.geometry.connector_log else expected.geometry.capture_log;
            var fixed = try A.Fixed.init(bounded, graph, expected_descriptors, source_log, capture_log, limits.arithmetic);
            defer fixed.deinit();
            const independent_semantic = try semanticPin(context, expected, graph, owned.semantic.claims, owned.semantic.roots, limits);
            if (!std.meta.eql(independent_semantic, owned.semantic)) return error.UntrustedSourceUnifiedSemanticPin;
            if (kind == .raw)
                try RawKernel.verifyFixedRoots(bounded, &context.admitted.source, context.raw_plan, expected, .{ .operands = limits.raw, .max_interaction_cells = limits.interaction.max_cells })
            else {
                var premix_fixed = try FoldFixed.Columns.init(bounded, expected, independently_admitted_fold_rows, limits.protocol.fold_cores);
                defer premix_fixed.deinit();
                const groups = [_][]const Column{ premix_fixed.source.columns, premix_fixed.core.items, premix_fixed.capture.columns };
                try requireFixedRoots(bounded, context.fold_plan.config, &groups, &.{ expected.roots[0], expected.roots[2], expected.roots[4] });
            }
            try requireFixedRoots(bounded, context.fold_plan.config, &.{fixed.columns}, &.{owned.semantic.roots[0]});
            const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);
            var verifier = try Verifier.init(a, context.fold_plan.config);
            defer verifier.deinit(a);
            var channel = if (kind == .raw)
                try RawStage.replayChannel(context.raw_plan, expected)
            else blk: {
                var result = Protocol.foldFirstChannel(context.fold_plan, expected);
                for (expected.roots) |root| result.mixRoot(root);
                break :blk result;
            };
            // Register the six actual roots without mixing them twice into the
            // separately reconstructed original premix channel.
            var registration_channel = suite.Channel{};
            const pregeometry = geometry(expected, &fixed);
            // Component construction validates the independently reconstructed
            // complete tree inventories and separate claim closures.
            channel.mixRoot(abiId());
            try Protocol.beginSemantic(&channel, kind, independent_semantic.premix_identity, context.epoch, graph, owned.semantic.claims);
            // Relations follow both semantic roots in the exact original PCS
            // commitment order, before any requesting interaction is sampled.
            channel.mixRoot(owned.semantic.roots[0]);
            channel.mixRoot(owned.semantic.roots[1]);
            const relations = try Protocol.drawPageRelations(bounded, &channel, owned.semantic, independent_semantic);
            const component_owner = try C.Owner.init(bounded, graph, &fixed.plan, &fixed.arithmetic, &fixed.source_inputs, &fixed.capture_inputs, pregeometry, relations, owned.claims, core_setup, arithmetic_setup, limits.composition);
            defer component_owner.deinit();
            for (expected.roots, 0..) |root, tree| try verifier.commit(a, root, component_owner.composition.?.logs[tree], &registration_channel);
            try verifier.commit(a, owned.semantic.roots[0], component_owner.composition.?.logs[6], &registration_channel);
            try verifier.commit(a, owned.semantic.roots[1], component_owner.composition.?.logs[7], &registration_channel);
            mixClaims(&channel, owned.claims);
            try verifier.commit(a, commitments[8], component_owner.composition.?.logs[8], &channel);
            const components = [_]core.air.components.Component{component_owner.asVerifierComponent()};
            const proof_start = channel;
            var frame: ?CaptureFrame.ForKind(kind) = null;
            defer if (frame) |*retained| retained.deinit(a);
            var expanded: core.verifier.ProofCapture(suite.Hasher) = undefined;
            var owns_capture = false;
            defer if (owns_capture) expanded.deinit(a);
            if (capture_out != null) {
                frame = try CaptureFrame.ForKind(kind).init(a, owned.claims, independent_semantic, pregeometry, component_owner);
                try core.verifier.verifyBorrowedWithProofCapture(suite.Hasher, suite.MerkleChannel, a, &components, &channel, &verifier, &owned.stark, &expanded);
                owns_capture = true;
                try frame.?.requireCaptured(a, &expanded, context.fold_plan.config, component_owner);
            } else {
                if (!take) unreachable;
                owns_proof = false; // original verifier consumes vectors on errors.
                try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, &components, &channel, &verifier, owned.stark);
            }
            const receipt = VerifiedPage{ .admission_id = context.admitted.identity, .source_seal = context.sealed.digest, .premix_identity = independent_semantic.premix_identity, .graph_identity = graph.identity, .page_index = index(expected), .input_requests = graph.input_requests, .claims = owned.semantic.claims, .final_channel = channel.digestBytes() };
            if (capture_out) |out| {
                var published = Captured{ .proof = expanded, .frame = frame.?, .pin = expected, .config = context.fold_plan.config, .relations = relations, .proof_start = proof_start, .final_channel = channel, .receipt = receipt, .seal = undefined };
                published.seal = published.identity();
                out.* = published;
                owns_capture = false;
                frame = null;
            }
            return receipt;
        }
    };
}
pub fn requireFixedRoots(a: std.mem.Allocator, config: core.pcs.PcsConfig, groups: []const []const Column, expected: []const [32]u8) !void {
    if (groups.len != expected.len) return error.UntrustedSourcePageFixedRoots;
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    var scheme = try engine.pcs.CommitmentSchemeProver(Cpu, suite.Hasher, suite.MerkleChannel).init(a, config);
    defer scheme.deinit(a);
    scheme.setCoefficientRetentionPolicy(.never);
    var channel = suite.Channel{};
    for (groups) |columns| try scheme.commitBorrowedStreaming(a, columns, 16, &channel);
    var roots = try scheme.roots(a);
    defer roots.deinit(a);
    if (!std.mem.eql([32]u8, roots.items, expected)) return error.UntrustedSourcePageFixedRoots;
}
