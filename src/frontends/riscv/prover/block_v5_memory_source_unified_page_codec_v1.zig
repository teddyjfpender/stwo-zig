//! Strict bounded ten-tree PAGE artifact. File hashes and decoded claims are
//! proposals; only Page.verifyOwned produces a genuine fresh PAGE result.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const postcard = @import("interop_postcard");
const suite = core.proof_suites.Blake3;
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Protocol = @import("block_v5_memory_source_unified_page_protocol_v1.zig");
const ProofModule = @import("block_v5_memory_source_unified_page_proof_v1.zig");
const Components = @import("block_v5_memory_source_unified_page_components_v1.zig");
const Wire = @import("guest_precompile/proof_artifact_wire.zig");
const Writer = @import("bounded_artifact_writer_v1.zig").Writer;
const Tables = @import("../air/lookups/tables/schema.zig");
pub const MAGIC = "B5PGART1";
pub const Limits = struct {
    max_proof_bytes: usize = 64 << 20,
    max_artifact_bytes: usize = 65 << 20,
};
pub fn ForKind(comptime kind: Semantic.Kind) type {
    return struct {
        const Page = ProofModule.ForKind(kind);
        const C = Components.ForKind(kind);
        const SEMANTIC_SUMS = std.meta.fields(@FieldType(Semantic.Claims, "source")).len + 1 + std.meta.fields(@FieldType(Semantic.Claims, "fold")).len;
        const RELATION_SUMS = C.CoreAirs.len + 2 + (if (kind == .raw) 32 else 24) + C.SourceInput.PAIRS + C.CaptureInput.PAIRS + 4;
        pub const HEADER_BYTES: usize = MAGIC.len + 8 + 4 * 32 + 8 + 3 * 32 + 4 + 8 + 2 * 32 + 16 * (SEMANTIC_SUMS + RELATION_SUMS) + 3 * 8;
        fn requireLimits(limits: Limits) !void {
            if (limits.max_proof_bytes == 0 or limits.max_artifact_bytes < HEADER_BYTES or limits.max_proof_bytes > limits.max_artifact_bytes - HEADER_BYTES)
                return error.InvalidSourcePageArtifactLimits;
        }
        fn writeSemantic(writer: *Writer, pin: Protocol.SemanticPin) !void {
            try writer.writeAll(&pin.premix_identity);
            try writer.writeAll(&pin.source_epoch);
            try writer.writeAll(&pin.graph_identity);
            try Wire.writeInt(writer, u32, pin.circuit_id);
            try Wire.writeInt(writer, u64, pin.input_requests);
            for (pin.roots) |root| try writer.writeAll(&root);
            inline for (std.meta.fields(@TypeOf(pin.claims.source))) |field| try writer.writeClaim(@field(pin.claims.source, field.name));
            try writer.writeClaim(pin.claims.indexed);
            inline for (std.meta.fields(@TypeOf(pin.claims.fold))) |field| try writer.writeClaim(@field(pin.claims.fold, field.name));
        }
        fn readSemantic(cursor: *Wire.Cursor) !Protocol.SemanticPin {
            var pin: Protocol.SemanticPin = undefined;
            @memcpy(&pin.premix_identity, try cursor.take(32));
            @memcpy(&pin.source_epoch, try cursor.take(32));
            @memcpy(&pin.graph_identity, try cursor.take(32));
            pin.circuit_id = try cursor.readInt(u32);
            pin.input_requests = try cursor.readInt(u64);
            for (&pin.roots) |*root| @memcpy(root, try cursor.take(32));
            inline for (std.meta.fields(@TypeOf(pin.claims.source))) |field| @field(pin.claims.source, field.name) = try cursor.readQm31();
            pin.claims.indexed = try cursor.readQm31();
            inline for (std.meta.fields(@TypeOf(pin.claims.fold))) |field| @field(pin.claims.fold, field.name) = try cursor.readQm31();
            return pin;
        }
        fn writeRelations(writer: *Writer, claims: C.Claims) !void {
            for (claims.core) |sum| try writer.writeClaim(sum);
            for (claims.capture.sums) |sum| try writer.writeClaim(sum);
            try Wire.writeInt(writer, u64, claims.capture.wire_requests);
            for (claims.source_inputs.sums) |sum| try writer.writeClaim(sum);
            try Wire.writeInt(writer, u64, claims.source_inputs.requests);
            for (claims.capture_inputs.sums) |sum| try writer.writeClaim(sum);
            try Wire.writeInt(writer, u64, claims.capture_inputs.requests);
            for (claims.arithmetic) |sum| try writer.writeClaim(sum);
        }
        fn readRelations(cursor: *Wire.Cursor) !C.Claims {
            var claims: C.Claims = undefined;
            for (&claims.core) |*sum| sum.* = try cursor.readQm31();
            for (&claims.capture.sums) |*sum| sum.* = try cursor.readQm31();
            claims.capture.wire_requests = try cursor.readInt(u64);
            for (&claims.source_inputs.sums) |*sum| sum.* = try cursor.readQm31();
            claims.source_inputs.requests = try cursor.readInt(u64);
            for (&claims.capture_inputs.sums) |*sum| sum.* = try cursor.readQm31();
            claims.capture_inputs.requests = try cursor.readInt(u64);
            for (&claims.arithmetic) |*sum| sum.* = try cursor.readQm31();
            return claims;
        }
        /// Statically chosen ten-tree schema, actual graph-derived arithmetic
        /// capacities and exact independent hash/provider inventories. This
        /// allocation guard has no authority to accept the decoded equations.
        pub fn preflight(body: []const u8, context: *const ProofModule.Context, expected: Page.Pin, admission: *const Page.Admission, limits: Limits) !void {
            try requireLimits(limits);
            const counts = [Protocol.PROOF_COMMITMENTS]u32{
                C.SOURCE_FIXED,                                 C.SOURCE_MAIN,     C.CORE_FIXED,                                               C.CORE_MAIN,                                                                                                                                                   C.CAPTURE_FIXED, C.CAPTURE_MAIN,
                C.ARITHMETIC_FIXED_OFFSET + C.ARITHMETIC_FIXED, C.ARITHMETIC_MAIN, C.ARITHMETIC_INTERACTION_OFFSET + C.ARITHMETIC_INTERACTION, @intCast(core.verifier_types.compositionColumnCount(C.SPLIT, core.fields.qm31.SECURE_EXTENSION_DEGREE) orelse return error.InvalidSourcePageArtifactGeometry),
            };
            var maximum: u32 = if (kind == .raw) expected.raw.page.row_log else expected.page.row_log;
            for (expected.geometry.logs) |log| maximum = @max(maximum, log);
            for (admission.fixed.arithmetic.logs) |log| maximum = @max(maximum, log);
            maximum = @max(maximum, Tables.logSize(.bitwise));
            maximum = @max(maximum, Tables.logSize(.range_check_8_8));
            const capture_log = if (kind == .raw) expected.geometry.connector_log else expected.geometry.capture_log;
            maximum = @max(maximum, capture_log);
            const config = context.fold_plan.config;
            if (config.lifting_log_size) |lifting| {
                if (lifting < maximum or lifting > 30) return error.InvalidSourcePageArtifactGeometry;
                maximum = lifting;
            }
            try postcard.proof_preflight.validateFor(Protocol.PROOF_COMMITMENTS, body, .{
                .config = .{ .pow_bits = config.pow_bits, .log_blowup_factor = config.fri_config.log_blowup_factor, .n_queries = config.fri_config.n_queries, .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound, .fold_step = config.fri_config.fold_step, .lifting_log_size = config.lifting_log_size },
                .tree_columns = counts,
                .max_column_log_size = maximum,
                .sample_width_limits = .{ 1, 1, 1, 1, 1, 1, 1, 1, 2, 1 },
                .allow_zero_samples = true,
                .hash_size = 32,
                .max_wire_bytes = limits.max_proof_bytes,
            });
        }
        pub fn encode(a: std.mem.Allocator, proof: *const Page.Proof, context: *const ProofModule.Context, expected: Page.Pin, independently_admitted_fold_rows: []const Semantic.FoldRow, proof_limits: ProofModule.Limits, limits: Limits) ![]u8 {
            try requireLimits(limits);
            try context.require(a, proof_limits);
            return encodeProposal(a, proof, context, expected, independently_admitted_fold_rows, proof_limits, limits);
        }
        /// Encode a proposal under independently supplied page admission. This
        /// performs no verification and returns bytes, never a fresh receipt.
        /// Synchronous roster publishers separately check the complete context
        /// at entry and exit; standalone callers use the full-checking wrapper.
        pub fn encodeProposal(a: std.mem.Allocator, proof: *const Page.Proof, context: *const ProofModule.Context, expected: Page.Pin, independently_admitted_fold_rows: []const Semantic.FoldRow, proof_limits: ProofModule.Limits, limits: Limits) ![]u8 {
            try requireLimits(limits);
            try Page.admit(proof, context, expected, proof_limits);
            var budget = engine.host_budget_allocator.HostBudgetAllocator.init(a, proof_limits.max_receiver_heap_bytes);
            var admission = try Page.Admission.init(budget.allocator(), context, expected, independently_admitted_fold_rows, proof.semantic.claims, proof_limits);
            defer admission.deinit();
            if (!std.meta.eql(proof.semantic.graph_identity, admission.graph.identity) or proof.semantic.input_requests != admission.graph.input_requests)
                return error.UntrustedSourceUnifiedSemanticPin;
            var writer = Writer.init(a, limits.max_artifact_bytes);
            defer writer.deinit();
            try writer.writeAll(MAGIC);
            try Wire.writeInt(&writer, u32, Protocol.VERSION);
            try Wire.writeInt(&writer, u32, @intFromEnum(kind));
            try writer.writeAll(&Page.abiId());
            try writer.writeAll(&context.admitted.identity);
            try writer.writeAll(&context.sealed.digest);
            try writer.writeAll(&(try Page.identity(context, expected, proof_limits)));
            const length_at = writer.bytes.items.len;
            try Wire.writeInt(&writer, u64, 0);
            try writeSemantic(&writer, proof.semantic);
            try writeRelations(&writer, proof.claims);
            if (writer.bytes.items.len != HEADER_BYTES) return error.InvalidSourcePageArtifact;
            try postcard.serializeProof(suite.Hasher, &writer, proof.stark);
            const length = writer.bytes.items.len - HEADER_BYTES;
            if (length == 0 or length > limits.max_proof_bytes) return error.SourcePageArtifactResourceLimit;
            try preflight(writer.bytes.items[HEADER_BYTES..], context, expected, &admission, limits);
            std.mem.writeInt(u64, writer.bytes.items[length_at..][0..8], length, .little);
            return writer.toOwnedSlice();
        }
        pub fn decode(a: std.mem.Allocator, raw: []const u8, context: *const ProofModule.Context, expected: Page.Pin, independently_admitted_fold_rows: []const Semantic.FoldRow, proof_limits: ProofModule.Limits, limits: Limits) !Page.Proof {
            return decodeInternal(true, a, raw, context, expected, independently_admitted_fold_rows, proof_limits, limits);
        }
        /// Bounded proposal decoding only. Exact page identity, graph, masks,
        /// vector capacities and original proof framing remain checked. This
        /// cannot produce a VerifiedPage or authorize any source equation.
        pub fn decodeProposal(a: std.mem.Allocator, raw: []const u8, context: *const ProofModule.Context, expected: Page.Pin, independently_admitted_fold_rows: []const Semantic.FoldRow, proof_limits: ProofModule.Limits, limits: Limits) !Page.Proof {
            return decodeInternal(false, a, raw, context, expected, independently_admitted_fold_rows, proof_limits, limits);
        }
        fn decodeInternal(comptime check_context: bool, a: std.mem.Allocator, raw: []const u8, context: *const ProofModule.Context, expected: Page.Pin, independently_admitted_fold_rows: []const Semantic.FoldRow, proof_limits: ProofModule.Limits, limits: Limits) !Page.Proof {
            try requireLimits(limits);
            if (raw.len > limits.max_artifact_bytes or proof_limits.max_receiver_heap_bytes == 0) return error.SourcePageArtifactResourceLimit;
            var cursor = Wire.Cursor.init(raw);
            if (!std.mem.eql(u8, try cursor.take(MAGIC.len), MAGIC) or try cursor.readInt(u32) != Protocol.VERSION or try cursor.readInt(u32) != @intFromEnum(kind) or
                !std.mem.eql(u8, try cursor.take(32), &Page.abiId()) or !std.mem.eql(u8, try cursor.take(32), &context.admitted.identity) or
                !std.mem.eql(u8, try cursor.take(32), &context.sealed.digest) or !std.mem.eql(u8, try cursor.take(32), &(try Page.identity(context, expected, proof_limits)))) return error.UntrustedSourcePageArtifact;
            const length = try cursor.readInt(u64);
            if (length == 0 or length > limits.max_proof_bytes) return error.SourcePageArtifactResourceLimit;
            const semantic = try readSemantic(&cursor);
            const claims = try readRelations(&cursor);
            const body = try cursor.take(@intCast(length));
            try cursor.requireDone();
            // Reject bounded framing/identity failures without allocating any
            // graph, transcript or nested proof vector. The independent full
            // roster is still rechecked before public graph reconstruction.
            if (check_context) try context.require(a, proof_limits);
            // Reconstruct graph capacities from admitted public PAGE claims
            // before decoding any nested PCS/FRI array lengths.
            var budget = engine.host_budget_allocator.HostBudgetAllocator.init(a, proof_limits.max_receiver_heap_bytes);
            var admission = try Page.Admission.init(budget.allocator(), context, expected, independently_admitted_fold_rows, semantic.claims, proof_limits);
            defer admission.deinit();
            if (!std.meta.eql(semantic.graph_identity, admission.graph.identity) or semantic.circuit_id != admission.graph.circuit_id or semantic.input_requests != admission.graph.input_requests or
                claims.source_inputs.requests != admission.fixed.source_inputs.requests or claims.capture_inputs.requests != admission.fixed.capture_inputs.requests)
                return error.UntrustedSourceUnifiedSemanticPin;
            try preflight(body, context, expected, &admission, limits);
            var stream = std.io.fixedBufferStream(body);
            var stark = try postcard.deserializeProof(suite.Hasher, a, stream.reader());
            errdefer stark.deinit(a);
            const proof = Page.Proof{ .abi = Page.abiId(), .pin = expected, .semantic = semantic, .claims = claims, .stark = stark };
            try Page.admit(&proof, context, expected, proof_limits);
            if (stream.pos != body.len) return error.InvalidSourcePageArtifact;
            return proof;
        }
    };
}
