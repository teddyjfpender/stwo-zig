//! Fixed statement fan-out for the Ethereum public-sum circuit.
//! Construct only from the native owner's admitted public-input view. This
//! value owns its schedule; it borrows neither graph buffers nor proof values.
//! One schedule supplies row-10 multiplicities and row-11 wire producers.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const public_sums = @import("recursive_common_ethereum_incremental_leaf_public_sums_v4.zig");
const sums_layout = @import("recursive_common_ethereum_incremental_leaf_public_sums_v4_support.zig");
const air = frontend.recursion.air;
const M31 = core.fields.m31.M31;
const input = air.statement_input_witness;
const semantics = air.statement_semantics_input_witness;
const provider = air.statement_input_roots_v3;
const clocks = frontend.recursion.ethereum_clock_routing_v1;

pub const SCHEMA_VERSION: u32 = 6;
pub const WORD_COUNT = air.statement_input.CANONICAL_WORD_COUNT;
pub const CLOCK_WORD_COUNT = clocks.WORD_COUNT;
pub const Error = error{InvalidEthereumStatementRouting};

pub const Plan = struct {
    pub const PublicationConsumerAir = air.ethereum_publication_control_v1;
    pub const ConsumerAir = air.statement_semantics_bytes_v2;
    const ByteRoute = struct { node: u32 = 0, uses: u32 = 0 };
    byte_routes: [WORD_COUNT][2]ByteRoute = .{[2]ByteRoute{ .{}, .{} }} ** WORD_COUNT,
    wire_uses: [WORD_COUNT]u32,
    native_root_routes: ?[2]ByteRoute = null,
    clock_uses: [CLOCK_WORD_COUNT]u32 = undefined,
    program_identity: [32]u8,
    local_publication: bool = true,
    additional_word_uses: [WORD_COUNT]u32 = .{0} ** WORD_COUNT,

    /// Source indices are part of the fixed public-sum ABI: selector, then
    /// every canonical statement word. Zero-use inputs need no source row.
    pub fn init(bindings: []const public_sums.InputSourceV4, uses: []const u32, program_identity: [32]u8) Error!Plan {
        if (bindings.len != uses.len or bindings.len < 1 + WORD_COUNT or
            std.meta.activeTag(bindings[0]) != .segment_selector)
            return error.InvalidEthereumStatementRouting;
        var result: Plan = .{ .wire_uses = undefined, .program_identity = program_identity };
        for (bindings[1..][0..WORD_COUNT], uses[1..][0..WORD_COUNT], 0..) |source, count, word| {
            if (!std.meta.eql(source, public_sums.InputSourceV4{ .statement_word = @intCast(word) }) or count >= core.fields.m31.Modulus)
                return error.InvalidEthereumStatementRouting;
            result.wire_uses[word] = count;
        }
        const byte_start = 1 + WORD_COUNT + sums_layout.CLOCK_LIMB_COUNT;
        const byte_end = byte_start + sums_layout.REGISTER_BYTE_COUNT;
        if (bindings.len < byte_end) return error.InvalidEthereumStatementRouting;
        for (bindings[1 + WORD_COUNT .. byte_start], uses[1 + WORD_COUNT .. byte_start], 0..) |source, count, index| {
            const coordinate: public_sums.RegisterClockCoordinateV4 = .{
                .boundary = @enumFromInt(index / (32 * 2)),
                .register = @intCast((index / 2) % 32),
                .limb = @intCast(index % 2),
            };
            if (!std.meta.eql(source, public_sums.InputSourceV4{ .register_clock_limb = coordinate }) or count >= core.fields.m31.Modulus)
                return error.InvalidEthereumStatementRouting;
            result.clock_uses[index] = count;
        }
        for (bindings[byte_start..byte_end], uses[byte_start..byte_end], 0..) |source, count, index| {
            const coordinate: public_sums.RegisterByteCoordinateV4 = .{
                .boundary = @enumFromInt(index / (32 * 4)),
                .register = @intCast((index / 4) % 32),
                .byte = @intCast(index % 4),
            };
            if (!std.meta.eql(source, public_sums.InputSourceV4{ .register_byte = coordinate }) or count >= core.fields.m31.Modulus)
                return error.InvalidEthereumStatementRouting;
            const layout = frontend.recursion.span_statement.canonical_layout;
            const state = if (coordinate.boundary == .entry) layout.entry_state_start else layout.exit_state_start;
            const word = state + layout.machine_state_registers_start_offset + @as(usize, coordinate.register) * 2 + coordinate.byte / 2;
            result.byte_routes[word][coordinate.byte % 2] = .{ .node = @intCast(byte_start + index), .uses = count };
        }
        var global_words: usize = 0;
        var native_roots: usize = 0;
        var root_routes: [2]ByteRoute = undefined;
        for (bindings[1 + WORD_COUNT ..], 1 + WORD_COUNT..) |source, index| {
            if (source == .native_continuation_root) {
                if (native_roots >= 2 or source.native_continuation_root != native_roots or uses[index] == 0 or uses[index] >= core.fields.m31.Modulus) return error.InvalidEthereumStatementRouting;
                root_routes[native_roots] = .{ .node = @intCast(index), .uses = uses[index] };
                native_roots += 1;
            }
            if (source == .global_statement_word) {
                if (source.global_statement_word != global_words or global_words >= WORD_COUNT)
                    return error.InvalidEthereumStatementRouting;
                global_words += 1;
            }
            if (std.meta.activeTag(source) == .register_clock_limb and index >= byte_start)
                return error.InvalidEthereumStatementRouting;
            if (std.meta.activeTag(source) == .register_byte and (index < byte_start or index >= byte_end))
                return error.InvalidEthereumStatementRouting;
            if (std.meta.activeTag(source) == .statement_word)
                return error.InvalidEthereumStatementRouting;
        }
        if (global_words != 0 and global_words != WORD_COUNT) return error.InvalidEthereumStatementRouting;
        if (native_roots != 0 and native_roots != 2) return error.InvalidEthereumStatementRouting;
        if (native_roots == 2) result.native_root_routes = root_routes;
        result.local_publication = global_words == 0;
        return result;
    }

    pub fn rowCount(self: *const Plan) usize {
        var count: usize = CLOCK_WORD_COUNT + @as(usize, if (self.usesNativeRoots()) 2 else 0);
        for (0..WORD_COUNT) |word| count += @intFromBool(self.usesStatement(word));
        return count;
    }

    /// Call only with counts derived from admitted source descriptors. Values
    /// do not enter this schedule; the resulting counts are bound by identity
    /// and by the committed provider preprocessing.
    pub fn withAdditionalUses(self: Plan, counts: [WORD_COUNT]u32) Error!Plan {
        var result = self;
        for (&result.additional_word_uses, counts) |*uses, count| {
            uses.* = std.math.add(u32, uses.*, count) catch return error.InvalidEthereumStatementRouting;
            if (uses.* >= core.fields.m31.Modulus - 8) return error.InvalidEthereumStatementRouting;
        }
        return result;
    }

    pub fn usesNativeRoots(self: *const Plan) bool {
        return self.native_root_routes != null;
    }

    pub fn nativeRootSourceUses(self: *const Plan, side: u1) u32 {
        _ = side;
        return @intFromBool(self.usesNativeRoots());
    }

    pub fn nativeRootConsumerRow(self: *const Plan, side: u1) ?semantics.Row {
        const routes = self.native_root_routes orelse return null;
        return .{
            .source = .statement,
            .integer = false,
            .active_kinds = semantics.ProofKindSet.SEGMENT,
            .circuit_id = public_sums.CIRCUIT_ID,
            .node_id = routes[side].node,
            .use_count = routes[side].uses,
            .statement_scope = air.vm_statement_roots.NATIVE_CONTINUATION_SCOPE,
            .word_index = side,
        };
    }

    pub fn clockProviderUses(_: *const Plan, index: usize) u32 {
        return clocks.sourceUses(index);
    }

    pub fn clockConsumerRow(self: *const Plan, index: usize) semantics.Row {
        return .{
            .source = .statement,
            .integer = true,
            .active_kinds = semantics.ProofKindSet.SEGMENT,
            .circuit_id = public_sums.CIRCUIT_ID,
            .node_id = @intCast(1 + WORD_COUNT + index),
            .use_count = self.clock_uses[index],
            .statement_scope = clocks.STATEMENT_SCOPE,
            .word_index = @intCast(index),
        };
    }

    /// A source is consumed once and emits the graph's exact wire fan-out.
    /// The two VM-composition roots are a separate, fixed consumer in this
    /// same provider schedule. Binary/empty routing retains its old behavior.
    pub fn extraUses(self: *const Plan, row: input.Row) u32 {
        return (if (self.usesNativeRoots()) @as(u32, 0) else provider.Routing.extraUses(row)) + @as(u32, @intFromBool(row.segment_mask == 1 and self.local_publication)) +
            @as(u32, @intFromBool(row.segment_mask == 1 and self.usesStatement(row.word_index))) +
            (if (row.segment_mask == 1) self.additional_word_uses[row.word_index] else 0);
    }

    pub fn publicationConsumerRow(_: *const Plan, word: usize, value: M31) PublicationConsumerAir.Relation.Row {
        var pp = [_]u32{0} ** PublicationConsumerAir.PREPROCESSED_COLUMN_COUNT;
        pp[9] = 1;
        pp[10] = 1;
        pp[11] = air.statement_input.SEGMENT_STATEMENT_SCOPE;
        pp[12] = @intCast(word);
        return PublicationConsumerAir.wordRow(value, pp);
    }

    pub fn providerRow(self: *const Plan, row: input.Row, words: input.StatementWitness) !provider.Relation.Row {
        return provider.Routing.logicalRowForPlan(row, words, self);
    }

    pub fn consumerRow(self: *const Plan, word: usize) ?semantics.Row {
        const uses = self.wire_uses[word];
        if (!self.usesStatement(word)) return null;
        return .{
            .source = .statement,
            .integer = semantics.isIntegerWord(word),
            .active_kinds = semantics.ProofKindSet.SEGMENT,
            .circuit_id = public_sums.CIRCUIT_ID,
            .node_id = @intCast(1 + word),
            .use_count = uses,
            .statement_scope = air.statement_input.SEGMENT_STATEMENT_SCOPE,
            .word_index = @intCast(word),
        };
    }

    fn usesStatement(self: *const Plan, word: usize) bool {
        return self.wire_uses[word] != 0 or self.byte_routes[word][0].uses != 0 or self.byte_routes[word][1].uses != 0;
    }

    pub fn byteColumns(self: *const Plan, row: semantics.Row) [4]M31 {
        if (row.circuit_id != public_sums.CIRCUIT_ID or row.source != .statement or
            row.statement_scope != air.statement_input.SEGMENT_STATEMENT_SCOPE)
            return .{M31.zero()} ** 4;
        const routes = self.byte_routes[row.word_index];
        return .{ M31.fromCanonical(routes[0].node), M31.fromCanonical(routes[0].uses), M31.fromCanonical(routes[1].node), M31.fromCanonical(routes[1].uses) };
    }

    pub fn logicalConsumerRow(self: *const Plan, row: semantics.Row, value: M31) !ConsumerAir.Relation.Row {
        return ConsumerAir.logicalRow(row, value, .segment_leaf, self.byteColumns(row));
    }

    pub fn identity(self: *const Plan) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig/ethereum-statement-routing/v4\x00");
        hash.update(&provider.SEMANTIC_DIGEST);
        hash.update(&ConsumerAir.SEMANTIC_DIGEST);
        hash.update(&air.transcript_payload_clocks_v2.SEMANTIC_DIGEST);
        hash.update(&PublicationConsumerAir.SEMANTIC_DIGEST);
        hash.update(&self.program_identity);
        if (self.native_root_routes) |routes| {
            hash.update("native-continuation-roots/v1\x00");
            for (routes) |route| {
                var encoded: [8]u8 = undefined;
                std.mem.writeInt(u32, encoded[0..4], route.node, .little);
                std.mem.writeInt(u32, encoded[4..8], route.uses, .little);
                hash.update(&encoded);
            }
        }
        hash.update(&.{@intFromBool(self.local_publication)});
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, SCHEMA_VERSION, .little);
        hash.update(&bytes);
        for ([_]u32{ clocks.SCHEMA_VERSION, clocks.STATEMENT_SCOPE, clocks.WORD_COUNT, clocks.WIRE_START }) |value| {
            std.mem.writeInt(u32, &bytes, value, .little);
            hash.update(&bytes);
        }
        for (self.clock_uses) |uses| {
            std.mem.writeInt(u32, &bytes, uses, .little);
            hash.update(&bytes);
        }
        for (self.wire_uses) |uses| {
            std.mem.writeInt(u32, &bytes, uses, .little);
            hash.update(&bytes);
        }
        for (self.additional_word_uses) |uses| {
            std.mem.writeInt(u32, &bytes, uses, .little);
            hash.update(&bytes);
        }
        for (self.byte_routes) |pair| for (pair) |route| {
            std.mem.writeInt(u32, &bytes, route.node, .little);
            hash.update(&bytes);
            std.mem.writeInt(u32, &bytes, route.uses, .little);
            hash.update(&bytes);
        };
        return hash.finalResult();
    }
};
