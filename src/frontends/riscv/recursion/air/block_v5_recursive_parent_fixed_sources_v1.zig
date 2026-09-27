//! Original execution source routing from compiled schemas and fixed receipts.
//! No transcript is privately executed; main suppliers remain a live-proof duty.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Arena = @import("stable_graph_arena_v1.zig");
const Storage = @import("blake3_parent_row_storage.zig");
const Scalar = @import("scalar_wire_source.zig");
const Pack = @import("qm31_pack_wire.zig");
const Encoding = @import("blake3_field_bytes.zig");
const Word = @import("blake3_private_word.zig");
const Boundary = @import("blake3_boundary.zig");
const Lower = @import("verifier_arithmetic_lowering.zig");
const SampleLinks = @import("blake3_sample_links.zig");
const ChallengeLinks = @import("blake3_challenge_links.zig");
const Terminal = @import("blake3_terminal_links.zig");
const Native = @import("blake3_native_transcript.zig");
const Recorder = @import("blake3_native_recorder.zig");
const RootSources = @import("blake3_root_sources.zig");
const Fixed = @import("block_v5_recursive_fixed_port_rows_v1.zig").ForSlots(.{ 12, 11, 10, 2, 9 });
const slots = .{ 12, 11, 10, 2, 9 };
const Mode = enum { parent, packed_parent, native_word, native_page };
const Lists = struct {
    a: std.mem.Allocator,
    lists: std.meta.Tuple(&.{ std.ArrayList(Storage.FixedRow(Scalar)), std.ArrayList(Storage.FixedRow(Pack)), std.ArrayList(Storage.FixedRow(Encoding)), std.ArrayList(Storage.FixedRow(Boundary)), std.ArrayList(Storage.FixedRow(Word)) }) = .{ .empty, .empty, .empty, .empty, .empty },
    fn add(self: *Lists, comptime slot: usize, row: Storage.Airs[slot].Row) !void {
        const index = comptime blk: {
            for (slots, 0..) |s, i| if (s == slot) break :blk i;
            @compileError("invalid fixed source slot");
        };
        try self.lists[index].append(self.a, Storage.compactFixed(Storage.Airs[slot], row));
    }
    fn finish(self: *Lists) !Fixed {
        var counts: [slots.len]usize = undefined;
        inline for (0..slots.len) |i| counts[i] = self.lists[i].items.len;
        var result = try Fixed.init(self.a, counts);
        inline for (slots, 0..) |slot, i| for (self.lists[i].items) |row| try result.append(slot, row);
        try result.finish();
        return result;
    }
};
pub fn ForPieces(comptime PiecesType: type) type {
    return ForPiecesMode(PiecesType, false);
}
/// Statically selected requester/public parent compiler. Only packed inputs
/// handled by the separate original nested packing port are omitted here.
pub fn ForPackedPieces(comptime PiecesType: type) type {
    return ForPiecesMode(PiecesType, true);
}
fn ForPiecesMode(comptime PiecesType: type, comptime packed_public: bool) type {
    return struct {
        pub const Owned = struct {
            const Self = @This();
            allocator: std.mem.Allocator,
            lease: ?*Budget,
            arena: Arena.Owned,
            challenges: Fixed,
            claims: Fixed,
            samples: Fixed,
            terminal: Fixed,
            payload_bytes: Fixed,
            roots: Fixed,
            pub fn init(a: std.mem.Allocator, pieces: *const PiecesType, fixed_root: [32]u8) !*Self {
                try pieces.shape.validate();
                try pieces.composition.circuit.validate();
                try pieces.arithmetic.validateAgainst(pieces.shape);
                try pieces.transcript.validateAgainst(pieces.shape);
                return compile(a, pieces.shape, &pieces.composition, &pieces.arithmetic.deep_graph, &pieces.arithmetic.fri_graph, &pieces.transcript.fixed, fixed_root, if (packed_public) .packed_parent else .parent);
            }
            /// Structural native routing only. The typed family wrapper must
            /// validate original admission and transcript provenance before and
            /// after compilation; this method cannot nominate an expected key.
            pub fn compileNativeWord(a: std.mem.Allocator, shape: anytype, composition: anytype, dg: *const @import("pcs_deep_circuit.zig").Circuit, fg: *const @import("fri_verifier_circuit.zig").Circuit, plan: *const @import("blake3_transcript_plan.zig").Plan) !*Self {
                try shape.validateAgainst(shape.row_log, shape.config);
                try composition.validateAgainst(shape);
                try dg.validate();
                try fg.validate();
                if (!std.meta.eql(dg.profile_digest, shape.deepProfile().identityDigest()) or !std.meta.eql(fg.profile_digest, shape.friProfile().identityDigest())) return error.InvalidNativeFixedSourceProfile;
                try plan.validate();
                return compile(a, shape, composition, dg, fg, plan, @splat(0), .native_word);
            }
            /// PAGE structural compiler: the typed wrapper validates the real
            /// independently admitted native owner and transcript at both ends.
            /// All initial eight roots and equation public inputs stay external.
            pub fn compileNativePage(a: std.mem.Allocator, profile: anytype, composition: anytype, dg: *const @import("pcs_deep_circuit.zig").Circuit, fg: *const @import("fri_verifier_circuit.zig").Circuit, plan: *const @import("blake3_transcript_plan.zig").Plan) !*Self {
                if (@TypeOf(profile.*).commitment_trees != 10) @compileError("native PAGE source ports require ten commitments");
                try profile.validate();
                try composition.circuit.validate();
                try dg.validate();
                try fg.validate();
                if (!std.meta.eql(dg.profile_digest, profile.deepProfile().identityDigest()) or !std.meta.eql(fg.profile_digest, profile.friProfile().identityDigest())) return error.InvalidNativeFixedSourceProfile;
                try plan.validate();
                return compile(a, profile, composition, dg, fg, plan, @splat(0), .native_page);
            }
            fn compile(a: std.mem.Allocator, shape: anytype, composition: anytype, dg: *const @import("pcs_deep_circuit.zig").Circuit, fg: *const @import("fri_verifier_circuit.zig").Circuit, plan: *const @import("blake3_transcript_plan.zig").Plan, fixed_root: [32]u8, comptime mode: Mode) !*Self {
                const relations = if (mode == .native_word) @import("block_v5_ram_lanes_composition_v1.zig").RELATION_COUNT else @import("universal_challenges.zig").RELATION_COUNT;
                const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
                errdefer if (lease) |owner| owner.destroy();
                const self = try a.create(Self);
                errdefer a.destroy(self);
                var arena = try Arena.Owned.init(a);
                errdefer arena.deinit();
                const temp = arena.allocator();
                const graphs = .{ composition.circuit.graph(), dg.graph(), fg.graph() };
                var use_counts: [3][]u32 = undefined;
                inline for (graphs, 0..) |graph, i| use_counts[i] = try Lower.computeUseCountsInto(graph, try temp.alloc(u32, graph.nodes.len));
                var sources = ChallengeLinks.Sources{ .sample_start = 0, .claim_start = 0, .composition = std.math.maxInt(u32), .oods = std.math.maxInt(u32), .universal_start = std.math.maxInt(u32) };
                var claim_nodes: std.ArrayList(u32) = .empty;
                var sample_nodes: std.ArrayList(u32) = .empty;
                var challenge_count: usize = 0;
                for (composition.sources, 0..) |source, node| switch (source) {
                    .claim => |index| {
                        if (index != claim_nodes.items.len) return error.InvalidExecutionPayload;
                        try claim_nodes.append(temp, @intCast(node));
                    },
                    .sample => |index| {
                        if (index != sample_nodes.items.len) return error.InvalidExecutionPayload;
                        try sample_nodes.append(temp, @intCast(node));
                    },
                    .challenge => |index| {
                        if (index != challenge_count) return error.InvalidExecutionChallenge;
                        if (index == 0) sources.universal_start = @intCast(node);
                        if (node != sources.universal_start + index) return error.InvalidExecutionChallenge;
                        challenge_count += 1;
                    },
                    .composition => {
                        if (sources.composition != std.math.maxInt(u32)) return error.InvalidExecutionChallenge;
                        sources.composition = @intCast(node);
                    },
                    .oods => {
                        if (sources.oods != std.math.maxInt(u32)) return error.InvalidExecutionChallenge;
                        sources.oods = @intCast(node);
                    },
                    .packed_public_input => if (mode != .packed_parent) return error.UnsupportedRecursiveParentFixedPublicPorts,
                    .public_input => if (mode != .native_word and mode != .native_page) return error.UnsupportedRecursiveParentFixedPublicPorts,
                };
                if (challenge_count != relations * 2 or sources.composition == std.math.maxInt(u32) or sources.oods == std.math.maxInt(u32)) return error.InvalidExecutionChallenge;
                var challenges = Lists{ .a = temp };
                const links = try ChallengeLinks.build(temp, plan.fixed.draw_outputs, sources, dg, fg, relations, fg.fold_widths.len);
                for (links, 0..) |link, index| {
                    const first: u32 = @intCast(index * 4);
                    const nodes: [4]u32 = .{ first, first + 1, first + 2, first + 3 };
                    var weight: u32 = 0;
                    if (link.composition) |node| {
                        weight = use_counts[0][node];
                        if (weight != 0) try challenges.add(11, try Pack.weightedFixedRow(.{ .source_circuit = 5_000_003, .source_nodes = nodes, .destination_circuit = 1500, .destination_wire = node }, weight));
                    }
                    if (link.scalar) |destination| {
                        for (destination.nodes, 0..) |node, word| try challenges.add(12, try Scalar.routedRow(@intCast(1500 + 2 * destination.lane), node, use_counts[destination.lane][node], 5_000_003, nodes[word], M.zero()));
                        weight = try std.math.add(u32, weight, 1);
                    }
                    for (nodes, 0..) |node, word| try challenges.add(12, try Scalar.routedRow(5_000_003, node, weight, link.source.circuit, try std.math.add(u32, link.source.first_wire, @intCast(word)), M.zero()));
                }
                var claims = Lists{ .a = temp };
                for (claim_nodes.items, 0..) |node, claim| {
                    const first: u32 = @intCast(claim * 4);
                    const nodes: [4]u32 = .{ first, first + 1, first + 2, first + 3 };
                    const weight = try std.math.add(u32, use_counts[0][node], 1);
                    for (nodes) |source| try claims.add(12, try Scalar.logicalRow(5_000_012, source, weight, M.zero()));
                    try claims.add(11, try Pack.weightedFixedRow(.{ .source_circuit = 5_000_012, .source_nodes = nodes, .destination_circuit = 1500, .destination_wire = node }, weight));
                }
                var samples = Lists{ .a = temp };
                const sample_map = try SampleLinks.build(temp, dg, sample_nodes.items.len, 0);
                for (sample_nodes.items, sample_map) |node, link| {
                    const weight = try std.math.add(u32, use_counts[0][node], 1);
                    for (link.deep) |deep_node| try samples.add(12, try Scalar.logicalRow(1502, deep_node, try std.math.add(u32, use_counts[1][deep_node], weight), M.zero()));
                }
                for (sample_nodes.items, sample_map) |node, link| {
                    const weight = try std.math.add(u32, use_counts[0][node], 1);
                    try samples.add(11, try Pack.weightedFixedRow(.{ .source_circuit = 1502, .source_nodes = link.deep, .destination_circuit = 1500, .destination_wire = node }, weight));
                }
                var payload_bytes = Lists{ .a = temp };
                const payload_count = try std.math.add(usize, claim_nodes.items.len, sample_nodes.items.len);
                const encoding_rows = try temp.alloc(?Encoding.Row, payload_count);
                @memset(encoding_rows, null);
                for (plan.fixed.payload_reads) |receipt| {
                    const is_claim = receipt.source.circuit == Recorder.CLAIM_CIRCUIT;
                    const is_sample = receipt.source.circuit == Native.SAMPLE_SOURCE.circuit;
                    if (!is_claim and !is_sample) continue;
                    if (receipt.source.first_wire % 4 != 0 or receipt.uses.len % 4 != 0) return error.InvalidExecutionPayload;
                    const nodes = if (is_claim) claim_nodes.items else sample_nodes.items;
                    const offset: usize = receipt.source.first_wire / 4;
                    const count = receipt.uses.len / 4;
                    if (offset > nodes.len or count > nodes.len - offset) return error.InvalidExecutionPayload;
                    for (nodes[offset..][0..count], 0..) |node, i| {
                        const item = (if (is_claim) @as(usize, 0) else claim_nodes.items.len) + offset + i;
                        if (encoding_rows[item] != null) return error.InvalidExecutionPayload;
                        encoding_rows[item] = try Encoding.fixedRow(.{ .source_circuit = 1500, .source_wire = node, .destination_circuit = receipt.source.circuit, .destination_first = try std.math.add(u32, receipt.source.first_wire, @intCast(i * 4)), .uses = receipt.uses[i * 4 ..][0..4].* });
                    }
                }
                for (encoding_rows) |row| try payload_bytes.add(10, row orelse return error.InvalidExecutionPayload);
                var terminal = Lists{ .a = temp };
                const coefficient_count = try fg.profile().lastLayerCoefficientCount();
                var mapping = try Terminal.build(temp, dg, fg, shape.config.fri_config.n_queries, coefficient_count);
                defer mapping.deinit();
                var selected: ?@import("blake3_transcript_witness.zig").PayloadReads = null;
                for (plan.fixed.payload_reads) |receipt| {
                    if (receipt.source.circuit != Native.TERMINAL_SOURCE.circuit) continue;
                    if (selected != null or !std.meta.eql(receipt.source, Native.TERMINAL_SOURCE)) return error.InvalidNativeTerminalEncoding;
                    selected = receipt;
                }
                const receipt = selected orelse return error.InvalidNativeTerminalEncoding;
                if (receipt.uses.len != coefficient_count * 4) return error.InvalidNativeTerminalEncoding;
                for (mapping.coefficients, 0..) |nodes, i| {
                    for (nodes) |node| try terminal.add(12, try Scalar.logicalRow(1504, node, try std.math.add(u32, use_counts[2][node], 1), M.zero()));
                    try terminal.add(11, try Pack.fixedRow(.{ .source_circuit = 1504, .source_nodes = nodes, .destination_circuit = 5_000_011, .destination_wire = @intCast(i) }));
                    try terminal.add(10, try Encoding.fixedRow(.{ .source_circuit = 5_000_011, .source_wire = @intCast(i), .destination_circuit = receipt.source.circuit, .destination_first = try std.math.add(u32, receipt.source.first_wire, @intCast(i * 4)), .uses = receipt.uses[i * 4 ..][0..4].* }));
                }
                var roots = Lists{ .a = temp };
                var root_index: usize = if (mode == .native_page) 8 else if (mode == .native_word) 2 else 0;
                for (plan.fixed.root_reads) |root_receipt| {
                    if (root_receipt.source.circuit != RootSources.CIRCUIT) continue;
                    const source = try RootSources.caller(root_index);
                    if (!std.meta.eql(source, root_receipt.source)) return error.InvalidExecutionRoots;
                    for (root_receipt.uses, 0..) |reads, coordinate| {
                        const uses = try std.math.add(u32, reads, std.math.cast(u32, shape.config.fri_config.n_queries) orelse return error.InvalidParentQueryLink);
                        const wire = try std.math.add(u32, source.first_wire, @intCast(coordinate));
                        if (root_index == 0) try roots.add(2, try Boundary.logicalRow(source.circuit, wire, M.fromCanonical(uses), std.mem.readInt(u32, fixed_root[coordinate * 4 ..][0..4], .little))) else try roots.add(9, try Word.logicalRow(source.circuit, wire, uses, 0));
                    }
                    root_index += 1;
                }
                if (root_index != (if (mode == .native_page) @as(usize, 10) else 4) + shape.widths.len) return error.InvalidExecutionRoots;
                const nonce_source = @import("blake3_transcript_witness.zig").Caller{ .circuit = 4_100_001, .first_wire = 2 };
                var nonce_reads: [2]u32 = @splat(0);
                var phases: usize = 0;
                for (plan.fixed.payload_reads) |nonce_receipt| {
                    if (nonce_receipt.source.circuit != nonce_source.circuit) continue;
                    if (!std.meta.eql(nonce_receipt.source, nonce_source) or nonce_receipt.uses.len != 2) return error.InvalidExecutionRoots;
                    for (&nonce_reads, nonce_receipt.uses) |*uses, reads| uses.* = try std.math.add(u32, uses.*, reads);
                    phases += 1;
                }
                if (phases != 2) return error.InvalidExecutionRoots;
                for (nonce_reads, 0..) |uses, coordinate| try roots.add(9, try Word.logicalRow(nonce_source.circuit, nonce_source.first_wire + @as(u32, @intCast(coordinate)), uses, 0));
                const challenge_rows = try challenges.finish();
                const claim_rows = try claims.finish();
                const sample_rows = try samples.finish();
                const terminal_rows = try terminal.finish();
                const payload_rows = try payload_bytes.finish();
                const root_rows = try roots.finish();
                self.* = .{ .allocator = a, .lease = lease, .arena = arena, .challenges = challenge_rows, .claims = claim_rows, .samples = sample_rows, .terminal = terminal_rows, .payload_bytes = payload_rows, .roots = root_rows };
                return self;
            }
            pub fn deinit(self: *Self) void {
                const a = self.allocator;
                const lease = self.lease;
                self.arena.deinit();
                a.destroy(self);
                if (lease) |owner| owner.destroy();
            }
        };
    };
}
const Default = ForPieces(@import("../block_v5_recursive_parent_fixed_pieces_v1.zig").Owned);
pub const Owned = Default.Owned;
