//! Actual shared parent cohorts for public tuple arithmetic plus unchanged
//! B5SS channel/draw AIR. All raw inputs are consumed by the new public bus.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const storage = @import("blake3_parent_row_storage.zig");
const direct = @import("blake3_direct_cohort_columns_v1.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
const scalar = @import("scalar_wire_source.zig");
const pack = @import("qm31_pack_wire.zig");
const boundary = @import("blake3_boundary.zig");
const DefaultComposition = @import("block_v5_global_public_export_composition_v1.zig");
const DefaultPublic = @import("../block_v5_global_public_export_policy_v1.zig");
const DefaultBus = @import("../block_v5_global_public_export_bus_v1.zig");
const U = @import("universal_challenges.zig");
const Recorder = @import("blake3_native_recorder.zig");
const t = @import("blake3_transcript_witness.zig");
const transcript = @import("blake3_transcript_plan.zig");
pub const GRAPH: u32 = 4_300_100;
const BRIDGE: u32 = 4_300_102;
const SEAL: u32 = 4_300_103;
const TRANSCRIPT: u32 = 2_000_000;
const Fusion = @import("arithmetic_fusion_rows.zig");
const all_slots = blk: {
    var slots: [storage.Airs.len]usize = undefined;
    for (&slots, 0..) |*slot, i| slot.* = i;
    break :blk slots;
};
const FixedRows = @import("block_v5_recursive_fixed_port_rows_v1.zig").ForSlots(all_slots);
pub fn ForModules(comptime Public: type, comptime Composition: type, comptime Bus: type) type {
    return struct {
        const Factory = @This();
        pub const Prepared = struct {
            rows: storage.Prepared,
            wires: []Bus.Wire,
            identity: [32]u8,
            pub fn deinit(self: *@This()) void {
                self.rows.allocator.free(self.wires);
                self.rows.deinit();
                self.* = undefined;
            }
        };
        /// Exact original fixed tails; no MAIN columns or successful proof token.
        pub const FixedPrepared = struct {
            rows: FixedRows,
            wires: []Bus.Wire,
            identity: [32]u8,
            pub const complete_fixed_setup = false;
            pub fn deinit(self: *@This()) void {
                self.rows.allocator.free(self.wires);
                self.rows.deinit();
                self.* = undefined;
            }
        };
        fn empty(a: std.mem.Allocator, inputs: usize) !storage.Prepared {
            var result = storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = inputs };
            inline for (0..storage.Airs.len) |i| result.fixed[i] = &.{};
            errdefer result.deinit();
            inline for (storage.Airs, 0..) |Air, i| {
                var emitter = try direct.ForAir(Air).init(a, 0);
                defer emitter.deinit();
                const taken = try emitter.take();
                result.main[i] = taken.main;
                result.fixed[i] = taken.fixed;
            }
            return result;
        }
        /// Freshly validates every source before lowering; copied graph values cannot
        /// select another public claim or challenge even when the sums happen to agree.
        pub fn prepare(a: std.mem.Allocator, owner: *const Public.Owner, graph: *const Composition.Prepared, attempt_capacity: u32) !Factory.Prepared {
            return prepareKernel(false, a, owner, graph, attempt_capacity);
        }
        /// Independently admitted public values are checked by the same kernel.
        /// Only lowering and transcript fixed preprocessing are materialized.
        pub fn prepareFixed(a: std.mem.Allocator, owner: *const Public.Owner, graph: *const Composition.Prepared, attempt_capacity: u32) !Factory.FixedPrepared {
            return prepareKernel(true, a, owner, graph, attempt_capacity);
        }
        fn prepareKernel(comptime fixed_only: bool, a: std.mem.Allocator, owner: *const Public.Owner, graph: *const Composition.Prepared, attempt_capacity: u32) !(if (fixed_only) Factory.FixedPrepared else Factory.Prepared) {
            try owner.validate();
            if (@hasDecl(Composition.Prepared, "validate")) try graph.validate(owner);
            try graph.circuit.validate();
            try graph.relations.validate();
            if (attempt_capacity == 0 or graph.inputs.len != graph.sources.len or graph.sources.len != graph.circuit.input_count or graph.values.len != graph.circuit.nodes.len) return error.InvalidGlobalPublicGraph;
            const public_values = Bus.Values{ .public = owner };
            var expected_channel = (try owner.policy.native(0)).admitted.sealed.sharedChannel();
            const independently_drawn = try U.UniversalRelations.draw(a, &expected_channel);
            const checked = try a.alloc(Q, graph.values.len);
            defer a.free(checked);
            var challenge_count: usize = 0;
            for (graph.sources, graph.inputs) |source, value| switch (source) {
                .public => |coordinate| {
                    const words = try public_values.at(.{ .circuit = GRAPH, .wire = 0, .uses = 1, .source = coordinate });
                    if (!value.eql(Q.fromM31Array(words))) return error.UntrustedGlobalPublicGraphInput;
                },
                .challenge => |index| {
                    if (index != challenge_count or index >= U.DRAW_COUNT) return error.InvalidGlobalPublicChallenge;
                    const element = independently_drawn.elements[index / 2];
                    const expected = if (index % 2 == 0) element.z else element.alpha_powers[1];
                    if (!value.eql(expected)) return error.UntrustedGlobalPublicChallenge;
                    challenge_count += 1;
                },
            };
            if (challenge_count != U.DRAW_COUNT) return error.InvalidGlobalPublicChallenge;
            for (graph.relations.elements, independently_drawn.elements) |actual, expected| if (!actual.z.eql(expected.z) or !actual.alpha_powers[1].eql(expected.alpha_powers[1])) return error.UntrustedGlobalPublicChallenge;
            try graph.circuit.evaluateInto(graph.inputs, checked);
            for (checked, graph.values) |actual, expected| if (!actual.eql(expected)) return error.MutatedGlobalPublicGraph;
            const lane = lower.Lane{ .circuit_id = GRAPH, .active_in = .segment, .circuit_identity = graph.circuit.identity_digest, .graph = graph.circuit.graph() };
            var binary = lane;
            binary.circuit_id += 1;
            binary.active_in = .binary;
            const reference = try lower.Reference.seal(&.{ lane, binary });
            var plan = try lower.Plan.init(a, reference);
            defer plan.deinit();
            var arithmetic = if (fixed_only) fixed: {
                var fused = try Fusion.materializeFixed(a, &plan, reference, .segment_leaf);
                defer fused.deinit();
                var row_counts: [storage.Airs.len]usize = @splat(0);
                inline for (.{ 18, 3, 4, 5 }, 0..) |slot, i| row_counts[slot] = fused.fixed[i].len;
                for (plan.public_terms) |term| if (term.active_in == .segment) {
                    if (term.role == .request) return error.InvalidGlobalPublicGraphBoundary;
                    row_counts[2] += 1;
                };
                var rows = try FixedRows.init(a, row_counts);
                errdefer rows.deinit();
                inline for (.{ 18, 3, 4, 5 }, 0..) |slot, i| for (fused.fixed[i]) |tail| try rows.append(slot, tail);
                for (plan.public_terms) |term| if (term.active_in == .segment) {
                    const weight = M.fromCanonical(term.multiplicity);
                    try rows.appendLogicalFixed(2, try boundary.logicalCoordinates(term.circuit_id, term.node_id, if (term.role == .emit) weight else weight.neg(), term.value.toM31Array()));
                };
                try rows.finish();
                break :fixed rows;
            } else live: {
                const evaluation = lower.Evaluation{ .circuit_identity = graph.circuit.identity_digest, .values = graph.values };
                var fused = try @import("arithmetic_fusion_rows.zig").materializeColumns(a, &plan, reference, .{ .lanes = &.{ evaluation, evaluation } }, .segment_leaf);
                defer fused.deinit();
                var live_arithmetic = try empty(a, graph.inputs.len);
                errdefer live_arithmetic.deinit();
                inline for (.{ 3, 4, 5 }, .{ &fused.multiply, &fused.inverse, &fused.linear }) |i, cohort| {
                    const taken = try cohort.take();
                    live_arithmetic.releaseCohort(i);
                    live_arithmetic.main[i] = taken.main;
                    live_arithmetic.fixed[i] = taken.fixed;
                }
                var openings = try direct.ForAir(storage.Airs[18]).init(a, fused.opening.len);
                defer openings.deinit();
                for (fused.opening) |row| try openings.append(row);
                const opened = try openings.take();
                live_arithmetic.releaseCohort(18);
                live_arithmetic.main[18] = opened.main;
                live_arithmetic.fixed[18] = opened.fixed;
                var boundary_count: usize = 0;
                for (plan.public_terms) |term| if (term.active_in == .segment) {
                    boundary_count += 1;
                };
                var anchored = try direct.ForAir(storage.Airs[2]).init(a, boundary_count);
                defer anchored.deinit();
                for (plan.public_terms) |term| if (term.active_in == .segment) {
                    if (term.role == .request) return error.InvalidGlobalPublicGraphBoundary;
                    const weight = M.fromCanonical(term.multiplicity);
                    try anchored.append(try boundary.logicalCoordinates(term.circuit_id, term.node_id, if (term.role == .emit) weight else weight.neg(), term.value.toM31Array()));
                };
                const anchors = try anchored.take();
                live_arithmetic.releaseCohort(2);
                live_arithmetic.main[2] = anchors.main;
                live_arithmetic.fixed[2] = anchors.fixed;
                break :live live_arithmetic;
            };
            defer arithmetic.deinit();
            const counts = try a.alloc(u32, graph.circuit.nodes.len);
            defer a.free(counts);
            const uses = try lower.computeLaneUseCountsInto(lane, counts);
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const temp = arena.allocator();
            var recorder = Recorder.Recorder{ .a = temp, .universal_relations = true };
            const source = if (@hasDecl(Public.Owner, "sealedCells")) try owner.sealedCells() else try owner.policy.sealedCells();
            const native = try owner.policy.native(0);
            const UniversalChannel = @import("../../prover/block_v5_universal_channel_v1.zig");
            recorder.mixU32s(&.{ UniversalChannel.TAG, UniversalChannel.VERSION });
            recorder.mixPublicRoot(.{ .circuit = SEAL, .first_wire = 0 }, native.admitted.sealed.digest);
            _ = try U.UniversalRelations.draw(temp, &recorder);
            try recorder.check();
            if (recorder.relation_count != U.RELATION_COUNT or recorder.root_count != 0) return error.InvalidGlobalPublicChallenge;
            var draw_plan = try transcript.Plan.init(a, .{ .namespace = TRANSCRIPT, .attempt_capacity = attempt_capacity }, recorder.operations.items);
            defer draw_plan.deinit();
            // Fixed mode never invokes the live transcript witness compiler.
            var live: if (fixed_only) void else t.Prepared = if (fixed_only) {} else try draw_plan.prepare(a, recorder.operations.items);
            defer if (!fixed_only) live.deinit();
            if (!fixed_only) {
                if (!std.meta.eql(live.final_digest.?, expected_channel.digestBytes()) or live.next_draw != expected_channel.n_draws) return error.InvalidGlobalPublicChallenge;
            }
            var wires: std.ArrayList(Bus.Wire) = .empty;
            errdefer wires.deinit(a);
            for (draw_plan.fixed.root_reads) |read| {
                if (read.source.circuit != SEAL or read.source.first_wire != 0 or read.operation >= recorder.operations.items.len or recorder.operations.items[read.operation] != .routed_root) return error.InvalidGlobalPublicChallenge;
                for (read.uses, 0..) |weight, limb| if (weight != 0) try wires.append(a, .{ .circuit = SEAL, .wire = @intCast(limb), .uses = weight, .source = .{ .original = .{ .child = source.child, .kind = .frame_cell, .coordinate = source.first + @as(u32, @intCast(limb)) } } });
            }
            var scalars: std.ArrayList(scalar.Row) = .empty;
            defer scalars.deinit(temp);
            var packs: std.ArrayList(pack.Row) = .empty;
            defer packs.deinit(temp);
            for (graph.sources, graph.inputs, 0..) |input_source, value, node| switch (input_source) {
                .public => |coordinate| if (uses[node] != 0) {
                    try wires.append(a, .{ .circuit = GRAPH, .wire = @intCast(node), .uses = uses[node], .source = coordinate });
                },
                .challenge => |index| {
                    const draw = try findDraw(&draw_plan, index / 2);
                    const operation = recorder.operations.items[draw.operation];
                    if (operation != .secure or operation.secure.output == null or operation.secure.output.? != .universal or operation.secure.output.?.universal != index / 2 or draw.words != 8) return error.InvalidGlobalPublicChallenge;
                    const first: u32 = index * 4;
                    const nodes: [4]u32 = .{ first, first + 1, first + 2, first + 3 };
                    const words = value.toM31Array();
                    for (words, 0..) |word, part| {
                        if (!word.eql(operation.secure.values[4 * (index % 2) + part])) return error.InvalidGlobalPublicChallenge;
                        try scalars.append(temp, try scalar.routedRow(BRIDGE, nodes[part], uses[node], draw.source.circuit, draw.source.first_wire + 4 * (index % 2) + @as(u32, @intCast(part)), word));
                    }
                    if (uses[node] != 0) try packs.append(temp, try pack.weightedLogicalRow(.{ .source_circuit = BRIDGE, .source_nodes = nodes, .destination_circuit = GRAPH, .destination_wire = @intCast(node) }, value, uses[node]));
                },
            };
            var result = if (fixed_only) fixed: {
                var row_counts: [storage.Airs.len]usize = undefined;
                inline for (storage.Airs, 0..) |Air, i| {
                    const transcript_rows = if (comptime i == 0) draw_plan.fixed.g_rows else if (comptime i == 1) draw_plan.fixed.xor_rows else if (comptime i == 2 or i == 6 or i == 7 or i == 8 or i == 14 or i == 15) draw_plan.fixed.cohortRows(i) else &[_]Air.Row{};
                    const extra = if (comptime i == 12) scalars.items else if (comptime i == 11) packs.items else &[_]Air.Row{};
                    row_counts[i] = try std.math.add(usize, arithmetic.rows[i].len, try std.math.add(usize, transcript_rows.len, extra.len));
                }
                var rows = try FixedRows.init(a, row_counts);
                errdefer rows.deinit();
                inline for (storage.Airs, 0..) |Air, i| {
                    const transcript_rows = if (comptime i == 0) draw_plan.fixed.g_rows else if (comptime i == 1) draw_plan.fixed.xor_rows else if (comptime i == 2 or i == 6 or i == 7 or i == 8 or i == 14 or i == 15) draw_plan.fixed.cohortRows(i) else &[_]Air.Row{};
                    const extra = if (comptime i == 12) scalars.items else if (comptime i == 11) packs.items else &[_]Air.Row{};
                    // Exact original append order: transcript, arithmetic, bridge.
                    for (transcript_rows) |row| try rows.appendLogicalFixed(i, row);
                    for (arithmetic.rows[i]) |tail| try rows.append(i, tail);
                    for (extra) |row| try rows.appendLogicalFixed(i, row);
                }
                try rows.finish();
                break :fixed rows;
            } else live_result: {
                var live_result = try empty(a, graph.inputs.len);
                errdefer live_result.deinit();
                inline for (storage.Airs, 0..) |Air, i| {
                    const transcript_rows = if (comptime i == 0) live.g_rows else if (comptime i == 1) live.xor_rows else if (comptime i == 2 or i == 6 or i == 7 or i == 8 or i == 14 or i == 15) live.cohortRows(i) else &[_]Air.Row{};
                    const fixed_rows = if (comptime i == 0) draw_plan.fixed.g_rows else if (comptime i == 1) draw_plan.fixed.xor_rows else if (comptime i == 2 or i == 6 or i == 7 or i == 8 or i == 14 or i == 15) draw_plan.fixed.cohortRows(i) else &[_]Air.Row{};
                    const extra = if (comptime i == 12) scalars.items else if (comptime i == 11) packs.items else &[_]Air.Row{};
                    const count = try std.math.add(usize, arithmetic.fixed[i].len, try std.math.add(usize, transcript_rows.len, extra.len));
                    if (fixed_rows.len != transcript_rows.len) return error.InvalidGlobalPublicTranscriptRows;
                    var emitter = try direct.ForAir(Air).init(a, count);
                    defer emitter.deinit();
                    for (transcript_rows, fixed_rows) |row, fixed| {
                        for (row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], fixed[Air.PHYSICAL_MAIN_COLUMN_COUNT..]) |actual, expected| if (!actual.eql(expected)) return error.InvalidGlobalPublicTranscriptRows;
                        try emitter.append(row);
                    }
                    for (arithmetic.fixed[i], 0..) |fixed, logical| {
                        var row: Air.Row = undefined;
                        const committed = @import("framework_interaction.zig").committedRow(logical, arithmetic.main[i][0].log_size);
                        for (arithmetic.main[i], row[0..Air.PHYSICAL_MAIN_COLUMN_COUNT]) |column, *value| value.* = column.values[committed];
                        row[Air.PHYSICAL_MAIN_COLUMN_COUNT..].* = fixed;
                        try emitter.append(row);
                    }
                    for (extra) |row| try emitter.append(row);
                    const taken = try emitter.take();
                    live_result.releaseCohort(i);
                    live_result.main[i] = taken.main;
                    live_result.fixed[i] = taken.fixed;
                }
                break :live_result live_result;
            };
            errdefer result.deinit();
            var identity = core.channel.blake3.Channel{};
            identity.mixU32s(&.{ 0x42354752, Composition.VERSION, GRAPH, BRIDGE, SEAL, TRANSCRIPT, attempt_capacity });
            identity.mixRoot(graph.semantic_identity);
            identity.mixRoot(graph.circuit.identity_digest);
            identity.mixRoot(reference.authority_digest);
            identity.mixRoot(draw_plan.id);
            for (graph.sources) |coordinate| switch (coordinate) {
                .public => |public| {
                    identity.mixU32s(&.{@intFromEnum(std.meta.activeTag(public))});
                    switch (public) {
                        .original => |v| identity.mixU32s(&.{ v.child, @intFromEnum(v.kind), v.coordinate, v.part }),
                        .public_word => |v| identity.mixU32s(&.{ v.window, v.word }),
                        .public_byte => |v| identity.mixU32s(&.{ v.window, v.word, v.part }),
                        .public_digest => |v| identity.mixU32s(&.{ v.window, v.word, v.part }),
                        .outer_register_byte => |v| identity.mixU32s(&.{ @intFromBool(v.final), v.register, v.part }),
                        .term_byte => |v| identity.mixU32s(&.{ v.window, @intFromEnum(v.kind), v.limb, v.part }),
                    }
                },
                .challenge => |index| identity.mixU32s(&.{ 0xFFFFFFFF, index }),
            };
            return .{ .rows = result, .wires = try wires.toOwnedSlice(a), .identity = identity.digestBytes() };
        }
        fn findDraw(plan: *const transcript.Plan, relation: u32) !t.DrawOutput {
            var found: ?t.DrawOutput = null;
            for (plan.fixed.draw_outputs) |output| if (output.role == .universal and output.role.universal == relation) {
                if (found != null) return error.InvalidGlobalPublicChallenge;
                found = output;
            };
            return found orelse error.InvalidGlobalPublicChallenge;
        }
    };
}
const Default = ForModules(DefaultPublic, DefaultComposition, DefaultBus);
pub const Prepared = Default.Prepared;
pub const prepare = Default.prepare;
pub const FixedPrepared = Default.FixedPrepared;
pub const prepareFixed = Default.prepareFixed;
