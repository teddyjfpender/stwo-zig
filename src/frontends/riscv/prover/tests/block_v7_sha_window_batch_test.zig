//! Scoped two-window SHA proof: public original CPU/memory tuples close each
//! caller; one arithmetic inventory serves both. Not a full execution root.
const std = @import("std");
const f = @import("../../recursion/air/blake3_proof_fixture.zig");
const gate = @import("../../recursion/air/blake3_proof_gate_test_support.zig");
const Batch = @import("../block_v7_sha_window_batch_v1.zig");
const Caller = @import("../../air/guest_precompile/sha256_global_wire_caller_v1.zig");
const Provider = @import("../../air/guest_precompile/sha256_compression_rows.zig");
const Source = @import("../../air/guest_precompile/sha256_packed_source.zig");
const Boundary = @import("../../air/guest_precompile/sha256_memory_proof_boundary.zig");
const Entry = @import("../../runner/guest_precompile/sha256_compression_v1.zig").Entry;
const Sha = @import("../../air/guest_precompile/sha256_compression.zig");
const Roster = @import("../../recursion/air/universal_component_roster.zig");
const F = Roster.ForAirs(.{ Source, Provider.Schedule, Provider.Round, Provider.FeedForward, Caller, Caller, Boundary, Boundary }, &.{ "sources", "schedules", "rounds", "feed_forward", "window0", "window1", "public0", "public1" });
const Control = @import("../block_v7_sha_window_control_projection_v1.zig");
const Trace = @import("../block_v7_memory_trace_v1.zig");
const Component = @import("../block_v7_shared_word_projection_v1.zig").For(Control.Spec);
const ProjectionState = struct {
    rows: [2][]Caller.Row,
    boundaries: [2][]Boundary.Row,
    offsets: [2]f.M31,
    logs: [F.Airs.len]u32,
    forge_window_claims: bool,
    auth: Control.Owner,
    relations: ?f.universal.UniversalRelations = null,
    generated: [2]?Trace.Generated(4) = .{ null, null },
    claims: [2][4]f.QM31 = undefined,
    expected: [2][3]f.QM31 = undefined,
    components: [2]Component = undefined,
    pub fn deinit(self: *@This()) void {
        for (&self.generated) |*generated| if (generated.*) |*item| item.deinit();
    }
};
const kinds = @import("../../air/guest_precompile/sha256_component_profile.zig").lookup_kinds;
fn entry(seed: u8, pc: u32) Entry {
    const block: [64]u8 = @splat(seed);
    return .{ .instruction = @import("../../isa/sha256_compression_v1.zig").encode(3, 9), .call = .{ .execution_clock = 7, .pc = pc, .state_register = 3, .block_register = 9, .state_ptr = 4096, .block_ptr = 8192, .pointer_previous_clocks = .{ 1, 2 }, .memory_previous_clocks = @splat(3), .state = Sha.initial_state, .block = block, .output = Sha.compress(Sha.initial_state, block) } };
}
fn windows(entries: *const [2]Entry) [2]Batch.Window {
    return .{
        .{ .index = 0, .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 10 }, .entries = entries[0..1] },
        .{ .index = 2, .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 101, .cycle_count = 10 }, .entries = entries[1..2] },
    };
}
fn preprocessing(a: std.mem.Allocator, entries: [2]Entry) ![]f.Column {
    var columns: std.ArrayList(f.Column) = .empty;
    try @import("../../air/guest_precompile/sha256_preprocessed.zig").append(a, 2, false, &columns);
    for (0..2) |_| {
        const values = try a.alloc(f.M31, 16);
        @memset(values, f.M31.zero());
        values[0] = f.M31.one();
        try columns.append(a, .{ .log_size = 4, .values = values });
    }
    for (entries) |item| try f.project(Boundary, a, try Boundary.rows(a, item.call), 6, 0, &columns);
    for (kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
const Protocol = struct {
    admissions: []const Batch.Admission,
    state: *ProjectionState,
    pub const EXTRA_COMPONENT_COUNT = 2;
    pub fn config(_: @This()) !f.core.pcs.PcsConfig {
        return @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config();
    }
    pub fn mix(self: @This(), ch: *f.Channel) !void {
        _ = try Batch.validate(self.admissions, .{});
        ch.mixU32s(&.{ 0x42375342, 2, @intCast(self.admissions.len) });
        ch.mixRoot(Caller.SEMANTIC_DIGEST);
        var selection: [7]u32 = undefined;
        for (&selection, self.state.auth.selected) |*out, value| out.* = value;
        ch.mixU32s(&selection);
        (try self.config()).mixInto(ch);
        for (self.admissions) |item| {
            ch.mixU32s(&.{ item.index, item.calls, item.frame.cycle_count });
            ch.mixU64(item.frame.global_first_cycle);
        }
    }
    pub fn drawRelations(self: @This(), a: std.mem.Allocator, ch: *f.Channel) !f.universal.UniversalRelations {
        const vm = try f.universal.UniversalRelations.draw(a, ch);
        const relations = try @import("../../air/guest_precompile/sha256_relations.zig").draw(a, ch, vm);
        if (self.state.relations) |existing| {
            try std.testing.expectEqualDeep(existing, relations);
        } else {
            self.state.relations = relations;
            for (0..2) |i| {
                self.state.expected[i] = try expectedControl(a, relations, self.state.boundaries[i]);
                var source = try Trace.Matrix.init(a, 4, Control.Spec.MAIN_COUNT + Control.Spec.FIXED_COUNT, 1 << 20);
                defer source.deinit();
                for (self.state.rows[i], 0..) |row, logical| for (row[0 .. Control.Spec.MAIN_COUNT + Control.Spec.FIXED_COUNT], 0..) |value, column| source.set(column, logical, value);
                const spec = Control.Spec{ .owner = &self.state.auth, .relations = &self.state.relations.?, .wire_offset = f.QM31.fromBase(self.state.offsets[i]), .sums = @splat(f.QM31.zero()) };
                self.state.generated[i] = try Trace.interactions(4, a, source, spec, 1 << 20);
                self.state.claims[i] = self.state.generated[i].?.sums;
                if (self.state.forge_window_claims) {
                    self.state.claims[i][0] = self.state.expected[i][0].neg();
                    self.state.claims[i][1] = self.state.expected[i][1].neg();
                    self.state.claims[i][2] = self.state.expected[i][2].neg().sub(self.state.claims[i][3]);
                }
            }
        }
        return relations;
    }
    pub fn appendExtraInteraction(self: @This(), a: std.mem.Allocator, columns: *std.ArrayList(f.Column)) !void {
        const original = F.Manifest{ .log_sizes = self.state.logs };
        inline for (0..2) |i| {
            const placement = try original.placement(@enumFromInt(4 + i));
            self.state.components[i] = try Component.init(.{ .owner = &self.state.auth, .relations = &self.state.relations.?, .wire_offset = f.QM31.fromBase(self.state.offsets[i]), .sums = self.state.claims[i] }, 4, .{ placement.preprocessed_offset, placement.main_offset, @intCast(columns.items.len) });
            const generated = &self.state.generated[i].?;
            for (0..Control.Spec.INTERACTION_COUNT) |column| try columns.append(a, .{ .log_size = 4, .values = generated.matrix.columns[column].values });
        }
    }
    pub fn extraProverHandles(self: @This()) [2]f.prover.air.component_prover.ComponentProver {
        return .{ self.state.components[0].asProverComponent(), self.state.components[1].asProverComponent() };
    }
    pub fn extraVerifierHandles(self: @This()) [2]f.core.air.components.Component {
        return .{ self.state.components[0].asVerifierComponent(), self.state.components[1].asVerifierComponent() };
    }
    pub fn mixExtraClaims(self: @This(), ch: *f.Channel) !void {
        ch.mixU32s(&.{ 0x42375342, 3, 2 });
        for (self.state.claims) |physical| ch.mixFelts(&physical);
    }
    pub fn mixClaims(self: @This(), ch: *f.Channel, claims: []const f.QM31) !void {
        for (self.state.claims, self.state.expected) |physical, expected| {
            const projected = Control.totals(physical);
            for (projected, expected) |actual, wanted| if (!actual.add(wanted).isZero()) return error.UnclosedShaWindow;
        }
        ch.mixU32s(&.{ 0x42375342, 2 });
        ch.mixFelts(claims);
    }
    pub fn admitRoot(_: @This(), _: f.Hasher.Hash) !void {}
};
// Exact public tuple projection, evaluated from independently selected fixed
// boundary rows. No SHA computation, RAM gap or producer success receipt.
fn expectedControl(a: std.mem.Allocator, relations: f.universal.UniversalRelations, rows: []const Boundary.Row) ![3]f.QM31 {
    var definition = try Boundary.build(a);
    defer definition.deinit();
    const plan = try f.binding.Binding(Boundary).authenticate(&definition);
    const Visitor = struct {
        relations: *const f.universal.UniversalRelations,
        sums: [3]f.QM31 = @splat(f.QM31.zero()),
        pub fn accepts(_: *@This(), _: @import("../../air/lang/types.zig").RelationSchemaId) bool {
            return true;
        }
        pub fn visit(self: *@This(), _: u8, domain: @import("../../air/lang/relation.zig").Domain, numerator: f.QM31, values: []const f.QM31) !void {
            const index: usize = switch (domain) {
                .program_access => 0,
                .registers_state => 1,
                .memory_access => if (values[0].isZero()) 2 else return,
                else => return error.InvalidPublicControlBoundary,
            };
            self.sums[index] = self.sums[index].add(try numerator.div(try self.relations.get(domain).combineSecure(values)));
        }
    };
    var visitor = Visitor{ .relations = &relations };
    for (rows) |row| {
        var secure: [Boundary.LOGICAL_INPUT_COUNT]f.QM31 = undefined;
        for (&secure, row) |*out, value| out.* = f.QM31.fromBase(value);
        try plan.visitPreparedEntriesFor(f.QM31, secure, &visitor);
    }
    return visitor.sums;
}
const Attack = enum { none, wrong_parameter, swap_windows, swap_windows_forged_claims };
fn proofCase(attack: Attack) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const entries = [2]Entry{ entry(0x37, 1024), entry(0x91, 2048) };
    const trusted_windows = windows(&entries);
    var admissions: [2]Batch.Admission = undefined;
    var offsets: [2]f.M31 = undefined;
    for (trusted_windows, &admissions, &offsets) |window_policy, *admitted, *offset| {
        admitted.* = .{ .index = window_policy.index, .frame = window_policy.frame, .calls = @intCast(window_policy.entries.len) };
        offset.* = try Caller.offsetForFrame(window_policy.frame);
    }
    var witness_entries = entries;
    if (attack == .swap_windows or attack == .swap_windows_forged_claims) std.mem.swap(Entry, &witness_entries[0], &witness_entries[1]);
    const window = windows(&witness_entries);
    var batch = try Batch.prepare(a, &window, .{});
    defer batch.deinit();
    try std.testing.expectEqual(@as(u32, 0), batch.offsets[0].toU32());
    try std.testing.expectEqual(@as(u32, 100), batch.offsets[1].toU32());
    const boundaries = [2][]Boundary.Row{ try Boundary.rows(a, entries[0].call), try Boundary.rows(a, entries[1].call) };
    const rows = batch.compression.tuple() ++ .{ batch.callers[0], batch.callers[1], boundaries[0], boundaries[1] };
    const logs = batch.compression.geometry.logs ++ [_]u32{ 4, 4, 6, 6 };
    const pp = try preprocessing(a, entries);
    var altered = entries;
    altered[1].call.output[0] ^= 1;
    const false_pp = try preprocessing(a, altered);
    const empty: [0]f.M31 = .{};
    const parameters = .{ empty, empty, empty, empty, [1]f.M31{offsets[0]}, [1]f.M31{if (attack == .wrong_parameter) f.M31.zero() else offsets[1]}, empty, empty };
    var state = ProjectionState{ .rows = .{ batch.callers[0], batch.callers[1] }, .boundaries = boundaries, .auth = try Control.Owner.init(a), .offsets = offsets, .logs = logs, .forge_window_claims = attack == .swap_windows_forged_claims };
    defer state.deinit();
    try gate.ForBackendWithTables(f.Cpu, kinds).runForParametersProtocol(F, a, rows, logs, pp, false_pp, parameters, Protocol{ .admissions = &admissions, .state = &state }, void);
}
test "SHA batch two windows same local clock share one original arithmetic STARK" {
    try proofCase(.none);
}
test "SHA batch recommitted caller under another window offset fails original STARK" {
    try std.testing.expectError(error.ConstraintsNotSatisfied, proofCase(.wrong_parameter));
}
test "SHA batch rejects overlapping ownership and modular clocks" {
    const entries = [2]Entry{ entry(0x37, 1024), entry(0x91, 2048) };
    var window = windows(&entries);
    window[1].frame.global_first_cycle = 5;
    try std.testing.expectError(error.InvalidShaBatchWindow, Batch.prepare(std.testing.allocator, &window, .{}));
    window = windows(&entries);
    window[1].index = 0;
    try std.testing.expectError(error.InvalidShaBatchWindow, Batch.prepare(std.testing.allocator, &window, .{}));
    window = windows(&entries);
    window[1].frame.global_first_cycle = 0x7fffffff - 1;
    try std.testing.expectError(error.GlobalShaWireClockExceedsField, Batch.prepare(std.testing.allocator, &window, .{}));
}

test "SHA batch full window substitution with rebuilt arithmetic IDs rejects" {
    try std.testing.expectError(error.UnclosedShaWindow, proofCase(.swap_windows));
}
test "SHA batch swapped windows with compensating physical claims fail original STARK" {
    try std.testing.expectError(error.ConstraintsNotSatisfied, proofCase(.swap_windows_forged_claims));
}
