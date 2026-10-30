//! Cold compiler for the original execution-parent AIR. No MAIN columns, child
//! witness values, CPU commitments, or transcript challenges are accepted here.
//! The returned program is metadata, not a proof or an execution receipt.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Protocol = @import("../../frontends/riscv/recursion/blake3_execution_parent_protocol.zig");
const Rows = @import("../../frontends/riscv/recursion/air/blake3_parent_row_storage.zig");
const Roster = @import("../../frontends/riscv/recursion/air/blake3_native_parent_roster.zig").Roster;
const Binding = @import("../../frontends/riscv/recursion/air/universal_relation_binding.zig");
const Direct = @import("../../frontends/riscv/recursion/air/direct_constraint_program.zig");
const Export = @import("../../frontends/riscv/recursion/air/framework_polynomial_export_v1.zig");
const Shape = @import("../../frontends/riscv/recursion/air/universal_typed_verifier_component.zig");
const Universal = @import("../../frontends/riscv/recursion/air/universal_challenges.zig");
const Provider = @import("../../frontends/riscv/recursion/air/universal_provider_relations.zig");
const Table = @import("../../frontends/riscv/air/lookups/tables/component.zig");
const TableExport = @import("../../frontends/riscv/air/lookups/tables/framework_export.zig");
const Schema = @import("../../frontends/riscv/air/lookups/tables/schema.zig");
const Q = core.fields.qm31.QM31;
const NativeProtocol = @import("../../frontends/riscv/recursion/block_v7_native_parent_protocol_v1.zig");
const MixedProtocol = @import("../../frontends/riscv/recursion/block_v7_mixed_protocol_v1.zig");
const SharedMixedProtocol = @import("../../frontends/riscv/recursion/block_v7_shared_epoch_mixed_protocol_v1.zig");
pub const PrefixPlan = @import("resident_parent_prefix_plan_v1.zig");
pub const AIR_COUNT = Rows.Airs.len;
pub const COMPONENT_COUNT = AIR_COUNT + 2;
pub const KINDS = [_]Schema.Kind{ .bitwise, .range_check_8_8 };
pub const PolynomialProgram = engine.air.component_prover.OwnedFrameworkPolynomialProgramV1;
pub const Limits = struct { max_trace_log: u32 = 25, max_resident_bytes: usize = 96 << 30 };
pub const Mask = struct {
    /// Offsets are relative to the ORIGINAL common mask-domain step, not a
    /// component's own trace step. Ordered pairs must not be sorted.
    offsets: [2]i32 = .{ 0, 0 },
    count: u8 = 1,
};
pub const Tree = struct { column_logs: []u32, masks: []Mask, lifted_log: u32 };
pub const Cohort = struct {
    trace_log: u32,
    evaluation_log: u32,
    columns: [3]u32,
    first_column: [3]u32,
    first_constraint: u32,
    constraints: u32,
    claim_index: u32,
    program_identity: [32]u8,
};
pub const FriLayer = struct { evaluation_log: u32, fold_step: u32, cumulative_fold: u32, leaf_log: u32 };
pub const Data = struct {
    /// Base geometry only when native_admission is present.
    admission: Protocol.Admission,
    native_admission: ?NativeProtocol.Admission = null,
    mixed_admission: ?MixedProtocol.Admission = null,
    shared_mixed_admission: ?SharedMixedProtocol.Admission = null,
    transcript_prefix: PrefixPlan.Prefix,
    cohorts: [COMPONENT_COUNT]Cohort,
    programs: [COMPONENT_COUNT]PolynomialProgram,
    trees: [4]Tree,
    composition_log: u32,
    composition_split: u32,
    mask_log: u32,
    fri_log: u32,
    fri_layers: []FriLayer,
    total_constraints: u32,
    /// Conservative resident polynomial+Merkle storage, excluding controller
    /// scratch, witness wires and terminal buffers. Never a whole-proof cap.
    polynomial_bytes: usize,
    identity: [32]u8,
    pub fn proofKeyID(self: *const Data) [32]u8 {
        if (self.native_admission) |native| return native.expected_id;
        if (self.mixed_admission) |mixed| return mixed.expected_id;
        if (self.shared_mixed_admission) |mixed| return mixed.expected_id;
        return self.admission.expected_id;
    }
    pub fn validate(self: *const Data) !void {
        try self.admission.validate();
        var count: u32 = 0;
        inline for (.{ "native_admission", "mixed_admission", "shared_mixed_admission" }) |name| if (@field(self, name)) |original| {
            count += 1;
            try original.validate();
            if (!std.meta.eql(self.admission.key.config, original.key.config) or
                !std.meta.eql(self.admission.key.context, original.key.context) or
                !std.meta.eql(self.admission.key.log_sizes, original.key.log_sizes) or
                !std.meta.eql(self.admission.key.preprocessed_root, original.key.preprocessed_root)) return error.InvalidResidentOriginalGeometry;
        };
        if (count > 1) return error.AmbiguousResidentOriginalProtocol;
    }
};
const Storage = struct { backing: std.mem.Allocator, arena: std.heap.ArenaAllocator, data: Data };
pub const Owned = opaque {
    pub fn derive(backing: std.mem.Allocator, admission: Protocol.Admission, limits: Limits) !*Owned {
        try admission.validate();
        if (limits.max_trace_log < 1 or limits.max_trace_log > 28 or limits.max_resident_bytes == 0) return error.InvalidResidentParentLimit;
        for (admission.key.log_sizes) |log| if (log > limits.max_trace_log) return error.ResidentParentResourceLimit;
        const self = try backing.create(Storage);
        errdefer backing.destroy(self);
        var arena = std.heap.ArenaAllocator.init(backing);
        errdefer arena.deinit();
        const a = arena.allocator();
        var data: Data = undefined;
        data.admission = admission;
        data.native_admission = null;
        data.mixed_admission = null;
        data.shared_mixed_admission = null;
        data.transcript_prefix = try PrefixPlan.derive(a, &admission, COMPONENT_COUNT);
        data.composition_split = @import("../../frontends/riscv/recursion/air/roster_composition_geometry.zig").ForAirs(Rows.Airs).quotient_log_blowup;
        data.composition_log = 0;
        data.mask_log = 0;
        data.total_constraints = 0;
        var starts: [3]u32 = @splat(0);
        inline for (Rows.Airs, 0..) |Air, i| {
            // Build and authenticate the original compiler arena. Exported
            // relation signs, weights, pairings and direct roots are unchanged.
            var definition = if (@hasDecl(Air, "Location")) try Air.build(a, .generated) else try Air.build(a);
            defer definition.deinit();
            const relations = try Binding.Binding(Air).authenticate(&definition);
            const direct = try Direct.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
            data.programs[i] = try Export.exportLocalPrepared(Air, a, &direct, &relations);
            const Layout = Shape.Layout(Air, Binding.Binding(Air));
            const log = admission.key.log_sizes[i];
            const counts: [3]u32 = .{ Air.PREPROCESSED_COLUMN_COUNT, Air.PHYSICAL_MAIN_COLUMN_COUNT, Air.INTERACTION_COLUMN_COUNT };
            data.cohorts[i] = .{ .trace_log = log, .evaluation_log = log + Layout.QUOTIENT_LOG_BLOWUP, .columns = counts, .first_column = starts, .first_constraint = data.total_constraints, .constraints = Layout.CONSTRAINT_COUNT, .claim_index = i, .program_identity = data.programs[i].identity };
            try advance(&data, &starts, i);
        }
        const dummy = Universal.UniversalRelations.dummy();
        const providers = try Provider.SharedProviderRelations.init(&dummy);
        for (KINDS, AIR_COUNT..) |kind, i| {
            const count: u32 = @intCast(1 + Schema.arity(kind));
            var tuple: [Schema.MAX_ARITY]usize = undefined;
            for (tuple[0..Schema.arity(kind)], 0..) |*slot, j| slot.* = j + 1;
            const table = try Table.LookupTableComponent.initProver(kind, 0, tuple[0..Schema.arity(kind)], 0, 0, &providers.native, Q.zero());
            data.programs[i] = try TableExport.exportProgram(a, &table, &.{ count, 1, 4 });
            data.cohorts[i] = .{ .trace_log = Schema.logSize(kind), .evaluation_log = table.maxConstraintLogDegreeBound(), .columns = .{ count, 1, 4 }, .first_column = starts, .first_constraint = data.total_constraints, .constraints = Table.N_CONSTRAINTS, .claim_index = @intCast(i), .program_identity = data.programs[i].identity };
            try advance(&data, &starts, i);
        }
        // Reuse the original complete roster's normalized quotient degree.
        // Each intrinsic component quotient is extended before global lifting;
        // the physical split and OODS mask domain must match that normalization.
        if (data.composition_log <= data.composition_split) return error.InvalidResidentParentGeometry;
        data.mask_log = @max(data.mask_log, data.composition_log - data.composition_split);
        const blowup = admission.key.config.fri_config.log_blowup_factor;
        for (0..3) |tree| {
            data.trees[tree] = .{ .column_logs = try a.alloc(u32, starts[tree]), .masks = try a.alloc(Mask, starts[tree]), .lifted_log = 0 };
            for (data.cohorts) |cohort| {
                const begin = cohort.first_column[tree];
                @memset(data.trees[tree].column_logs[begin..][0..cohort.columns[tree]], cohort.trace_log);
                data.trees[tree].lifted_log = @max(data.trees[tree].lifted_log, cohort.trace_log + blowup);
            }
        }
        // Derive ordered masks from the original verifier methods, including
        // previous,current typed tails versus current,previous table tails.
        inline for (Rows.Airs, 0..) |Air, i| {
            var masks = try Roster.Component(Air).staticMaskPoints(admission.key.log_sizes[i], a, core.circle.CirclePointQM31.identity(), data.mask_log);
            defer masks.deinitDeep(a);
            try copyMasks(&data, i, masks);
        }
        for (KINDS, AIR_COUNT..) |kind, i| {
            var masks = try Table.LookupTableComponent.staticMaskPoints(kind, a, core.circle.CirclePointQM31.identity(), data.mask_log);
            defer masks.deinitDeep(a);
            try copyMasks(&data, i, masks);
        }
        const composition_columns: usize = @as(usize, 4) << @intCast(data.composition_split);
        data.trees[3] = .{ .column_logs = try a.alloc(u32, composition_columns), .masks = try a.alloc(Mask, composition_columns), .lifted_log = data.composition_log - data.composition_split + blowup };
        @memset(data.trees[3].column_logs, data.composition_log - data.composition_split);
        @memset(data.trees[3].masks, .{});
        data.fri_log = 0;
        data.polynomial_bytes = 0;
        for (&data.trees) |*tree| {
            if (admission.key.config.lifting_log_size) |lift| tree.lifted_log = @max(tree.lifted_log, lift);
            if (tree.lifted_log > 30) return error.InvalidResidentParentGeometry;
            data.fri_log = @max(data.fri_log, tree.lifted_log);
            var words: usize = 0;
            for (tree.column_logs) |log| words = try std.math.add(usize, words, try std.math.add(usize, pow(log), pow(log + blowup)));
            const hashes = try std.math.sub(usize, try std.math.mul(usize, 2, pow(tree.lifted_log)), 1);
            data.polynomial_bytes = try std.math.add(usize, data.polynomial_bytes, try std.math.add(usize, try std.math.mul(usize, words, 4), try std.math.mul(usize, hashes, 32)));
        }
        if (data.polynomial_bytes > limits.max_resident_bytes) return error.ResidentParentResourceLimit;
        const fri_config = admission.key.config.fri_config;
        const final_log = fri_config.log_last_layer_degree_bound + blowup;
        if (final_log >= data.fri_log) return error.InvalidResidentParentGeometry;
        const fri = try core.fri.geometry.FriGeometry.initRuntime(data.fri_log, .{ .round_count = try std.math.divCeil(u32, data.fri_log - final_log, fri_config.fold_step), .fold_step = fri_config.fold_step, .final_log = final_log, .packed_log = if (fri_config.fold_step > 1) core.fri.LOG_PACKED_LEAF_SIZE else 0 });
        data.fri_layers = try a.alloc(FriLayer, fri.roundCount());
        for (data.fri_layers, 0..) |*layer, i| {
            const evaluation_log = try fri.evaluationLog(i);
            const fold_step = try fri.roundFold(i);
            const packing_log: u32 = if ((if (i == 0) fri_config.fold_step else fold_step) > 1 and evaluation_log >= core.fri.LOG_PACKED_LEAF_SIZE) core.fri.LOG_PACKED_LEAF_SIZE else 0;
            layer.* = .{ .evaluation_log = evaluation_log, .fold_step = fold_step, .cumulative_fold = try fri.cumulativeFold(i), .leaf_log = evaluation_log - packing_log };
        }
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo/riscv-cuda/resident-execution-parent-program/v1\x00");
        hash.update(&admission.expected_id);
        for (data.cohorts) |cohort| hash.update(&cohort.program_identity);
        hash.update(@embedFile("resident_parent_program_v1.zig"));
        data.identity = hash.finalResult();
        self.* = .{ .backing = backing, .arena = arena, .data = data };
        return @ptrCast(self);
    }
    /// Finite original native public-provider protocol; no base admission is
    /// used as proof authority. The complete public frame and wire schedule
    /// are cloned so producer aliases cannot mutate an admitted GPU request.
    pub fn deriveNative(backing: std.mem.Allocator, admission: NativeProtocol.Admission, limits: Limits) !*Owned {
        return deriveOriginal("native_admission", backing, admission, limits);
    }
    pub fn deriveMixed(backing: std.mem.Allocator, admission: MixedProtocol.Admission, limits: Limits) !*Owned {
        return deriveOriginal("mixed_admission", backing, admission, limits);
    }
    pub fn deriveSharedMixed(backing: std.mem.Allocator, admission: SharedMixedProtocol.Admission, limits: Limits) !*Owned {
        return deriveOriginal("shared_mixed_admission", backing, admission, limits);
    }
    fn deriveOriginal(comptime field: []const u8, backing: std.mem.Allocator, admission: anytype, limits: Limits) !*Owned {
        try admission.validate();
        const key = Protocol.Key{ .profile = admission.key.profile, .config = admission.key.config, .context = admission.key.context, .log_sizes = admission.key.log_sizes, .preprocessed_root = admission.key.preprocessed_root };
        const owned = try derive(backing, try Protocol.Admission.init(key, try key.identity()), limits);
        errdefer owned.deinit();
        const storage: *Storage = @ptrCast(@alignCast(owned));
        const a = storage.arena.allocator();
        var cloned = admission;
        cloned.wires = try a.dupe(@TypeOf(admission.wires[0]), admission.wires);
        cloned.roster = try a.dupe(@TypeOf(admission.roster[0]), admission.roster);
        const children = try a.alloc(@TypeOf(admission.values.children[0]), admission.values.children.len);
        for (children, admission.values.children) |*out, child| out.* = try child.clone(a);
        cloned.values.children = children;
        try cloned.validate();
        @field(storage.data, field) = cloned;
        storage.data.transcript_prefix = try PrefixPlan.derive(a, &cloned, COMPONENT_COUNT);
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo/resident-parent/original-protocol/v1\x00");
        hash.update(field);
        hash.update(&storage.data.identity);
        hash.update(&cloned.expected_id);
        hash.update(&try cloned.publicInputIdentity());
        storage.data.identity = hash.finalResult();
        try storage.data.validate();
        return owned;
    }
    pub fn view(self: *const Owned) *const Data {
        const p: *const Storage = @ptrCast(@alignCast(self));
        return &p.data;
    }
    pub fn deinit(self: *Owned) void {
        const p: *Storage = @ptrCast(@alignCast(self));
        const a = p.backing;
        p.arena.deinit();
        a.destroy(p);
    }
};
fn advance(data: *Data, starts: *[3]u32, i: usize) !void {
    const cohort = data.cohorts[i];
    for (starts, cohort.columns) |*offset, count| offset.* = try std.math.add(u32, offset.*, count);
    data.total_constraints = try std.math.add(u32, data.total_constraints, cohort.constraints);
    data.composition_log = @max(data.composition_log, cohort.trace_log + data.composition_split);
    data.mask_log = @max(data.mask_log, cohort.trace_log);
}
fn copyMasks(data: *Data, i: usize, masks: core.air.components.MaskPoints) !void {
    const current = core.circle.CirclePointQM31.identity();
    const previous = @import("../../frontends/riscv/air/logup_equations.zig").prevRowPoint(data.mask_log, current);
    if (masks.items.len != 3) return error.InvalidResidentParentMasks;
    const cohort = data.cohorts[i];
    for (masks.items, 0..) |columns, tree| {
        if (columns.len != cohort.columns[tree]) return error.InvalidResidentParentMasks;
        for (columns, 0..) |points, column| {
            if (points.len == 0 or points.len > 2) return error.InvalidResidentParentMasks;
            var result = Mask{ .count = @intCast(points.len) };
            for (points, 0..) |point, j| result.offsets[j] = if (point.eql(current)) 0 else if (point.eql(previous)) -1 else return error.InvalidResidentParentMasks;
            data.trees[tree].masks[cohort.first_column[tree] + column] = result;
        }
    }
}
fn pow(log: u32) usize {
    return @as(usize, 1) << @intCast(log);
}

pub fn fixtureAdmission() !Protocol.Admission {
    const key = Protocol.Key{ .context = .{ .child_key_id = @splat(1), .child_config = Protocol.PCS_CONFIG, .graph_ids = @splat(@splat(2)), .transcript_plan_id = @splat(3) }, .log_sizes = @splat(2), .preprocessed_root = @splat(4) };
    return Protocol.Admission.init(key, try key.identity());
}
test "resident parent derives original complete roster and ordered masks without MAIN" {
    const owned = try Owned.derive(std.testing.allocator, try fixtureAdmission(), .{});
    defer owned.deinit();
    const p = owned.view();
    try std.testing.expectEqual(@as(usize, 25), p.programs.len);
    var constraints: u32 = 0;
    for (p.cohorts, 0..) |cohort, i| {
        try std.testing.expectEqual(i, cohort.claim_index);
        try std.testing.expectEqual(constraints, cohort.first_constraint);
        constraints += cohort.constraints;
        try p.programs[i].validate(&.{ cohort.columns[0], cohort.columns[1], cohort.columns[2] });
        const last = cohort.first_column[2] + cohort.columns[2] - 1;
        const mask = p.trees[2].masks[last];
        try std.testing.expectEqual(@as(u8, 2), mask.count);
        try std.testing.expectEqualSlices(i32, if (i < AIR_COUNT) &.{ -1, 0 } else &.{ 0, -1 }, &mask.offsets);
    }
    try std.testing.expectEqual(constraints, p.total_constraints);
    try std.testing.expectError(error.ResidentParentResourceLimit, Owned.derive(std.testing.allocator, try fixtureAdmission(), .{ .max_resident_bytes = 1 }));
    var bad = try fixtureAdmission();
    bad.key.log_sizes[0] += 1;
    try std.testing.expectError(error.UntrustedBlake3ParentKey, Owned.derive(std.testing.allocator, bad, .{}));
}

test "resident native protocol preserves original public framing and owns producer aliases" {
    const a = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    const NativePublic = @import("../../frontends/riscv/recursion/block_v7_native_public_v1.zig");
    const words = try temp.alloc(u32, 24);
    for (words, 0..) |*w, i| w.* = @intCast(11 + i);
    const fields = try temp.alloc(Q, 1);
    fields[0] = Q.fromU32Unchecked(1, 2, 3, 4);
    const public = try temp.alloc(Q, 1);
    public[0] = Q.fromU32Unchecked(5, 6, 7, 8);
    var values = NativePublic.Values{ .allocator = temp, .template = @splat(17), .statement = .{ .allocator = temp, .words = words, .felts = fields, .first = &.{}, .claims = &.{}, .sealed_offset = 16, .roots_offset = .{ 0, 8, 0 } }, .public = public, .roots_count = 2 };
    const wires = try temp.alloc(NativePublic.Wire, 1);
    wires[0] = .{ .circuit = 1500, .wire = 0, .uses = 1, .source = .public_input, .coordinate = 0 };
    const roster = [_]NativeProtocol.Bus.Expected{.{ .profile = values.template, .epoch = try values.statement.digest(16), .roots = .{ try values.statement.digest(0), try values.statement.digest(8), @splat(0) }, .root_count = 2 }};
    const base = try fixtureAdmission();
    const key = try NativeProtocol.Key.fromGeometry(base.key, wires, &roster);
    const admission = try NativeProtocol.Admission.init(key, try key.identity(), wires, .{ .children = &.{values} }, &roster);
    const owned = try Owned.deriveNative(a, admission, .{});
    defer owned.deinit();
    const p = owned.view();
    try std.testing.expect(!std.meta.eql(p.proofKeyID(), p.admission.expected_id));
    try std.testing.expectEqualDeep(admission.expected_id, p.proofKeyID());
    var expected = core.channel.blake3.Channel{};
    try admission.mix(&expected);
    var actual = core.channel.blake3.Channel{};
    for (p.transcript_prefix.frames) |frame| {
        const payload = p.transcript_prefix.words[frame.first..][0..frame.count];
        switch (frame.kind) {
            .words => actual.mixU32s(payload),
            .root => {
                var root: [32]u8 = undefined;
                for (payload, 0..) |w, i| std.mem.writeInt(u32, root[i * 4 ..][0..4], w, .little);
                actual.mixRoot(root);
            },
            .felts => {
                const q = try temp.alloc(Q, payload.len / 4);
                for (q, 0..) |*v, i| v.* = Q.fromU32Unchecked(payload[i * 4], payload[i * 4 + 1], payload[i * 4 + 2], payload[i * 4 + 3]);
                actual.mixFelts(q);
            },
        }
    }
    try std.testing.expectEqualDeep(expected, actual);
    const claims = [_]Q{Q.one()} ** COMPONENT_COUNT;
    try admission.mixClaims(&expected, &claims);
    actual.mixU32s(p.transcript_prefix.words[p.transcript_prefix.claims_start..][0..3]);
    actual.mixFelts(&claims);
    try std.testing.expectEqualDeep(expected, actual);
    // Old producer slices are no longer aliases into admitted program state.
    words[0] ^= 1;
    fields[0] = Q.zero();
    public[0] = Q.zero();
    wires[0].uses = 2;
    try p.validate();
    try std.testing.expectEqual(@as(u32, 1), p.native_admission.?.wires[0].uses);
    try std.testing.expectEqual(@as(u32, 11), p.native_admission.?.values.children[0].statement.words[0]);
}
