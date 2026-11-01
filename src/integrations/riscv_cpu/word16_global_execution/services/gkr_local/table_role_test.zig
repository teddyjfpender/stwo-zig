//! Real ROM/range/public-register fragments, not standalone execution closure.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Ch = core.channel.raw_mod_m31.Om31Channel;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = struct {
    pub fn mixRoot(c: *Ch, root: H.Hash) void {
        core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel.mixRoot(&c.inner, root);
    }
};
const Prover = engine.engine.ForField(O).ProverEngine(@import("stwo_cpu_backend").CpuBackend, H, MC, Ch);
const GV = engine.lookups.gkr_verifier.ForField(O);
const GP = engine.lookups.gkr_prover.ForField(O);
const Table = @import("table_role.zig");
const Role = @import("role.zig");
const Frame = @import("frame.zig");
const Inputs = @import("inputs.zig");
const a = std.testing.allocator;
fn public() Table.Boundary {
    var p = A.word16_cpu.public.Public{ .steps = 17, .initial_pc = 4, .final_pc = 8, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) };
    for (1..32) |i| {
        p.initial_registers[i] = i * 0x0afffe0ffaff;
        p.final_registers[i] = p.initial_registers[i] + 0x010203040506;
        p.register_clocks[i] = @intCast(2 * i);
    }
    return .{ .value = p, .cpu_log = 5 };
}
fn frame(kind: Table.Kind) Frame.Instance {
    const role: @import("../../../word16_execution/geometry.zig").Role = switch (kind) {
        .rom => .rom,
        .boundary => .boundary,
        .range8 => .range8,
        .range16 => .range16,
        .and_table => .and_table,
        .shift_table => .shift_table,
        .selection => .selection,
    };
    return .{ .origin = .{ .core = role }, .row_log = switch (kind) {
        .rom, .boundary => 5,
        .range8 => 8,
        else => 16,
    }, .terms = @import("roster.zig").terms(role), .fixed_offset = 0, .main_offset = 0 };
}
fn count(logical: usize) M {
    return M.fromCanonical(@intCast(1 + logical % 7));
}
const Provider = struct {
    kind: Table.Kind,
    fixed: []const M,
    pub fn emit(self: @This(), instance: Frame.Instance, logical: usize, sink: *Inputs.RowSink) !void {
        const rows = try instance.rows();
        const p = A.witness.physical(logical, instance.row_log);
        const component = Table.Component{ .kind = self.kind, .data = undefined, .inter_offset = 0, .boundary = if (self.kind == .boundary) public() else null };
        const shape = component.mainShape();
        var fixed: [34]O = undefined;
        var main: [16]O = undefined;
        for (fixed[0..shape.fixed], 0..) |*v, c| v.* = O.fromBase(self.fixed[c * rows + p]);
        for (main[0..shape.main]) |*v| v.* = O.fromBase(count(logical));
        component.emitLocalFor(O, fixed[0..shape.fixed], main[0..shape.main], sink);
    }
};
fn config() !core.pcs.ForField(O).PcsConfig {
    return .{ .pow_bits = 0, .fri_config = try core.fri.ForField(O).FriConfig.init(0, 1, 12) };
}
const Bundle = struct { stark: Prover.ExtendedProof, gkr: GP.ProveBatchResult };
fn produce(kind: Table.Kind, stale_count: bool) !Bundle {
    const instance = frame(kind);
    const rows = try instance.rows();
    const template = Table.Component{ .kind = kind, .data = undefined, .inter_offset = 0, .boundary = if (kind == .boundary) public() else null };
    const shape = template.mainShape();
    const fixed = try a.alloc(M, shape.fixed * rows);
    defer a.free(fixed);
    @memset(fixed, M.zero());
    for (0..rows) |logical| {
        const p = A.witness.physical(logical, instance.row_log);
        switch (kind) {
            .rom => {
                fixed[p] = M.one();
                fixed[rows + p] = M.fromCanonical(@intCast(4 * logical));
            },
            .range8 => {
                fixed[p] = M.fromCanonical(@intCast(logical));
            },
            .boundary => {
                fixed[logical * rows + p] = M.one();
            },
            else => return error.UnsupportedTestFixture,
        }
    }
    const main = try a.alloc(M, shape.main * rows);
    defer a.free(main);
    for (0..rows) |logical| for (0..shape.main) |c| {
        main[c * rows + A.witness.physical(logical, instance.row_log)] = count(logical);
    };
    if (stale_count) main[A.witness.physical(7, instance.row_log)] = main[A.witness.physical(7, instance.row_log)].add(M.one());
    const cfg = try config();
    var ch = Ch.init();
    cfg.mixInto(&ch);
    var scheme = try Prover.init(a, cfg);
    var owns = true;
    errdefer if (owns) scheme.deinit(a);
    var fixed_columns: [34]engine.pcs.ColumnEvaluation = undefined;
    for (fixed_columns[0..shape.fixed], 0..) |*column, c| column.* = .{ .log_size = instance.row_log, .values = fixed[c * rows ..][0..rows] };
    try scheme.commit(a, fixed_columns[0..shape.fixed], &ch);
    var main_columns: [16]engine.pcs.ColumnEvaluation = undefined;
    for (main_columns[0..shape.main], 0..) |*column, c| column.* = .{ .log_size = instance.row_log, .values = main[c * rows ..][0..rows] };
    try scheme.commit(a, main_columns[0..shape.main], &ch);
    const challenges = @import("challenges.zig").For(O).draw(&ch);
    var inputs = try Inputs.Inputs.init(a, &.{instance}, &challenges, Provider{ .kind = kind, .fixed = fixed });
    defer inputs.deinit();
    var gkr = try GP.proveBatch(a, &ch, inputs.layers);
    errdefer gkr.deinit(a);
    const eta = ch.drawSecureFelt();
    const pending = @import("child.zig").Pending{ .artifact = gkr.artifact, .challenges = challenges, .eta = eta, .digest = @splat(0) };
    var witness = try @import("witness.zig").Witness.init(a, &.{instance}, &inputs, &gkr.artifact, eta);
    defer witness.deinit();
    var inter: [16]engine.pcs.ColumnEvaluation = undefined;
    for (&inter, 0..) |*column, c| column.* = .{ .log_size = instance.row_log, .values = witness.columns[0][c * rows ..][0..rows] };
    try scheme.commit(a, &inter, &ch);
    const component = Table.Component{ .kind = kind, .data = try Role.Data.init(instance, &pending, 0), .inter_offset = 0, .boundary = template.boundary };
    owns = false;
    return .{ .stark = try Prover.prove(a, &.{component.asProverComponent()}, &ch, scheme, .{}), .gkr = gkr };
}
fn verify(bundle: *Bundle, kind: Table.Kind, wrong_public: bool) !void {
    const instance = frame(kind);
    const cfg = try config();
    var ch = Ch.init();
    cfg.mixInto(&ch);
    var receiver = try core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(H, MC).init(a, cfg);
    defer receiver.deinit(a);
    var boundary = if (kind == .boundary) public() else null;
    if (wrong_public) boundary.?.value.final_registers[1] ^= 1;
    const template = Table.Component{ .kind = kind, .data = undefined, .inter_offset = 0, .boundary = boundary };
    const shape = template.mainShape();
    const commitments = bundle.stark.proof.commitment_scheme_proof.commitments.items;
    var fixed_logs: [34]u32 = @splat(instance.row_log);
    var main_logs: [16]u32 = @splat(instance.row_log);
    try receiver.commit(a, commitments[0], fixed_logs[0..shape.fixed], &ch);
    try receiver.commit(a, commitments[1], main_logs[0..shape.main], &ch);
    const challenges = @import("challenges.zig").For(O).draw(&ch);
    var artifact = try GV.partiallyVerifyBatch(a, &.{.LogUp}, &bundle.gkr.proof, &ch);
    defer artifact.deinit(a);
    const pending = @import("child.zig").Pending{ .artifact = artifact, .challenges = challenges, .eta = ch.drawSecureFelt(), .digest = @splat(0) };
    const component = Table.Component{ .kind = kind, .data = try Role.Data.init(instance, &pending, 0), .inter_offset = 0, .boundary = boundary };
    try receiver.commit(a, commitments[2], &([_]u32{instance.row_log} ** 16), &ch);
    const proof = bundle.stark.proof;
    bundle.stark.proof = undefined;
    try core.verifier.ForField(O).verify(H, MC, a, &.{component.asVerifierComponent()}, &ch, &receiver, proof);
}
test "ROM range8 and public REG fragments bind original table queries through shared packed2n kernel" {
    for ([_]Table.Kind{ .rom, .range8, .boundary }) |kind| {
        var bundle = try produce(kind, false);
        defer bundle.gkr.deinit(a);
        defer bundle.stark.aux.deinit(a);
        try verify(&bundle, kind, false);
    }
}
test "table GKR rejects arithmetic-valid stale multiplicity and changed public register endpoint" {
    var bad = produce(.range8, true) catch |err| switch (err) {
        error.ConstraintsNotSatisfied, error.InvalidLastLayerDegree => null,
        else => return err,
    };
    if (bad) |*bundle| {
        defer bundle.gkr.deinit(a);
        defer bundle.stark.aux.deinit(a);
        try std.testing.expectError(error.OodsNotMatching, verify(bundle, .range8, false));
    }
    var endpoint = try produce(.boundary, false);
    defer endpoint.gkr.deinit(a);
    defer endpoint.stark.aux.deinit(a);
    try std.testing.expectError(error.OodsNotMatching, verify(&endpoint, .boundary, true));
}

fn dense(seed: u32) O {
    var coordinates: [8]M = undefined;
    for (&coordinates, 0..) |*c, i| c.* = M.fromCanonical(seed + @as(u32, @intCast(97 * i)));
    return O.fromM31Array(coordinates);
}
test "every table role shares native and packed MAIN query authority across16 distinct rows" {
    const E = A.evaluation;
    const F = E.PackedFields.BaseForField(O);
    const S = E.PackedFields.SecureForField(O);
    var ch = Ch.init();
    const challenges = @import("challenges.zig").For(O).draw(&ch);
    var weights: [128]O = undefined;
    var packed_weights: [128]S = undefined;
    for (&weights, &packed_weights, 0..) |*w, *p, i| {
        w.* = dense(@intCast(13 + 19 * i));
        p.* = S.splat(w.*);
    }
    for (std.enums.values(Table.Kind)) |kind| {
        const component = Table.Component{ .kind = kind, .data = undefined, .inter_offset = 0, .boundary = if (kind == .boundary) public() else null };
        const shape = component.mainShape();
        const instance = frame(kind);
        const lanes: usize = @as(usize, 1) << @intCast(try instance.laneLog());
        var fixed: [34]F = undefined;
        var main: [16]F = undefined;
        for (fixed[0..shape.fixed], 0..) |*value, c| {
            var values: [E.LANES]M = undefined;
            for (&values, 0..) |*v, i| v.* = M.fromCanonical(@intCast(1 + 37 * c + 11 * i));
            value.* = F.fromLanes(values);
        }
        for (main[0..shape.main], 0..) |*value, c| {
            var values: [E.LANES]M = undefined;
            for (&values, 0..) |*v, i| v.* = M.fromCanonical(@intCast(3 + 71 * c + 17 * i));
            value.* = F.fromLanes(values);
        }
        var packet_projection = @import("binding.zig").ProjectionFor(F){ .challenges = &challenges, .lane_weights = packed_weights[0..lanes], .terms = instance.terms };
        component.emitLocalFor(F, fixed[0..shape.fixed], main[0..shape.main], &packet_projection);
        try packet_projection.finish();
        var main_residual: [1]S = undefined;
        var main_sink = E.SinkFor(F){ .values = &main_residual };
        try component.emitMainFor(F, fixed[0..shape.fixed], main[0..shape.main], (&([_]F{F.zero()} ** 16))[0..shape.main], &main_sink);
        for (0..E.LANES) |i| {
            var native_fixed: [34]O = undefined;
            var native_main: [16]O = undefined;
            for (native_fixed[0..shape.fixed], fixed[0..shape.fixed]) |*v, p| v.* = O.fromBase(p.lane(i));
            for (native_main[0..shape.main], main[0..shape.main]) |*v, p| v.* = O.fromBase(p.lane(i));
            var native = @import("binding.zig").ProjectionFor(O){ .challenges = &challenges, .lane_weights = weights[0..lanes], .terms = instance.terms };
            component.emitLocalFor(O, native_fixed[0..shape.fixed], native_main[0..shape.main], &native);
            try native.finish();
            for (packet_projection.numerator.coordinates(), native.numerator.toM31Array()) |p, n| try std.testing.expectEqual(n, p.lane(i));
            for (packet_projection.denominator.coordinates(), native.denominator.toM31Array()) |p, n| try std.testing.expectEqual(n, p.lane(i));
            var residual: [1]O = undefined;
            var native_sink = E.SinkFor(O){ .values = &residual };
            try component.emitMainFor(O, native_fixed[0..shape.fixed], native_main[0..shape.main], (&([_]O{O.zero()} ** 16))[0..shape.main], &native_sink);
            try std.testing.expectEqual(native_sink.count, main_sink.count);
            if (native_sink.count != 0) for (main_residual[0].coordinates(), residual[0].toM31Array()) |p, n| try std.testing.expectEqual(n, p.lane(i));
        }
    }
}
