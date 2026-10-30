//! Direct original STARK verifier. Receiver derives Source from Admission; no
//! NativeParent proof or successful native AIR verification token is consumed.
const std = @import("std");
const core = @import("stwo_core");
const b = @import("stwo_circuit_frontend").builder;
const channel = b.blake3_channel_reuse_v1;
const pcs = b.blake3_pcs_reuse_v1;
const Lower = b.riscv_composition_lowering_v1;
const Sources = @import("../../../frontends/riscv/recursion/block_v8_endpoint_join_source_v1.zig");
const G = @import("../../../frontends/riscv/recursion/air/composition_graph_recorder.zig");
const Input = @import("../../../frontends/riscv/recursion/air/blake3_execution_composition.zig").Source;
const Ops = @import("../../../frontends/riscv/recursion/air/blake3_original_op_schedule_v1.zig");
const Caller = @import("../../../frontends/riscv/recursion/air/blake3_transcript_witness.zig").Caller;
const Q = core.fields.qm31.QM31;
const W = b.wrappers.U32Wrapper(b.Var);
pub const production_active = false;
pub const LAYOUT_VERSION: u32 = 2;
pub const GROUPED_DEEP_LAYOUT: u32 = 0x47445031;
pub const QuotientCensus = struct {
    responses: usize,
    groups: usize,
    current_divisions: usize,
    grouped_divisions: usize,
};
pub const Authority = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    /// Borrowed independently reconstructed receiver profile.
    source: Sources.Source,
    schedule: Ops.Owned,
    circuit: G.Circuit,
    sources: []Input,
    geometry: pcs.Geometry,
    values: Sources.Value,
    relation_pairs: usize,
    seal: [32]u8,
    pub fn init(a: std.mem.Allocator, source: Sources.Source) !Authority {
        return switch (source) {
            inline else => |p, k| blk: {
                const Adapter = Sources.Adapter(k);
                try p.validate();
                var arena = std.heap.ArenaAllocator.init(a);
                errdefer arena.deinit();
                var schedule = try Adapter.Transcript.opSchedule(a, p, 1, .{});
                errdefer schedule.deinit();
                var compiled = try Adapter.Composition.compile(a, p);
                errdefer compiled.deinit();
                var values = try source.values(a);
                errdefer values.deinit();
                const trees = try arena.allocator().alloc(pcs.Tree, p.shape.columns.len);
                var at: usize = 0;
                for (trees, p.shape.columns) |*tree, logs| {
                    const columns = try arena.allocator().alloc(pcs.Column, logs.len);
                    for (columns, logs) |*col, log| {
                        const offsets = p.shape.layouts[at].offsets();
                        const masks = try arena.allocator().alloc(pcs.Mask, offsets.len);
                        for (masks, offsets) |*mask, offset| mask.* = .{ .row_log = if (p.shape.mask_logs.len == 0) p.shape.mask_log else p.shape.mask_logs[at], .offset = @intCast(offset) };
                        col.* = .{ .log_size = try std.math.sub(u32, log, p.shape.config.fri_config.log_blowup_factor), .masks = masks };
                        at += 1;
                    }
                    tree.* = .{ .columns = columns };
                }
                const geometry = pcs.Geometry{ .config = p.shape.config, .trees = trees };
                try geometry.validate();
                if (geometry.config.pow_bits != 26 or geometry.config.fri_config.n_queries != 70) return error.UnsupportedOriginalCircuitSecurityProfile;
                var out = Authority{ .allocator = a, .arena = arena, .source = source, .schedule = schedule, .circuit = compiled.circuit, .sources = compiled.sources, .geometry = geometry, .values = values, .relation_pairs = Adapter.Profile.RELATION_PAIRS, .seal = undefined };
                out.seal = try out.identity();
                const census = try out.quotientCensus(a);
                std.debug.print("RISC_ORIGINAL_QUOTIENT_CENSUS family={s} responses={d} groups={d} current_divisions={d} grouped_divisions={d}\n", .{ @tagName(k), census.responses, census.groups, census.current_divisions, census.grouped_divisions });
                break :blk out;
            },
        };
    }
    /// Geometry-only native point-batch census. The key is the canonical BASE
    /// circle offset, never the sampled OODS point or a guessed equality. It
    /// mirrors responses() and native buildColumnSampleBatchesFromParallelInputs,
    /// including the periodic response BEFORE each two-mask column's samples.
    /// This measures a possible grouped implementation; it emits NO gates and
    /// changes neither the verifier nor its beta-power order.
    pub fn quotientCensus(v: *const Authority, a: std.mem.Allocator) !QuotientCensus {
        try v.geometry.validate();
        var groups = std.AutoHashMap(u64, void).init(a);
        defer groups.deinit();
        var responses_count: usize = 0;
        const generator = core.poly.circle.canonic.CanonicCoset.new((try v.geometry.friGeometry()).startLog()).step();
        for (v.geometry.trees) |tree| for (tree.columns) |column| {
            if (column.masks.len == 2) {
                const offset = maskOffset(column.masks[1]).add(generator.repeatedDouble(column.log_size + v.geometry.config.fri_config.log_blowup_factor));
                try groups.put(pointKey(offset), {});
                responses_count = try std.math.add(usize, responses_count, 1);
            }
            for (column.masks) |mask| {
                try groups.put(pointKey(maskOffset(mask)), {});
                responses_count = try std.math.add(usize, responses_count, 1);
            }
        };
        const count = groups.count();
        return .{ .responses = responses_count, .groups = count, .current_divisions = try std.math.mul(usize, responses_count, v.geometry.config.fri_config.n_queries), .grouped_divisions = try std.math.mul(usize, count, v.geometry.config.fri_config.n_queries) };
    }
    pub fn identity(v: *const Authority) ![32]u8 {
        var ch = core.proof_suites.Blake3.Channel{};
        ch.mixU32s(&.{ 0x52384f43, LAYOUT_VERSION, GROUPED_DEEP_LAYOUT, @intFromEnum(std.meta.activeTag(v.source)), @intCast(v.relation_pairs) });
        ch.mixRoot(v.schedule.seal);
        ch.mixRoot(v.circuit.identity_digest);
        ch.mixRoot(try v.geometry.identity());
        ch.mixRoot(v.values.template);
        ch.mixU64(v.values.roots_count);
        ch.mixU32s(v.values.statement.words);
        ch.mixFelts(v.values.statement.felts);
        ch.mixFelts(v.values.public);
        for (v.sources) |source| {
            ch.mixU32s(&.{@intFromEnum(std.meta.activeTag(source))});
            switch (source) {
                .composition, .oods => {},
                inline else => |i| ch.mixU32s(&.{i}),
            }
        }
        return ch.digestBytes();
    }
    pub fn validate(v: *const Authority) !void {
        try v.schedule.validate();
        try v.values.validate();
        try v.circuit.validate();
        switch (v.source) {
            inline else => |p| {
                try p.validate();
                if (!std.meta.eql(p.seal, v.schedule.profile_seal)) return error.MutatedOriginalCircuitAuthority;
            },
        }
        if (v.sources.len != v.circuit.input_count or !std.meta.eql(v.seal, try v.identity())) return error.MutatedOriginalCircuitAuthority;
    }
    pub fn deinit(v: *Authority) void {
        v.circuit.deinit();
        v.allocator.free(v.sources);
        v.values.deinit();
        v.schedule.deinit();
        v.arena.deinit();
        v.* = undefined;
    }
    pub fn nativeWords(v: *const Authority, source: Caller, len: usize) ![]const u32 {
        if (source.circuit != v.schedule.public_circuit) return error.InvalidOriginalCircuitRoute;
        return span(u32, v.schedule.frame.words, source.first_wire, len);
    }
    pub fn nativeFelts(v: *const Authority, source: Caller, len: usize) ![]const Q {
        if (source.circuit != v.schedule.public_circuit or source.first_wire < v.schedule.frame.words.len) return error.InvalidOriginalCircuitRoute;
        const offset = source.first_wire - v.schedule.frame.words.len;
        if (offset % 4 != 0) return error.InvalidOriginalCircuitRoute;
        return span(Q, v.schedule.frame.felts, offset / 4, len);
    }
};
pub const Result = struct {
    words: []const W,
    felts: []const b.Var,
    public_values: []const b.Var,
    roots: []const channel.Digest,
    sampled_values: []const b.Var,
    challenges: []const b.Var,
    composition: b.Var,
    oods: pcs.Oods,
    pcs_result: pcs.Result,
};
pub fn build(comptime V: type, ctx: *b.Context(V), authority: *const Authority, material: *const @import("material.zig").Owned) !Result {
    try authority.validate();
    const proof = try material.allocate(V, ctx, authority.geometry);
    std.debug.print("RISC_ORIGINAL_STAGE family={s} stage=allocated variables={d}\n", .{ @tagName(std.meta.activeTag(authority.source)), ctx.circuit.n_vars });
    const words = try wordWires(V, ctx, authority.schedule.frame.words);
    const felts = try feltWires(V, ctx, authority.schedule.frame.felts);
    // Instance-specific receiver key: all physical claims remain witnesses,
    // and these exact variables feed original FS and every typed equation.
    const public = try publicWires(V, ctx, authority, felts);
    const nroots = authority.values.roots_count;
    if (nroots > proof.roots.len or 8 * nroots > words.len) return error.InvalidOriginalCircuitRoots;
    for (proof.roots[0..nroots], 0..) |root, tree| for (root, 0..) |word, i| {
        const index = words.len - 8 * nroots + 8 * tree + i;
        try ctx.eq(word.get(), words[index].get());
        words[index] = word;
    };
    var transcript = try channel.Channel(V).init(ctx);
    const challenges = try ctx.scratch().alloc(b.Var, 2 * authority.relation_pairs);
    const filled = try ctx.scratch().alloc(bool, challenges.len);
    @memset(filled, false);
    var alpha: ?b.Var = null;
    var oods: ?pcs.Oods = null;
    for (authority.schedule.operations) |op| {
        switch (op) {
            .restart => transcript = try channel.Channel(V).init(ctx),
            .words => |v| try transcript.mixU32s(ctx, try constantWords(V, ctx, v)),
            .felts => |v| {
                const wires = try ctx.scratch().alloc(b.Var, v.len);
                for (wires, v) |*wire, val| wire.* = try ctx.constant(val);
                try transcript.mixFelts(ctx, wires);
            },
            .integer => |v| try transcript.mixU64(ctx, .{ try b.wrappers.constU32(V, ctx, @truncate(v)), try b.wrappers.constU32(V, ctx, @truncate(v >> 32)) }),
            .root => |v| {
                const vals = rootWords(v);
                try transcript.mixRoot(ctx, (try constantWords(V, ctx, &vals))[0..8].*);
            },
            .routed_words => |v| try transcript.mixU32s(ctx, try routedWords(authority, words, v.source, v.values.len)),
            .routed_integer => |v| try transcript.mixU64(ctx, (try routedWords(authority, words, v.source, 2))[0..2].*),
            .routed_root => |v| {
                const root = if (v.source.circuit == authority.schedule.public_circuit) (try routedWords(authority, words, v.source, 8))[0..8].* else blk: {
                    if (v.source.circuit != 4_000_003 or v.source.first_wire % 8 != 0 or v.source.first_wire / 8 >= proof.roots.len) return error.InvalidOriginalCircuitRoute;
                    break :blk proof.roots[v.source.first_wire / 8];
                };
                try transcript.mixRoot(ctx, root);
            },
            .routed_felts => |v| {
                const offset = try feltOffset(authority, v.source);
                try transcript.mixFelts(ctx, try span(b.Var, felts, offset, v.values.len));
            },
            .secure => |v| {
                const role = v.output orelse return error.InvalidOriginalCircuitDrawRole;
                switch (role) {
                    .universal, .riscv_relation => |relation| {
                        if (v.consumption != .two or relation >= authority.relation_pairs) return error.InvalidOriginalCircuitDrawRole;
                        const pair = try transcript.drawSecurePair(ctx, 1);
                        for (pair, 0..) |wire, half| {
                            const i = 2 * relation + half;
                            if (filled[i]) return error.InvalidOriginalCircuitDrawRole;
                            filled[i] = true;
                            challenges[i] = wire;
                        }
                    },
                    .universal_half => |half| {
                        const i = 2 * half.relation + half.half;
                        if (v.consumption != .one or i >= filled.len or filled[i]) return error.InvalidOriginalCircuitDrawRole;
                        challenges[i] = try transcript.drawSecureFelt(ctx, 1);
                        filled[i] = true;
                    },
                    .composition => {
                        if (v.consumption != .one or alpha != null) return error.InvalidOriginalCircuitDrawRole;
                        alpha = try transcript.drawSecureFelt(ctx, 1);
                    },
                    .oods => {
                        if (v.consumption != .one or alpha == null) return error.InvalidOriginalCircuitDrawRole;
                        oods = try pcs.drawOods(V, ctx, &transcript);
                    },
                    else => return error.InvalidOriginalCircuitPrefix,
                }
            },
            else => return error.InvalidOriginalCircuitPrefix,
        }
        if (oods != null) break;
    }
    for (filled) |present| if (!present) return error.InvalidOriginalCircuitDrawRole;
    const opening = oods orelse return error.InvalidOriginalCircuitPrefix;
    const random = alpha orelse return error.InvalidOriginalCircuitPrefix;
    const inputs = try ctx.scratch().alloc(b.Var, authority.sources.len);
    const live = try Lower.liveness(ctx.scratch(), &authority.circuit);
    const used_challenges = try ctx.scratch().alloc(bool, challenges.len);
    @memset(used_challenges, false);
    var used_composition = false;
    for (inputs, authority.sources, live.inputs) |*wire, source, used| {
        wire.* = switch (source) {
            .sample => |i| try checkedAt(proof.sampled_values, i),
            .public_input => |i| try checkedAt(public, i),
            .challenge => |i| blk: {
                if (i >= challenges.len) return error.InvalidOriginalCircuitInput;
                used_challenges[i] = used_challenges[i] or used;
                break :blk challenges[i];
            },
            .composition => blk: {
                used_composition = used_composition or used;
                break :blk random;
            },
            .oods => opening.seed,
            else => return error.InvalidOriginalCircuitInput,
        };
    }
    for (challenges, used_challenges) |wire, used| if (!used) try ctx.markAsUnused(wire);
    // A one-constraint original has no Horner random power. Its transcript
    // still draws/checks the full block; only the unused derived scalar drops.
    if (!used_composition) try ctx.markAsUnused(random);
    std.debug.print("RISC_ORIGINAL_STAGE family={s} stage=transcript variables={d}\n", .{ @tagName(std.meta.activeTag(authority.source)), ctx.circuit.n_vars });
    try Lower.constrain(V, ctx, &authority.circuit, inputs);
    std.debug.print("RISC_ORIGINAL_STAGE family={s} stage=typed_air variables={d}\n", .{ @tagName(std.meta.activeTag(authority.source)), ctx.circuit.n_vars });
    const result = try pcs.verifyAfterOodsGrouped(V, ctx, authority.geometry, &transcript, proof, opening);
    std.debug.print("RISC_ORIGINAL_STAGE family={s} stage=pcs variables={d}\n", .{ @tagName(std.meta.activeTag(authority.source)), ctx.circuit.n_vars });
    return .{ .words = words, .felts = felts, .public_values = public, .roots = proof.roots, .sampled_values = proof.sampled_values, .challenges = challenges, .composition = random, .oods = opening, .pcs_result = result };
}
fn rootWords(root: [32]u8) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, i| word.* = std.mem.readInt(u32, root[4 * i ..][0..4], .little);
    return result;
}

fn span(comptime T: type, all: []const T, first: usize, len: usize) ![]const T {
    if (first > all.len or len > all.len - first) return error.InvalidOriginalCircuitRoute;
    return all[first..][0..len];
}
fn checkedAt(all: []const b.Var, i: usize) !b.Var {
    return (try span(b.Var, all, i, 1))[0];
}
fn routedWords(a: *const Authority, words: []const W, source: Caller, len: usize) ![]const W {
    if (source.circuit != a.schedule.public_circuit) return error.InvalidOriginalCircuitRoute;
    return span(W, words, source.first_wire, len);
}
fn feltOffset(a: *const Authority, source: Caller) !usize {
    if (source.circuit != a.schedule.public_circuit or source.first_wire < a.schedule.frame.words.len) return error.InvalidOriginalCircuitRoute;
    const offset = source.first_wire - a.schedule.frame.words.len;
    if (offset % 4 != 0) return error.InvalidOriginalCircuitRoute;
    return offset / 4;
}
fn constantWords(comptime V: type, ctx: *b.Context(V), vals: []const u32) ![]const W {
    const wires = try ctx.scratch().alloc(W, vals.len);
    for (wires, vals) |*wire, val| wire.* = try b.wrappers.constU32(V, ctx, val);
    return wires;
}
fn wordWires(comptime V: type, ctx: *b.Context(V), vals: []const u32) ![]W {
    const wires = try ctx.scratch().alloc(W, vals.len);
    for (wires, vals) |*wire, val| {
        wire.* = try b.wrappers.guessU32(V, ctx, b.wrappers.u32Value(V, val));
        try ctx.eq(wire.get(), (try b.wrappers.constU32(V, ctx, val)).get());
    }
    return wires;
}
fn feltWires(comptime V: type, ctx: *b.Context(V), vals: []const Q) ![]b.Var {
    const wires = try ctx.scratch().alloc(b.Var, vals.len);
    for (wires, vals) |*wire, val| {
        wire.* = try ctx.guess(b.ivalue.fromQm31(V, val));
        try ctx.eq(wire.*, try ctx.constant(val));
    }
    return wires;
}

fn publicWires(comptime V: type, ctx: *b.Context(V), a: *const Authority, felts: []const b.Var) ![]const b.Var {
    // Ordinal mappings below follow canonical recordClaims/publicValues methods;
    // matching field values never selects a reference.
    const values = a.values.public;
    const result = try feltWires(V, ctx, values);
    switch (a.source) {
        .local => |p| {
            const count = p.claims.native.len + 11 + 2 + 1 + 6;
            if (felts.len != count or result.len < 8 + count) return error.InvalidOriginalCircuitClaimFrame;
            @memcpy(result[8..][0..count], felts);
        },
        .global => {
            if (felts.len != 10 or result.len != 10) return error.InvalidOriginalCircuitClaimFrame;
            @memcpy(result, felts);
        },
        .bridge => |p| {
            if (felts.len != p.claims.len or result.len != felts.len + 1) return error.InvalidOriginalCircuitClaimFrame;
            @memcpy(result[0..felts.len], felts);
            var aggregate = ctx.zero();
            for (felts) |claim| aggregate = try ctx.add(aggregate, claim);
            result[felts.len] = aggregate;
        },
        .mixed => |p| {
            const base = p.claims.native.len + 11 + 2;
            var arithmetic: usize = 0;
            for (p.claims.caller_arithmetic.componentClaims()) |view| arithmetic += view.detailed.len + @intFromBool(view.has_batch_frame);
            const basic = p.claims.caller_basic.program_claims.len + p.claims.caller_basic.state_claims.len + p.claims.caller_basic.table_claims.len;
            const ram = p.claims.caller_ram.len;
            const caller = arithmetic + basic + ram;
            if (felts.len != base + caller + 7 or result.len < 8 + base + 7 + arithmetic + 1 + 8 + basic + ram) return error.InvalidOriginalCircuitClaimFrame;
            @memcpy(result[8..][0..base], felts[0..base]);
            @memcpy(result[8 + base ..][0..7], felts[base + caller ..][0..7]);
            const start = 8 + base + 7;
            @memcpy(result[start..][0..arithmetic], felts[base..][0..arithmetic]);
            var at_felt = base;
            var total = ctx.zero();
            for (p.claims.caller_arithmetic.componentClaims()) |view| {
                if (view.has_batch_frame) {
                    at_felt += view.detailed.len;
                    total = try ctx.add(total, felts[at_felt]);
                    at_felt += 1;
                } else {
                    if (view.detailed.len != 1) return error.InvalidOriginalCircuitClaimFrame;
                    total = try ctx.add(total, felts[at_felt]);
                    at_felt += 1;
                }
            }
            result[start + arithmetic] = total;
            @memcpy(result[start + arithmetic + 1 + 8 ..][0 .. basic + ram], felts[base + arithmetic ..][0 .. basic + ram]);
        },
    }
    // Structural mappings must reproduce canonical publicValues, including
    // derived aggregates. These are circuit equalities, never host authority.
    for (result, values) |wire, value| try ctx.eq(wire, try ctx.constant(value));
    return result;
}

fn maskOffset(mask: pcs.Mask) core.circle.CirclePointM31 {
    return if (mask.offset == 0) core.circle.CirclePointM31.zero() else core.poly.circle.canonic.CanonicCoset.new(mask.row_log).step().mulSigned(mask.offset);
}
fn pointKey(point: core.circle.CirclePointM31) u64 {
    return (@as(u64, point.x.toU32()) << 32) | point.y.toU32();
}
