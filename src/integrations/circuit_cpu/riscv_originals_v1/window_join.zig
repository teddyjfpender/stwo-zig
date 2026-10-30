//! One opt-in circuit verifies the original STARK roster and its exact endpoint
//! rebinding, CPU chain and global RAM closure. No NativeParent is produced.
const std = @import("std");
const core = @import("stwo_core");
const b = @import("stwo_circuit_frontend").builder;
const Lower = b.riscv_composition_lowering_v1;
const Admission = @import("admission.zig");
const Verifier = @import("verifier.zig");
const Material = @import("material.zig");
const Statement = @import("statement.zig");
const Sources = @import("../../../frontends/riscv/recursion/block_v8_endpoint_join_source_v1.zig");
const Public = @import("../../../frontends/riscv/recursion/block_v8_endpoint_join_public_v1.zig");
const JoinGraph = @import("../../../frontends/riscv/recursion/block_v8_endpoint_join_graph_v1.zig");
const Q = core.fields.qm31.QM31;
pub const production_active = false;
pub const OUTPUTS: usize = 8;
pub const Authority = struct {
    allocator: std.mem.Allocator,
    admission: Admission.Owned,
    sources: []Verifier.Authority,
    /// Shallow views into sources[i].values; only the array itself is owned.
    children: []Sources.Value,
    graph: JoinGraph.Owned,
    statement: Statement.Statement,
    seal: [32]u8,

    pub fn derive(a: std.mem.Allocator, metadata: Admission.Metadata) !Authority {
        return fromAdmission(a, try Admission.Owned.derive(a, metadata));
    }
    /// Consumes admission ownership on both success AND error.
    pub fn fromAdmission(a: std.mem.Allocator, admitted: Admission.Owned) !Authority {
        var admission = admitted;
        errdefer admission.deinit();
        if (admission.sources.len < 3 or admission.sources.len > 64) return error.InvalidOriginalWindowRoster;
        const sources = try a.alloc(Verifier.Authority, admission.sources.len);
        errdefer a.free(sources);
        var initialized: usize = 0;
        errdefer for (sources[0..initialized]) |*source| source.deinit();
        const children = try a.alloc(Sources.Value, sources.len);
        errdefer a.free(children);
        for (sources, admission.sources, children) |*source, original, *child| {
            source.* = try Verifier.Authority.init(a, original);
            initialized += 1;
            child.* = source.values;
        }
        const values = Public.Values{ .children = children, .extra = &admission.extra };
        try values.validate();
        var graph = try JoinGraph.Owned.compile(a, values, sources.len - 2);
        errdefer graph.deinit();
        var out = Authority{
            .allocator = a,
            .admission = admission,
            .sources = sources,
            .children = children,
            .graph = graph,
            .statement = .{ .span = admission.span, .roster_id = undefined, .closure_id = undefined, .source_count = @intCast(sources.len) },
            .seal = undefined,
        };
        out.statement.roster_id = out.rosterIdentity();
        out.statement.closure_id = out.closureIdentity();
        out.seal = try out.identity();
        try out.validate();
        return out;
    }
    pub fn deinit(v: *Authority) void {
        v.graph.deinit();
        v.allocator.free(v.children);
        for (v.sources) |*source| source.deinit();
        v.allocator.free(v.sources);
        v.admission.deinit();
        v.* = undefined;
    }
    pub fn identity(v: *const Authority) ![32]u8 {
        var ch = core.proof_suites.Blake3.Channel{};
        ch.mixU32s(&.{ 0x52384f41, 1 });
        ch.mixRoot(try v.statement.digest());
        ch.mixRoot(v.rosterIdentity());
        ch.mixRoot(v.closureIdentity());
        return ch.digestBytes();
    }
    fn rosterIdentity(v: *const Authority) [32]u8 {
        var ch = core.proof_suites.Blake3.Channel{};
        ch.mixU32s(&.{ 0x52384f52, 1, @intCast(v.sources.len) });
        for (v.sources) |source| ch.mixRoot(source.seal);
        ch.mixFelts(&v.admission.extra);
        return ch.digestBytes();
    }
    fn closureIdentity(v: *const Authority) [32]u8 {
        var ch = core.proof_suites.Blake3.Channel{};
        ch.mixU32s(&.{ 0x52384f47, 1 });
        ch.mixRoot(v.graph.circuit.identity_digest);
        ch.mixU64(v.graph.sources.len);
        for (v.graph.sources) |wire| ch.mixU32s(&.{ wire.circuit, wire.wire, wire.uses, @intFromBool(wire.negative), @intFromEnum(wire.kind), wire.child, wire.coordinate, if (wire.part) |part| part else 4 });
        return ch.digestBytes();
    }
    pub fn validate(v: *const Authority) !void {
        try v.statement.validate();
        try v.graph.circuit.validate();
        if (v.sources.len < 3 or v.sources.len > 64 or v.sources.len != v.admission.sources.len or v.children.len != v.sources.len or v.statement.source_count != v.sources.len or v.graph.sources.len != v.graph.circuit.input_count or !std.meta.eql(v.statement.span, v.admission.span)) return error.MutatedOriginalWindowAuthority;
        for (v.sources, v.admission.sources, v.children) |*source, original, child| {
            try source.validate();
            if (std.meta.activeTag(source.source) != std.meta.activeTag(original) or !std.meta.eql(source.source.seal(), original.seal()) or child.public.ptr != source.values.public.ptr or child.public.len != source.values.public.len or child.statement.words.ptr != source.values.statement.words.ptr or child.statement.words.len != source.values.statement.words.len or child.statement.felts.ptr != source.values.statement.felts.ptr or child.statement.felts.len != source.values.statement.felts.len or child.roots_count != source.values.roots_count or !std.meta.eql(child.template, source.values.template)) return error.MutatedOriginalWindowAuthority;
        }
        const words = try v.statement.encodeWords();
        for (words[32..98], 0..) |word, i| for (0..4) |byte| {
            if (!v.admission.extra[4 * i + byte].eql(Q.fromU32Unchecked((word >> @as(u5, @intCast(8 * byte))) & 255, 0, 0, 0))) return error.MutatedOriginalWindowAuthority;
        };
        if (!std.meta.eql(v.statement.roster_id, v.rosterIdentity()) or !std.meta.eql(v.statement.closure_id, v.closureIdentity()) or !std.meta.eql(v.seal, try v.identity())) return error.MutatedOriginalWindowAuthority;
    }
};
pub const Result = struct {
    digest: b.blake3_channel_reuse_v1.Digest,
    statement: Statement.Wires,
    sources: []const Verifier.Result,
};

pub fn build(comptime V: type, ctx: *b.Context(V), authority: *const Authority, materials: []const Material.Owned) !Result {
    try authority.validate();
    if (materials.len != authority.sources.len) return error.InvalidOriginalWindowMaterialRoster;
    const statement = try authority.statement.allocate(V, ctx);
    const extra = try statement.cpuBytes(V, ctx);
    const results = try ctx.scratch().alloc(Verifier.Result, materials.len);
    const root_cells = try ctx.scratch().alloc([]?b.Var, materials.len);
    for (results, authority.sources, materials, root_cells) |*result, *source, *material, *cells| {
        result.* = try Verifier.build(V, ctx, source, material);
        cells.* = try ctx.scratch().alloc(?b.Var, try std.math.mul(usize, source.values.roots_count, 8));
        @memset(cells.*, null);
    }
    const inputs = try ctx.scratch().alloc(b.Var, authority.graph.sources.len);
    for (inputs, authority.graph.sources) |*input, wire| {
        if (wire.part != null or wire.negative or wire.uses != 1) return error.InvalidOriginalWindowClosureReference;
        if (wire.child == results.len) {
            if (wire.kind != .child_term or wire.coordinate >= extra.len) return error.InvalidOriginalWindowClosureReference;
            input.* = extra[wire.coordinate];
            continue;
        }
        if (wire.child >= results.len) return error.InvalidOriginalWindowClosureReference;
        const child = &results[wire.child];
        input.* = switch (wire.kind) {
            .child_term => blk: {
                if (wire.coordinate >= child.public_values.len) return error.InvalidOriginalWindowClosureReference;
                break :blk child.public_values[wire.coordinate];
            },
            .child_cell => blk: {
                if (wire.coordinate >= root_cells[wire.child].len or wire.coordinate / 8 >= child.roots.len) return error.InvalidOriginalWindowClosureReference;
                const cache = &root_cells[wire.child][wire.coordinate];
                if (cache.* == null) cache.* = try rootWordCell(V, ctx, child.roots[wire.coordinate / 8][wire.coordinate % 8]);
                break :blk cache.*.?;
            },
            else => return error.InvalidOriginalWindowClosureReference,
        };
    }
    try Lower.constrain(V, ctx, &authority.graph.circuit, inputs);
    const digest = try statement.digest(V, ctx);
    var outputs: [OUTPUTS]b.Var = undefined;
    for (&outputs, digest) |*out, word| out.* = word.get();
    try ctx.setOutputs(&outputs);
    return .{ .digest = digest, .statement = statement, .sources = results };
}

/// Exact four U8 coordinates of the same authenticated PCS root word. There
/// are no independently guessed or host-matched digest bytes in the join.
fn rootWordCell(comptime V: type, ctx: *b.Context(V), word: Statement.W) !b.Var {
    const bits = try b.extract_bits.extractBits(V, ctx, b.simd.Simd.fromPacked(&.{word.get()}, 2), 16);
    var cell = ctx.zero();
    for (0..4) |byte| {
        var value = ctx.zero();
        for (0..8) |bit| {
            const scalar = try b.simd.unpackIdx(V, ctx, bits[8 * (byte % 2) + bit], byte / 2);
            const power = try ctx.constant(Q.fromU32Unchecked(@as(u32, 1) << @intCast(bit), 0, 0, 0));
            value = try ctx.add(value, try ctx.mul(scalar, power));
        }
        var basis: [4]u32 = @splat(0);
        basis[byte] = 1;
        const scale = try ctx.constant(Q.fromU32Unchecked(basis[0], basis[1], basis[2], basis[3]));
        cell = try ctx.add(cell, try ctx.mul(value, scale));
    }
    return cell;
}
