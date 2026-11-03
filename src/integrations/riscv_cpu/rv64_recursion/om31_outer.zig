//! Ordered fold of independently admitted native OM31 circuit proofs.
//! The digest binds child authority identities and public outputs. Execution
//! adjacency/manifest coverage remains the application receiver's obligation.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const V = @import("om31_native/mod.zig");
const C = V.common;
const F = V.F;
const Q = C.Q;
const M = core.fields.m31.M31;
const B = circuit.builder;
const Word = B.wrappers.U32Wrapper(C.Var);
const Eval = Outer.program.ForLane(F);
const List = circuit.common.component_list;
const A = @import("stwo_riscv_frontend").rv64_air;
const domain: u32 = 0x4f464c31;
pub const Child = struct {
    authority: *const Outer.prove.Authority,
    produced: *const Outer.prove.Produced,
    capture: *const Outer.prove.Capture,
};
pub const Graph = struct {
    ctx: C.Context,
    output_digest: [32]u8,
    pub fn deinit(self: *Graph) void {
        self.ctx.deinit();
        self.* = undefined;
    }
};
fn word(ctx: *C.Context, value: u32) !Word {
    return .newUnsafe(try ctx.constant(B.wrappers.u32Value(Q, value).get()));
}
fn digestWords(ctx: *C.Context, digest: [32]u8) ![8]Word {
    return (try B.blake.constantHash(Q, ctx, B.blake.hashValueFromDigest(Q, digest))).words;
}
fn shape(a: std.mem.Allocator, key: *const Outer.prove.Authority) !V.Shape {
    const logs = try a.alloc([]const u32, 4);
    const masks = try a.alloc([]const []const i32, 4);
    for (0..3) |t| logs[t] = try key.treeLogs(a, t);
    const composition = try a.alloc(u32, 16);
    @memset(composition, key.bound.max_evaluation_log_size - 1);
    logs[3] = composition;
    for (masks, logs) |*tree, sizes| {
        const columns = try a.alloc([]const i32, sizes.len);
        @memset(columns, &.{});
        tree.* = columns;
    }
    for (key.bound.components) |component| {
        for (component.preprocessed_indices) |idx| @constCast(masks[0])[idx] = &.{0};
        for (1..3) |t| {
            const span = try Outer.geometry.span(component, @intCast(t));
            const offsets = try Outer.geometry.offsets(a, component, @intCast(t));
            for (offsets, 0..) |offset, col| @constCast(masks[t])[span.start + col] = try a.dupe(i32, offset.items);
        }
    }
    for (@constCast(masks[3])) |*offset| offset.* = &.{0};
    const result = V.Shape{ .tree_column_log_sizes = logs, .mask_offsets = masks, .global_log = key.bound.max_evaluation_log_size - 1, .composition_log_split = 1, .pcs = try Outer.protocol.targetConfig() };
    try result.validate();
    return result;
}
const Statement = struct {
    key: *const Outer.prove.Authority,
    outputs: []const C.Var,
    output_words: []const Word,
    claims: [List.N_COMPONENTS]F,
    challenges: *Challenges,
    const Challenges = struct { z: F, alpha: F };
    pub fn mixPublic(self: @This(), ctx: *C.Context, channel: *C.Channel) !void {
        try channel.mixConfig(ctx, try Outer.protocol.targetConfig());
        const marker = [_]Word{ try word(ctx, 0x434f4d38), try word(ctx, 1), try word(ctx, 8) };
        try channel.mixU32s(ctx, &marker);
        var profile: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(Outer.protocol.domain, &profile, .{});
        const profile_words = try digestWords(ctx, profile);
        try channel.mixU32s(ctx, &profile_words);
        const public = try ctx.scratch().alloc(Word, 9 + self.output_words.len);
        @memcpy(public[0..8], &(try digestWords(ctx, self.key.identity)));
        public[8] = try word(ctx, @intCast(self.outputs.len));
        @memcpy(public[9..], self.output_words);
        try channel.mixU32s(ctx, public);
    }
    pub fn nTreesBeforeChallenges(_: @This()) usize {
        return 2;
    }
    pub fn drawChallenges(self: @This(), ctx: *C.Context, channel: *C.Channel) !Challenges {
        self.challenges.* = .{ .z = try channel.draw(ctx), .alpha = try channel.draw(ctx) };
        return self.challenges.*;
    }
    fn outputTerm(ctx: *C.Context, words: []const Word, address: usize, challenges: Challenges) !F {
        var power = F.one();
        var denominator = F.zero();
        const prefix = [_]M{ M.fromCanonical(List.GATE_RELATION_ID), M.fromU64(address) };
        for (prefix) |coordinate| {
            denominator = denominator.add(power.mulM31(coordinate));
            power = power.mul(challenges.alpha);
        }
        for (words, 0..) |coordinate, i| {
            const base = try circuit.native_verifier.channel.wordToM31(Q, ctx, coordinate);
            denominator = denominator.add(power.mul(C.base(base)));
            if (i + 1 < words.len) power = power.mul(challenges.alpha);
        }
        return denominator.sub(challenges.z).inv();
    }
    pub fn mixClaims(self: @This(), ctx: *C.Context, channel: *C.Channel) !void {
        var sum = F.zero();
        for (self.claims) |claim| sum = sum.add(claim);
        for (0..self.outputs.len) |i| sum = sum.add(try outputTerm(ctx, self.output_words[4 * i ..][0..4], circuit.witness.trace.U_VAR_IDX + 1 + i, self.challenges.*));
        const u_words = try ctx.scratch().alloc(Word, 4);
        for (u_words, circuit.witness.trace.U_VALUE.toM31Array()) |*out, coordinate| out.* = try word(ctx, coordinate.v);
        sum = sum.add(try outputTerm(ctx, u_words, circuit.witness.trace.U_VAR_IDX, self.challenges.*));
        try C.eq(ctx, sum, F.zero());
        try channel.mixFelts(ctx, &self.claims);
    }
    const Read = struct {
        component: @import("stwo_cairo_frontend").witness.composition_bundle.Component,
        masks: []const []const []const F,
        offsets: [2][]std.ArrayList(i32),
        fn get(raw: *const anyopaque, tree: u8, col: u32, offset: i32) !F {
            const self: *const Read = @ptrCast(@alignCast(raw));
            if (tree == 0) {
                if (offset != 0 or col >= self.component.preprocessed_indices.len) return error.MissingOm31CircuitMask;
                const global = self.component.preprocessed_indices[col];
                if (global >= self.masks[0].len or self.masks[0][global].len != 1) return error.MissingOm31CircuitMask;
                return self.masks[0][global][0];
            }
            if (tree > 2 or col >= self.offsets[tree - 1].len) return error.MissingOm31CircuitMask;
            const span = try Outer.geometry.span(self.component, tree);
            const offsets = self.offsets[tree - 1][col].items;
            const global = span.start + col;
            if (global >= self.masks[tree].len or self.masks[tree][global].len != offsets.len) return error.MissingOm31CircuitMask;
            for (offsets, 0..) |wanted, i| if (offset == wanted) return self.masks[tree][global][i];
            return error.MissingOm31CircuitMask;
        }
    };
    pub fn evalComposition(self: @This(), ctx: *C.Context, point: V.Point, masks: []const []const []const F, randomness: F, challenges: Challenges) !F {
        const n = self.key.bound.total_constraints;
        const powers = try ctx.scratch().alloc(F, n);
        var power = F.one();
        for (powers, 0..) |*p, i| {
            p.* = power;
            if (i + 1 < powers.len) power = power.mul(randomness);
        }
        var result = F.zero();
        for (self.key.bound.components, self.claims) |component, claim| {
            const parameters = try Eval.extensionParameters(ctx.scratch(), &component, challenges.z, challenges.alpha, claim);
            const read = Read{ .component = component, .masks = masks, .offsets = .{ try Outer.geometry.offsets(ctx.scratch(), component, 1), try Outer.geometry.offsets(ctx.scratch(), component, 2) } };
            const inverse = try A.geometry.denominatorInverseFor(F, .{ .x = point.x, .y = point.y }, self.key.bound.max_evaluation_log_size - 1, component.trace_log_size);
            for (component.parts) |part| {
                const roots = try Eval.evaluate(ctx.scratch(), part.program, .{ .context = &read, .get = Read.get }, parameters);
                for (roots, 0..) |root, r| result = result.add(root.mul(inverse).mul(powers[n - 1 - component.random_coefficient_offset - part.rc_base - r]));
            }
        }
        return result;
    }
};

fn messageWords(a: std.mem.Allocator, children: [2]Child) ![]u32 {
    var count: usize = 2;
    for (children) |child| count += 9 + 4 * child.produced.outputs.len;
    const words = try a.alloc(u32, count);
    errdefer a.free(words);
    words[0] = domain;
    words[1] = 1;
    var at: usize = 2;
    for (children) |child| {
        if (child.produced.outputs.len != child.authority.pp.n_outputs) return error.InvalidOm31CircuitOutputCount;
        for (0..8) |i| words[at + i] = std.mem.readInt(u32, child.authority.identity[4 * i ..][0..4], .little);
        at += 8;
        words[at] = @intCast(child.produced.outputs.len);
        at += 1;
        for (child.produced.outputs) |output| for (output.toM31Array()) |coordinate| {
            words[at] = coordinate.v;
            at += 1;
        };
    }
    return words;
}
pub fn expectedDigest(children: [2]Child) ![32]u8 {
    const a = std.heap.page_allocator;
    const words = try messageWords(a, children);
    defer a.free(words);
    var h = std.crypto.hash.blake2.Blake2s256.init(.{});
    var bytes: [4]u8 = undefined;
    for (words) |w| {
        std.mem.writeInt(u32, &bytes, w, .little);
        h.update(&bytes);
    }
    var digest: [32]u8 = undefined;
    h.final(&digest);
    return digest;
}
pub fn buildFold(a: std.mem.Allocator, children: [2]Child) !Graph {
    var ctx = try C.Context.init(a, 8);
    errdefer ctx.deinit();
    ctx.assert_eq_on_eval = true;
    C.lane.begin(&ctx);
    defer C.lane.finish() catch {};
    var message: std.ArrayList(Word) = .empty;
    defer message.deinit(a);
    try message.appendSlice(a, &.{ try word(&ctx, domain), try word(&ctx, 1) });
    for (children) |child| {
        try Outer.protocol.validateConfig(child.produced.proof.proof.commitment_scheme_proof.config);
        const geometry = try shape(ctx.scratch(), child.authority);
        const captured = try V.proof.fromNative(ctx.scratch(), &child.produced.proof.proof, child.capture, &geometry);
        const guessed = try V.proof.guess(&ctx, &captured, &geometry);
        const trusted_fixed = try B.blake.constantHash(Q, &ctx, B.blake.hashValueFromDigest(Q, child.authority.fixedRoot()));
        for (guessed.commitments[0].words, trusted_fixed.words) |actual, expected| try ctx.eq(actual.get(), expected.get());
        const outputs = try ctx.scratch().alloc(C.Var, child.produced.outputs.len);
        for (outputs, child.produced.outputs) |*out, value| out.* = try ctx.guess(value);
        const output_words = try B.blake.unpackQm31sToU32Words(Q, &ctx, outputs);
        var claims: [List.N_COMPONENTS]F = undefined;
        for (&claims, child.produced.claims.toArray()) |*out, value| out.* = try F.guess(&ctx, value);
        var challenges: Statement.Challenges = undefined;
        _ = try V.verify(&ctx, &geometry, &guessed, Statement{ .key = child.authority, .outputs = outputs, .output_words = output_words, .claims = claims, .challenges = &challenges });
        try message.appendSlice(a, &(try digestWords(&ctx, child.authority.identity)));
        try message.append(a, try word(&ctx, @intCast(outputs.len)));
        try message.appendSlice(a, output_words);
    }
    try C.lane.check();
    const digest = try B.blake.blake2sU32s(Q, &ctx, message.items, 4 * message.items.len);
    var outputs: [8]C.Var = undefined;
    for (&outputs, digest.words) |*out, w| out.* = w.get();
    try ctx.setOutputs(&outputs);
    // Native PCS verifier emits terminal arithmetic/transcript intermediates
    // that are intentionally unused; all asserted verification equalities and
    // guessed-input yield gates are retained, as in the native PCS fixtures.
    try ctx.finalize(false);
    return .{ .ctx = ctx, .output_digest = try expectedDigest(children) };
}
