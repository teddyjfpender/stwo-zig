//! Complete child-verifier adapter for the hybrid STARK and its GKR section.
//! Geometry and AIR come from the receiver's pinned source authority.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const V = @import("../rv64_recursion/om31_native/mod.zig");
const C = V.common;
const F = V.F;
const Q = C.Q;
const Word = circuit.builder.wrappers.U32Wrapper(C.Var);
const P = @import("profile.zig");
const R = @import("hybrid_receiver.zig");
const H = @import("hybrid_air.zig");
const HC = @import("hybrid_component.zig");
const CG = @import("circuit.zig");
pub const common = C;
pub const CODE_ID = blk: {
    @setEvalBranchQuota(10000000);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo/rv64/hybrid-child-code/v1\x00");
    hash.update(@embedFile("circuit.zig"));
    hash.update(@embedFile("child_verifier.zig"));
    break :blk hash.finalResult();
};
/// Isolated complete child graph used by the qualification executable. This
/// does not provide execution-summary admission or select a production format.
pub fn checkFixture(a: std.mem.Allocator, key: *const R.Key, outputs: []const Q, claims: Outer.witness.Claims, section: *const @import("section.zig").Section, proof: *const Outer.protocol.Proof, capture: *const Outer.prove.Capture) !void {
    var ctx = try C.Context.init(a, 0);
    defer ctx.deinit();
    C.lane.begin(&ctx);
    var active = true;
    defer if (active) C.lane.finish() catch {};
    const geometry = try shape(ctx.scratch(), key);
    const captured = try V.proof.fromNativeCapped(ctx.scratch(), proof, capture, &geometry, key.profile.foldMerkleCapLog());
    const guessed = try V.proof.guess(&ctx, &captured, &geometry);
    var identity: [8]Word = undefined;
    for (&identity, 0..) |*out, i| out.* = try circuit.builder.wrappers.guessU32(Q, &ctx, circuit.builder.wrappers.u32Value(Q, std.mem.readInt(u32, key.identity[4 * i ..][0..4], .little)));
    const output_vars = try ctx.scratch().alloc(C.Var, outputs.len);
    for (output_vars, outputs) |*out, value| out.* = try ctx.guess(value);
    const output_words = try circuit.builder.blake.unpackQm31sToU32Words(Q, &ctx, output_vars);
    var claim_vars: [P.N_COMPONENTS]F = undefined;
    for (&claim_vars, claims.toArray()) |*out, value| out.* = try F.guess(&ctx, value);
    var state: State = .{};
    defer state.deinit(ctx.gpa);
    const wired = try CG.wireSection(&ctx, section);
    _ = try V.verify(&ctx, &geometry, &guessed, Statement{ .key = key, .identity = identity, .outputs = output_vars, .output_words = output_words, .claims = claim_vars, .section = wired, .state = &state });
    active = false;
    try C.lane.finish();
    try ctx.finalize(false);
    if (!try ctx.isCircuitValid()) return error.InvalidHybridChildCircuit;
    std.debug.print("HYBRID_CHILD_CIRCUIT_OK vars={} outputs={}\n", .{ ctx.circuit.n_vars, outputs.len });
}
pub const Late = struct { gamma: F, rho: [P.MAX_INSTANCES]F };
pub const State = struct {
    z: F = undefined,
    alpha: F = undefined,
    verified: CG.Result = undefined,
    late: Late = undefined,
    verified_ready: bool = false,
    /// The verifier artifact owns host arrays of wire IDs, not circuit gates.
    /// Release them after the complete child verifier, including error paths.
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        if (self.verified_ready) self.verified.deinit(a);
        self.verified_ready = false;
    }
};
pub fn shape(a: std.mem.Allocator, key: *const R.Key) !V.Shape {
    const logs = try a.alloc([]const u32, 4);
    logs[0] = try key.source.treeLogs(a, 0);
    logs[1] = try key.source.treeLogs(a, 1);
    logs[2] = try key.interLogs(a);
    const composition = try a.alloc(u32, 16);
    @memset(composition, key.source.bound.max_evaluation_log_size - 1);
    logs[3] = composition;
    const masks = try a.alloc([]const []const i32, 4);
    for (masks, logs) |*tree, sizes| {
        const columns = try a.alloc([]const i32, sizes.len);
        @memset(columns, &.{});
        tree.* = columns;
    }
    for (key.artifacts, key.source.bound.components) |artifact, captured| {
        for (artifact.program.inputs) |input| {
            if (P.gkrBound(artifact.component) and input.tree == 2 and input.column >= 16) continue;
            const global = if (input.tree == 0) captured.preprocessed_indices[input.column] else if (input.tree == 1) (try Outer.geometry.span(captured, 1)).start + input.column else H.interactionStart(artifact.component) + input.column;
            const previous = masks[input.tree][global];
            var found = false;
            for (previous) |offset| if (offset == input.offset) {
                found = true;
                break;
            };
            if (!found) {
                const next = try a.alloc(i32, previous.len + 1);
                @memcpy(next[0..previous.len], previous);
                next[previous.len] = input.offset;
                @constCast(masks[input.tree])[global] = next;
            }
        }
    }
    for (@constCast(masks[3])) |*offset| offset.* = &.{0};
    const result = V.Shape{ .tree_column_log_sizes = logs, .mask_offsets = masks, .global_log = key.source.bound.max_evaluation_log_size - 1, .composition_log_split = 1, .pcs = key.config };
    try result.validate();
    return result;
}
fn word(ctx: *C.Context, value: u32) !Word {
    return circuit.builder.wrappers.constU32(Q, ctx, value);
}
pub const Statement = struct {
    key: *const R.Key,
    identity: [8]Word,
    outputs: []const C.Var,
    output_words: []const Word,
    claims: [P.N_COMPONENTS]F,
    section: CG.Wired,
    state: *State,
    pub fn mixPublic(self: @This(), ctx: *C.Context, channel: *C.Channel) !void {
        try channel.mixConfig(ctx, self.key.config);
        try channel.mixConstU32s(ctx, &.{ 0x434f4d38, 1, 8 });
        var profile: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(self.key.profile.domainName(), &profile, .{});
        const profile_words = try circuit.builder.blake.constantHash(Q, ctx, circuit.builder.blake.hashValueFromDigest(Q, profile));
        try channel.mixU32s(ctx, &profile_words.words);
        const public = try ctx.scratch().alloc(Word, 9 + self.output_words.len);
        @memcpy(public[0..8], &self.identity);
        public[8] = try word(ctx, @intCast(self.outputs.len));
        @memcpy(public[9..], self.output_words);
        try channel.mixU32s(ctx, public);
    }
    pub fn nTreesBeforeChallenges(_: @This()) usize {
        return 2;
    }
    pub fn drawChallenges(self: @This(), ctx: *C.Context, channel: *C.Channel) !void {
        self.state.z = try channel.draw(ctx);
        self.state.alpha = try channel.draw(ctx);
    }
    fn outputTerm(self: @This(), ctx: *C.Context, words: []const Word, address: usize) !F {
        var power = F.one();
        var denominator = F.zero();
        for ([_]u32{ circuit.common.component_list.GATE_RELATION_ID, @intCast(address) }) |coordinate| {
            denominator = denominator.add(power.mulM31(core.fields.m31.M31.fromCanonical(coordinate)));
            power = power.mul(self.state.alpha);
        }
        for (words, 0..) |coordinate, i| {
            denominator = denominator.add(power.mul(C.base(try circuit.native_verifier.channel.wordToM31(Q, ctx, coordinate))));
            if (i + 1 < words.len) power = power.mul(self.state.alpha);
        }
        return denominator.sub(self.state.z).inv();
    }
    pub fn mixClaims(self: @This(), ctx: *C.Context, channel: *C.Channel) !void {
        var external = F.zero();
        for (self.claims, 0..) |claim, i| {
            if (P.gkrBound(@enumFromInt(i))) try C.eq(ctx, claim, F.zero());
            external = external.add(claim);
        }
        for (0..self.outputs.len) |i| external = external.add(try self.outputTerm(ctx, self.output_words[4 * i ..][0..4], circuit.witness.trace.U_VAR_IDX + 1 + i));
        var u_words: [4]Word = undefined;
        for (&u_words, circuit.witness.trace.U_VALUE.toM31Array()) |*out, coordinate| out.* = try word(ctx, coordinate.v);
        external = external.add(try self.outputTerm(ctx, &u_words, circuit.witness.trace.U_VAR_IDX));
        try channel.mixFelts(ctx, &self.claims);
        var strict = CG.Channel{ .context = ctx, .inner = channel.raw };
        self.state.verified = try CG.verify(ctx, &strict, &self.key.class, &self.section);
        self.state.verified_ready = true;
        self.state.late.gamma = strict.drawSecureFelt();
        for (self.state.late.rho[0..self.key.class.instances.len]) |*rho| rho.* = strict.drawSecureFelt();
        try strict.finish();
        channel.raw = strict.inner;
        try CG.requireClosure(ctx, &self.state.verified, external);
    }
    pub fn evalComposition(self: @This(), ctx: *C.Context, point: V.Point, masks: []const []const []const F, randomness: F, _: void) !F {
        var count: usize = 0;
        for (self.key.artifacts) |artifact| count += artifact.program.roots.len;
        const powers = try ctx.scratch().alloc(F, count);
        var power = F.one();
        for (powers, 0..) |*out, i| {
            out.* = power;
            if (i + 1 < count) power = power.mul(randomness);
        }
        var result = F.zero();
        var at: usize = 0;
        for (self.key.artifacts, self.key.source.bound.components, self.claims) |*artifact, *captured, claim| {
            const parameters = try artifact.parametersFor(F, ctx.scratch(), captured, self.state.z, self.state.alpha, &self.key.class, &self.state.verified, &self.state.late, claim);
            const component = HC.Component{ .allocator = ctx.scratch(), .source = captured, .artifact = artifact, .fixed_logs = &self.key.source.fixed_logs, .class = &self.key.class, .verified = undefined, .parameters = &.{} };
            const mask = struct { items: []const []const []const F }{ .items = masks };
            const roots = try component.valuesAtPointFor(F, ctx.scratch(), .{ .x = point.x, .y = point.y }, &mask, self.key.source.bound.max_evaluation_log_size - 1, self.state.verified.artifact.ood_point, parameters);
            const inverse = try @import("stwo_riscv_frontend").rv64_air.geometry.denominatorInverseFor(F, .{ .x = point.x, .y = point.y }, self.key.source.bound.max_evaluation_log_size - 1, captured.trace_log_size);
            for (roots) |root| {
                result = result.add(root.mul(inverse).mul(powers[count - 1 - at]));
                at += 1;
            }
        }
        return result;
    }
};
