//! In-circuit verifier gadget for the outer LogUp-GKR section (profile outer_gkr_om31_strict_v1),
//! for the leaf/fold circuits that verify an outer child proof. OM31 lanes (two QM31 wires), the
//! raw-Blake OM31 channel evaluated in circuit, the SAME numerical verifier (verifier_kernel) as
//! the CPU reference, and a constant shape per class: every count is a class constant, proof values
//! are guessed wires.
//!
//! Strict draws: each draw constrains all eight raw words < 2p before reducing them, i.e. the circuit
//! is unsatisfiable on exactly the transcripts the CPU reference rejects (section.zig).
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const lane = @import("../rv64_recursion/om31_circuit_lane.zig");
const C = @import("../logup_gkr/om31_circuit_verifier.zig");
const P = @import("profile.zig");
const S = @import("section.zig");
const builder = circuit.builder;
const raw = circuit.native_verifier.raw_mod_channel;
pub const F = C.F;
pub const Q = C.Q;
const O = C.O;
pub const Context = C.Context;
const Var = builder.Var;
const Word = builder.wrappers.U32Wrapper(Var);
const Error = builder.context.Error;
const M31 = core.fields.m31.M31;
pub const kernel = C.kernel;

/// Constrains word < 2p = 2^32 - 2. With 16-bit limbs (lo, hi): word >= 2p iff hi = 0xffff and
/// lo in {0xfffe, 0xffff}. t = hi - 0xffff, s = (lo - 0xfffe)(lo - 0xffff) are base-field values and
/// p = 3 mod 4 (-1 is a non-residue), so t^2 + s^2 = 0 iff t = s = 0. The eight factors of one draw
/// are multiplied and the product is shown nonzero with one guessed inverse.
fn inadmissibleFactor(ctx: *Context, word: Word) Error!Var {
    const packed_word = [1]Var{word.get()};
    const lanes = builder.simd.Simd.fromPacked(&packed_word, 2);
    const lo = try builder.simd.unpackIdx(Q, ctx, lanes, 0);
    const hi = try builder.simd.unpackIdx(Q, ctx, lanes, 1);
    const t = try ctx.sub(hi, try ctx.constant(Q.fromBase(M31.fromCanonical(0xffff))));
    const s = try ctx.mul(
        try ctx.sub(lo, try ctx.constant(Q.fromBase(M31.fromCanonical(0xfffe)))),
        try ctx.sub(lo, try ctx.constant(Q.fromBase(M31.fromCanonical(0xffff)))),
    );
    return ctx.add(try ctx.mul(t, t), try ctx.mul(s, s));
}
pub fn requireAdmissible(ctx: *Context, words: *const [8]Word) Error!void {
    var product = try inadmissibleFactor(ctx, words[0]);
    for (words[1..]) |w| product = try ctx.mul(product, try inadmissibleFactor(ctx, w));
    const value = ctx.get(product);
    // Witness: the inverse when it exists; zero otherwise (the constraint then fails, never panics).
    const witness = if (value.isZero()) Q.zero() else Q.one().div(value) catch Q.zero();
    const inverse = try ctx.guess(witness);
    try ctx.eq(try ctx.mul(product, inverse), ctx.one());
}

/// Strict in-circuit channel with the kernel's infallible interface (errors latched, reported by
/// finish(); a partial graph is never accepted).
pub const Channel = struct {
    context: *Context,
    inner: raw.Om31Channel,
    failure: ?Error = null,
    draws: u32 = 0,
    pub fn init(context: *Context) Error!Channel {
        return .{ .context = context, .inner = try raw.Om31Channel.init(Q, context) };
    }
    pub fn mixFelts(self: *Channel, values: []const F) void {
        if (self.failure != null) return;
        const wires = self.context.scratch().alloc(raw.Om31Var, values.len) catch |err| {
            self.failure = err;
            return;
        };
        for (wires, values) |*wire, value| wire.* = .{ .c0 = value.c0.v, .c1 = value.c1.v };
        self.inner.mixFelts(Q, self.context, wires) catch |err| {
            self.failure = err;
        };
    }
    pub fn mixConstU32s(self: *Channel, values: []const u32) void {
        if (self.failure != null) return;
        const words = self.context.scratch().alloc(Word, values.len) catch |err| {
            self.failure = err;
            return;
        };
        for (words, values) |*w, v| w.* = builder.wrappers.constU32(Q, self.context, v) catch |err| {
            self.failure = err;
            return;
        };
        self.inner.mixU32s(Q, self.context, words) catch |err| {
            self.failure = err;
        };
    }
    pub fn drawSecureFelt(self: *Channel) F {
        if (self.failure != null) return F.zero();
        const words = self.inner.drawU32s(Q, self.context) catch |err| {
            self.failure = err;
            return F.zero();
        };
        requireAdmissible(self.context, &words) catch |err| {
            self.failure = err;
            return F.zero();
        };
        const value = raw.reduceBlock(Q, self.context, &words) catch |err| {
            self.failure = err;
            return F.zero();
        };
        self.draws += 1;
        return F.wire(value.c0, value.c1);
    }
    /// In-circuit twin of section.benchChannel() (bench/test starting transcript; in production
    /// the parent's channel already holds the child's outer transcript at the hook point).
    pub fn initBench(context: *Context) Error!Channel {
        var c = try init(context);
        c.mixConstU32s(&.{ 0x4f47_4b52, 0x42454e43 });
        if (c.failure) |err| return err;
        return c;
    }
    pub fn finish(self: *const Channel) Error!void {
        if (self.failure) |err| return err;
        try lane.check();
    }
};

pub const Wired = struct {
    salt: F,
    proof: C.Proof,
};
/// Guess every proof value of a natively decoded section. The class (not the proof) fixes shape.
pub fn wireSection(context: *Context, section: *const S.Section) !Wired {
    try S.checkShape(section.class, &section.proof);
    return .{ .salt = try F.guess(context, section.salt), .proof = try C.wireProof(context, &section.proof) };
}

pub const Result = struct {
    artifact: kernel.Artifact(F),
    root_sum: F,
    pub fn deinit(self: *Result, a: std.mem.Allocator) void {
        self.artifact.deinit(a);
    }
};
/// In-circuit verify: header constants + salt, batched GKR, root poles excluded (inverse
/// constraints), root sum returned for the caller's closure equation. The caller binds the terminal
/// claims to its authenticated input evaluations with `requireTerminal`.
pub fn verify(context: *Context, channel: *Channel, class: *const P.Class, wired: *const Wired) !Result {
    try class.validate();
    if (wired.proof.sumcheck_proofs.len != class.layers() or wired.proof.output_claims_by_instance.len != class.instances.len) return error.OuterGkrShapeMismatch;
    for (wired.proof.sumcheck_proofs, 0..) |sc, depth| {
        if (sc.round_polys.len != depth) return error.OuterGkrShapeMismatch;
        for (sc.round_polys) |poly| if (poly.coefficients.len != P.COEFFICIENTS_PER_ROUND) return error.OuterGkrShapeMismatch;
    }
    var buf: [12 + P.MAX_INSTANCES]u32 = undefined;
    channel.mixConstU32s(try class.header(&buf));
    channel.mixFelts(&.{wired.salt});
    const gates = [_]S.G.Gate{.LogUp} ** P.MAX_INSTANCES;
    var artifact = try kernel.partiallyVerifyBatch(F, context.gpa, gates[0..class.instances.len], &wired.proof, channel, C.Checks{ .context = context });
    errdefer artifact.deinit(context.gpa);
    try channel.finish();
    for (artifact.n_variables_by_instance, class.instances) |n, inst| if (n != inst.variables()) return error.OuterGkrShapeMismatch;
    // Leading coefficients nonzero (constant mixing length is only unambiguous with deg = 3).
    for (wired.proof.sumcheck_proofs) |sc| for (sc.round_polys) |poly| {
        _ = poly.coefficients[P.COEFFICIENTS_PER_ROUND - 1].inv();
    };
    var root_sum = F.zero();
    for (wired.proof.output_claims_by_instance) |root| root_sum = root_sum.add(root[0].mul(root[1].inv()));
    try lane.check();
    return .{ .artifact = artifact, .root_sum = root_sum };
}
pub fn requireClosure(context: *Context, result: *const Result, external_sum: F) !void {
    try (C.Checks{ .context = context }).requireEq(result.root_sum.add(external_sum), F.zero(), .terminal);
}
pub fn requireTerminal(context: *Context, result: *const Result, expected: []const [2]F) !void {
    var views: [P.MAX_INSTANCES][]const F = undefined;
    if (expected.len > P.MAX_INSTANCES) return error.OuterGkrShapeMismatch;
    for (expected, 0..) |*e, i| views[i] = e;
    try kernel.verifyTerminalInputs(F, &result.artifact, views[0..expected.len], C.Checks{ .context = context });
}

pub const Cost = struct {
    blake_g_gate: u64,
    qm31_ops: u64,
    m31_to_u32: u64,
    triple_xor: u64,
    eq: u64,
    variables: u64,
    draws: u32,
    valid: bool,
};
/// Builds the gadget for one section (terminal claims guessed equal to the artifact's claims, as the
/// leaf's binding columns would supply them; closure against `external_sum`) and returns its gate
/// counts. Used for the production-shape cost receipt on GPU-proved sections.
pub fn measure(a: std.mem.Allocator, section: *const S.Section, external_sum: O, terminal: ?[]const [2]O) !Cost {
    var context = try Context.init(a, 0);
    defer context.deinit();
    lane.begin(&context);
    var bound = true;
    defer if (bound) lane.finish() catch {};
    const wired = try wireSection(&context, section);
    var channel = try Channel.initBench(&context);
    var result = try verify(&context, &channel, section.class, &wired);
    defer result.deinit(a);
    try requireClosure(&context, &result, try F.guess(&context, external_sum));
    const expected = try a.alloc([2]F, section.class.instances.len);
    defer a.free(expected);
    for (expected, result.artifact.claims_to_verify_by_instance, 0..) |*e, claims, i| {
        if (terminal) |t| {
            e.* = .{ try F.guess(&context, t[i][0]), try F.guess(&context, t[i][1]) };
        } else e.* = .{ try F.guess(&context, claims[0].value()), try F.guess(&context, claims[1].value()) };
    }
    try requireTerminal(&context, &result, expected);
    try channel.finish();
    bound = false;
    try lane.finish();
    try context.finalize(false);
    const g = context.gate_counts;
    return .{ .blake_g_gate = g.blake_g_gate, .qm31_ops = g.qm31_ops, .m31_to_u32 = g.m31_to_u32, .triple_xor = g.triple_xor, .eq = g.eq, .variables = context.circuit.n_vars, .draws = channel.draws, .valid = try context.isCircuitValid() };
}
