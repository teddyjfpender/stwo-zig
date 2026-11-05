//! Resident hybrid outer proof controller. The original factory supplies only
//! MAIN/FIXED; a tagged higher-layer extension supplies GKR, late binding and
//! the source-owned hybrid GPU composition. Every device refusal is terminal.
const std = @import("std");
const core = @import("stwo_core");
const api = @import("stwo_prover_api");
const engine = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const Native = Outer.device_prove;
const D = api.device_pcs;
const R = @import("hybrid_receiver.zig");
const HC = @import("hybrid_component.zig");
const P = @import("profile.zig");
const S = @import("section.zig");
const Legacy = @import("binding.zig");
const O = core.fields.om31.OM31;
pub const TAG: [32]u8 = blk: {
    @setEvalBranchQuota(100000);
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("stwo/rv64/outer-hybrid-factory/v1", &out, .{});
    break :blk out;
};
pub const Stage = struct { claims: Outer.witness.Claims, section: S.Section };
pub const Source = struct {
    context: *anyopaque,
    base: Native.Source,
    composition: *const api.device_composition.ResidentOm31Stage,
    /// Starts from the supplied immutable transcript snapshot. It computes the
    /// classic claims, mixes them before GKR, and returns owned proof material.
    gkr: *const fn (*anyopaque, std.mem.Allocator, *const R.Key, D.Scope, O, O, *const S.RawChannel) anyerror!Stage,
    /// Called only after independent GKR verification, strict late draws and
    /// lookup closure. It commits exactly128INTER columns and configures the
    /// hybrid composition stage with the same receiver-derived terminal data.
    interaction: *const fn (*anyopaque, std.mem.Allocator, *const R.Key, D.Scope, O, O, *const S.Verified, *const Legacy.Challenges) anyerror!D.Tree,
    release: *const fn (*anyopaque) void,
};
pub const Interface = struct {
    /// Consumes base ONLY on success; failure leaves its ownership to caller.
    prepare: *const fn (*anyopaque, *anyopaque, std.mem.Allocator, *const R.Key, Native.Source) anyerror!Source,
};
pub fn attach(base: Native.Factory, context: *anyopaque, interface: *const Interface) Native.Factory {
    var out = base;
    out.extension = .{ .tag = TAG, .base_context = base.context, .context = context, .interface = interface };
    return out;
}
pub fn extension(factory: Native.Factory) !struct { context: *anyopaque, interface: *const Interface } {
    const extra = factory.extension orelse return error.HybridFactoryRequired;
    if (!std.mem.eql(u8, &extra.tag, &TAG) or extra.base_context != factory.context) return error.InvalidHybridFactoryExtension;
    return .{ .context = extra.context, .interface = @ptrCast(@alignCast(extra.interface)) };
}
pub const Produced = struct {
    base: Outer.prove.Produced,
    section: S.Section,
    pub fn deinit(self: *@This()) void {
        self.section.deinit(self.base.allocator);
        self.base.deinit();
        self.* = undefined;
    }
};
fn statement(key: *const R.Key, outputs: []const Outer.protocol.Q) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("stwo/circuit/hybrid-om31/resident-request/v2\x00");
    h.update(&key.identity);
    var word: [4]u8 = undefined;
    std.mem.writeInt(u32, &word, @intCast(outputs.len), .little);
    h.update(&word);
    for (outputs) |output| for (output.toM31Array()) |coordinate| {
        std.mem.writeInt(u32, &word, coordinate.v, .little);
        h.update(&word);
    };
    return h.finalResult();
}
pub fn proveFromCircuit(a: std.mem.Allocator, key: *const R.Key, graph: *const circuit.builder.Context(Outer.protocol.Q), expected: []const Outer.protocol.Q, ordinal: u32, factory: Native.Factory, fixed: ?*const Native.PrecommittedFixed) !Produced {
    const ext = try extension(factory);
    try key.source.requireProverData();
    if (!graph.trace_only or !graph.finalized or !graph.record_gates or graph.witness_metadata == null) return error.TraceOnlyGraphRequired;
    if (expected.len != key.source.pp.n_outputs) return error.InvalidOm31CircuitOutputCount;
    for (expected) |output| for (output.toM31Array()) |coordinate| if (coordinate.v >= core.fields.m31.Modulus) return error.NoncanonicalOm31CircuitOutput;
    if (key.source.device_fixed != (fixed != null)) return error.InvalidOm31DeviceFixedRoot;
    const outputs = try a.dupe(Outer.protocol.Q, expected);
    errdefer a.free(outputs);
    const requested = D.Scope{ .statement = statement(key, outputs), .fixed = key.source.fixedRoot(), .main = @splat(0), .ordinal = ordinal };
    const base = if (fixed) |setup| blk: {
        if (setup.scope.ordinal != ordinal or !std.mem.eql(u8, &setup.tree.root, &key.source.fixedRoot())) return error.InvalidOm31DeviceFixedRoot;
        break :blk try setup.prepare_from_circuit(setup.context, a, key.source, graph, requested);
    } else try (factory.prepare_from_circuit orelse return error.TraceOnlySourceRequired)(factory.context, a, key.source, graph, requested);
    var base_owned = true;
    defer if (base_owned) base.release(base.context);
    if (!std.mem.eql(u8, &base.scope.statement, &requested.statement) or !std.mem.eql(u8, &base.scope.fixed, &requested.fixed) or base.scope.ordinal != ordinal or !std.mem.eql(u8, &base.scope.main, &base.main.root)) return error.InvalidOm31CircuitDeviceScope;
    const main_logs = try key.source.treeLogs(a, 1);
    defer a.free(main_logs);
    try Native.validateTree(main_logs, base.main);
    const source = try ext.interface.prepare(ext.context, factory.context, a, key, base);
    base_owned = false;
    defer source.release(source.context);
    if (source.base.context != base.context or !std.meta.eql(source.base.scope, base.scope)) return error.InvalidHybridSourceCustody;
    var channel = try key.begin(a, outputs);
    var scheme = try Outer.protocol.Engine.init(a, key.config);
    var owns = true;
    defer if (owns) scheme.deinit(a);
    scheme.device_om31_pcs_stage = base.pcs;
    scheme.device_om31_composition_stage = source.composition;
    scheme.device_om31_scope = base.scope;
    if (base.fixed) |tree| {
        if (fixed == null or !std.mem.eql(u8, &tree.root, &key.source.fixedRoot())) return error.InvalidOm31DeviceFixedRoot;
        try Native.validateTree(&key.source.fixed_logs, tree);
        if (tree.columns[0].device.?.context_token != base.main.columns[0].device.?.context_token) return error.MixedOm31CircuitDeviceContexts;
        try scheme.adoptDeviceOm31TraceTree(0, tree, &channel);
    } else {
        if (fixed != null) return error.MissingOm31DeviceFixedTree;
        try scheme.trees.ensureUnusedCapacity(a, 1);
        scheme.trees.appendAssumeCapacity(try key.source.retainFixed());
        Outer.protocol.MC.mixRoot(&channel, key.source.fixedRoot());
    }
    try scheme.adoptDeviceOm31TraceTree(1, base.main, &channel);
    const draws = Outer.prove.draw(&channel);
    var stage = try source.gkr(source.context, a, key, base.scope, draws.z, draws.alpha, &channel);
    errdefer stage.section.deinit(a);
    const claims = stage.claims.toArray();
    for (claims, 0..) |claim, i| if (P.gkrBound(@enumFromInt(i)) and !claim.isZero()) return error.InvalidHybridClassicClaim;
    channel.mixFelts(&claims);
    stage.section.class = &key.class;
    var verified = try S.verify(a, &channel, &stage.section);
    defer verified.deinit(a);
    var strict = S.StrictChannel{ .inner = channel };
    const late = Legacy.drawChallenges(&strict, key.class.instances.len);
    if (strict.rejected) return error.OuterGkrDrawRejected;
    channel = strict.inner;
    const elements = Outer.witness.Elements.init(draws.z, draws.alpha);
    try S.requireClosure(&verified, try Outer.witness.lookupSum(outputs, stage.claims, &elements));
    const inter = try source.interaction(source.context, a, key, base.scope, draws.z, draws.alpha, &verified, &late);
    const inter_logs = try key.interLogs(a);
    defer a.free(inter_logs);
    try Native.validateTree(inter_logs, inter);
    if (inter.columns[0].device.?.context_token != base.main.columns[0].device.?.context_token) return error.MixedOm31CircuitDeviceContexts;
    try scheme.adoptDeviceOm31TraceTree(2, inter, &channel);
    var bound: [P.N_COMPONENTS]HC.Component = undefined;
    var components: [P.N_COMPONENTS]engine.air.component_prover.ForField(O).ComponentProver = undefined;
    var made: usize = 0;
    defer for (bound[0..made]) |component| a.free(component.parameters);
    for (&bound, &components, key.artifacts, key.source.bound.components, claims) |*component, *out, *artifact, *captured, claim| {
        const params = try artifact.parameters(a, captured, draws.z, draws.alpha, &key.class, &verified, &late, claim);
        component.* = .{ .allocator = a, .source = captured, .artifact = artifact, .fixed_logs = &key.source.fixed_logs, .class = &key.class, .verified = &verified, .parameters = params };
        made += 1;
        out.* = component.asProverComponent();
    }
    owns = false;
    const proof = try Outer.protocol.Engine.prove(a, &components, &channel, scheme, .{});
    return .{ .base = .{ .allocator = a, .outputs = outputs, .claims = stage.claims, .proof = proof }, .section = stage.section };
}
