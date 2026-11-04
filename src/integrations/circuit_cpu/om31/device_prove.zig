//! Native OM31 circuit controller over explicit resident device stages. The
//! default CPU controller is unchanged. Device refusal is terminal; no host
//! MAIN/INTER matrices or polynomial stand-ins are constructed here.
const std = @import("std");
const api = @import("stwo_prover_api");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const P = @import("protocol.zig");
const Native = @import("prove.zig");
const Witness = @import("witness.zig");
const D = api.device_pcs;
pub const Interaction = struct { tree: D.Tree, claims: Witness.Claims };
pub const Source = struct {
    context: *anyopaque,
    scope: D.Scope,
    main: D.Tree,
    fixed: ?D.Tree = null,
    pcs: *const D.Stage,
    composition: *const api.device_composition.ResidentOm31Stage,
    /// Must generate/commit exact native cumulative INTER under these fresh
    /// challenges. The owner retains both trees until release after PCS.
    generate: *const fn (*anyopaque, std.mem.Allocator, *const Native.Authority, D.Scope, P.O, P.O) anyerror!Interaction,
    release: *const fn (*anyopaque) void,
};
pub const PrecommittedFixed = struct {
    context: *anyopaque,
    tree: D.Tree,
    scope: D.Scope,
    prepare_from_circuit: *const fn (*anyopaque, std.mem.Allocator, *const Native.Authority, *const circuit.builder.Context(P.Q), D.Scope) anyerror!Source,
    release: *const fn (*anyopaque) void,
};
/// Device-free, factory-owned host preparation of one exact finalized graph
/// (e.g. the device assignment plan). It may be built on any thread before
/// device admission; it is bound to `graph` by identity and consumed only by a
/// device source preparing that same graph. `destroy` releases an unconsumed one.
pub const HostPrepared = struct {
    context: *anyopaque,
    graph: *const anyopaque,
    destroy: *const fn (*anyopaque) void,
};
/// Host-only producer hint (fold v2): the geometry class of the fold graph the
/// calling thread is about to prove, or null. Device factories may key
/// topology-only caches (assignment plans) by it; it never enters a proof.
pub threadlocal var class_hint: ?[32]u8 = null;
pub const Factory = struct {
    context: *anyopaque,
    /// Optional device-free host stage. Thread-safe with respect to this
    /// factory's device work: it never touches device or active-proof state.
    prepare_host: ?*const fn (*anyopaque, std.mem.Allocator, *const circuit.builder.Context(P.Q)) anyerror!HostPrepared = null,
    /// Moves a HostPrepared into this factory's next trace-only source. Takes
    /// ownership on every path; a refused value is destroyed before returning.
    stage_host: ?*const fn (*anyopaque, HostPrepared) anyerror!void = null,
    /// Discards a staged value that no source consumed. Idempotent.
    unstage_host: ?*const fn (*anyopaque) void = null,
    /// Explicit default-off prover setup. Receivers/restores never invoke it.
    precommit_fixed: ?*const fn (*anyopaque, std.mem.Allocator, *const circuit.common.preprocessed.PreprocessedCircuit, u32) anyerror!PrecommittedFixed = null,
    /// Consumes only immutable authority and narrow builder assignments; source
    /// MAIN generation and commitment happen on device. Failure is atomic and
    /// owns no result. On success Source owns all temporary/device allocations.
    prepare: *const fn (*anyopaque, std.mem.Allocator, *const Native.Authority, []const P.Q, D.Scope) anyerror!Source,
    /// Explicit trace-only ingress. The independently constructed source owns
    /// compact proof seeds and the original topology; no CPU values stand-in.
    prepare_from_circuit: ?*const fn (*anyopaque, std.mem.Allocator, *const Native.Authority, *const circuit.builder.Context(P.Q), D.Scope) anyerror!Source = null,
};
fn statement(key: *const Native.Authority, outputs: []const P.Q) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo/circuit/native-om31/resident-request/v1\x00");
    hash.update(&key.identity);
    var word: [4]u8 = undefined;
    std.mem.writeInt(u32, &word, @intCast(outputs.len), .little);
    hash.update(&word);
    for (outputs) |output| for (output.toM31Array()) |m| {
        std.mem.writeInt(u32, &word, m.v, .little);
        hash.update(&word);
    };
    return hash.finalResult();
}
/// Structural validation is followed by the device stage's stronger physical
/// lease/context/generation/scope checks. An address is never host dereferenced.
pub fn validateTree(logs: []const u32, tree: D.Tree) !void {
    if (logs.len != tree.columns.len or logs.len == 0) return error.InvalidOm31CircuitDeviceGeometry;
    var context: ?u64 = null;
    for (logs, tree.columns) |log, column| {
        const device = column.device orelse return error.Om31CircuitHostDeviceColumn;
        if (log != column.log_size or log < 4 or log > 28 or column.coefficients.len != 0 or device.context_token == 0 or device.generation == 0 or device.count != @as(u64, 1) << @intCast(log)) return error.InvalidOm31CircuitDeviceGeometry;
        if (context) |token| {
            if (token != device.context_token) return error.MixedOm31CircuitDeviceContexts;
        } else context = device.context_token;
    }
}
pub fn prove(a: std.mem.Allocator, key: *const Native.Authority, values: []const P.Q, ordinal: u32, factory: Factory) !Native.Produced {
    try key.requireProverData();
    const start = circuit.witness.trace.U_VAR_IDX + 1;
    if (values.len < start or key.pp.n_outputs > values.len - start) return error.InvalidOm31CircuitOutputCount;
    const outputs = try a.dupe(P.Q, values[start..][0..key.pp.n_outputs]);
    return proveOwned(a, key, outputs, values, ordinal, factory, null, null);
}
/// Expected outputs come from the independently authenticated public statement.
/// The circuit MAIN must produce precisely those values: the existing output
/// lookup closure and STARK verification bind them under the unchanged AIR.
pub fn proveFromCircuit(a: std.mem.Allocator, key: *const Native.Authority, graph: *const circuit.builder.Context(P.Q), expected: []const P.Q, ordinal: u32, factory: Factory) !Native.Produced {
    if (factory.prepare_from_circuit == null) return error.TraceOnlySourceRequired;
    try key.requireProverData();
    if (!graph.trace_only or !graph.finalized or !graph.record_gates or graph.witness_metadata == null) return error.TraceOnlyGraphRequired;
    if (expected.len != key.pp.n_outputs) return error.InvalidOm31CircuitOutputCount;
    for (expected) |value| for (value.toM31Array()) |coordinate| if (coordinate.v >= core.fields.m31.Modulus) return error.NoncanonicalOm31CircuitOutput;
    const outputs = try a.dupe(P.Q, expected);
    return proveOwned(a, key, outputs, &.{}, ordinal, factory, graph, null);
}
pub fn proveFromPrecommittedCircuit(a: std.mem.Allocator, key: *const Native.Authority, graph: *const circuit.builder.Context(P.Q), expected: []const P.Q, ordinal: u32, fixed: *const PrecommittedFixed) !Native.Produced {
    try key.requireProverData();
    if (fixed.scope.ordinal != ordinal or !key.device_fixed or !std.mem.eql(u8, &fixed.tree.root, &key.fixedRoot())) return error.InvalidOm31DeviceFixedRoot;
    try validateTree(&key.fixed_logs, fixed.tree);
    if (!graph.trace_only or !graph.finalized or !graph.record_gates or graph.witness_metadata == null) return error.TraceOnlyGraphRequired;
    if (expected.len != key.pp.n_outputs) return error.InvalidOm31CircuitOutputCount;
    for (expected) |value| for (value.toM31Array()) |coordinate| if (coordinate.v >= core.fields.m31.Modulus) return error.NoncanonicalOm31CircuitOutput;
    const outputs = try a.dupe(P.Q, expected);
    return proveOwned(a, key, outputs, &.{}, ordinal, undefined, graph, fixed);
}
fn proveOwned(a: std.mem.Allocator, key: *const Native.Authority, outputs: []P.Q, values: []const P.Q, ordinal: u32, factory: Factory, graph: ?*const circuit.builder.Context(P.Q), precommitted: ?*const PrecommittedFixed) !Native.Produced {
    errdefer a.free(outputs);
    try key.requireProverData();
    const requested = D.Scope{ .statement = statement(key, outputs), .fixed = key.fixedRoot(), .main = @splat(0), .ordinal = ordinal };
    if (key.device_fixed != (precommitted != null)) return error.InvalidOm31DeviceFixedRoot;
    const source = if (precommitted) |fixed| try fixed.prepare_from_circuit(fixed.context, a, key, graph.?, requested) else if (graph) |ctx| try factory.prepare_from_circuit.?(factory.context, a, key, ctx, requested) else try factory.prepare(factory.context, a, key, values, requested);
    defer source.release(source.context);
    if (!std.mem.eql(u8, &source.scope.statement, &requested.statement) or !std.mem.eql(u8, &source.scope.fixed, &requested.fixed) or source.scope.ordinal != ordinal or !std.mem.eql(u8, &source.scope.main, &source.main.root)) return error.InvalidOm31CircuitDeviceScope;
    const main_logs = try key.treeLogs(a, 1);
    defer a.free(main_logs);
    try validateTree(main_logs, source.main);
    var channel = try Native.begin(a, key, outputs);
    var scheme = try P.Engine.init(a, try P.targetConfig());
    var owns = true;
    defer if (owns) scheme.deinit(a);
    scheme.device_om31_pcs_stage = source.pcs;
    scheme.device_om31_composition_stage = source.composition;
    scheme.device_om31_scope = source.scope;
    if (source.fixed) |fixed| {
        if (precommitted == null or !std.mem.eql(u8, &fixed.root, &key.fixedRoot())) return error.InvalidOm31DeviceFixedRoot;
        try validateTree(&key.fixed_logs, fixed);
        if (fixed.columns[0].device.?.context_token != source.main.columns[0].device.?.context_token) return error.MixedOm31CircuitDeviceContexts;
        try scheme.adoptDeviceOm31TraceTree(0, fixed, &channel);
    } else {
        if (precommitted != null) return error.MissingOm31DeviceFixedTree;
        try scheme.trees.ensureUnusedCapacity(a, 1);
        scheme.trees.appendAssumeCapacity(try key.retainFixed());
        P.MC.mixRoot(&channel, key.fixedRoot());
    }
    try scheme.adoptDeviceOm31TraceTree(1, source.main, &channel);
    const challenges = Native.draw(&channel);
    const interaction = try source.generate(source.context, a, key, source.scope, challenges.z, challenges.alpha);
    const inter_logs = try key.treeLogs(a, 2);
    defer a.free(inter_logs);
    try validateTree(inter_logs, interaction.tree);
    if (interaction.tree.columns[0].device.?.context_token != source.main.columns[0].device.?.context_token) return error.MixedOm31CircuitDeviceContexts;
    const elements = Witness.Elements.init(challenges.z, challenges.alpha);
    if (!(try Witness.lookupSum(outputs, interaction.claims, &elements)).isZero()) return error.InvalidOm31CircuitLookupSum;
    channel.mixFelts(&interaction.claims.toArray());
    try scheme.adoptDeviceOm31TraceTree(2, interaction.tree, &channel);
    const bound = try Native.bind(a, key, challenges.z, challenges.alpha, interaction.claims);
    defer a.free(bound);
    const Component = engine.air.component_prover.ForField(P.O).ComponentProver;
    const components = try a.alloc(Component, bound.len);
    defer a.free(components);
    for (components, bound) |*out, *component| out.* = component.asProverComponent();
    owns = false;
    const proof = try P.Engine.prove(a, components, &channel, scheme, .{});
    return .{ .allocator = a, .outputs = outputs, .claims = interaction.claims, .proof = proof };
}
test "native OM31 device controller rejects host geometry and mixed custody" {
    const ptr: [*]const u32 = @ptrFromInt(4096);
    var columns = [_]D.Column{ .{ .log_size = 4, .device = .{ .words = ptr, .count = 16, .context_token = 1, .generation = 1 } }, .{ .log_size = 4, .device = .{ .words = ptr, .count = 16, .context_token = 1, .generation = 1 } } };
    try validateTree(&.{ 4, 4 }, .{ .root = @splat(0), .columns = &columns });
    columns[1].device.?.context_token = 2;
    try std.testing.expectError(error.MixedOm31CircuitDeviceContexts, validateTree(&.{ 4, 4 }, .{ .root = @splat(0), .columns = &columns }));
    columns[1].device = null;
    try std.testing.expectError(error.Om31CircuitHostDeviceColumn, validateTree(&.{ 4, 4 }, .{ .root = @splat(0), .columns = &columns }));
    columns[1] = columns[0];
    columns[1].device.?.count = 32;
    try std.testing.expectError(error.InvalidOm31CircuitDeviceGeometry, validateTree(&.{ 4, 4 }, .{ .root = @splat(0), .columns = &columns }));
    const implementation: *const fn (std.mem.Allocator, *const Native.Authority, []const P.Q, u32, Factory) anyerror!Native.Produced = prove;
    _ = implementation;
}

test "trace-only device ingress requires explicit graph source before allocation" {
    const Never = struct {
        fn prepare(_: *anyopaque, _: std.mem.Allocator, _: *const Native.Authority, _: []const P.Q, _: D.Scope) !Source {
            return error.UnexpectedLegacyFallback;
        }
    };
    var key: Native.Authority = undefined;
    var graph: circuit.builder.Context(P.Q) = undefined;
    var context: u8 = 0;
    const factory = Factory{ .context = &context, .prepare = Never.prepare };
    try std.testing.expectError(error.TraceOnlySourceRequired, proveFromCircuit(std.testing.allocator, &key, &graph, &.{}, 0, factory));
}
