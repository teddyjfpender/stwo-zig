//! Explicit CPU producer for the existing M7 wire and receiver authority.
//! No GPU factory, alternate AIR, changed transcript or receiver fallback.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const R = @import("hybrid_receiver.zig");
const P = @import("profile.zig");
const S = @import("section.zig");
const W = @import("cpu_witness.zig");
const HC = @import("hybrid_component.zig");
const Legacy = @import("binding.zig");
const O = core.fields.om31.OM31;
const Capture = Outer.stage_capture;
const Metrics = @import("cpu_metrics.zig");
pub const Produced = @import("hybrid_device.zig").Produced;

pub fn prove(a: std.mem.Allocator, key: *const R.Key, values: []const Outer.protocol.Q, expected: []const Outer.protocol.Q) !Produced {
    return proveImpl(a, key, values, expected, null);
}
pub fn proveWithInputsForTesting(a: std.mem.Allocator, key: *const R.Key, values: []const Outer.protocol.Q, expected: []const Outer.protocol.Q, mutate: *const fn (*S.Inputs) anyerror!void) !Produced {
    if (!@import("builtin").is_test) return error.TestOnly;
    return proveImpl(a, key, values, expected, mutate);
}
fn proveImpl(a: std.mem.Allocator, key: *const R.Key, values: []const Outer.protocol.Q, expected: []const Outer.protocol.Q, mutate: ?*const fn (*S.Inputs) anyerror!void) !Produced {
    if (!key.profile.hybrid()) return error.HybridCpuRequiresM7Profile;
    try key.source.requireProverData();
    if (key.source.fixed == null or key.source.device_fixed) return error.HybridCpuRequiresHostFixed;
    var capture = try Capture.Capture.init(a);
    defer if (capture) |*active| active.deinit();
    const recorder = if (capture) |*active| &active.recorder else null;
    var witness_scope = try Capture.Scope.begin(recorder, "outer_witness", "Hybrid circuit MAIN witness");
    defer witness_scope.end();
    var base = try circuit.witness.trace.writeTrace(a, values, key.source.pp);
    witness_scope.end();
    defer base.deinit();
    if (!std.meta.eql(base.log_sizes, key.source.logs) or expected.len != base.output_values.len) return error.InvalidHybridGeometry;
    for (expected, base.output_values) |want, actual| if (!want.eql(actual)) return error.HybridCpuOutputMismatch;
    const outputs = try a.dupe(Outer.protocol.Q, expected);
    errdefer a.free(outputs);
    var channel = try key.begin(a, outputs);
    var scheme = try Outer.protocol.Engine.init(a, key.config);
    var owns = true;
    defer if (owns) scheme.deinit(a);
    try scheme.trees.ensureUnusedCapacity(a, 1);
    scheme.trees.appendAssumeCapacity(try key.source.retainFixed());
    Outer.protocol.MC.mixRoot(&channel, key.source.fixedRoot());
    var main_scope = try Capture.Scope.begin(recorder, "outer_main_commit", "Hybrid circuit MAIN preparation and commitment");
    defer main_scope.end();
    try scheme.commit(a, base.columns, &channel);
    main_scope.end();
    const draws = Outer.prove.draw(&channel);
    const elements = Outer.witness.Elements.init(draws.z, draws.alpha);
    const raw = try circuit.witness.trace.RawLookupRows.init(base.columns, key.source.pp);
    var classic_scope = try Capture.Scope.begin(recorder, "outer_classic_witness", "Hybrid retained classic lookup witness");
    defer classic_scope.end();
    var classic = try W.classic(a, &key.class, &raw, &elements);
    classic_scope.end();
    defer classic.deinit(a);
    const claims = classic.claims.toArray();
    channel.mixFelts(&claims);
    var input_scope = try Capture.Scope.begin(recorder, "outer_gkr_inputs", "Hybrid lane-major lookup facts");
    defer input_scope.end();
    var inputs = try W.inputs(a, &key.class, &raw, &elements);
    input_scope.end();
    var inputs_owned = true;
    defer if (inputs_owned) inputs.deinit(a);
    circuit.witness.trace.freeColumns(base.allocator, base.takeColumns());
    if (mutate) |corrupt| try corrupt(&inputs);
    var gkr_scope = try Capture.Scope.begin(recorder, "outer_gkr_prove", "Hybrid lookup GKR section");
    defer gkr_scope.end();
    var section = try S.proveCpu(a, &channel, &key.class, &inputs);
    gkr_scope.end();
    errdefer section.deinit(a);
    var verify_scope = try Capture.Scope.begin(recorder, "outer_gkr_verify", "Independent native GKR section check");
    defer verify_scope.end();
    var verified = try S.verify(a, &channel, &section);
    verify_scope.end();
    defer verified.deinit(a);
    var strict = S.StrictChannel{ .inner = channel };
    const late = Legacy.drawChallenges(&strict, key.class.instances.len);
    if (strict.rejected) return error.OuterGkrDrawRejected;
    channel = strict.inner;
    try S.requireClosure(&verified, try Outer.witness.lookupSum(outputs, classic.claims, &elements));
    var binding_scope = try Capture.Scope.begin(recorder, "outer_binding_witness", "Hybrid Eq and terminal binding witness");
    defer binding_scope.end();
    const inter = try W.interaction(a, &key.class, &inputs, &verified, &late, &classic);
    binding_scope.end();
    defer circuit.witness.trace.freeColumns(a, inter);
    inputs.deinit(a);
    inputs_owned = false;
    classic.deinit(a);
    var commit_scope = try Capture.Scope.begin(recorder, "outer_interaction_commit", "Hybrid circuit INTER preparation and commitment");
    defer commit_scope.end();
    try scheme.commit(a, inter, &channel);
    commit_scope.end();
    var bound: [P.N_COMPONENTS]HC.Component = undefined;
    var components: [P.N_COMPONENTS]engine.air.component_prover.ForField(O).ComponentProver = undefined;
    var made: usize = 0;
    var metrics: [P.N_COMPONENTS]Metrics.Counters = @splat(.{});
    var labels: [P.N_COMPONENTS][]const u8 = undefined;
    for (std.enums.values(P.Component), &labels) |kind, *label| label.* = @tagName(kind);
    defer for (bound[0..made]) |component| a.free(component.parameters);
    for (&bound, &components, key.artifacts, key.source.bound.components, claims, &metrics) |*component, *out, *artifact, *captured, claim, *counter| {
        const parameters = try artifact.parameters(a, captured, draws.z, draws.alpha, &key.class, &verified, &late, claim);
        component.* = .{ .allocator = a, .source = captured, .artifact = artifact, .fixed_logs = &key.source.fixed_logs, .class = &key.class, .verified = &verified, .parameters = parameters, .cpu_metrics = if (capture != null) counter else null };
        made += 1;
        out.* = component.asProverComponent();
    }
    owns = false;
    var proof = try Outer.protocol.Engine.prove(a, &components, &channel, scheme, .{ .recorder = recorder });
    errdefer proof.deinit(a);
    if (capture) |*active| {
        try active.save(key.identity);
        try Metrics.save(a, active.directory, key.identity, &metrics, &labels);
    }
    return .{ .base = .{ .allocator = a, .outputs = outputs, .claims = classic.claims, .proof = proof }, .section = section };
}
