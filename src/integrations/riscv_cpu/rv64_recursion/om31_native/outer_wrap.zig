//! Actual native-OM31 circuit proving, independent fresh reception and bounded
//! serialization. This owns immutable topology and proof material together.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const Outer = @import("stwo_circuit_cpu_integration").om31.prove;
const Wire = @import("stwo_circuit_cpu_integration").om31.wire;
pub const Device = @import("stwo_circuit_cpu_integration").om31.device_prove;
const C = @import("common.zig");
const PP = circuit.common.preprocessed.PreprocessedCircuit;
pub const Timings = struct {
    preprocess_ns: u64,
    prove_ns: u64,
    verify_ns: u64,
    restore_ns: u64 = 0,
    // Host-only setup attribution; never enters a proof or authority identity.
    finalize_ns: u64 = 0,
    preprocessed_columns_ns: u64 = 0,
    authority_ns: u64 = 0,
};
pub const Wrapped = struct {
    allocator: std.mem.Allocator,
    pp: *PP,
    authority: *Outer.Authority,
    produced: Outer.Produced,
    capture: Outer.Capture,
    digest: [32]u8,
    timings: Timings,
    restored: bool = false,
    pub fn deinit(self: *Wrapped) void {
        self.capture.deinit(self.allocator);
        self.produced.deinit();
        self.authority.deinit();
        self.allocator.destroy(self.authority);
        self.pp.deinit(self.allocator);
        self.allocator.destroy(self.pp);
        self.* = undefined;
    }
    pub fn serialize(self: *const Wrapped, a: std.mem.Allocator) ![]u8 {
        return Wire.encode(a, self.authority.identity, self.produced.outputs, self.produced.claims, &self.produced.proof.proof);
    }
    /// Call after fresh verification and durable serialization. A parent needs
    /// the child's original verifier metadata and proof, not its wide proving
    /// setup. Repeated calls are harmless; proving again is explicitly refused.
    pub fn retireProverData(self: *Wrapped) usize {
        if (self.authority.retired) return 0;
        self.authority.retireProverData();
        var bytes: usize = 0;
        for (&self.pp.columns) |*column| {
            bytes += column.values.len * @sizeOf(@import("stwo_core").fields.m31.M31);
            self.allocator.free(column.values);
            column.values = &.{};
        }
        return bytes;
    }
};
/// Context must already be finalized by its concrete statement authority. Padding follows its exact graph counts; no external registry or legacy
/// profile is accepted here.
pub fn wrapGraph(a: std.mem.Allocator, ctx: *C.Context, digest: [32]u8) !Wrapped {
    return wrapGraphOrLoad(a, ctx, digest, null);
}
/// Restore only after independently rebuilding this graph's PP and Authority.
/// Encoded authority is never admitted; decode and fresh verification bind the
/// bytes to the receiver-derived topology and expected public digest.
pub fn wrapGraphOrLoad(a: std.mem.Allocator, ctx: *C.Context, digest: [32]u8, encoded: ?[]const u8) !Wrapped {
    return wrapGraphOrLoadWithFactory(a, ctx, digest, encoded, 0, null);
}
/// Explicit device selection is terminal on refusal; cached bytes still use
/// independent native reception and never invoke a proving backend.
pub fn wrapGraphOrLoadWithFactory(a: std.mem.Allocator, ctx: *C.Context, digest: [32]u8, encoded: ?[]const u8, ordinal: u32, factory: ?Device.Factory) !Wrapped {
    if (ctx.circuit.output.items.len != 9) return error.CurrentOm31OutputCount;
    if (ctx.trace_only and encoded == null and (factory == null or factory.?.prepare_from_circuit == null)) return error.TraceOnlySourceRequired;
    if (!ctx.trace_only and !try ctx.isCircuitValid()) return error.CurrentOm31LeafRejects;
    var timer = try std.time.Timer.start();
    try circuit.common.finalize.padToTargets(C.Q, ctx, circuit.common.finalize.computePaddedSizes(.fromBuilder(&ctx.circuit)));
    const finalize_ns = timer.read();
    const pp = try a.create(PP);
    errdefer a.destroy(pp);
    pp.* = try PP.fromBuilderCircuit(a, &ctx.circuit);
    errdefer pp.deinit(a);
    const columns_end_ns = timer.read();
    const authority = try a.create(Outer.Authority);
    errdefer a.destroy(authority);
    // Cached reception always rebuilds the CPU fixed authority. Only new
    // explicitly selected device proofs may use trusted device precommit.
    var precommitted: ?Device.PrecommittedFixed = if (ctx.trace_only and encoded == null and factory != null and factory.?.precommit_fixed != null)
        try factory.?.precommit_fixed.?(factory.?.context, a, pp, ordinal)
    else
        null;
    defer if (precommitted) |fixed| fixed.release(fixed.context);
    authority.* = if (precommitted) |fixed| try Outer.Authority.initForDeviceProver(a, pp, fixed.tree.root) else try Outer.Authority.init(a, pp);
    errdefer authority.deinit();
    const preprocess_ns = timer.lap();
    const columns_ns = columns_end_ns - finalize_ns;
    const authority_ns = preprocess_ns - columns_end_ns;
    if (factory != null) std.log.info("CUDA_OUTER_PREPROCESS ordinal={d} finalize_ns={d} columns_ns={d} authority_ns={d} total_ns={d} fixed_setup_backend={s}", .{ ordinal, finalize_ns, columns_ns, authority_ns, preprocess_ns, if (precommitted != null) @as([]const u8, "device_candidate") else "cpu" });
    if (factory != null) std.log.info("CUDA_OUTER_AUTHORITY ordinal={d} vars={d} row_logs={any}", .{ ordinal, ctx.circuit.n_vars, authority.logs.toArray() });
    var produced = if (encoded) |bytes| blk: {
        var decoded = try Wire.decode(a, authority.identity, 8, bytes);
        errdefer decoded.deinit();
        // The prover-only auxiliary caches are not part of the native proof.
        // Restored proofs need no such caches; all containers are owned-safe
        // empty values so Produced.deinit remains the single cleanup path.
        break :blk Outer.Produced{ .allocator = a, .outputs = decoded.outputs, .claims = decoded.claims, .proof = .{ .proof = decoded.proof, .aux = .{ .unsorted_query_locations = &.{}, .trace_decommitment = .{ .items = &.{} }, .fri = .{ .first_layer = .{ .all_values = &.{}, .decommitment = .{ .all_node_values = &.{} } }, .inner_layers = &.{} } } } };
    } else if (factory) |gpu| blk: {
        if (!ctx.trace_only) break :blk try Device.prove(a, authority, ctx.values(), ordinal, gpu);
        var expected: [8]C.Q = undefined;
        for (&expected, 0..) |*out, i| out.* = circuit.builder.ivalue.packU32(C.Q, std.mem.readInt(u32, digest[4 * i ..][0..4], .little));
        if (precommitted) |*fixed| break :blk try Device.proveFromPrecommittedCircuit(a, authority, ctx, &expected, ordinal, fixed);
        break :blk try Device.proveFromCircuit(a, authority, ctx, &expected, ordinal, gpu);
    } else try Outer.prove(a, authority, ctx.values());
    errdefer produced.deinit();
    const source_ns = timer.lap();
    try requireDigest(produced.outputs, digest);
    var capture = try Outer.verify(a, authority, produced.outputs, produced.claims, &produced.proof.proof);
    errdefer capture.deinit(a);
    return .{ .allocator = a, .pp = pp, .authority = authority, .produced = produced, .capture = capture, .digest = digest, .restored = encoded != null, .timings = .{ .preprocess_ns = preprocess_ns, .finalize_ns = finalize_ns, .preprocessed_columns_ns = columns_ns, .authority_ns = authority_ns, .prove_ns = if (encoded != null) 0 else source_ns, .verify_ns = timer.lap(), .restore_ns = if (encoded != null) source_ns else 0 } };
}
// ---------------------------------------------------------------------------
// Staged form of wrapGraphOrLoadWithFactory for NEW trace-only device proofs.
// The three stages execute exactly the same operations in exactly the same
// order on the same graph as the monolithic function; only the thread that
// runs each stage changes. Host prep is device-free and may run on any thread
// ahead of device admission. Proof bytes are therefore unchanged.
// ---------------------------------------------------------------------------

/// Device-free host stage output: padded graph (mutated in place), owned
/// preprocessed columns and an optional factory-owned assignment plan.
pub const HostPrep = struct {
    pp: ?*PP,
    host: ?Device.HostPrepared = null,
    finalize_ns: u64 = 0,
    columns_ns: u64 = 0,
    host_plan_ns: u64 = 0,
    pub fn deinit(self: *HostPrep, a: std.mem.Allocator) void {
        if (self.host) |h| h.destroy(h.context);
        self.host = null;
        if (self.pp) |pp| {
            pp.deinit(a);
            a.destroy(pp);
        }
        self.pp = null;
    }
};
/// Stage 1 (any thread, no device): pad to the exact original targets, build
/// PP columns, then build the factory's assignment plan from the padded graph.
pub fn prepareHost(a: std.mem.Allocator, ctx: *C.Context, factory: Device.Factory) !HostPrep {
    if (ctx.circuit.output.items.len != 9) return error.CurrentOm31OutputCount;
    if (!ctx.trace_only or factory.prepare_from_circuit == null) return error.TraceOnlySourceRequired;
    var timer = try std.time.Timer.start();
    try circuit.common.finalize.padToTargets(C.Q, ctx, circuit.common.finalize.computePaddedSizes(.fromBuilder(&ctx.circuit)));
    const finalize_ns = timer.lap();
    const pp = try a.create(PP);
    errdefer a.destroy(pp);
    pp.* = try PP.fromBuilderCircuit(a, &ctx.circuit);
    var result = HostPrep{ .pp = pp, .finalize_ns = finalize_ns, .columns_ns = timer.lap() };
    errdefer result.deinit(a);
    if (factory.prepare_host) |prepare| {
        result.host = try prepare(factory.context, a, ctx);
        result.host_plan_ns = timer.lap();
    }
    return result;
}
/// Device stage output: proof material before the independent native verify.
pub const Proved = struct {
    pp: *PP,
    authority: *Outer.Authority,
    produced: Outer.Produced,
    timings: Timings,
    pub fn deinit(self: *Proved, a: std.mem.Allocator) void {
        self.produced.deinit();
        self.authority.deinit();
        a.destroy(self.authority);
        self.pp.deinit(a);
        a.destroy(self.pp);
        self.* = undefined;
    }
};
/// Stage 2 (the device lane): FIXED precommit, authority, staged assignment
/// handoff and device proof. Consumes `prep` (PP and staged plan) on every path.
pub fn proveDevice(a: std.mem.Allocator, ctx: *C.Context, prep: *HostPrep, digest: [32]u8, ordinal: u32, factory: Device.Factory) !Proved {
    const pp = prep.pp orelse return error.MissingHostPrep;
    prep.pp = null;
    errdefer {
        pp.deinit(a);
        a.destroy(pp);
    }
    if (prep.host) |host| {
        prep.host = null;
        const stage = factory.stage_host orelse {
            host.destroy(host.context);
            return error.HostPrepStagingUnsupported;
        };
        // stage_host takes ownership on every path (destroys it on refusal).
        try stage(factory.context, host);
    }
    // A staged plan not consumed by the device source (early failure) is
    // discarded; a consumed plan has already moved into source custody.
    defer if (factory.unstage_host) |unstage| unstage(factory.context);
    var timer = try std.time.Timer.start();
    const authority = try a.create(Outer.Authority);
    errdefer a.destroy(authority);
    var precommitted: ?Device.PrecommittedFixed = if (factory.precommit_fixed) |precommit| try precommit(factory.context, a, pp, ordinal) else null;
    defer if (precommitted) |fixed| fixed.release(fixed.context);
    authority.* = if (precommitted) |fixed| try Outer.Authority.initForDeviceProver(a, pp, fixed.tree.root) else try Outer.Authority.init(a, pp);
    errdefer authority.deinit();
    const authority_ns = timer.lap();
    std.log.info("CUDA_OUTER_PREPROCESS ordinal={d} finalize_ns={d} columns_ns={d} authority_ns={d} total_ns={d} fixed_setup_backend={s}", .{ ordinal, prep.finalize_ns, prep.columns_ns, authority_ns, prep.finalize_ns + prep.columns_ns + authority_ns, if (precommitted != null) @as([]const u8, "device_candidate") else "cpu" });
    std.log.info("CUDA_OUTER_AUTHORITY ordinal={d} vars={d} row_logs={any}", .{ ordinal, ctx.circuit.n_vars, authority.logs.toArray() });
    var expected: [8]C.Q = undefined;
    for (&expected, 0..) |*out, i| out.* = circuit.builder.ivalue.packU32(C.Q, std.mem.readInt(u32, digest[4 * i ..][0..4], .little));
    const produced = if (precommitted) |*fixed| try Device.proveFromPrecommittedCircuit(a, authority, ctx, &expected, ordinal, fixed) else try Device.proveFromCircuit(a, authority, ctx, &expected, ordinal, factory);
    return .{ .pp = pp, .authority = authority, .produced = produced, .timings = .{ .preprocess_ns = prep.finalize_ns + prep.columns_ns + authority_ns, .finalize_ns = prep.finalize_ns, .preprocessed_columns_ns = prep.columns_ns, .authority_ns = authority_ns, .prove_ns = timer.read(), .verify_ns = 0 } };
}
/// Stage 3 (any thread, no device): canonical digest check and the same fresh
/// independent native verification/capture the monolithic path performs.
pub fn finishProved(a: std.mem.Allocator, proved: *Proved, digest: [32]u8) !Wrapped {
    var timer = try std.time.Timer.start();
    try requireDigest(proved.produced.outputs, digest);
    var capture = try Outer.verify(a, proved.authority, proved.produced.outputs, proved.produced.claims, &proved.produced.proof.proof);
    errdefer capture.deinit(a);
    var timings = proved.timings;
    timings.verify_ns = timer.read();
    const result = Wrapped{ .allocator = a, .pp = proved.pp, .authority = proved.authority, .produced = proved.produced, .capture = capture, .digest = digest, .restored = false, .timings = timings };
    proved.* = undefined;
    return result;
}
/// Output values must be canonical packed raw-u32 words, not arbitrary QM31s
/// that happen to reduce to the same field value.
pub fn requireDigest(outputs: []const C.Q, expected: [32]u8) !void {
    if (outputs.len != 8) return error.CurrentOm31OutputCount;
    for (outputs, 0..) |value, i| {
        const coordinates = value.toM31Array();
        if (coordinates[0].v > 65535 or coordinates[1].v > 65535 or coordinates[2].v != 0 or coordinates[3].v != 0) return error.NoncanonicalCurrentOm31Output;
        const word = coordinates[0].v | (coordinates[1].v << 16);
        if (word != std.mem.readInt(u32, expected[4 * i ..][0..4], .little)) return error.CurrentOm31OutputDigest;
    }
}
