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
    /// PP/Authority owned by a class cache (fold v2); never freed here.
    borrowed: bool = false,
    pub fn deinit(self: *Wrapped) void {
        self.capture.deinit(self.allocator);
        self.produced.deinit();
        if (self.borrowed) {
            self.* = undefined;
            return;
        }
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
    if (@import("topology_fingerprint.zig").enabled()) {
        var label: [48]u8 = undefined;
        @import("topology_fingerprint.zig").report(ctx, try std.fmt.bufPrint(&label, "node-{d:0>4}", .{ordinal}), "padded");
        std.debug.print("TOPOLOGY_AUTHORITY node={d} identity={x} fixed_root={x} vars={d} row_logs={any}\n", .{ ordinal, authority.identity, authority.fixedRoot(), ctx.circuit.n_vars, authority.logs.toArray() });
    }
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
/// Receiver-only fold v2 path: restore and freshly verify `encoded` under a
/// class authority the receiver itself built (from an honest trace-only graph
/// of the same geometry class). No producer byte selects the authority; the
/// digest check binds the guessed child identity/FIXED root words.
pub fn restoreWithAuthority(a: std.mem.Allocator, pp: *PP, authority: *Outer.Authority, digest: [32]u8, encoded: []const u8) !Wrapped {
    var timer = try std.time.Timer.start();
    var decoded = try Wire.decode(a, authority.identity, 8, encoded);
    errdefer decoded.deinit();
    var produced = Outer.Produced{ .allocator = a, .outputs = decoded.outputs, .claims = decoded.claims, .proof = .{ .proof = decoded.proof, .aux = .{ .unsorted_query_locations = &.{}, .trace_decommitment = .{ .items = &.{} }, .fri = .{ .first_layer = .{ .all_values = &.{}, .decommitment = .{ .all_node_values = &.{} } }, .inner_layers = &.{} } } } };
    errdefer produced.deinit();
    const restore_ns = timer.lap();
    try requireDigest(produced.outputs, digest);
    var capture = try Outer.verify(a, authority, produced.outputs, produced.claims, &produced.proof.proof);
    errdefer capture.deinit(a);
    return .{ .allocator = a, .pp = pp, .authority = authority, .produced = produced, .capture = capture, .digest = digest, .restored = true, .borrowed = true, .timings = .{ .preprocess_ns = 0, .prove_ns = 0, .restore_ns = restore_ns, .verify_ns = timer.lap() } };
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
