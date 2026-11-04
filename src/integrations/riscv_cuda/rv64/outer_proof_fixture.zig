//! Actual native OM31 circuit proof qualification through the production device
//! factory. Modes live in the existing AIR tool; this is not another prover.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const Service = @import("pcs_native.zig");
const TC = @import("trace_commit.zig");
const RC = @import("resident_composition.zig");
const Device = @import("outer_source.zig");
pub const Mode = enum { control, gpu, verify, control_dag, gpu_dag, verify_dag, gpu_trace, control_hints, gpu_trace_hints, gpu_trace_hints_fixed, verify_hints };
pub fn run(a: std.mem.Allocator, mode: Mode, input: []const u8, directory: []const u8) !void {
    const fixed_device = mode == .gpu_trace_hints_fixed;
    const trace_only = mode == .gpu_trace or mode == .gpu_trace_hints or fixed_device;
    const production_hints = mode == .control_hints or mode == .gpu_trace_hints or fixed_device or mode == .verify_hints;
    const dag = production_hints or trace_only or mode == .control_dag or mode == .gpu_dag or mode == .verify_dag;
    var ctx = if (trace_only) try circuit.builder.Context(Outer.protocol.Q).initTraceOnly(a, 8) else if (dag) try circuit.builder.Context(Outer.protocol.Q).initWithWitnessOrigins(a, 8) else try circuit.builder.Context(Outer.protocol.Q).init(a, 8);
    defer ctx.deinit();
    const expected: [32]u8 = @splat(0x42);
    var outputs: [8]circuit.builder.Var = undefined;
    for (&outputs, 0..) |*out, i| out.* = try ctx.guess(circuit.builder.ivalue.packU32(Outer.protocol.Q, std.mem.readInt(u32, expected[4 * i ..][0..4], .little)));
    if (dag) {
        const x = try ctx.guess(Outer.protocol.Q.fromU32Unchecked(11, 3, 7, 9));
        const y = try ctx.guess(Outer.protocol.Q.fromU32Unchecked(17, 0, 0, 0));
        const reciprocal = try ctx.inv(y);
        const quotient = try ctx.div(x, y);
        const sum = try ctx.add(reciprocal, quotient);
        const lanes = circuit.builder.simd.Simd.fromPacked(&.{x}, 4);
        _ = try circuit.builder.simd.guessInvOrZero(Outer.protocol.Q, &ctx, lanes);
        _ = try circuit.builder.simd.guessLsb(Outer.protocol.Q, &ctx, lanes);
        _ = try ctx.permuteNamed(&.{ sum, x, y }, .sort_by_u_coordinate);
    }
    if (production_hints) {
        const B = circuit.builder;
        const raw: u32 = 0xfedcba98;
        const packed_word = try B.wrappers.guessU32(Outer.protocol.Q, &ctx, B.wrappers.u32Value(Outer.protocol.Q, raw));
        var octets: [4]B.Var = undefined;
        for (&octets, 0..) |*out, i| {
            const octet: u8 = @truncate(raw >> @intCast(i * 8));
            out.* = try ctx.guessU16(Outer.protocol.Q.fromU32Unchecked(octet, 0, 0, 0));
            const complement = try ctx.guessU16(Outer.protocol.Q.fromU32Unchecked(255 - @as(u32, octet), 0, 0, 0));
            try ctx.noteWitnessByte(out.*, packed_word.get(), @intCast(i), false);
            try ctx.noteWitnessByte(complement, packed_word.get(), @intCast(i), true);
            try ctx.eq(try ctx.add(out.*, complement), try ctx.constant(Outer.protocol.Q.fromU32Unchecked(255, 0, 0, 0)));
        }
        const k = try ctx.constant(Outer.protocol.Q.fromU32Unchecked(256, 0, 0, 0));
        const low = try ctx.add(octets[0], try ctx.mul(octets[1], k));
        const high = try ctx.add(octets[2], try ctx.mul(octets[3], k));
        const imag = try ctx.constant(Outer.protocol.Q.fromU32Unchecked(0, 1, 0, 0));
        try ctx.eq(packed_word.get(), try ctx.add(low, try ctx.mul(high, imag)));
        for ([_]u32{ 0, 17 }) |count| {
            const value = try ctx.guess(Outer.protocol.Q.fromU32Unchecked(count, 0, 0, 0));
            const nonzero = try ctx.guess(if (count == 0) Outer.protocol.Q.zero() else Outer.protocol.Q.one());
            const inverse = try ctx.guess(if (count == 0) Outer.protocol.Q.zero() else try Outer.protocol.Q.fromU32Unchecked(count, 0, 0, 0).inv());
            const zero = try ctx.guess(Outer.protocol.Q.zero());
            try ctx.noteWitnessHint(nonzero, .is_nonzero, value, ctx.zero());
            try ctx.noteWitnessHint(inverse, .pointwise_inverse_or_zero, value, ctx.zero());
            try ctx.noteWitnessHint(zero, .zero, ctx.zero(), ctx.zero());
            try ctx.eq(try ctx.mul(value, inverse), nonzero);
            try ctx.eq(try ctx.mul(nonzero, try ctx.sub(nonzero, ctx.one())), ctx.zero());
            try ctx.eq(zero, ctx.zero());
        }
    }
    try ctx.setOutputs(&outputs);
    try ctx.finalize(false);
    try circuit.common.finalize.padToTargets(Outer.protocol.Q, &ctx, circuit.common.finalize.computePaddedSizes(.fromBuilder(&ctx.circuit)));
    var pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &ctx.circuit);
    defer pp.deinit(a);
    var key = try Outer.prove.Authority.init(a, &pp);
    defer key.deinit();
    try std.fs.cwd().makePath(directory);
    var dir = try std.fs.cwd().openDir(directory, .{});
    defer dir.close();
    if (mode == .verify or mode == .verify_dag or mode == .verify_hints) {
        const bytes = try std.fs.cwd().readFileAlloc(a, input, Outer.wire.MAX_BYTES);
        defer a.free(bytes);
        var decoded = try Outer.wire.decode(a, key.identity, 8, bytes);
        defer decoded.deinit();
        var capture = try Outer.prove.verify(a, &key, decoded.outputs, decoded.claims, &decoded.proof);
        defer capture.deinit(a);
        try checkOutputs(decoded.outputs, expected);
        std.debug.print("OM31_OUTER_DEVICE_FRESH_RECEIVER accepted=true profile=q108-p20-fold4\n", .{});
        return;
    }
    if (mode == .control or mode == .control_dag or mode == .control_hints) {
        var proof = try Outer.prove.prove(a, &key, ctx.values());
        defer proof.deinit();
        var capture = try Outer.prove.verify(a, &key, proof.outputs, proof.claims, &proof.proof.proof);
        defer capture.deinit(a);
        const encoded = try Outer.wire.encode(a, key.identity, proof.outputs, proof.claims, &proof.proof.proof);
        defer a.free(encoded);
        try dir.writeFile(.{ .sub_path = "control.om31", .data = encoded });
        return;
    }
    var service = try Service.Context.init(input, 0, 28 << 30);
    defer service.deinit();
    try service.enableImmutableSetup(2 << 30);
    var commit = try TC.Context.init(&service);
    defer commit.deinit();
    var composition = try RC.Context.initNumerical(a, &service);
    defer composition.deinit();
    var factory = try Device.Context.init(a, &service, &commit, &composition);
    defer factory.deinit();
    const selected_factory = if (fixed_device) try factory.factoryWithDeviceFixed() else if (dag and !trace_only) try factory.factoryForWitness(&ctx) else factory.factory();
    if (dag and !trace_only) factory.assignment.?.check_reference = true; // Qualification-only full D2H equality.
    var first: ?[]u8 = null;
    defer if (first) |bytes| a.free(bytes);
    var expected_outputs: [8]Outer.protocol.Q = undefined;
    for (&expected_outputs, 0..) |*out, i| out.* = circuit.builder.ivalue.packU32(Outer.protocol.Q, std.mem.readInt(u32, expected[4 * i ..][0..4], .little));
    for (0..2) |ordinal| {
        var timer = try std.time.Timer.start();
        var proof = if (fixed_device) try proveFixed(a, &key, &ctx, &expected_outputs, @intCast(ordinal), selected_factory) else if (trace_only) try Outer.device_prove.proveFromCircuit(a, &key, &ctx, &expected_outputs, @intCast(ordinal), selected_factory) else try Outer.device_prove.prove(a, &key, ctx.values(), @intCast(ordinal), selected_factory);
        defer proof.deinit();
        const prove_ns = timer.lap();
        var capture = try Outer.prove.verify(a, &key, proof.outputs, proof.claims, &proof.proof.proof);
        defer capture.deinit(a);
        try checkOutputs(proof.outputs, expected);
        const encoded = try Outer.wire.encode(a, key.identity, proof.outputs, proof.claims, &proof.proof.proof);
        defer a.free(encoded);
        if (first) |old| {
            if (!std.mem.eql(u8, old, encoded)) return error.WarmOuterProofByteMismatch;
        } else first = try a.dupe(u8, encoded);
        if (dir.readFileAlloc(a, "control.om31", Outer.wire.MAX_BYTES)) |control| {
            defer a.free(control);
            if (!std.mem.eql(u8, control, encoded)) return error.NativeOuterProofByteMismatch;
        } else |err| if (err != error.FileNotFound) return err;
        const name = try std.fmt.allocPrint(a, "gpu-{}.om31", .{ordinal});
        defer a.free(name);
        try dir.writeFile(.{ .sub_path = name, .data = encoded });
        std.debug.print("OM31_OUTER_DEVICE_PROOF ordinal={} fresh_accepted=true bytes={} prove_ns={} profile=q108-p20-fold4\n", .{ ordinal, encoded.len, prove_ns });
    }
    if (trace_only) {
        var wrong = expected_outputs;
        wrong[0] = wrong[0].add(Outer.protocol.Q.one());
        if (if (fixed_device) proveFixed(a, &key, &ctx, &wrong, 2, selected_factory) else Outer.device_prove.proveFromCircuit(a, &key, &ctx, &wrong, 2, selected_factory)) |result| {
            var unexpected = result;
            unexpected.deinit();
            return error.InvalidPublicOutputsAccepted;
        } else |err| if (err != error.InvalidOm31CircuitLookupSum) return err;
        if (ctx.value_table.items.len != 0 or ctx.value_table.capacity != 0) return error.TraceOnlyCpuAssignmentsAllocated;
        std.debug.print("OM31_OUTER_TRACE_ONLY cpu_assignment_words=0 gpu_assignment_readback_words=0 wrong_public_outputs_rejected=true\n", .{});
        if (fixed_device) {
            if (factory.active != null or factory.fixed_pending != null) return error.FixedPrecommitOwnerRetained;
            try service.requireNoRequestLeases();
            std.debug.print("OM31_OUTER_DEVICE_FIXED zero_request_leases=true no_host_fixed_tree=true\n", .{});
        }
    } else if (dag) {
        try assignmentMutant(a, input, &ctx, &key, false);
        try assignmentMutant(a, input, &ctx, &key, true);
        std.debug.print("OM31_OUTER_DEVICE_ASSIGNMENT_MUTANTS rejected=2 separate_terminal_sessions=true\n", .{});
    }
}
fn assignmentMutant(a: std.mem.Allocator, library: []const u8, graph: *const circuit.builder.Context(Outer.protocol.Q), key: *const Outer.prove.Authority, zero_inverse: bool) !void {
    // A rejected native callback intentionally poisons its session. Each
    // malformed witness therefore has separate bounded custody and teardown.
    var service = try Service.Context.init(library, 0, 28 << 30);
    defer service.deinit();
    try service.enableImmutableSetup(2 << 30);
    var commit = try TC.Context.init(&service);
    defer commit.deinit();
    var composition = try RC.Context.initNumerical(a, &service);
    defer composition.deinit();
    var factory = try Device.Context.init(a, &service, &commit, &composition);
    defer factory.deinit();
    const selected = try factory.factoryForWitness(graph);
    const assignment = &factory.assignment.?;
    if (!zero_inverse) assignment.seeds[0].value[0] = 0x7fffffff else {
        const input = for (graph.witness_metadata.?.origins.items) |origin| {
            if (origin.kind == .inverse) break origin.a;
        } else return error.MissingInverseFixture;
        var found = false;
        for (assignment.seeds) |*seed| if (seed.out == input) {
            seed.value = @splat(0);
            found = true;
            break;
        };
        if (!found) return error.MissingInverseInputSeed;
    }
    try requireAssignmentRejection(a, key, graph.values(), 2, &factory, selected);
}

fn requireAssignmentRejection(a: std.mem.Allocator, key: *const Outer.prove.Authority, values: []const Outer.protocol.Q, ordinal: u32, factory: *Device.Context, selected: Outer.device_prove.Factory) !void {
    if (Outer.device_prove.prove(a, key, values, ordinal, selected)) |result| {
        var unexpected = result;
        unexpected.deinit();
        return error.InvalidAssignmentAccepted;
    } else |err| if (err != error.InvalidCircuitDeviceAssignment) return err;
    if (factory.active != null) return error.FailedAssignmentOwnerRetained;
}
fn checkOutputs(outputs: []const Outer.protocol.Q, digest: [32]u8) !void {
    if (outputs.len != 8) return error.OuterOutputCount;
    for (outputs, 0..) |output, i| if (!output.eql(circuit.builder.ivalue.packU32(Outer.protocol.Q, std.mem.readInt(u32, digest[4 * i ..][0..4], .little)))) return error.OuterDigestMismatch;
}

/// Qualification uses a separately rebuilt CPU authority as the root oracle;
/// production's optional wrapper builds the device authority without that work.
fn proveFixed(a: std.mem.Allocator, cpu_key: *const Outer.prove.Authority, graph: *const circuit.builder.Context(Outer.protocol.Q), outputs: []const Outer.protocol.Q, ordinal: u32, factory: Outer.device_prove.Factory) !Outer.prove.Produced {
    var fixed = try factory.precommit_fixed.?(factory.context, a, cpu_key.pp, ordinal);
    defer fixed.release(fixed.context);
    if (!std.mem.eql(u8, &cpu_key.fixedRoot(), &fixed.tree.root)) return error.DeviceFixedRootOracleMismatch;
    var key = try Outer.prove.Authority.initForDeviceProver(a, cpu_key.pp, fixed.tree.root);
    defer key.deinit();
    if (key.fixed != null or !key.device_fixed) return error.UnexpectedHostFixedTree;
    if (!std.mem.eql(u8, &key.identity, &cpu_key.identity)) return error.DeviceFixedAuthorityOracleMismatch;
    std.debug.print("OM31_OUTER_DEVICE_FIXED cpu_fixed_root_parity=true cpu_authority_identity_parity=true ordinal={}\n", .{ordinal});
    return Outer.device_prove.proveFromPrecommittedCircuit(a, &key, graph, outputs, ordinal, &fixed);
}
