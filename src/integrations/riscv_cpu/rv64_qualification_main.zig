//! Generate independently expected fixtures and genuine/captured native proofs.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const native = @import("stwo_riscv_cpu_integration").rv64;
const rv = @import("stwo_riscv_frontend").rv64_air;
const wire = @import("stwo_proof_wire");
const B = @import("stwo_cpu_backend").CpuBackend;
const P = rv.protocol;
const a = std.heap.page_allocator;
const program = [_]u32{ 0x00108093, 0x00108093, 0x00113023, 0x00013183, 0x001181b3 };
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 2) return error.ExpectedOutputDirectory;
    try std.fs.cwd().makePath(args[1]);
    var directory = try std.fs.cwd().openDir(args[1], .{});
    defer directory.close();
    var initial: [32]u64 = @splat(0);
    initial[1] = 0x12345678ffffffff;
    initial[2] = 0x200004000;
    var final = initial;
    final[1] +%= 2;
    final[3] = final[1] +% final[1];
    var cells = [_]rv.statement.Cell{.{ .address = initial[2], .initial = 0xaabbccddeeff0011, .final = final[1] }};
    const expected = native.Statement{ .program_base = 0x100001000, .program = &program, .initial_pc = 0x100001000, .final_pc = 0x100001014, .initial_registers = initial, .final_registers = final, .memory = &cells, .steps = 5 };
    var bundle = try native.prove(a, expected);
    defer bundle.deinit(a);
    try benchmark(directory, expected, &bundle);
    try writeExpected(directory, "valid", expected);
    try writeBundle(directory, "valid", bundle.metadata, bundle.proof);
    // The expected statement is separate from proof-controlled metadata.
    for ([_][]const u8{ "source", "ram", "permission" }, 0..) |name, kind| {
        var public = expected;
        var forged = public;
        var expected_cells = cells;
        var forged_cells = cells;
        if (kind == 0) {
            forged.initial_registers[1] +%= 1;
            public.final_registers[1] +%= 1;
            public.final_registers[3] = public.final_registers[1] +% public.final_registers[1];
            expected_cells[0].final = public.final_registers[1];
            forged_cells[0].final = public.final_registers[1];
        } else if (kind == 1) {
            forged_cells[0].initial ^= 1;
        } else {
            expected_cells[0].initial = expected_cells[0].final;
            expected_cells[0].writable = false;
            forged_cells[0].initial = forged_cells[0].final;
        }
        public.memory = &expected_cells;
        forged.memory = &forged_cells;
        forged.final_registers = public.final_registers;
        var witness = try rv.witness.Witness.build(a, forged);
        defer witness.deinit();
        var failed = try failedProof(public, &witness);
        defer failed.deinit(a);
        try writeExpected(directory, name, public);
        try writeBundle(directory, name, witness.metadata, failed.proof);
    }
}
fn writeExpected(directory: std.fs.Dir, name: []const u8, public: native.Statement) !void {
    const path = try std.fmt.allocPrint(a, "{s}-expected.json", .{name});
    defer a.free(path);
    const bytes = try std.json.Stringify.valueAlloc(a, public, .{});
    defer a.free(bytes);
    try directory.writeFile(.{ .sub_path = path, .data = bytes });
}
fn writeBundle(directory: std.fs.Dir, name: []const u8, metadata: native.Metadata, proof: native.Proof) !void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const bytes = try std.json.Stringify.valueAlloc(alloc, .{ .metadata = metadata, .proof = try wire.proofToWire(alloc, proof) }, .{});
    try directory.writeFile(.{ .sub_path = try std.fmt.allocPrint(alloc, "{s}-bundle.json", .{name}), .data = bytes });
}
fn failedProof(public: native.Statement, witness: *const rv.witness.Witness) !core.proof.ExtendedStarkProof(P.Hasher) {
    var trace = try rv.trace.Trace.init(a, public, witness.metadata, witness.rows);
    defer trace.deinit();
    var channel = P.Channel{};
    try P.mix(&channel, public, witness.metadata, trace.log_size);
    const Scheme = engine.pcs.CommitmentSchemeProver(B, P.Hasher, P.MerkleChannel);
    var scheme = try Scheme.init(a, P.config());
    var owned = true;
    errdefer if (owned) scheme.deinit(a);
    const fixed = try trace.columns(a, 0);
    defer a.free(fixed);
    const main_columns = try trace.columns(a, 1);
    defer a.free(main_columns);
    try scheme.commit(a, fixed, &channel);
    try scheme.commit(a, main_columns, &channel);
    const challenges = rv.relations.Challenges.draw(&channel);
    const target = try rv.relations.expected(public, witness.metadata, challenges);
    _ = try trace.generateInteraction(challenges);
    const interaction = try trace.columns(a, 2);
    defer a.free(interaction);
    try scheme.commit(a, interaction, &channel);
    var component = try rv.component.Component.init(trace.log_size, trace.projection, challenges, target);
    const components = [_]engine.air.component_prover.ComponentProver{component.asProverComponent()};
    var diagnostic: ?@import("stwo_prover_api").ProveDiagnostic = null;
    var failed: ?core.proof.ExtendedStarkProof(P.Hasher) = null;
    owned = false;
    if (engine.prove.proveExWithExecutionDiagnosedRetainingFailure(B, P.Hasher, P.MerkleChannel, a, &components, &channel, scheme, false, null, null, null, &diagnostic, &failed)) |unexpected| {
        var proof = unexpected;
        proof.deinit(a);
        return error.ForgeryAccepted;
    } else |err| if (err != error.ConstraintsNotSatisfied) return err;
    return failed orelse error.MissingCapturedProof;
}

fn benchmark(directory: std.fs.Dir, public: native.Statement, bundle: *const native.Bundle) !void {
    const encoded = try wire.encodeProofBytesBinary(a, bundle.proof);
    defer a.free(encoded);
    var timer = try std.time.Timer.start();
    var setup = try native.PreparedSetup.init(a, public, bundle.metadata);
    defer setup.deinit();
    const setup_ns = timer.lap();
    var samples: [7]u64 = undefined;
    var decode: [7]u64 = undefined;
    for (&samples, &decode) |*sample, *decoding| {
        timer.reset();
        const proof = try wire.decodeProofBytesBinary(a, encoded);
        decoding.* = timer.lap();
        try setup.verifyOwned(a, public, bundle.metadata, proof);
        sample.* = timer.read();
    }
    const bytes = try std.json.Stringify.valueAlloc(a, .{ .verified = true, .proof_bytes = encoded.len, .independent_setup_ns = setup_ns, .decode_ns = decode, .prepared_verify_ns = samples, .fixed_columns = setup.projection.fixed_count, .main_columns = setup.projection.main_count, .interaction_columns = 36, .rows = 32 }, .{});
    defer a.free(bytes);
    try directory.writeFile(.{ .sub_path = "native-benchmark.json", .data = bytes });
}
