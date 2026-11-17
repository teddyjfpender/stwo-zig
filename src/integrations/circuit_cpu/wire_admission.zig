//! Concrete recursion transport origins; diagnostic I/O never replaces a cause.
const std = @import("std");
const wire = @import("stwo_circuit_recursion_wire");
const core = @import("stwo_core");
const Entry = core.error_codes.Entry;
const binary = wire.circuit_serialize;
const felt = wire.circuit_felt_stream;
fn emit(comptime origin: []const u8, entry: ?Entry) void {
    var storage: [384]u8 = undefined;
    var stderr = std.fs.File.stderr().writer(&storage);
    emitTo(&stderr.interface, origin, entry);
}
fn emitTo(out: *std.Io.Writer, comptime origin: []const u8, entry: ?Entry) void {
    const owned = entry orelse return;
    std.json.Stringify.value(.{ .schema = "recursion_transport_rejection_v1", .provider = "stwo_circuit_recursion_wire", .origin = origin, .code = owned.code, .class = owned.class }, .{}, out) catch return;
    out.writeByte('\n') catch return;
    out.flush() catch {};
}
pub fn decodeBinary(gpa: std.mem.Allocator, bytes: []const u8, config: binary.ProofConfig) !binary.DecodedProof {
    var failure: ?Entry = null;
    return binary.deserializeProofDiagnosed(gpa, bytes, config, &failure) catch |err| {
        emit("circuit_serialize.deserializeProof", failure);
        return err;
    };
}
pub fn encodeBinary(gpa: std.mem.Allocator, proof: *const binary.Proof, config: binary.ProofConfig) ![]u8 {
    var failure: ?Entry = null;
    return binary.serializeProofAllocDiagnosed(gpa, proof, config, &failure) catch |err| {
        emit("circuit_serialize.serializeProofAlloc", failure);
        return err;
    };
}
pub fn leafDigest(gpa: std.mem.Allocator, leaf: wire.leaf_proof_json.LeafInput) ![8]u32 {
    var failure: ?Entry = null;
    return leaf.outputDigestDiagnosed(gpa, &failure) catch |err| {
        emit("leaf_proof_json.LeafInput.outputDigest", failure);
        return err;
    };
}
pub fn writeRoot(out: *std.Io.Writer, proof: *const felt.CairoCircuitProof) !void {
    var storage: [384]u8 = undefined;
    var stderr = std.fs.File.stderr().writer(&storage);
    return writeRootTo(out, proof, &stderr.interface);
}
fn writeRootTo(out: *std.Io.Writer, proof: *const felt.CairoCircuitProof, diagnostic: *std.Io.Writer) !void {
    var failure: ?Entry = null;
    felt.writeJsonDiagnosed(out, proof, &failure) catch |err| {
        emitTo(diagnostic, "circuit_felt_stream.writeJson", failure);
        return err;
    };
}

test "actual recursion transports preserve positive bytes digest and owned causes" {
    const a = std.testing.allocator;
    const config: binary.ProofConfig = .{ .n_preprocessed_columns = 0, .component_shapes = &.{}, .log_trace_size = 3, .fri = .{ .pow_bits = 0, .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 1, .fold_step = 1 } };
    const bytes = try a.alloc(u8, config.serializedLen());
    defer a.free(bytes);
    @memset(bytes, 0);
    var decoded = try decodeBinary(a, bytes, config);
    defer decoded.deinit();
    const back = try encodeBinary(a, &decoded.proof, config);
    defer a.free(back);
    try std.testing.expectEqualSlices(u8, bytes, back);
    try std.testing.expectError(error.NotEnoughData, decodeBinary(a, bytes[0..1], config));
    var bad = decoded.proof;
    var one = [_]core.fields.qm31.QM31{core.fields.qm31.QM31.zero()};
    bad.claimed_sums = &one;
    try std.testing.expectError(error.ShapeMismatch, encodeBinary(a, &bad, config));
    const leaf: wire.leaf_proof_json.LeafInput = .{ .proof = .{ .circuit_preprocessed_root = .{ .words = @splat(0) }, .circuit_hash = .{ .words = @splat(0) }, .proof = &.{} }, .output_preimage = &.{ "1", "2" } };
    try std.testing.expectEqual(try leaf.outputDigest(a), try leafDigest(a, leaf));
    var invalid = leaf;
    invalid.output_preimage = &.{"+"};
    try std.testing.expectError(error.InvalidDecimalFelt, leafDigest(a, invalid));
}

test "decimal digest every allocation failure is owned and diagnostic write cannot replace it" {
    const Runner = struct {
        fn run(a: std.mem.Allocator) !void {
            var failure: ?Entry = null;
            _ = wire.blake2_felt252.outputDigestDiagnosed(a, &.{ "1", "2" }, &failure) catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                try std.testing.expectEqual(@as(u16, 0x5802), failure.?.code);
                var none: [0]u8 = .{};
                var writer = std.Io.Writer.fixed(&none);
                emitTo(&writer, "leaf_proof_json.LeafInput.outputDigest", failure);
                return err;
            };
            try std.testing.expect(failure == null);
        }
    };
    try Runner.run(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Runner.run, .{});
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    emitTo(&out.writer, "leaf_proof_json.LeafInput.outputDigest", wire.error_codes.fromDecimal(error.InvalidDecimalFelt));
    try std.testing.expectEqualStrings("{\"schema\":\"recursion_transport_rejection_v1\",\"provider\":\"stwo_circuit_recursion_wire\",\"origin\":\"leaf_proof_json.LeafInput.outputDigest\",\"code\":22529,\"class\":\"invalid_input\"}\n", out.written());
}

test "actual root writer emits only concrete codec failure and preserves primary writer errors" {
    const a = std.testing.allocator;
    const Q = core.fields.qm31.QM31;
    var poly = [_]Q{Q.zero()};
    var proof: felt.CairoCircuitProof = .{ .output_values = &.{}, .interaction_pow = 0, .claimed_sums = @splat(Q.zero()), .channel_salt = 0, .stark_proof = .{
        .fri_config = .{ .pow_bits = 0, .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 3, .fold_step = 1 },
        .commitments = &.{},
        .sampled_values = &.{},
        .decommitments = &.{},
        .queried_values = &.{},
        .proof_of_work = 0,
        .fri_proof = .{ .first_layer = .{ .fri_witness = &.{}, .decommitment = &.{}, .commitment = @splat(0) }, .inner_layers = &.{}, .last_layer_poly = &poly },
    } };
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();
    var diagnostic: std.Io.Writer.Allocating = .init(a);
    defer diagnostic.deinit();
    try writeRootTo(&out.writer, &proof, &diagnostic.writer);
    try std.testing.expectEqual(@as(usize, 0), diagnostic.written().len);
    var legacy: std.Io.Writer.Allocating = .init(a);
    defer legacy.deinit();
    try felt.writeJson(&legacy.writer, &proof);
    try std.testing.expectEqualStrings(legacy.written(), out.written());
    proof.stark_proof.fri_proof.last_layer_poly = &.{};
    out.clearRetainingCapacity();
    try std.testing.expectError(error.InvalidLinePoly, writeRootTo(&out.writer, &proof, &diagnostic.writer));
    try std.testing.expectEqualStrings("{\"schema\":\"recursion_transport_rejection_v1\",\"provider\":\"stwo_circuit_recursion_wire\",\"origin\":\"circuit_felt_stream.writeJson\",\"code\":22786,\"class\":\"invalid_input\"}\n", diagnostic.written());
    diagnostic.clearRetainingCapacity();
    proof.stark_proof.fri_proof.last_layer_poly = &poly;
    var none: [0]u8 = .{};
    var failing = std.Io.Writer.fixed(&none);
    try std.testing.expectError(error.WriteFailed, writeRootTo(&failing, &proof, &diagnostic.writer));
    try std.testing.expectEqual(@as(usize, 0), diagnostic.written().len);
    proof.stark_proof.fri_proof.last_layer_poly = &.{};
    // Failed diagnostics do not replace the codec error or primary output.
    try std.testing.expectError(error.InvalidLinePoly, writeRootTo(&out.writer, &proof, &failing));
}
