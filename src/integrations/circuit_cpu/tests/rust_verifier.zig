//! Upstream `verify_circuit` (`crates/circuit_verifier/src/verify.rs` of
//! https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230) on Zig circuit proofs.
//!
//! With `STWO_CIRCUIT_R7_EMIT_DIR` set, the R7 tests write each proof's
//! CircuitSerialize bytes and a `verify-circuit` request; the oracle's
//! verdicts on those files are committed as `vectors/circuit/r7/verify/`,
//! and the tests require their own bytes to be the ones the Rust verifier
//! accepted.

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");

const FriConfigV2 = core.pcs.config_v2.FriConfigV2;
const preprocessed = circuit.common.preprocessed;
const Json = std.json.Value;

fn field(value: Json, name: []const u8) Json {
    return value.object.get(name) orelse std.debug.panic("verdict is missing {s}", .{name});
}

fn expectHex(expected: Json, actual: []const u8) !void {
    try std.testing.expectEqualStrings(expected.string, &std.fmt.bytesToHex(actual[0..32].*, .lower));
}

/// `vectors/circuit/r7/verify/<label>.json` is upstream `verify_circuit`'s
/// verdict (oracle `verify-circuit`) on the bytes this test emitted with
/// `STWO_CIRCUIT_R7_EMIT_DIR`; the Zig bytes must be the ones it accepted.
pub fn expectAccepted(allocator: std.mem.Allocator, comptime label: []const u8, digest: *const [32]u8) !void {
    const bytes = try std.fs.cwd().readFileAlloc(allocator, "vectors/circuit/r7/verify/" ++ label ++ ".json", 1 << 20);
    defer allocator.free(bytes);
    var parsed = try std.json.parseFromSlice(Json, allocator, bytes, .{});
    defer parsed.deinit();
    const body = field(parsed.value, "body");
    try std.testing.expect(field(body, "accepted").bool);
    try expectHex(field(body, "proof_sha256"), digest);
}

/// With `STWO_CIRCUIT_R7_EMIT_DIR`, writes the CircuitSerialize bytes and the
/// oracle's `verify-circuit` request for them.
pub fn emit(
    allocator: std.mem.Allocator,
    label: []const u8,
    encoded: []const u8,
    proof: anytype,
    pp: *const preprocessed.PreprocessedCircuit,
) !void {
    const directory = std.process.getEnvVarOwned(allocator, "STWO_CIRCUIT_R7_EMIT_DIR") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return,
        else => return err,
    };
    defer allocator.free(directory);
    var dir = try std.fs.cwd().openDir(directory, .{});
    defer dir.close();
    const proof_name = try std.fmt.allocPrint(allocator, "{s}.proof", .{label});
    defer allocator.free(proof_name);
    try dir.writeFile(.{ .sub_path = proof_name, .data = encoded });

    const Request = struct {
        pcs_config: struct {
            fri_config: FriConfigV2,
            trace_lifting_log_size: u32,
            preprocessed_lifting_log_size: u32,
        },
        preprocessed_column_log_sizes: []const struct { []const u8, u32 },
        preprocessed_root: [8]u32,
        output_digest: [8]u32,
    };
    const layout = pp.layout();
    var columns: [preprocessed.N_PREPROCESSED_COLUMNS]struct { []const u8, u32 } = undefined;
    for (layout.entries, &columns) |entry, *column| column.* = .{ entry.id, entry.log_size };
    var digest: [8]u32 = undefined;
    for (proof.output_values, &digest) |value, *word| {
        const limbs = value.toM31Array();
        word.* = limbs[0].toU32() | (limbs[1].toU32() << 16);
    }
    const root = proof.stark_proof.proof.commitment_scheme_proof.commitments.items[0];
    const request = Request{
        .pcs_config = .{
            .fri_config = proof.pcs_config.fri_config,
            .trace_lifting_log_size = proof.pcs_config.trace_lifting_log_size,
            .preprocessed_lifting_log_size = proof.pcs_config.preprocessed_lifting_log_size,
        },
        .preprocessed_column_log_sizes = &columns,
        .preprocessed_root = circuit.common.circuit_hash.leU32sFromBytes(8, &root),
        .output_digest = digest,
    };
    const json = try std.json.Stringify.valueAlloc(allocator, request, .{});
    defer allocator.free(json);
    const request_name = try std.fmt.allocPrint(allocator, "{s}.request.json", .{label});
    defer allocator.free(request_name);
    try dir.writeFile(.{ .sub_path = request_name, .data = json });
}
