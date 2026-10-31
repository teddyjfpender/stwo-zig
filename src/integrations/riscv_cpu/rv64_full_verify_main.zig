//! Independent receiver: expected request and immutable ROM, no execution journal.
const std = @import("std");
const native = @import("stwo_riscv_cpu_integration").rv64_full;
const Statement = native.Statement;
const Claims = native.Claims;
const Control = @import("stwo_riscv_frontend").rv64_air.control_policy.Policy;
const wire = @import("stwo_proof_wire");
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 4 and args.len != 5) return error.ExpectedStatementClaimsProof;
    // Optional final argument is trusted caller policy, never inferred from
    // producer JSON or the proof. Omission preserves the legacy bytes profile.
    const control: Control = if (args.len == 5) std.meta.stringToEnum(Control, args[4]) orelse return error.InvalidControlPolicy else .bytes_v1;
    const statement_bytes = try std.fs.cwd().readFileAlloc(a, args[1], 64 * 1024 * 1024);
    defer a.free(statement_bytes);
    const claims_bytes = try std.fs.cwd().readFileAlloc(a, args[2], 16384);
    defer a.free(claims_bytes);
    const bytes = try std.fs.cwd().readFileAlloc(a, args[3], 64 * 1024 * 1024);
    defer a.free(bytes);
    var timer = try std.time.Timer.start();
    const public = try std.json.parseFromSlice(Statement, a, statement_bytes, .{});
    defer public.deinit();
    const claims = try std.json.parseFromSlice(Claims, a, claims_bytes, .{});
    defer claims.deinit();
    const proof = try wire.decodeProofBytesBinary(a, bytes);
    const decode_ns = timer.lap();
    var setup = native.PreparedSetup.initWithControl(a, public.value, control) catch |err| {
        var owned = proof;
        owned.deinit(a);
        return err;
    };
    defer setup.deinit();
    const setup_ns = timer.lap();
    try setup.verifyOwned(a, public.value, claims.value, proof);
    const verify_ns = timer.lap();
    const report = try std.json.Stringify.valueAlloc(a, .{ .control_policy = control, .verified = true, .whole_guest_proof = true, .execution_witness_available = false, .decode_ns = decode_ns, .independent_setup_ns = setup_ns, .verify_ns = verify_ns, .proof_bytes = bytes.len }, .{});
    defer a.free(report);
    try std.fs.File.stdout().writeAll(report);
    try std.fs.File.stdout().writeAll("\n");
}
