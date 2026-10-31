//! Fresh receiver for the versioned CPU+Keccak+DIV service profile.
const std = @import("std");
const lean = @import("../../rv64_keccak_cpu.zig");
const wire = @import("stwo_proof_wire");
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 4) return error.ExpectedPublicClaimsProof;
    const public_bytes = try std.fs.cwd().readFileAlloc(a, args[1], 64 << 20);
    defer a.free(public_bytes);
    const claim_bytes = try std.fs.cwd().readFileAlloc(a, args[2], 16384);
    defer a.free(claim_bytes);
    const proof_bytes = try std.fs.cwd().readFileAlloc(a, args[3], 64 << 20);
    defer a.free(proof_bytes);
    const public = try std.json.parseFromSlice(lean.Public, a, public_bytes, .{});
    defer public.deinit();
    const claims = try std.json.parseFromSlice(lean.Claims, a, claim_bytes, .{});
    defer claims.deinit();
    var timer = try std.time.Timer.start();
    var setup = try lean.PreparedSetup.init(a, public.value);
    const setup_ns = timer.lap();
    defer setup.deinit();
    try setup.verifyOwned(a, public.value, claims.value, try wire.decodeProofBytesBinary(a, proof_bytes));
    const report = try std.json.Stringify.valueAlloc(a, .{ .verified = true, .one_pcs_execution = true, .execution_profile = public.value.execution_profile, .division_provider_present = public.value.division_roster == .present, .multiplication_provider_present = public.value.arithmetic_policy == .division_multiplication_services_v3 and public.value.multiplication_roster == .present, .keccak_provider_present = public.value.roster == .paired, .secp_add_provider_present = public.value.secp.add.roster == .present, .secp_double_provider_present = public.value.secp.double.roster == .present, .public_cell_boundary_control = true, .ethereum_block_proof = false, .independent_setup_ns = setup_ns, .verify_with_decode_ns = timer.lap(), .proof_bytes = proof_bytes.len, .setup_identity = setup.cacheIdentity() }, .{});
    defer a.free(report);
    try std.fs.File.stdout().writeAll(report);
    try std.fs.File.stdout().writeAll("\n");
}
