//! Synthetic boolean AIR fixture; independent producer/receiver process gate.
const std = @import("std");
const core = @import("stwo_core");
const Fixture = @import("poseidon2_stark_test.zig");
const a = std.heap.page_allocator;
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 6) return error.ExpectedModeDegreeFoldBinaryPath;
    const degree = try std.fmt.parseInt(u32, args[2], 10);
    if (degree == 4) return run(core.fields.qm31.QM31, args);
    if (degree == 8) return run(core.fields.om31.OM31, args);
    return error.UnsupportedSecureField;
}
fn run(comptime S: type, args: []const [:0]u8) !void {
    const F = Fixture.ForField(S);
    const Profile = core.vcs_lifted.poseidon2_profile.ForField(S);
    const Wire = @import("stwo_proof_wire").ForHasher(S, Profile.MerkleHasher);
    const fold = try std.fmt.parseInt(u32, args[3], 10);
    if (fold != 1 and fold != 4) return error.UnsupportedFold;
    const binary = if (std.mem.eql(u8, args[4], "binary")) true else if (std.mem.eql(u8, args[4], "json")) false else return error.UnsupportedCodec;
    if (std.mem.eql(u8, args[1], "produce")) {
        var p = try F.produceTraceWithFold(a, false, fold);
        defer p.deinit(a);
        const bytes = if (binary) try Wire.encodeProofBytesBinary(a, p.proof) else try Wire.encodeProofBytes(a, p.proof);
        defer a.free(bytes);
        var file = try std.fs.cwd().createFile(args[5], .{});
        defer file.close();
        try file.writeAll(bytes);
        std.debug.print("P2_FIXTURE produced profile={s} bytes={d}\n", .{ Profile.protocol_name, bytes.len });
    } else if (std.mem.eql(u8, args[1], "verify")) {
        const bytes = try std.fs.cwd().readFileAlloc(a, args[5], 1 << 20);
        defer a.free(bytes);
        const proof = if (binary) try Wire.decodeProofBytesBinary(a, bytes) else try Wire.decodeProofBytes(a, bytes);
        try F.verifyFold(a, proof, fold);
        std.debug.print("P2_FIXTURE receiver=accepted profile={s} bytes={d}\n", .{ Profile.protocol_name, bytes.len });
    } else return error.UnsupportedMode;
}
