//! Public values returned only after full-width artifact verification.
const std = @import("std");
pub const VerifiedPublic = struct {
    signer_calls: u32,
    keccak_calls: u32,
    halt_flag: bool,
    transcript: [32]u8,
    output_sha256: [32]u8,
    output_len: u32,
    steps: u32,
    elf_sha256: [32]u8,
    input_sha256: [32]u8,
    pub fn validateCspEcdsa(self: @This(), input: []const u8) !void {
        if (input.len != 161 or self.output_len != 32 or !self.halt_flag)
            return error.InvalidCspPublicIo;
        if (self.signer_calls != 1 or self.keccak_calls != 0) return error.InvalidPrecompileCallCount;
        var expected: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(input[0..32], &expected, .{});
        if (!std.mem.eql(u8, &expected, &self.output_sha256)) return error.CspOutputMismatch;
    }
};
test "CSP public summary requires signer halt and exact success output" {
    const input = [_]u8{7} ** 161;
    var public: VerifiedPublic = .{
        .signer_calls = 1,
        .keccak_calls = 0,
        .halt_flag = true,
        .transcript = @splat(0),
        .output_sha256 = undefined,
        .output_len = 32,
        .steps = 1,
        .elf_sha256 = @splat(0),
        .input_sha256 = @splat(0),
    };
    std.crypto.hash.sha2.Sha256.hash(input[0..32], &public.output_sha256, .{});
    try public.validateCspEcdsa(&input);
    try std.testing.expectError(error.InvalidCspPublicIo, public.validateCspEcdsa(input[0..160]));
    var bad = public;
    bad.halt_flag = false;
    try std.testing.expectError(error.InvalidCspPublicIo, bad.validateCspEcdsa(&input));
    bad = public;
    bad.output_len = 31;
    try std.testing.expectError(error.InvalidCspPublicIo, bad.validateCspEcdsa(&input));
    bad = public;
    bad.signer_calls = 0;
    try std.testing.expectError(error.InvalidPrecompileCallCount, bad.validateCspEcdsa(&input));
    bad = public;
    bad.keccak_calls = 1;
    try std.testing.expectError(error.InvalidPrecompileCallCount, bad.validateCspEcdsa(&input));
    bad = public;
    bad.output_sha256[0] ^= 1;
    try std.testing.expectError(error.CspOutputMismatch, bad.validateCspEcdsa(&input));
}
