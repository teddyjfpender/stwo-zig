//! Native verified Ethereum completion commitment (NOT a recursive STARK).
//! Produced only after a fresh verifier checks every Word16 CPU and service
//! proof, global RAM/Keccak/secp debts, independent genesis, and terminal ABI.
const std = @import("std");
const Image = @import("../../word16_execution/expected_image.zig").Owner;
const Keys = @import("keys.zig").Owner;
const E = @import("../services/execution.zig");
const P = @import("../services/protocol.zig");
const Native = @import("../services/native_certificate.zig");
const Receiver = @import("receiver.zig");
const Program = @import("../../word16_execution/program.zig").Program;

pub const Certificate = struct {
    digest: [32]u8,
    native: Native.Certificate,
    output: [43]u8,
    /// A full native multi-proof chain is not a single recursive proof.
    pub const recursively_verified = false;
};

pub fn verifyAndCommit(a: std.mem.Allocator, image: *const Image, keys: *const Keys, bundle: *const E.Bundle, max_steps: u64, batch_steps: u32) !Certificate {
    const output = (try Receiver.verify(a, image, keys, bundle, max_steps, batch_steps, true)) orelse return error.MissingVerifiedTerminal;
    var program = try Program.initWithAuthority(a, &image.authority);
    defer program.deinit();
    const expected: P.Expected = try Receiver.expected(image, program.identity, bundle, max_steps, batch_steps, true);
    // Independently rechecks all native STARK proofs, rather than allowing a
    // caller to bypass verification by passing a self-described 'verified'
    // root. This can later be consolidated into one opaque verified token;
    // it deliberately duplicates work rather than adding a trust boundary.
    const native = try Native.verifyAndCommit(a, keys.cpus, keys.truths, expected, bundle);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("STWO-RV64-WORD16-COMPLETE-ETHEREUM-NATIVE-CERTIFICATE-v1");
    hash.update(&native.digest);
    hash.update(&program.identity);
    hash.update(&image.identity);
    hash.update(&output);
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return .{ .digest = digest, .native = native, .output = output };
}
pub fn verifyPinned(a: std.mem.Allocator, image: *const Image, keys: *const Keys, bundle: *const E.Bundle, max_steps: u64, batch_steps: u32, pinned: [32]u8) !Certificate {
    const certificate = try verifyAndCommit(a, image, keys, bundle, max_steps, batch_steps);
    if (!std.mem.eql(u8, &certificate.digest, &pinned)) return error.EthereumNativeCertificateMismatch;
    return certificate;
}
