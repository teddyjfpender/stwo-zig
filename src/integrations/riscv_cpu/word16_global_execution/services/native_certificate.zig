//! Canonical native multi-proof statement for future Word16 recursion.
 //!
 //! This object is made ONLY after the current complete mixed-services native
 //! receiver accepts every CPU and truth STARK and closes the typed relations.
 //! It is a SHA-256 commitment to accepted proofs, public boundaries and
 //! admission. It is NOT a recursively verified STARK or settlement proof.
const std = @import("std");
const Hash = std.crypto.hash.sha2.Sha256;
const E = @import("execution.zig");
const P = @import("protocol.zig");
const R = @import("roster.zig");
const Q = @import("../protocol.zig").Q;
pub const Digest = [32]u8;

pub const Certificate = struct {
    digest: Digest,
    manifest: Digest,
    cpu_proofs: u32,
    truth_proofs: u32,
    steps: u64,
    /// Host-native certificate only. No circuit or 128-bit claim is implied.
    pub const recursively_verified = false;
    pub const whole_protocol_128_qualified = false;
};

fn int(h: *Hash, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    h.update(&bytes);
}
fn blob(h: *Hash, bytes: []const u8) void {
    int(h, u64, @intCast(bytes.len));
    h.update(bytes);
}
fn digest(h: *Hash, value: Digest) void {
    h.update(&value);
}
fn value(h: *Hash, q: Q) void {
    for (q.toM31Array()) |v| int(h, u32, v.v);
}
fn registerFile(h: *Hash, regs: [32]u64) void {
    for (regs) |r| int(h, u64, r);
}
fn cells(h: *Hash, words: anytype) void {
    int(h, u64, @intCast(words.len));
    for (words) |word| {
        int(h, u64, word.address);
        int(h, u64, word.state.value);
        int(h, u16, word.state.epoch);
        int(h, u32, word.state.tick);
        int(h, u8, word.state.rights);
    }
}
fn nativeStatement(expected: P.Expected, setups: []const *const R.CpuSetup, truths: []const R.Truth, bundle: *const E.Bundle) Certificate {
    var h = Hash.init(.{});
    h.update("STWO-RV64-WORD16-NATIVE-VERIFIED-CERTIFICATE-v1");
    // This exact image/program/admission is selected by the *fresh receiver*.
    digest(&h, expected.program_identity);
    digest(&h, expected.admission.image_identity);
    int(&h, u64, expected.admission.initial_pc);
    registerFile(&h, expected.admission.initial_registers);
    int(&h, u64, expected.admission.max_prefix_steps);
    int(&h, u64, expected.total_steps);
    int(&h, u64, expected.max_total_steps);
    int(&h, u64, expected.final_pc);
    registerFile(&h, expected.final_registers);

    // A manifest is only an inventory until the native receiver has checked
    // every actual STARK and its physical fixed/main roots. That happens
    // before this function is called.
    digest(&h, bundle.manifest.digest);
    int(&h, u32, @intCast(setups.len));
    int(&h, u32, @intCast(truths.len));
    for (bundle.manifest.specs, bundle.manifest.roots, 0..) |spec, roots, i| {
        int(&h, u32, @intCast(i));
        digest(&h, spec);
        digest(&h, roots.fixed.bytes);
        digest(&h, roots.main.bytes);
    }
    for (setups, bundle.cpus, 0..) |setup, item, i| {
        int(&h, u32, 0x43505531); // CPU1
        int(&h, u32, @intCast(i));
        digest(&h, setup.key.root);
        const req = item.request.base;
        int(&h, u16, req.epoch);
        int(&h, u64, req.cpu.initial_pc);
        int(&h, u64, req.cpu.final_pc);
        int(&h, u32, req.cpu.steps);
        registerFile(&h, req.cpu.initial_registers);
        registerFile(&h, req.cpu.final_registers);
        int(&h, u16, req.memory.epoch);
        int(&h, u32, req.memory.ls_count);
        cells(&h, req.memory.initial);
        cells(&h, req.memory.terminal);
        for (item.request.calls) |calls| int(&h, u32, calls);
        for (item.claims.values()) |claim| value(&h, claim);
        blob(&h, item.bytes);
    }
    for (truths, bundle.truths, 0..) |truth, item, i| {
        int(&h, u32, 0x54525431); // TRT1
        int(&h, u32, @intCast(i));
        int(&h, u32, @intFromEnum(truth.family()));
        int(&h, u32, truth.first());
        int(&h, u32, truth.count());
        digest(&h, truth.key().root);
        for (item.claims) |claim| value(&h, claim);
        blob(&h, item.bytes);
    }
    var result: Digest = undefined;
    h.final(&result);
    return .{
        .digest = result,
        .manifest = bundle.manifest.digest,
        .cpu_proofs = @intCast(setups.len),
        .truth_proofs = @intCast(truths.len),
        .steps = expected.total_steps,
    };
}

/// All inputs are still ordinary native public/proof inputs. Revalidate the
/// complete bundle under independent setups and expected statement FIRST.
/// Never expose a digest-only acceptance or accept a producer's 'verified'
/// flag. The returned digest can later become a public recursive statement
/// only after an actual in-circuit verifier proves its preimage.
pub fn verifyAndCommit(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, expected: P.Expected, bundle: *const E.Bundle) !Certificate {
    try E.verify(a, setups, truths, expected, bundle);
    return nativeStatement(expected, setups, truths, bundle);
}

/// A pinned native certificate requires full fresh native verification even
/// when its digest matches. This is not proof compression.
pub fn verifyPinned(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, expected: P.Expected, bundle: *const E.Bundle, pinned: Digest) !Certificate {
    const certificate = try verifyAndCommit(a, setups, truths, expected, bundle);
    if (!std.mem.eql(u8, &certificate.digest, &pinned)) return error.NativeCertificateMismatch;
    return certificate;
}
