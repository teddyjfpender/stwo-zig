//! Canonical kernel-declaration digests shared by the ABI contract and the
//! native generator that materializes them.
//!
//! The digests were once computed at comptime for every Native export, which
//! meant the comptime interpreter searched the 1.4 MB amalgamated shader source
//! 166 times and then hashed each declaration. That single table cost about
//! nine minutes of every build that touched the Metal backend. The generator
//! now runs these functions natively and checks the result in as
//! `abi_declaration_digests.zig`; a runtime test recomputes every entry so a
//! stale table fails closed.

const std = @import("std");

pub const hex_len = 64;

pub const DeclarationError = error{
    MissingKernelDeclaration,
    MalformedKernelDeclaration,
    NoSpaceLeft,
};

/// Returns the `kernel void <name>(...)` declaration slice for one export.
pub fn kernelDeclaration(source: []const u8, name: []const u8) DeclarationError![]const u8 {
    var prefix_buffer: [192]u8 = undefined;
    const prefix = try std.fmt.bufPrint(&prefix_buffer, "kernel void {s}(", .{name});
    const start = std.mem.indexOf(u8, source, prefix) orelse return error.MissingKernelDeclaration;
    const end = std.mem.indexOfPos(u8, source, start + prefix.len, ") {") orelse
        return error.MalformedKernelDeclaration;
    return source[start .. end + 1];
}

/// Hashes a declaration with formatting whitespace removed, keeping exactly one
/// separator between adjacent identifier tokens so ABI-relevant tokens bind.
pub fn canonicalDeclarationDigest(declaration: []const u8) [32]u8 {
    var digest = std.crypto.hash.sha2.Sha256.init(.{});
    var pending_space = false;
    var previous: ?u8 = null;
    for (declaration) |byte| {
        if (std.ascii.isWhitespace(byte)) {
            pending_space = true;
            continue;
        }
        if (pending_space and previous != null and tokenByte(previous.?) and tokenByte(byte))
            digest.update(" ");
        digest.update(&.{byte});
        pending_space = false;
        previous = byte;
    }
    return digest.finalResult();
}

pub fn declarationDigestHex(source: []const u8, name: []const u8) DeclarationError![hex_len]u8 {
    const declaration = try kernelDeclaration(source, name);
    return std.fmt.bytesToHex(canonicalDeclarationDigest(declaration), .lower);
}

fn tokenByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '_';
}

test "canonical declaration digests ignore formatting but bind ABI tokens" {
    const compact = "kernel void example(device uint*value[[buffer(0)]],uint i[[thread_position_in_grid]])";
    const formatted =
        \\kernel void example(
        \\    device uint *value [[buffer(0)]],
        \\    uint i [[thread_position_in_grid]]
        \\)
    ;
    try std.testing.expectEqualSlices(
        u8,
        &canonicalDeclarationDigest(compact),
        &canonicalDeclarationDigest(formatted),
    );

    const changed = "kernel void example(device uint*value[[buffer(1)]],uint i[[thread_position_in_grid]])";
    try std.testing.expect(!std.mem.eql(
        u8,
        &canonicalDeclarationDigest(compact),
        &canonicalDeclarationDigest(changed),
    ));
}

test "kernel declaration lookup fails closed" {
    const source = "kernel void a(uint i) {\n}\nkernel void b(uint j) {\n}\n";
    try std.testing.expectEqualStrings("kernel void b(uint j)", try kernelDeclaration(source, "b"));
    try std.testing.expectError(error.MissingKernelDeclaration, kernelDeclaration(source, "c"));
    try std.testing.expectError(
        error.MalformedKernelDeclaration,
        kernelDeclaration("kernel void a(uint i);", "a"),
    );
}
