//! Combined verifier statement for full-width BLAKE3, Ethereum and SHA AIRs.
//! This protocol identity does not activate executable-profile admission.
const std = @import("std");
const core = @import("stwo_core");
const ethereum = @import("blake3_ethereum_statement.zig");
const geometry = @import("../air/guest_precompile/ethereum_statement.zig");
const sha = @import("../air/guest_precompile/sha256_component_profile.zig");
const native_protocol = @import("blake3_execution_protocol.zig");
const Native = @import("../air/statement.zig").Blake3ExecutionStatement;
const Pin = @import("blake3_commitment_plan.zig").Admission;
pub const format_version: u32 = 1;
pub const Statement = struct {
    ethereum: ethereum.Statement,
    sha: sha.Profile,

    pub fn canonical(a: std.mem.Allocator, native: *const Native, pin: Pin, logs: ethereum.HashLogs, keccak: u32, signer: u32, sha_calls: u32, shapes: geometry.SecpShapes) !Statement {
        const certificate = try ethereum.admissionWithSha(a, native, pin, logs, keccak, signer, sha_calls);
        const result = Statement{
            .ethereum = try ethereum.Statement.canonicalWithAdmission(keccak, signer, shapes, certificate),
            .sha = try sha.Profile.canonical(sha_calls),
        };
        try result.validate(a, native, pin, logs);
        return result;
    }

    pub fn validate(self: *const Statement, a: std.mem.Allocator, native: *const Native, pin: Pin, logs: ethereum.HashLogs) !void {
        try ethereum.validateExtensionGeometry(&self.ethereum, native.total_steps);
        try self.sha.validate(native.total_steps);
        const expected = try ethereum.admissionWithSha(a, native, pin, logs, self.ethereum.counts.keccak_calls, self.ethereum.counts.signer_calls, self.sha.call_count);
        if (!std.meta.eql(expected, self.ethereum.admission)) return error.AdmissionCertificateMismatch;
    }

    /// Validate before transcript mutation. Bind both component manifests and
    /// combined bounds before commitments or relation challenges are drawn.
    pub fn mix(self: *const Statement, a: std.mem.Allocator, channel: anytype, config: core.pcs.PcsConfig, native: *const Native, pin: Pin, logs: ethereum.HashLogs) !void {
        try native_protocol.validateConfig(config);
        try self.validate(a, native, pin, logs);
        try self.mixValidated(channel, config, native, pin);
    }

    /// The containing protocol must finish config, geometry and coefficient
    /// admission before entering this allocation-free transcript operation.
    pub fn mixValidated(self: *const Statement, channel: anytype, config: core.pcs.PcsConfig, native: *const Native, pin: Pin) !void {
        channel.mixU32s(&.{ 0x42334553, format_version }); // B3ES
        native_protocol.mixAdmittedStatement(channel, config, native, pin);
        self.ethereum.mixValidatedInto(channel);
        try self.sha.mixInto(channel);
    }
};

pub const HashLogs = ethereum.HashLogs;
pub fn validateWithAllocator(a: std.mem.Allocator, extension: *const Statement, native: *const Native, pin: Pin, logs: HashLogs) !void {
    try extension.validate(a, native, pin, logs);
}
