//! CLI authority for the one-pass Ethereum leaf materializer.

const std = @import("std");
const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const contract = @import("ethereum_block_leaf_contract.zig");

pub const Options = struct {
    compact_tape_manifest: ?[]const u8 = null,
    compact_tape_root: ?[]const u8 = null,
    elf: []const u8,
    execution_profile_receipt: ?[]const u8 = null,
    expected_output: []const u8,
    input: []const u8,
    journal: []const u8,
    proof_profile: ProofProfileSelection,
    result: []const u8,
    segment_count: u32,
    segment_step_budget: usize,
    source_request: []const u8,
    source_root: []const u8,
    source_root_kind: SourceRootKind,

    pub fn parse(arguments: []const []const u8) !Options {
        if (arguments.len != 20 and arguments.len != 22 and
            arguments.len != 24 and arguments.len != 26)
            return error.InvalidArguments;
        var result = Options{
            .elf = undefined,
            .expected_output = undefined,
            .input = undefined,
            .journal = undefined,
            .proof_profile = undefined,
            .result = undefined,
            .segment_count = undefined,
            .segment_step_budget = undefined,
            .source_request = undefined,
            .source_root = undefined,
            .source_root_kind = undefined,
        };
        var seen: u13 = 0;
        var index: usize = 0;
        while (index < arguments.len) : (index += 2) {
            if (index + 1 >= arguments.len or arguments[index + 1].len == 0)
                return error.InvalidArguments;
            const name = arguments[index];
            const value = arguments[index + 1];
            if (std.mem.eql(u8, name, "--compact-tape-manifest")) {
                try take(&seen, 2048);
                result.compact_tape_manifest = value;
            } else if (std.mem.eql(u8, name, "--compact-tape-root")) {
                try take(&seen, 4096);
                result.compact_tape_root = value;
            } else if (std.mem.eql(u8, name, "--elf")) {
                try take(&seen, 1);
                result.elf = value;
            } else if (std.mem.eql(u8, name, "--execution-profile-receipt")) {
                try take(&seen, 1024);
                result.execution_profile_receipt = value;
            } else if (std.mem.eql(u8, name, "--expected-output")) {
                try take(&seen, 2);
                result.expected_output = value;
            } else if (std.mem.eql(u8, name, "--input")) {
                try take(&seen, 4);
                result.input = value;
            } else if (std.mem.eql(u8, name, "--journal")) {
                try take(&seen, 8);
                result.journal = value;
            } else if (std.mem.eql(u8, name, "--proof-profile")) {
                try take(&seen, 512);
                result.proof_profile = try ProofProfileSelection.parse(value);
            } else if (std.mem.eql(u8, name, "--result")) {
                try take(&seen, 16);
                result.result = value;
            } else if (std.mem.eql(u8, name, "--segment-count")) {
                try take(&seen, 32);
                result.segment_count = try std.fmt.parseInt(u32, value, 10);
            } else if (std.mem.eql(u8, name, "--segment-step-budget")) {
                try take(&seen, 64);
                result.segment_step_budget = try std.fmt.parseInt(
                    usize,
                    value,
                    10,
                );
            } else if (std.mem.eql(u8, name, "--source-request")) {
                try take(&seen, 128);
                result.source_request = value;
            } else if (std.mem.eql(u8, name, "--source-root")) {
                try take(&seen, 256);
                result.source_root = value;
                result.source_root_kind = .exact;
            } else if (std.mem.eql(u8, name, "--source-root-parent")) {
                try take(&seen, 256);
                result.source_root = value;
                result.source_root_kind = .precreated_parent;
            } else return error.InvalidArguments;
        }
        if (seen != 1023 and seen != 2047 and seen != 8191)
            return error.InvalidArguments;
        if ((result.compact_tape_manifest == null) !=
            (result.compact_tape_root == null))
        {
            return error.InvalidArguments;
        }
        if (result.compact_tape_root != null and
            result.execution_profile_receipt == null)
        {
            return error.CompactTapeProfilingReceiptRequired;
        }
        return result;
    }

    pub fn resolve(self: Options, allocator: std.mem.Allocator) !Options {
        var result = self;
        if (self.compact_tape_manifest) |path| {
            result.compact_tape_manifest = try artifact_io.resolveAbsolute(
                allocator,
                path,
            );
        }
        errdefer if (result.compact_tape_manifest) |path| allocator.free(path);
        if (self.compact_tape_root) |path| {
            result.compact_tape_root = try artifact_io.resolveAbsolute(
                allocator,
                path,
            );
        }
        errdefer if (result.compact_tape_root) |path| allocator.free(path);
        result.elf = try artifact_io.resolveAbsolute(allocator, self.elf);
        errdefer allocator.free(result.elf);
        if (self.execution_profile_receipt) |path| {
            result.execution_profile_receipt = try artifact_io.resolveAbsolute(
                allocator,
                path,
            );
        }
        errdefer if (result.execution_profile_receipt) |path|
            allocator.free(path);
        result.expected_output = try artifact_io.resolveAbsolute(
            allocator,
            self.expected_output,
        );
        errdefer allocator.free(result.expected_output);
        result.input = try artifact_io.resolveAbsolute(allocator, self.input);
        errdefer allocator.free(result.input);
        result.journal = try artifact_io.resolveAbsolute(allocator, self.journal);
        errdefer allocator.free(result.journal);
        result.result = try artifact_io.resolveAbsolute(allocator, self.result);
        errdefer allocator.free(result.result);
        result.source_request = try artifact_io.resolveAbsolute(
            allocator,
            self.source_request,
        );
        errdefer allocator.free(result.source_request);
        result.source_root = switch (self.source_root_kind) {
            .exact => try artifact_io.resolveAbsolute(
                allocator,
                self.source_root,
            ),
            .precreated_parent => try artifact_io.resolveCreateOnlyChild(
                allocator,
                self.source_root,
                artifact_io.ethereum_leaf_source_basename,
            ),
        };
        return result;
    }

    pub fn deinit(self: *Options, allocator: std.mem.Allocator) void {
        if (self.compact_tape_manifest) |path| allocator.free(path);
        if (self.compact_tape_root) |path| allocator.free(path);
        allocator.free(self.elf);
        if (self.execution_profile_receipt) |path| allocator.free(path);
        allocator.free(self.expected_output);
        allocator.free(self.input);
        allocator.free(self.journal);
        allocator.free(self.result);
        allocator.free(self.source_request);
        allocator.free(self.source_root);
        self.* = undefined;
    }
};

pub const ProofProfileSelection = enum {
    native_blake2s_v1,
    recursive_poseidon2_v2,

    fn parse(value: []const u8) !ProofProfileSelection {
        if (std.mem.eql(u8, value, contract.native_proof_profile_name))
            return .native_blake2s_v1;
        if (std.mem.eql(u8, value, contract.recursive_proof_profile_name))
            return .recursive_poseidon2_v2;
        return error.UnsupportedProofProfile;
    }
};

const SourceRootKind = enum { exact, precreated_parent };

fn take(seen: *u13, bit: u13) !void {
    if (seen.* & bit != 0) return error.DuplicateArgument;
    seen.* |= bit;
}
