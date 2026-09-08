//! Bounded durable transport for the Ethereum field wrapper verifier.
//! An expected circuit-file hash is supplied separately. A key carried by an
//! untrusted proof cannot choose its own verification authority.
const std = @import("std");
const verifier = @import("ethereum_wrapper_root_verifier_v1.zig");
const manifest_mod = @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const initial_manifest = @import("stwo_riscv_frontend").recursion.air.ethereum_initial_input_manifest_v1;
const public = @import("recursive_field_node_public_v2.zig");
const artifact = @import("recursive_temporal_secure_parent_artifact_v1.zig");
const usage = @import("stwo_prover_engine").measurement.process_usage;
const MAX_KEY_BYTES: usize = 64 * 1024 * 1024;
const MAX_INPUT_BYTES: usize = 128 * 1024;

pub const Ordinary = Types(manifest_mod);
pub const Initial38 = Types(initial_manifest);
pub const PublicInputsV1 = Ordinary.PublicInputsV1;
pub const OwnedKeyV1 = Ordinary.OwnedKeyV1;
pub const BundleLocationV1 = Location;
pub const ReceiptV1 = Ordinary.ReceiptV1;
pub const decodeInputs = Ordinary.decodeInputs;
pub const retainCandidate = Ordinary.retainCandidate;
pub const verifyDirectory = Ordinary.verifyDirectory;

// Candidate storage custody is independent of the admitted circuit profile.
const Location = struct {
    allocator: std.mem.Allocator,
    path: []u8,
    expected_key_sha256: [32]u8,

    pub fn deinit(self: *Location) void {
        self.allocator.free(self.path);
        self.* = undefined;
    }
};

pub fn Types(comptime ManifestMod: type) type {
    const Verifier = verifier.Types(ManifestMod);
    return struct {
        const Selected = @This();
        pub const PublicInputsV1 = struct {
            version: u16,
            node: public.NodePublicV2,
            claims: Verifier.ClaimsV1,
            interaction_pow_nonce: u64,
            proof_bytes: usize,
            proof_sha256: [32]u8,
        };

        pub const OwnedKeyV1 = opaque {
            const Storage = struct { allocator: std.mem.Allocator, parsed: std.json.Parsed(Verifier.KeyV1) };
            pub fn admit(allocator: std.mem.Allocator, bytes: []const u8, expected_sha256: [32]u8) !*Selected.OwnedKeyV1 {
                if (bytes.len == 0 or bytes.len > MAX_KEY_BYTES) return error.EthereumRootKeySizeMismatch;
                if (!std.meta.eql(hash(bytes), expected_sha256)) return error.EthereumRootKeyHashMismatch;
                const parsed = try std.json.parseFromSlice(Verifier.KeyV1, allocator, bytes, .{ .allocate = .alloc_always });
                errdefer parsed.deinit();
                try parsed.value.validate();
                const storage = try allocator.create(Storage);
                storage.* = .{ .allocator = allocator, .parsed = parsed };
                return @ptrCast(storage);
            }
            pub fn key(self: *const Selected.OwnedKeyV1) *const Verifier.KeyV1 {
                const storage: *const Storage = @ptrCast(@alignCast(self));
                return &storage.parsed.value;
            }
            pub fn deinit(self: *Selected.OwnedKeyV1) void {
                const storage: *Storage = @ptrCast(@alignCast(self));
                const allocator = storage.allocator;
                storage.parsed.deinit();
                allocator.destroy(storage);
            }
        };

        pub fn decodeInputs(allocator: std.mem.Allocator, bytes: []const u8) !Selected.PublicInputsV1 {
            if (bytes.len == 0 or bytes.len > MAX_INPUT_BYTES) return error.EthereumRootInputSizeMismatch;
            const parsed = try std.json.parseFromSlice(Selected.PublicInputsV1, allocator, bytes, .{});
            defer parsed.deinit();
            const value = parsed.value;
            if (value.version != Verifier.VERSION) return error.EthereumRootInputVersionMismatch;
            try value.node.validate();
            if (value.proof_bytes == 0 or value.proof_bytes > artifact.MAX_CANONICAL_PROOF_BYTES) return error.EthereumRootProofSizeMismatch;
            return value; // Fixed arrays and scalars only.
        }

        pub const BundleLocationV1 = Location;

        /// Retain real candidates even if later root verification fails. This creates
        /// no proof capability and never replaces an existing regression artifact.
        pub fn retainCandidate(allocator: std.mem.Allocator, key_json: []const u8, node: public.NodePublicV2, claims: Verifier.ClaimsV1, nonce: u64, proof: []const u8) !?Selected.BundleLocationV1 {
            const corpus = std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_PROOF_CORPUS") catch |err| switch (err) {
                error.EnvironmentVariableNotFound => return null,
                else => return err,
            };
            defer allocator.free(corpus);
            if (proof.len == 0 or proof.len > artifact.MAX_CANONICAL_PROOF_BYTES) return error.EthereumRootProofSizeMismatch;
            const key_hash = hash(key_json);
            const key = try Selected.OwnedKeyV1.admit(allocator, key_json, key_hash);
            defer key.deinit();
            try node.validate();
            _ = try claims.vector(&key.key().manifest);
            const proof_hash = hash(proof);
            const inputs_json = try std.json.Stringify.valueAlloc(allocator, Selected.PublicInputsV1{ .version = Verifier.VERSION, .node = node, .claims = claims, .interaction_pow_nonce = nonce, .proof_bytes = proof.len, .proof_sha256 = proof_hash }, .{});
            defer allocator.free(inputs_json);
            if (inputs_json.len > MAX_INPUT_BYTES) return error.EthereumRootInputSizeMismatch;
            const path = try std.fmt.allocPrint(allocator, "{s}/root-candidates/{x}", .{ corpus, proof_hash });
            errdefer allocator.free(path);
            try std.fs.cwd().makePath(path);
            var dir = try std.fs.cwd().openDir(path, .{});
            defer dir.close();
            // Reuse the complete-proof corpus's create/compare publication policy.
            const io = @import("recursive_common_ethereum_incremental_leaf_genuine_runtime_v4.zig");
            try io.writeReplayFile(dir, "key.json", key_json);
            try io.writeReplayFile(dir, "inputs.json", inputs_json);
            try io.writeReplayFile(dir, "proof.bin", proof);
            return .{ .allocator = allocator, .path = path, .expected_key_sha256 = key_hash };
        }

        pub const ReceiptV1 = struct {
            endpoint: []const u8 = if (ManifestMod == initial_manifest) "verified_ethereum_initial_field_leaf_wrapper" else "verified_ethereum_field_leaf_wrapper",
            verified: bool = true,
            native_inputs_used: bool = false,
            version: u16 = Verifier.VERSION,
            key_sha256: [32]u8,
            proof_sha256: [32]u8,
            coordinate: @import("recursive_node_artifact_v1.zig").TaskCoordinateV1,
            statement_words: [public.STATEMENT_WORD_COUNT]u32,
            proof_bytes: usize,
            request_ns: u64,
            verify_ns: u64,
            peak_footprint_bytes: ?u64,
            output_digest: [8]u32,
            transcript_digest: [8]u32,
        };

        pub fn verifyDirectory(allocator: std.mem.Allocator, path: []const u8, expected_key_sha256: [32]u8) !Selected.ReceiptV1 {
            var request_timer = try std.time.Timer.start();
            var dir = try std.fs.cwd().openDir(path, .{});
            defer dir.close();
            const key_json = try dir.readFileAlloc(allocator, "key.json", MAX_KEY_BYTES);
            defer allocator.free(key_json);
            const key = try Selected.OwnedKeyV1.admit(allocator, key_json, expected_key_sha256);
            defer key.deinit();
            const inputs_json = try dir.readFileAlloc(allocator, "inputs.json", MAX_INPUT_BYTES);
            defer allocator.free(inputs_json);
            const inputs = try Selected.decodeInputs(allocator, inputs_json);
            const proof = try dir.readFileAlloc(allocator, "proof.bin", inputs.proof_bytes);
            defer allocator.free(proof);
            if (proof.len != inputs.proof_bytes or !std.meta.eql(hash(proof), inputs.proof_sha256)) return error.EthereumRootProofIdentityMismatch;
            var timer = try std.time.Timer.start();
            const terminal = try Verifier.verify(allocator, key.key(), &inputs.node, inputs.claims, inputs.interaction_pow_nonce, proof);
            const verify_ns = timer.read();
            const sample = usage.sample() catch null;
            return .{
                .key_sha256 = expected_key_sha256,
                .proof_sha256 = inputs.proof_sha256,
                .coordinate = inputs.node.coordinate,
                .statement_words = inputs.node.statement_words,
                .proof_bytes = proof.len,
                .request_ns = request_timer.read(),
                .verify_ns = verify_ns,
                .peak_footprint_bytes = if (sample) |value| value.lifetime_peak_physical_footprint_bytes else null,
                .output_digest = inputs.node.output_digest,
                .transcript_digest = terminal,
            };
        }
    };
}

pub const ArgumentsV1 = struct { initial: bool, directory: []const u8, expected_key_sha256: [32]u8 };

pub fn parseArguments(args: []const []const u8) !ArgumentsV1 {
    const initial = args.len > 0 and std.mem.eql(u8, args[0], "--initial-v1");
    const position: usize = @intFromBool(initial);
    if (args.len != position + 2 or args[position + 1].len != 64 or std.mem.startsWith(u8, args[position], "--"))
        return error.ExpectedRootDirectoryAndIndependentKeySha256;
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, args[position + 1]);
    return .{ .initial = initial, .directory = args[position], .expected_key_sha256 = expected };
}

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const selected = try parseArguments(args[1..]);
    if (selected.initial) return writeReceipt(Initial38, allocator, selected);
    return writeReceipt(Ordinary, allocator, selected);
}

fn writeReceipt(comptime Command: type, allocator: std.mem.Allocator, args: ArgumentsV1) !void {
    const receipt = try Command.verifyDirectory(allocator, args.directory, args.expected_key_sha256);
    const output = try std.json.Stringify.valueAlloc(allocator, receipt, .{});
    defer allocator.free(output);
    try std.fs.File.stdout().writeAll(output);
    try std.fs.File.stdout().writeAll("\n");
}

pub fn hash(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}
