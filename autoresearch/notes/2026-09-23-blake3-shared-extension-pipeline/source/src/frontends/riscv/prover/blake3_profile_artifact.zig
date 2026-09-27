//! Shared full-width execution-profile artifact framing and fresh verification.
//! Fresh verification derives its key from authenticated metadata and supplied
//! source bytes, without retaining the runner or trusting an embedded proof key.
const std = @import("std");
const core = @import("stwo_core");
pub const VerifiedPublic = @import("blake3_verified_public.zig").VerifiedPublic;
pub fn ForProfile(comptime ethereum: bool) type {
    return ForExecutionProfile(if (ethereum) .rv32im_zkvm_ethereum_v1 else .rv32im_zkvm_v1);
}
pub fn ForExecutionProfile(comptime profile: @import("../isa/execution_profile.zig").ExecutionProfile) type {
    const ethereum = profile == .rv32im_zkvm_ethereum_v1;
    const extended = profile != .rv32im_zkvm_v1;
    if (extended and !ethereum and profile != .rv32im_zkvm_poseidon2_v1) @compileError("unsupported full-width artifact profile");
    return struct {
        const manifest = if (ethereum) @import("blake3_ethereum_manifest.zig") else if (extended) @import("blake3_poseidon_manifest.zig") else @import("blake3_execution_manifest.zig");
        const source_api = @import("blake3_execution_source.zig");
        const codec = if (ethereum) @import("blake3_ethereum_codec.zig") else if (extended) @import("blake3_poseidon_proof.zig").codec else @import("blake3_execution_codec.zig");
        const proof_api = if (ethereum) @import("blake3_ethereum_proof.zig") else if (extended) @import("blake3_poseidon_proof.zig") else @import("blake3_execution_proof.zig");
        pub const MAGIC = if (ethereum) "B3EVART1" else if (extended) "B3PVART1" else "B3RVART1";
        pub const HEADER_BYTES: usize = 28;
        pub const Limits = struct {
            max_bytes: usize = 768 * 1024 * 1024,
            max_elf_bytes: usize = 64 * 1024 * 1024,
            manifest: manifest.Limits = .{},
        };
        pub const Encoded = struct { bytes: []u8, statement_id: [32]u8 };
        pub const Sections = struct { manifest_bytes: []const u8, proof_bytes: []const u8 };
        pub fn hasMagic(prefix: []const u8) bool {
            return prefix.len >= MAGIC.len and std.mem.eql(u8, prefix[0..MAGIC.len], MAGIC);
        }
        pub fn split(raw: []const u8, limits: Limits) !Sections {
            if (raw.len > limits.max_bytes) return error.ExecutionArtifactTooLarge;
            if (raw.len < HEADER_BYTES) return error.TruncatedExecutionArtifact;
            if (!hasMagic(raw) or std.mem.readInt(u32, raw[8..12], .little) != 1) return error.InvalidExecutionArtifactVersion;
            const manifest_size = std.math.cast(usize, std.mem.readInt(u64, raw[12..20], .little)) orelse return error.ExecutionArtifactTooLarge;
            const proof_size = std.math.cast(usize, std.mem.readInt(u64, raw[20..28], .little)) orelse return error.ExecutionArtifactTooLarge;
            if (manifest_size < manifest.HEADER_BYTES or manifest_size > limits.manifest.max_bytes or proof_size < codec.HEADER_BYTES) return error.InvalidExecutionArtifactLength;
            const proof_start = try std.math.add(usize, HEADER_BYTES, manifest_size);
            if (try std.math.add(usize, proof_start, proof_size) != raw.len) return error.InvalidExecutionArtifactLength;
            return .{ .manifest_bytes = raw[HEADER_BYTES..proof_start], .proof_bytes = raw[proof_start..] };
        }
        pub fn encode(a: std.mem.Allocator, proof: *const proof_api.Proof, prepared: anytype, elf: []const u8, input: []const u8, limits: Limits) !Encoded {
            try sourceLimits(elf, input, limits);
            try prepared.validate(prepared.id);
            const shape = if (extended) &prepared.native else &prepared.shape;
            const source = try source_api.validateProfile(profile, a, elf, input, &shape.public_data);
            const metadata = if (extended)
                try manifest.encode(a, shape, prepared.extension, prepared.admission(), prepared.config, source, limits.manifest)
            else
                try manifest.encode(a, shape, prepared.admission(), prepared.config, source, limits.manifest);
            defer a.free(metadata);
            const body = try codec.encode(a, proof, prepared, prepared.id);
            defer a.free(body);
            const size = try std.math.add(usize, HEADER_BYTES, try std.math.add(usize, metadata.len, body.len));
            if (size > limits.max_bytes) return error.ExecutionArtifactTooLarge;
            const raw = try a.alloc(u8, size);
            @memcpy(raw[0..8], MAGIC);
            std.mem.writeInt(u32, raw[8..12], 1, .little);
            std.mem.writeInt(u64, raw[12..20], metadata.len, .little);
            std.mem.writeInt(u64, raw[20..28], body.len, .little);
            @memcpy(raw[HEADER_BYTES..][0..metadata.len], metadata);
            @memcpy(raw[HEADER_BYTES + metadata.len ..], body);
            return .{ .bytes = raw, .statement_id = manifest.identity(metadata) };
        }
        pub fn ForBackend(comptime Backend: type) type {
            return struct {
                const Api = proof_api.ForBackend(Backend);
                /// The expected manifest identity and policy are external caller inputs.
                pub fn verify(a: std.mem.Allocator, raw: []const u8, expected_statement: [32]u8, config: core.pcs.PcsConfig, elf: []const u8, input: []const u8, limits: Limits) ![32]u8 {
                    return verifyInternal(false, a, raw, expected_statement, config, elf, input, limits);
                }
                pub fn verifyPublic(a: std.mem.Allocator, raw: []const u8, expected_statement: [32]u8, config: core.pcs.PcsConfig, elf: []const u8, input: []const u8, limits: Limits) !VerifiedPublic {
                    return verifyInternal(true, a, raw, expected_statement, config, elf, input, limits);
                }
                fn verifyInternal(comptime public_summary: bool, a: std.mem.Allocator, raw: []const u8, expected_statement: [32]u8, config: core.pcs.PcsConfig, elf: []const u8, input: []const u8, limits: Limits) !(if (public_summary) VerifiedPublic else [32]u8) {
                    try sourceLimits(elf, input, limits);
                    const sections = try split(raw, limits);
                    var source: manifest.Source = undefined;
                    std.crypto.hash.sha2.Sha256.hash(elf, &source.elf_sha256, .{});
                    std.crypto.hash.sha2.Sha256.hash(input, &source.input_sha256, .{});
                    const prepared = blk: {
                        var decoded = try manifest.decode(a, sections.manifest_bytes, expected_statement, source, config, limits.manifest);
                        defer decoded.deinit();
                        const admitted = if (extended) &decoded.base else &decoded;
                        _ = try source_api.validateProfile(profile, a, elf, input, &admitted.statement.value.public_data);
                        break :blk if (extended)
                            try Api.PreparedVerifier.init(a, &admitted.statement.value, decoded.extension, try admitted.admission(), config)
                        else
                            try Api.PreparedVerifier.init(a, &admitted.statement.value, try admitted.admission(), config);
                    };
                    defer prepared.deinit();
                    const proof = try codec.decode(a, sections.proof_bytes, prepared, prepared.id);
                    const transcript = if (extended) try Api.verifyOwned(a, proof, prepared, prepared.id) else try Api.verifyPreparedOwned(a, proof, prepared, prepared.id);
                    if (!public_summary) return transcript;
                    const shape = if (extended) &prepared.native else &prepared.shape;
                    const io = shape.public_data.io_entries;
                    var hash = std.crypto.hash.sha2.Sha256.init(.{});
                    var remaining: usize = io.output_len;
                    // Prepared admission validated length, address order and padding.
                    if (remaining != 0) for (io.output_words[1..]) |word| {
                        var bytes: [4]u8 = undefined;
                        std.mem.writeInt(u32, &bytes, word.value, .little);
                        const used = @min(remaining, bytes.len);
                        hash.update(bytes[0..used]);
                        remaining -= used;
                    };
                    std.debug.assert(remaining == 0);
                    var output_sha256: [32]u8 = undefined;
                    hash.final(&output_sha256);
                    return .{ .signer_calls = if (ethereum) prepared.extension.counts.signer_calls else 0, .keccak_calls = if (ethereum) prepared.extension.counts.keccak_calls else 0, .halt_flag = if (shape.public_data.completion) |completion| completion.kind == .halt_flag else false, .transcript = transcript, .output_sha256 = output_sha256, .output_len = io.output_len, .steps = shape.total_steps, .elf_sha256 = source.elf_sha256, .input_sha256 = source.input_sha256 };
                }
            };
        }
        fn sourceLimits(elf: []const u8, input: []const u8, limits: Limits) !void {
            if (elf.len > limits.max_elf_bytes or input.len > limits.manifest.statement.max_input_bytes) return error.ExecutionSourceResourceLimit;
        }
    };
}
