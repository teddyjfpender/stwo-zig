//! A test-only reader of the fields the R6 fold rung needs from a circuit
//! registry JSON (`vectors/circuit/official/registries/*.json`). The
//! registry codec proper is the interchange package's `registry.zig`, which
//! this frontend may not depend on (frontends depend on no interchange
//! package); the circuit integrations use that codec.

const std = @import("std");
const blake2_hash = @import("stwo_core").vcs.blake2_hash;
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");

const circuit_hash = circuit.common.circuit_hash;

pub const DigestWords = [8][]const u8;

pub const FriConfig = struct {
    pow_bits: u32,
    log_blowup_factor: u32,
    log_last_layer_degree_bound: u32,
    n_queries: u32,
    fold_step: u32,

    pub fn toFriConfig(self: FriConfig) !core.pcs.config_v2.FriConfigV2 {
        return core.pcs.config_v2.FriConfigV2.init(self.pow_bits, self.log_last_layer_degree_bound, self.log_blowup_factor, self.n_queries, self.fold_step);
    }
};

pub const LogSizes = struct {
    eq: u32,
    qm31_ops: u32,
    m31_to_u32: u32,
    triple_xor: u32,
    blake_g_gate: u32,
};

pub const CircuitConfig = struct {
    fri_config: FriConfig,
    component_log_sizes: LogSizes,
};

pub const Entry = struct {
    config: []const u8,
    preprocessed_root: DigestWords,
    circuit_hash: DigestWords,
};

pub const Registry = struct {
    circuit_proof_configs: std.json.ArrayHashMap(CircuitConfig),
    leaf_verifiers: []const Entry,
    multiverifiers: []const Entry,
};

/// A registry digest: eight `0x`-prefixed hex words, little-endian bytes.
pub fn parseDigest(words: DigestWords) ![32]u8 {
    var out: [8]u32 = undefined;
    for (words, &out) |text, *word| {
        if (!std.mem.startsWith(u8, text, "0x")) return error.InvalidDigestWord;
        word.* = try std.fmt.parseInt(u32, text[2..], 16);
    }
    return blake2_hash.digestFromU32s(out);
}

pub fn load(allocator: std.mem.Allocator, path: []const u8) !std.json.Parsed(Registry) {
    const bytes = try std.fs.cwd().readFileAlloc(allocator, path, 1 << 20);
    defer allocator.free(bytes);
    return std.json.parseFromSlice(Registry, allocator, bytes, .{ .ignore_unknown_fields = true, .allocate = .alloc_always });
}
