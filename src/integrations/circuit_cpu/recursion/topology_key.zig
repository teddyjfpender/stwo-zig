//! Topology identity of a recursion circuit (design §3.5).
//!
//! A `TopologyKey` is the Blake2s-256 digest of everything a circuit's
//! topology depends on: gate lists, constants, padding, preprocessed columns
//! and circuit hash. Two circuits with the same key have the same topology,
//! so the preprocessed circuit built for one serves every later proof of the
//! key (`topology_cache.zig`).
//!
//! - **Leaf** (`crates/leaf_prover/src/prove_leaf.rs`,
//!   https://github.com/starkware-libs/proving at
//!   5a7c5ede4299c91a61df19a07cba4f7502c14230): the registry config name, the
//!   circuit FRI config and the shared padding target; the Cairo
//!   preprocessed-trace variant and the enabled components; the Cairo proof's
//!   FRI config and trace log size (the in-circuit verifier's `ProofConfig`);
//!   the ZK flag; the Cairo preprocessed root and the program, which
//!   `CairoStatement::new` interns as constants (`statement.rs:513,644`).
//! - **Fold**: the registry config name, the circuit FRI config and the
//!   shared target only. `CanonicalCircuit::build` derives the multiverifier
//!   from those alone; each child's root and digest are guessed and its
//!   circuit hash is computed in-circuit (`canonical.rs:45-105`).
//!
//! The key is an optimisation, not a trust boundary: a leaf proof is still
//! checked against the registry's circuit hash on every wrap (`leaf_wrap.zig`).
//!
//! Encoding: a domain tag, the protocol revision and the kind, then each field
//! as little-endian `u32` words; byte strings and slices carry a `u64` length.
//! The program enters as its SHA-256 over the little-endian limbs together
//! with the in-circuit program hash (`cairo_air_layout.programHash`).

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");

const layout = core.cairo_air_layout;
const FriConfigV2 = core.pcs.config_v2.FriConfigV2;
const ComponentSizes = circuit.common.finalize.ComponentSizes;
const Revision = core.protocol_revision.Revision;
const Blake2s256 = std.crypto.hash.blake2.Blake2s256;

/// Changes whenever the encoding below changes.
const domain_tag = "stwo-circuit-topology-key/v1";

/// The only revision recursion circuits exist under.
pub const revision: Revision = .proving_5a7c5ed;

pub const Kind = enum(u8) { leaf = 1, fold = 2 };

pub const TopologyKey = struct {
    digest: [Blake2s256.digest_length]u8,

    pub fn eql(self: TopologyKey, other: TopologyKey) bool {
        return std.mem.eql(u8, &self.digest, &other.digest);
    }

    pub fn format(self: TopologyKey, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeAll(&std.fmt.bytesToHex(self.digest, .lower));
    }
};

/// What a leaf verifier circuit's topology depends on. Borrowed.
pub const LeafKey = struct {
    config_name: []const u8,
    circuit_fri: FriConfigV2,
    target: ComponentSizes,
    variant: layout.Variant,
    /// One flag per `all_components()` slot.
    enabled_bits: []const bool,
    cairo_fri: FriConfigV2,
    trace_log_size: u32,
    zk_blinding: bool,
    cairo_preprocessed_root: [8]u32,
    program: []const layout.ProgramFelt,

    pub fn key(self: LeafKey) TopologyKey {
        var encoder = Encoder.begin(.leaf);
        encoder.bytes(self.config_name);
        encoder.fri(self.circuit_fri);
        encoder.sizes(self.target);
        encoder.bytes(@tagName(self.variant));
        encoder.length(self.enabled_bits.len);
        for (self.enabled_bits) |bit| encoder.word(@intFromBool(bit));
        encoder.fri(self.cairo_fri);
        encoder.word(self.trace_log_size);
        encoder.word(@intFromBool(self.zk_blinding));
        for (self.cairo_preprocessed_root) |word| encoder.word(word);
        encoder.length(self.program.len);
        encoder.digest(programSha256(self.program));
        for (layout.programHash(self.program)) |word| encoder.word(word);
        return encoder.finish();
    }
};

/// What the fold (multiverifier) circuit's topology depends on. Borrowed.
pub const FoldKey = struct {
    config_name: []const u8,
    circuit_fri: FriConfigV2,
    target: ComponentSizes,

    pub fn key(self: FoldKey) TopologyKey {
        var encoder = Encoder.begin(.fold);
        encoder.bytes(self.config_name);
        encoder.fri(self.circuit_fri);
        encoder.sizes(self.target);
        return encoder.finish();
    }
};

/// SHA-256 over the program limbs as little-endian `u32` words.
fn programSha256(program: []const layout.ProgramFelt) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (program) |felt| for (felt) |limb| {
        var word: [4]u8 = undefined;
        std.mem.writeInt(u32, &word, limb.toU32(), .little);
        hasher.update(&word);
    };
    return hasher.finalResult();
}

const Encoder = struct {
    hasher: Blake2s256,

    fn begin(kind: Kind) Encoder {
        var self = Encoder{ .hasher = Blake2s256.init(.{}) };
        self.bytes(domain_tag);
        self.bytes(@tagName(revision));
        self.word(@intFromEnum(kind));
        return self;
    }

    fn word(self: *Encoder, value: u32) void {
        var buffer: [4]u8 = undefined;
        std.mem.writeInt(u32, &buffer, value, .little);
        self.hasher.update(&buffer);
    }

    fn length(self: *Encoder, value: usize) void {
        var buffer: [8]u8 = undefined;
        std.mem.writeInt(u64, &buffer, value, .little);
        self.hasher.update(&buffer);
    }

    fn bytes(self: *Encoder, value: []const u8) void {
        self.length(value.len);
        self.hasher.update(value);
    }

    fn digest(self: *Encoder, value: [32]u8) void {
        self.hasher.update(&value);
    }

    fn fri(self: *Encoder, config: FriConfigV2) void {
        for ([_]u32{
            config.pow_bits,
            config.log_blowup_factor,
            config.log_last_layer_degree_bound,
            config.n_queries,
            config.fold_step,
        }) |value| self.word(value);
    }

    fn sizes(self: *Encoder, target: ComponentSizes) void {
        inline for (std.meta.fields(ComponentSizes)) |field| self.length(@field(target, field.name));
    }

    fn finish(self: *Encoder) TopologyKey {
        var out: TopologyKey = undefined;
        self.hasher.final(&out.digest);
        return out;
    }
};

const testing_fri = FriConfigV2{ .pow_bits = 26, .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 35, .fold_step = 4 };
const testing_target = ComponentSizes{ .eq = 1 << 20, .qm31_ops = 1 << 23, .m31_to_u32 = 1 << 20, .triple_xor = 1 << 19, .blake_g_gate = 1 << 23 };

fn testingLeaf(program: []const layout.ProgramFelt, bits: []const bool) LeafKey {
    return .{
        .config_name = "default",
        .circuit_fri = testing_fri,
        .target = testing_target,
        .variant = .canonical_small,
        .enabled_bits = bits,
        .cairo_fri = .{ .pow_bits = 16, .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 70, .fold_step = 1 },
        .trace_log_size = 20,
        .zk_blinding = false,
        .cairo_preprocessed_root = .{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .program = program,
    };
}

test "topology key: every leaf field changes the key" {
    const M31 = core.fields.m31.M31;
    var program = [_]layout.ProgramFelt{[_]M31{M31.zero()} ** layout.memory_values_limbs} ** 2;
    const bits = [_]bool{ true, false, true };
    const base = testingLeaf(&program, &bits).key();
    try std.testing.expect(base.eql(testingLeaf(&program, &bits).key()));

    var other = testingLeaf(&program, &bits);
    other.config_name = "other";
    try std.testing.expect(!base.eql(other.key()));
    other = testingLeaf(&program, &bits);
    other.circuit_fri.n_queries = 70;
    try std.testing.expect(!base.eql(other.key()));
    other = testingLeaf(&program, &bits);
    other.target.triple_xor = 1 << 20;
    try std.testing.expect(!base.eql(other.key()));
    other = testingLeaf(&program, &bits);
    other.variant = .canonical;
    try std.testing.expect(!base.eql(other.key()));
    const flipped = [_]bool{ true, true, true };
    other = testingLeaf(&program, &flipped);
    try std.testing.expect(!base.eql(other.key()));
    other = testingLeaf(&program, &bits);
    other.cairo_fri.pow_bits = 26;
    try std.testing.expect(!base.eql(other.key()));
    other = testingLeaf(&program, &bits);
    other.trace_log_size = 25;
    try std.testing.expect(!base.eql(other.key()));
    other = testingLeaf(&program, &bits);
    other.zk_blinding = true;
    try std.testing.expect(!base.eql(other.key()));
    other = testingLeaf(&program, &bits);
    other.cairo_preprocessed_root[7] = 9;
    try std.testing.expect(!base.eql(other.key()));
    other = testingLeaf(&program, &bits);
    other.program = program[0..1];
    try std.testing.expect(!base.eql(other.key()));
    var changed = program;
    changed[1][27] = M31.one();
    other = testingLeaf(&changed, &bits);
    try std.testing.expect(!base.eql(other.key()));
}

test "topology key: leaf and fold keys are separated by kind" {
    const fold = FoldKey{ .config_name = "default", .circuit_fri = testing_fri, .target = testing_target };
    try std.testing.expect(fold.key().eql(fold.key()));
    const leaf = testingLeaf(&.{}, &.{}).key();
    try std.testing.expect(!fold.key().eql(leaf));
    var other = fold;
    other.target.eq = 1 << 21;
    try std.testing.expect(!fold.key().eql(other.key()));
}
