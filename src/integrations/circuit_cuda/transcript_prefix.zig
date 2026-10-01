//! The circuit transcript boundary before `prove_ex`. Each operation is
//! explicit because the interaction witness depends on challenges drawn
//! halfway through this prefix. A resident CUDA sink can keep the channel
//! and the two challenges on the device; the host sink below is only a
//! byte-for-byte contract against the pinned Rust proof fixtures.
const std = @import("std");
const core = @import("stwo_core");

const QM31 = core.fields.qm31.QM31;
const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;
const profiles = core.vcs_lifted.channel_profile.proving_5a7c5ed;

pub const Stage = enum {
    initial,
    salt,
    fri_config,
    preprocessed,
    circuit_hash,
    claim,
    base,
    interaction_nonce,
    lookup_elements,
    interaction_claim,
    interaction,
};

/// `Sink` supplies `Root`, `Felts`, `Lookup` and operations named below.
/// The caller supplies authenticated commitment roots. The sink owns the
/// interaction PoW boundary; the device sink grinds without a host nonce.
pub fn Prefix(comptime Sink: type) type {
    return struct {
        sink: *Sink,
        stage: Stage = .initial,

        const Self = @This();

        fn require(self: *Self, expected: Stage) !void {
            if (self.stage != expected) return error.CircuitTranscriptOrder;
        }

        pub fn mixSalt(self: *Self, salt: u32) !void {
            try self.require(.initial);
            try self.sink.mixSalt(salt);
            self.stage = .salt;
        }

        pub fn mixFriConfig(self: *Self, config: PcsConfigV2) !void {
            try self.require(.salt);
            try self.sink.mixFriConfig(config);
            self.stage = .fri_config;
        }

        pub fn commitPreprocessed(self: *Self, root: Sink.Root) !void {
            try self.require(.fri_config);
            try self.sink.mixRoot(root);
            self.stage = .preprocessed;
        }

        pub fn mixCircuitHash(self: *Self, hash: Sink.Root) !void {
            try self.require(.preprocessed);
            try self.sink.mixRoot(hash);
            self.stage = .circuit_hash;
        }

        pub fn mixClaim(self: *Self, output_values: Sink.Felts) !void {
            try self.require(.circuit_hash);
            try self.sink.mixFelts(output_values);
            self.stage = .claim;
        }

        pub fn commitBase(self: *Self, root: Sink.Root) !void {
            try self.require(.claim);
            try self.sink.mixRoot(root);
            self.stage = .base;
        }

        pub fn absorbInteractionNonce(self: *Self, nonce: Sink.Nonce) !void {
            try self.require(.base);
            try self.sink.absorbPow(nonce, 20);
            self.stage = .interaction_nonce;
        }

        pub fn drawLookupElements(self: *Self) !Sink.Lookup {
            try self.require(.interaction_nonce);
            const lookup = try self.sink.drawLookupElements();
            self.stage = .lookup_elements;
            return lookup;
        }

        pub fn mixInteractionClaim(self: *Self, claimed_sums: Sink.Felts) !void {
            try self.require(.lookup_elements);
            try self.sink.mixFelts(claimed_sums);
            self.stage = .interaction_claim;
        }

        pub fn commitInteraction(self: *Self, root: Sink.Root) !void {
            try self.require(.interaction_claim);
            try self.sink.mixRoot(root);
            self.stage = .interaction;
        }

        pub fn admitComposition(self: *Self) !void {
            try self.require(.interaction);
        }
    };
}

/// Reference sink for fixture checks. Production CUDA proving must use the
/// resident transcript kernels rather than this host channel.
pub fn HostSink(comptime MC: type) type {
    return struct {
        channel: MC.Channel = .{},

        pub const Root = [32]u8;
        pub const Felts = []const QM31;
        pub const Nonce = u64;
        pub const Lookup = core.channel.lookup_transcript.LookupElements;

        pub fn mixSalt(self: *@This(), salt: u32) !void {
            core.channel.lookup_transcript.mixChannelSalt(&self.channel, salt);
        }

        pub fn mixFriConfig(self: *@This(), config: PcsConfigV2) !void {
            config.fri_config.mixInto(&self.channel);
        }

        pub fn mixFelts(self: *@This(), felts: Felts) !void {
            self.channel.mixFelts(felts);
        }

        pub fn mixRoot(self: *@This(), root: Root) !void {
            MC.mixRoot(&self.channel, root);
        }

        pub fn absorbPow(self: *@This(), nonce: Nonce, bits: u32) !void {
            if (!self.channel.verifyPowNonce(bits, nonce)) return error.InvalidInteractionNonce;
            self.channel.mixU64(nonce);
        }

        pub fn drawLookupElements(self: *@This()) !Lookup {
            return core.channel.lookup_transcript.drawLookupElements(std.heap.page_allocator, &self.channel);
        }
    };
}

pub const InternalHostSink = HostSink(profiles.Blake2sM31MerkleChannel);
pub const RootHostSink = HostSink(profiles.Blake2sMerkleChannel);

test "circuit CUDA prefix refuses out-of-order absorption" {
    var sink = InternalHostSink{};
    var prefix = Prefix(InternalHostSink){ .sink = &sink };
    try std.testing.expectError(error.CircuitTranscriptOrder, prefix.mixFriConfig(PcsConfigV2.fromFriAndTraceSize(
        try core.pcs.config_v2.FriConfigV2.init(10, 0, 1, 3, 1),
        20,
    )));
    try prefix.mixSalt(0);
    try std.testing.expectError(error.CircuitTranscriptOrder, prefix.mixSalt(0));
    try std.testing.expectError(error.CircuitTranscriptOrder, prefix.admitComposition());
}

test "circuit CUDA prefix matches all ten pinned Rust R7 transcripts" {
    const allocator = std.testing.allocator;
    for ([_][]const u8{ "vectors/circuit/r7/prove_small.json", "vectors/circuit/r7/prove_profiles.json" }, 0..) |path, fixture_index| {
        const bytes = try std.fs.cwd().readFileAlloc(allocator, path, 8 << 20);
        defer allocator.free(bytes);
        var fixture = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
        defer fixture.deinit();
        const body = try jsonField(fixture.value, "body");
        if (fixture_index == 0) {
            const proofs = (try jsonField(body, "proofs")).array.items;
            try std.testing.expectEqual(@as(usize, 6), proofs.len);
            for (proofs) |proof| try expectRustPrefix(InternalHostSink, allocator, proof);
        } else {
            const groups = (try jsonField(body, "profiles")).array.items;
            try std.testing.expectEqual(@as(usize, 2), groups.len);
            for (groups) |group| {
                const profile = (try jsonField(group, "profile")).string;
                const proofs = (try jsonField(group, "proofs")).array.items;
                try std.testing.expectEqual(@as(usize, 2), proofs.len);
                if (std.mem.eql(u8, profile, "internal")) {
                    for (proofs) |proof| try expectRustPrefix(InternalHostSink, allocator, proof);
                } else if (std.mem.eql(u8, profile, "root")) {
                    for (proofs) |proof| try expectRustPrefix(RootHostSink, allocator, proof);
                } else return error.InvalidCircuitFixture;
            }
        }
    }
}

fn expectRustPrefix(comptime Sink: type, allocator: std.mem.Allocator, proof: std.json.Value) !void {
    const config_json = try jsonField(proof, "pcs_config");
    const fri_json = try jsonField(config_json, "fri_config");
    const config = PcsConfigV2{
        .fri_config = try core.pcs.config_v2.FriConfigV2.init(
            try jsonU32(try jsonField(fri_json, "pow_bits")),
            try jsonU32(try jsonField(fri_json, "log_last_layer_degree_bound")),
            try jsonU32(try jsonField(fri_json, "log_blowup_factor")),
            try jsonU32(try jsonField(fri_json, "n_queries")),
            try jsonU32(try jsonField(fri_json, "fold_step")),
        ),
        .trace_lifting_log_size = try jsonU32(try jsonField(config_json, "trace_lifting_log_size")),
        .preprocessed_lifting_log_size = try jsonU32(try jsonField(config_json, "preprocessed_lifting_log_size")),
    };
    const commitments = (try jsonField(proof, "commitments")).array.items;
    if (commitments.len != 4) return error.InvalidCircuitFixture;
    const steps = (try jsonField(proof, "steps")).array.items;
    if (steps.len != 11) return error.InvalidCircuitFixture;
    var sink = Sink{};
    var prefix = Prefix(Sink){ .sink = &sink };
    try prefix.mixSalt(0);
    try expectStep(steps[0], .salt, sink.channel.digestBytes());
    try prefix.mixFriConfig(config);
    try expectStep(steps[1], .fri_config, sink.channel.digestBytes());
    try prefix.commitPreprocessed(try jsonRoot(commitments[0]));
    try expectStep(steps[2], .preprocessed, sink.channel.digestBytes());
    try prefix.mixCircuitHash(try jsonRoot(try jsonField(proof, "circuit_hash")));
    try expectStep(steps[3], .circuit_hash, sink.channel.digestBytes());

    const output_values = try jsonFelts(allocator, try jsonField(proof, "output_values"));
    defer allocator.free(output_values);
    try prefix.mixClaim(output_values);
    try expectStep(steps[4], .claim, sink.channel.digestBytes());
    try prefix.commitBase(try jsonRoot(commitments[1]));
    try expectStep(steps[5], .base, sink.channel.digestBytes());
    const nonce_json = try jsonField(try jsonField(proof, "interaction_pow_nonce"), "value");
    if (nonce_json != .string) return error.InvalidCircuitFixture;
    try prefix.absorbInteractionNonce(try std.fmt.parseInt(u64, nonce_json.string, 10));
    try expectStep(steps[6], .interaction_nonce, sink.channel.digestBytes());
    const lookup = try prefix.drawLookupElements();
    try expectStep(steps[7], .lookup_elements, sink.channel.digestBytes());
    try std.testing.expect(lookup.z.eql(try jsonFelt(try jsonField(proof, "interaction_z"))));
    try std.testing.expect(lookup.alpha.eql(try jsonFelt(try jsonField(proof, "interaction_alpha"))));

    const sum_pairs = (try jsonField(proof, "claimed_sums")).array.items;
    if (sum_pairs.len != 11) return error.InvalidCircuitFixture;
    var sums: [11]QM31 = undefined;
    for (sum_pairs, &sums) |pair, *sum| {
        if (pair != .array or pair.array.items.len != 2) return error.InvalidCircuitFixture;
        sum.* = try jsonFelt(pair.array.items[1]);
    }
    try prefix.mixInteractionClaim(&sums);
    try expectStep(steps[8], .interaction_claim, sink.channel.digestBytes());
    try prefix.commitInteraction(try jsonRoot(commitments[2]));
    try expectStep(steps[9], .interaction, sink.channel.digestBytes());
    try prefix.admitComposition();
}

fn expectStep(step: std.json.Value, stage: Stage, actual: [32]u8) !void {
    const names = [_][]const u8{
        "mix_channel_salt",  "mix_fri_config",            "commit_preprocessed",       "mix_circuit_hash",      "mix_claim",
        "commit_base_trace", "mix_interaction_pow_nonce", "draw_interaction_elements", "mix_interaction_claim", "commit_interaction_trace",
        "prove_ex",
    };
    const ordinal = @intFromEnum(stage) - 1;
    try std.testing.expectEqualStrings(names[ordinal], (try jsonField(step, "step")).string);
    const hex = std.fmt.bytesToHex(actual, .lower);
    try std.testing.expectEqualStrings((try jsonField(step, "channel_digest")).string, &hex);
}

fn jsonField(value: std.json.Value, key: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidCircuitFixture;
    return value.object.get(key) orelse error.InvalidCircuitFixture;
}

fn jsonU32(value: std.json.Value) !u32 {
    if (value != .integer or value.integer < 0) return error.InvalidCircuitFixture;
    return std.math.cast(u32, value.integer) orelse error.InvalidCircuitFixture;
}

fn jsonRoot(value: std.json.Value) ![32]u8 {
    if (value != .string or value.string.len != 64) return error.InvalidCircuitFixture;
    var root: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&root, value.string) catch return error.InvalidCircuitFixture;
    return root;
}

fn jsonFelt(value: std.json.Value) !QM31 {
    if (value != .array or value.array.items.len != 4) return error.InvalidCircuitFixture;
    return QM31.fromU32Unchecked(
        try jsonU32(value.array.items[0]),
        try jsonU32(value.array.items[1]),
        try jsonU32(value.array.items[2]),
        try jsonU32(value.array.items[3]),
    );
}

fn jsonFelts(allocator: std.mem.Allocator, value: std.json.Value) ![]QM31 {
    if (value != .array) return error.InvalidCircuitFixture;
    const felts = try allocator.alloc(QM31, value.array.items.len);
    errdefer allocator.free(felts);
    for (value.array.items, felts) |item, *felt| felt.* = try jsonFelt(item);
    return felts;
}
