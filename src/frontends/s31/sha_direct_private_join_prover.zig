//! One private-header direct SHA256d proof, with ten closed word claims and
//! one open Gate claim for the enclosing sparse-wide circuit. The public
//! statement contains only digest and verifier-pinned roster metadata.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const cpu = @import("stwo_circuit_cpu_integration");
const postcard = @import("interop_postcard");
const plan_mod = @import("sha_chip_plan.zig");
const sha = @import("s31_sha_provider").compression;
const profile = @import("sha_direct_private_join_profile.zig");
const native = @import("sha_direct_private_join_native_verifier.zig");
const caller = @import("sha_caller_stream_air.zig");
const caller_bus = @import("sha_caller_stream_bus.zig");
const schedule = @import("sha_schedule_direct_air.zig");
const schedule_bus = @import("sha_schedule_direct_word_logup.zig");
const round = @import("sha_round_direct_air.zig");
const round_bus = @import("sha_round_direct_word_logup.zig");
const feed = @import("sha_feed_direct_air.zig");
const feed_bus = @import("sha_feed_direct_word_logup.zig");
const word_bus = @import("sha_direct_word_bus.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const MC = cpu.prove.profiles.Blake2sM31MerkleChannel;
const H = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
const Engine = cpu.prove.Internal.Engine;
const Column = prover.pcs.ColumnEvaluation;

fn firstWords(block: [64]u8) [16]u32 {
    var result: [16]u32 = undefined;
    for (&result, 0..) |*word, i| word.* = std.mem.readInt(u32, block[4 * i ..][0..4], .big);
    return result;
}

pub const Witness = struct {
    allocator: std.mem.Allocator,
    statement: profile.PublicStatement,
    caller_fixed: ?caller.Columns = null,
    caller_bus_fixed: ?caller_bus.Columns = null,
    caller_main: ?caller.Columns = null,
    schedule_fixed: [profile.call_count]?schedule.Columns = @splat(null),
    round_fixed: [profile.call_count]?round.Columns = @splat(null),
    feed_fixed: [profile.call_count]?feed.Columns = @splat(null),
    schedule_main: [profile.call_count]?schedule.Columns = @splat(null),
    round_main: [profile.call_count]?round.Columns = @splat(null),
    feed_main: [profile.call_count]?feed.Columns = @splat(null),

    pub fn init(allocator: std.mem.Allocator, header: [80]u8, statement: profile.PublicStatement) !Witness {
        try statement.validate();
        const plan = plan_mod.prepare(header);
        if (!std.mem.eql(u8, &plan.digest, &statement.digest)) return error.WrongPrivateShaDigest;
        var self = Witness{ .allocator = allocator, .statement = statement };
        errdefer self.deinit();
        self.caller_fixed = try caller.writeFixed(allocator, statement);
        self.caller_bus_fixed = try caller_bus.writeFixed(allocator, statement.config);
        self.caller_main = try caller.writeMain(allocator, header);
        for (plan.calls, 0..) |call, i| {
            const initial_words = firstWords(call.block);
            const compression = sha.witness(call.state, call.block);
            if (!std.meta.eql(compression.output_state, call.output)) {
                return error.InvalidShaRoundWitness;
            }
            self.schedule_fixed[i] = try schedule.writeFixedPrivate(allocator);
            self.round_fixed[i] = try round.writeFixedPrivate(allocator);
            self.feed_fixed[i] = try feed.writeFixedPrivate(allocator);
            self.schedule_main[i] = try schedule.writeMain(allocator, .{ .first_words = initial_words });
            self.round_main[i] = try round.writeMain(allocator, .{
                .initial = call.state,
                .final = compression.states[64],
                .schedule = compression.schedule,
            });
            self.feed_main[i] = try feed.writeMain(allocator, .{
                .initial = call.state,
                .terminal = compression.states[64],
                .output = call.output,
            });
        }
        return self;
    }

    pub fn deinit(self: *Witness) void {
        if (self.caller_fixed) |*value| value.deinit();
        if (self.caller_bus_fixed) |*value| value.deinit();
        if (self.caller_main) |*value| value.deinit();
        for (&self.schedule_fixed) |*value| if (value.*) |*columns| columns.deinit();
        for (&self.round_fixed) |*value| if (value.*) |*columns| columns.deinit();
        for (&self.feed_fixed) |*value| if (value.*) |*columns| columns.deinit();
        for (&self.schedule_main) |*value| if (value.*) |*columns| columns.deinit();
        for (&self.round_main) |*value| if (value.*) |*columns| columns.deinit();
        for (&self.feed_main) |*value| if (value.*) |*columns| columns.deinit();
        self.* = undefined;
    }

    /// Borrowed column descriptors. The witness owns every backing array.
    pub fn fixedColumns(self: *const Witness, allocator: std.mem.Allocator) ![]Column {
        const layout = profile.Layout.init(.{});
        const columns = try allocator.alloc(Column, layout.total_fixed);
        @memcpy(columns[layout.caller_fixed..][0..caller.fixed_width], self.caller_fixed.?.values);
        @memcpy(columns[layout.caller_bus_fixed..][0..caller_bus.fixed_width], self.caller_bus_fixed.?.values);
        for (0..profile.call_count) |i| {
            @memcpy(columns[layout.schedule_fixed[i]..][0..schedule.fixed_width], self.schedule_fixed[i].?.values);
            @memcpy(columns[layout.round_fixed[i]..][0..round.fixed_width], self.round_fixed[i].?.values);
            @memcpy(columns[layout.feed_fixed[i]..][0..feed.fixed_width], self.feed_fixed[i].?.values);
        }
        return columns;
    }
    pub fn mainColumns(self: *const Witness, allocator: std.mem.Allocator) ![]Column {
        const layout = profile.Layout.init(.{});
        const columns = try allocator.alloc(Column, layout.total_main);
        @memcpy(columns[layout.caller_main..][0..caller.main_width], self.caller_main.?.values);
        for (0..profile.call_count) |i| {
            @memcpy(columns[layout.schedule_main[i]..][0..schedule.main_width], self.schedule_main[i].?.values);
            @memcpy(columns[layout.round_main[i]..][0..round.main_width], self.round_main[i].?.values);
            @memcpy(columns[layout.feed_main[i]..][0..feed.main_width], self.feed_main[i].?.values);
        }
        return columns;
    }

    pub fn writeInteractions(self: *const Witness, gate_elements: word_bus.Elements, word_elements: word_bus.Elements) !Interactions {
        var result = Interactions{ .allocator = self.allocator };
        errdefer result.deinit();
        result.caller = try caller_bus.writeInteraction(self.allocator, self.caller_bus_fixed.?.values, self.caller_main.?.values, self.statement.config, gate_elements, word_elements);
        for (0..profile.call_count) |i| {
            const id = self.statement.config.first_call_id + @as(u32, @intCast(i));
            result.schedule[i] = try schedule_bus.writeInteraction(self.allocator, self.schedule_fixed[i].?.values, self.schedule_main[i].?.values, id, word_elements);
            result.round[i] = try round_bus.writeInteraction(self.allocator, self.round_fixed[i].?.values, self.round_main[i].?.values, id, word_elements);
            result.feed[i] = try feed_bus.writeInteraction(self.allocator, self.feed_fixed[i].?.values, self.feed_main[i].?.values, id, word_elements);
        }
        return result;
    }
};

pub const Interactions = struct {
    allocator: std.mem.Allocator,
    caller: ?caller_bus.Interaction = null,
    schedule: [profile.call_count]?schedule_bus.Interaction = @splat(null),
    round: [profile.call_count]?round_bus.Interaction = @splat(null),
    feed: [profile.call_count]?feed_bus.Interaction = @splat(null),

    pub fn deinit(self: *Interactions) void {
        if (self.caller) |*value| value.deinit();
        for (&self.schedule) |*value| if (value.*) |*interaction| interaction.deinit();
        for (&self.round) |*value| if (value.*) |*interaction| interaction.deinit();
        for (&self.feed) |*value| if (value.*) |*interaction| interaction.deinit();
        self.* = undefined;
    }
    pub fn claims(self: *const Interactions) profile.Claims {
        var result: profile.Claims = undefined;
        result.gate = self.caller.?.gate_claimed_sum;
        result.word[0] = self.caller.?.word_claimed_sum;
        for (0..profile.call_count) |i| {
            result.word[1 + 3 * i] = self.schedule[i].?.claimed_sum;
            result.word[2 + 3 * i] = self.round[i].?.claimed_sum;
            result.word[3 + 3 * i] = self.feed[i].?.claimed_sum;
        }
        return result;
    }
    pub fn columns(self: *const Interactions, allocator: std.mem.Allocator) ![]Column {
        const layout = profile.Layout.init(.{});
        const result = try allocator.alloc(Column, layout.total_interaction);
        @memcpy(result[layout.caller_bus_interaction..][0..caller_bus.interaction_width], self.caller.?.columns);
        for (0..profile.call_count) |i| {
            @memcpy(result[layout.schedule_interaction[i]..][0..schedule_bus.interaction_width], self.schedule[i].?.columns);
            @memcpy(result[layout.round_interaction[i]..][0..round_bus.interaction_width], self.round[i].?.columns);
            @memcpy(result[layout.feed_interaction[i]..][0..feed_bus.interaction_width], self.feed[i].?.columns);
        }
        return result;
    }
};

pub const Artifact = struct {
    allocator: std.mem.Allocator,
    envelope: []u8,
    gate_claim: QM31,
    fixed_root: [32]u8,
    pub fn deinit(self: *Artifact) void {
        self.allocator.free(self.envelope);
        self.* = undefined;
    }
};

fn commit(scheme: *Engine.Scheme, allocator: std.mem.Allocator, columns: []const Column, channel: *MC.Channel) !void {
    const owned = try allocator.alloc(Column, columns.len);
    var ready: usize = 0;
    errdefer {
        for (owned[0..ready]) |column| allocator.free(column.values);
        allocator.free(owned);
    }
    for (columns, owned) |source, *target| {
        target.* = .{ .log_size = source.log_size, .values = try allocator.dupe(M31, source.values) };
        ready += 1;
    }
    try Engine.commit(scheme, allocator, owned, null, channel);
    try Engine.flushPendingCommit(scheme, allocator, channel);
}

pub fn proveOne(allocator: std.mem.Allocator, header: [80]u8, statement: profile.PublicStatement, pcs: core.pcs.config_v2.PcsConfigV2) !Artifact {
    var witness = try Witness.init(allocator, header, statement);
    defer witness.deinit();
    const fixed_columns = try witness.fixedColumns(allocator);
    defer allocator.free(fixed_columns);
    const main_columns = try witness.mainColumns(allocator);
    defer allocator.free(main_columns);
    const expected_fixed_root = try native.canonicalFixedRoot(allocator, statement, pcs);
    var channel = MC.Channel{};
    native.mixStatement(&channel, statement, pcs);
    var scheme = try Engine.initRevision(allocator, pcs);
    var scheme_owned = true;
    defer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setStorePolynomialsCoefficients();
    try commit(&scheme, allocator, fixed_columns, &channel);
    const fixed_root = scheme.trees.items[0].commitment.root();
    if (!std.mem.eql(u8, &fixed_root, &expected_fixed_root)) return error.NoncanonicalShaPrivateFixedRoot;
    try commit(&scheme, allocator, main_columns, &channel);
    const gate_challenge = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    const word_challenge = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    const gate_elements = word_bus.Elements.init(gate_challenge.z, gate_challenge.alpha);
    const word_elements = word_bus.Elements.init(word_challenge.z, word_challenge.alpha);
    var interactions = try witness.writeInteractions(gate_elements, word_elements);
    defer interactions.deinit();
    const claims = interactions.claims();
    try claims.validate();
    const interaction_columns = try interactions.columns(allocator);
    defer allocator.free(interaction_columns);
    const all_claims = [_]QM31{claims.gate} ++ claims.word;
    core.channel.lookup_transcript.mixInteractionClaim(&channel, &all_claims);
    try commit(&scheme, allocator, interaction_columns, &channel);
    var components = profile.Components.init(statement, claims, gate_elements, word_elements, profile.Layout.init(.{}));
    const handles = components.proverHandles();
    scheme_owned = false;
    var proof = try Engine.prove(allocator, &handles, &channel, scheme, .{ .include_all_preprocessed_columns = true });
    defer proof.deinit(allocator);
    var envelope: std.ArrayList(u8) = .empty;
    errdefer envelope.deinit(allocator);
    try native.appendEnvelopePrefix(allocator, &envelope, statement, pcs, claims);
    try postcard.serializeProof(H, envelope.writer(allocator), proof.proof);
    if (envelope.items.len > native.envelope_prefix_bytes + native.max_proof_bytes) return error.ShaPrivateJoinProofTooLarge;
    return .{ .allocator = allocator, .envelope = try envelope.toOwnedSlice(allocator), .gate_claim = claims.gate, .fixed_root = fixed_root };
}
