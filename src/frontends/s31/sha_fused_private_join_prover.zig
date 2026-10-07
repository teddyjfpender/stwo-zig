//! Private-header SHA256d witness joined through committed word claims.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const cpu = @import("stwo_circuit_cpu_integration");
const postcard = @import("interop_postcard");
const plan_mod = @import("sha_chip_plan.zig");
const sha = @import("s31_sha_provider").compression;
const profile = @import("sha_fused_private_join_profile.zig");
const native = @import("sha_fused_private_join_native_verifier.zig");
const caller = @import("sha_caller_stream_air.zig");
const caller_bus = @import("sha_caller_stream_bus.zig");
const fused = @import("sha_fused_air.zig");
const fused_bus = @import("sha_fused_word_logup.zig");
const feed = @import("sha_feed_direct_air.zig");
const feed_bus = @import("sha_feed_direct_word_logup.zig");
const word_bus = @import("sha_direct_word_bus.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const MC = cpu.prove.profiles.Blake2sM31MerkleChannel;
const H = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
const Engine = cpu.prove.Internal.Engine;
const Column = prover.pcs.ColumnEvaluation;

pub const Witness = struct {
    allocator: std.mem.Allocator,
    statement: profile.PublicStatement,
    caller_fixed: ?caller.Columns = null,
    caller_bus_fixed: ?caller_bus.Columns = null,
    caller_main: ?caller.Columns = null,
    fused_fixed: ?fused.Columns = null,
    fused_main: ?fused.Columns = null,
    feed_fixed: [profile.call_count]?feed.Columns = @splat(null),
    feed_main: [profile.call_count]?feed.Columns = @splat(null),

    pub fn init(allocator: std.mem.Allocator, header: [80]u8, statement: profile.PublicStatement) !Witness {
        try statement.validate();
        const plan = plan_mod.prepare(header);
        if (statement.digest_visibility == .public and !std.mem.eql(u8, &plan.digest, &statement.digest)) return error.WrongPrivateShaDigest;
        var self = Witness{ .allocator = allocator, .statement = statement };
        errdefer self.deinit();
        self.caller_fixed = try caller.writeFixed(allocator, statement);
        self.caller_bus_fixed = try caller_bus.writeFixed(allocator, statement.config);
        self.caller_main = try caller.writeMain(allocator, header);
        self.fused_fixed = try fused.writeFixed(allocator, statement.config.first_call_id);
        var fused_statements: fused.Statements = undefined;
        for (plan.calls, 0..) |call, i| {
            const compression = sha.witness(call.state, call.block);
            if (!std.meta.eql(compression.output_state, call.output)) return error.InvalidShaRoundWitness;
            fused_statements[i] = .{ .initial = call.state, .final = compression.states[64], .schedule = compression.schedule };
            self.feed_fixed[i] = try feed.writeFixedPrivate(allocator);
            self.feed_main[i] = try feed.writeMain(allocator, .{
                .initial = call.state,
                .terminal = compression.states[64],
                .output = call.output,
            });
        }
        self.fused_main = try fused.writeMain(allocator, fused_statements);
        return self;
    }
    pub fn deinit(self: *Witness) void {
        if (self.caller_fixed) |*value| value.deinit();
        if (self.caller_bus_fixed) |*value| value.deinit();
        if (self.caller_main) |*value| value.deinit();
        if (self.fused_fixed) |*value| value.deinit();
        if (self.fused_main) |*value| value.deinit();
        for (&self.feed_fixed) |*value| if (value.*) |*columns| columns.deinit();
        for (&self.feed_main) |*value| if (value.*) |*columns| columns.deinit();
        self.* = undefined;
    }
    pub fn fixedColumns(self: *const Witness, allocator: std.mem.Allocator) ![]Column {
        const layout = profile.Layout.init(.{});
        const columns = try allocator.alloc(Column, layout.total_fixed);
        @memcpy(columns[layout.caller_fixed..][0..caller.fixed_width], self.caller_fixed.?.values);
        @memcpy(columns[layout.caller_bus_fixed..][0..caller_bus.fixed_width], self.caller_bus_fixed.?.values);
        @memcpy(columns[layout.fused_fixed..][0..fused.fixed_width], self.fused_fixed.?.values);
        for (0..profile.call_count) |i| @memcpy(columns[layout.feed_fixed[i]..][0..feed.fixed_width], self.feed_fixed[i].?.values);
        return columns;
    }
    pub fn mainColumns(self: *const Witness, allocator: std.mem.Allocator) ![]Column {
        const layout = profile.Layout.init(.{});
        const columns = try allocator.alloc(Column, layout.total_main);
        @memcpy(columns[layout.caller_main..][0..caller.main_width], self.caller_main.?.values);
        @memcpy(columns[layout.fused_main..][0..fused.main_width], self.fused_main.?.values);
        for (0..profile.call_count) |i| @memcpy(columns[layout.feed_main[i]..][0..feed.main_width], self.feed_main[i].?.values);
        return columns;
    }
    pub fn writeInteractions(self: *const Witness, gate_elements: word_bus.Elements, word_elements: word_bus.Elements) !Interactions {
        var result = Interactions{ .allocator = self.allocator };
        errdefer result.deinit();
        result.caller = try caller_bus.writeInteraction(self.allocator, self.caller_bus_fixed.?.values, self.caller_main.?.values, self.statement.config, gate_elements, word_elements);
        result.fused = try fused_bus.writeInteraction(self.allocator, self.fused_fixed.?.values, self.fused_main.?.values, word_elements);
        for (0..profile.call_count) |i| {
            const id = self.statement.config.first_call_id + @as(u32, @intCast(i));
            result.feed[i] = try feed_bus.writeInteraction(self.allocator, self.feed_fixed[i].?.values, self.feed_main[i].?.values, id, word_elements);
        }
        return result;
    }
};

pub const Interactions = struct {
    allocator: std.mem.Allocator,
    caller: ?caller_bus.Interaction = null,
    fused: ?fused_bus.Interaction = null,
    feed: [profile.call_count]?feed_bus.Interaction = @splat(null),
    pub fn deinit(self: *Interactions) void {
        if (self.caller) |*value| value.deinit();
        if (self.fused) |*value| value.deinit();
        for (&self.feed) |*value| if (value.*) |*interaction| interaction.deinit();
        self.* = undefined;
    }
    pub fn claims(self: *const Interactions) profile.Claims {
        var result: profile.Claims = undefined;
        result.gate = self.caller.?.gate_claimed_sum;
        result.word[0] = self.caller.?.word_claimed_sum;
        result.word[1] = self.fused.?.claimed_sum;
        for (0..profile.call_count) |i| result.word[2 + i] = self.feed[i].?.claimed_sum;
        return result;
    }
    pub fn columns(self: *const Interactions, allocator: std.mem.Allocator) ![]Column {
        const layout = profile.Layout.init(.{});
        const result = try allocator.alloc(Column, layout.total_interaction);
        @memcpy(result[layout.caller_bus_interaction..][0..caller_bus.interaction_width], self.caller.?.columns);
        @memcpy(result[layout.fused_interaction..][0..fused_bus.interaction_width], self.fused.?.columns);
        for (0..profile.call_count) |i| @memcpy(result[layout.feed_interaction[i]..][0..feed_bus.interaction_width], self.feed[i].?.columns);
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
fn cloneColumns(allocator: std.mem.Allocator, columns: []const Column) ![]Column {
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
    return owned;
}
fn commit(scheme: *Engine.Scheme, allocator: std.mem.Allocator, columns: []const Column, channel: *MC.Channel) !void {
    // commitOwned consumes its input even on error; cloneColumns owns the
    // allocation only until it returns successfully.
    try Engine.commit(scheme, allocator, try cloneColumns(allocator, columns), null, channel);
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
