//! Witness-independent native-child BLAKE3 parent verification and capture.
const std = @import("std");
const core = @import("stwo_core");
const suite = @import("blake3_engine_protocol.zig");
const protocol = @import("blake3_native_parent_protocol.zig");
const artifact = @import("blake3_native_parent_artifact.zig");
const native = @import("air/blake3_native_parent_rows.zig");
const Roster = @import("air/blake3_native_parent_roster.zig").Roster;
const binding = @import("air/universal_relation_binding.zig");
const typed = @import("air/universal_typed_verifier_component.zig");
const universal = @import("air/universal_challenges.zig");
const schema = @import("../air/lookups/tables/schema.zig");
const Table = @import("../air/lookups/tables/verifier.zig").LookupTableVerifier;
const KINDS = [_]schema.Kind{ .bitwise, .range_check_8_8 };
fn Components() type {
    var types: [Roster.Airs.len]type = undefined;
    for (Roster.Airs, &types) |Air, *T| T.* = typed.ComponentForManifest(Air, binding.Binding(Air), Roster);
    return std.meta.Tuple(&types);
}
pub const Verified = struct {
    allocator: std.mem.Allocator,
    key_id: [32]u8,
    claims: artifact.Claims,
    channel: suite.Channel,
    capture: core.verifier.ProofCapture(suite.Hasher),
    pub fn deinit(self: *Verified) void {
        self.capture.deinit(self.allocator);
        self.* = undefined;
    }
};
/// Consumes the artifact proof on every path. Successful output owns its capture.
pub fn verify(owned: *artifact.Owned, admission: *const protocol.Admission) !Verified {
    defer owned.deinit();
    try owned.validate(admission);
    const a = owned.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    var definitions: Roster.Tuple(.definition) = undefined;
    var plans: Roster.Tuple(.plan) = undefined;
    var columns: [3]std.ArrayList(u32) = @splat(.empty);
    inline for (Roster.Airs, 0..) |Air, i| {
        definitions[i] = if (@hasDecl(Air, "Location")) try Air.build(temp, .generated) else try Air.build(temp);
        plans[i] = try binding.Binding(Air).authenticate(&definitions[i]);
        inline for (.{ Air.PREPROCESSED_COLUMN_COUNT, Air.PHYSICAL_MAIN_COLUMN_COUNT, Air.INTERACTION_COLUMN_COUNT }, 0..) |count, tree| {
            try columns[tree].appendNTimes(temp, admission.key.log_sizes[i], count);
        }
    }
    var table_pp: [2]usize = undefined;
    const table_main = columns[1].items.len;
    const table_interaction = columns[2].items.len;
    for (KINDS, &table_pp) |kind, *offset| {
        offset.* = columns[0].items.len;
        try columns[0].appendNTimes(temp, schema.logSize(kind), 1 + schema.arity(kind));
        try columns[1].append(temp, schema.logSize(kind));
        try columns[2].appendNTimes(temp, schema.logSize(kind), 4);
    }
    var scheme = try core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel).init(a, try admission.config());
    defer scheme.deinit(a);
    var channel = suite.Channel{};
    try admission.mix(&channel);
    const commitments = owned.proof.?.commitment_scheme_proof.commitments.items;
    try scheme.commit(a, commitments[0], columns[0].items, &channel);
    try scheme.commit(a, commitments[1], columns[1].items, &channel);
    const relations = try universal.UniversalRelations.draw(temp, &channel);
    const providers = try @import("air/universal_provider_relations.zig").SharedProviderRelations.init(&relations);
    try admission.mixClaims(&channel, &owned.claims);
    try scheme.commit(a, commitments[2], columns[2].items, &channel);
    const manifest = Roster.Manifest{ .log_sizes = admission.key.log_sizes };
    var components: Components() = undefined;
    var verifiers: [artifact.CLAIM_COUNT]core.air.components.Component = undefined;
    inline for (Roster.Airs, 0..) |Air, i| {
        const parameters = if (i >= 3 and i <= 5) native.selectors else [0]core.fields.m31.M31{};
        components[i] = try typed.ComponentForManifest(Air, binding.Binding(Air), Roster).init(&definitions[i], plans[i], &manifest, @enumFromInt(i), admission.key.log_sizes[i], parameters, &relations, owned.claims[i]);
        verifiers[i] = components[i].asVerifierComponent();
    }
    var tables: [2]Table = undefined;
    for (&tables, KINDS, table_pp, 0..) |*table, kind, offset, i| {
        var tuple: [schema.MAX_ARITY]usize = undefined;
        for (tuple[0..schema.arity(kind)], 0..) |*column, j| column.* = offset + 1 + j;
        table.* = try Table.initVerifier(kind, offset, tuple[0..schema.arity(kind)], table_main + i, table_interaction + 4 * i, &providers.native, owned.claims[Roster.Airs.len + i]);
        verifiers[Roster.Airs.len + i] = table.asVerifierComponent();
    }
    const proof = owned.proof.?;
    owned.proof = null; // Core verification consumes proof even on failure.
    var capture: core.verifier.ProofCapture(suite.Hasher) = undefined;
    try core.verifier.verifyWithProofCapture(suite.Hasher, suite.MerkleChannel, a, &verifiers, &channel, &scheme, proof, &capture);
    return .{ .allocator = a, .key_id = admission.expected_id, .claims = owned.claims, .channel = channel, .capture = capture };
}
