//! Role-0 cold composition-capture boundary.
//!
//! The concrete owner is supplied by the universal-36 cold verifier.
//! This adapter borrows its actual proof capture, recursive ingress, and
//! verifier-rerecorded graph and rechecks their pointer closure on every use.
//! It cannot be constructed from a graph digest or a stage-101 capture.

const std = @import("std");

const common_authority = @import("recursive_common_wrapper_authority_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const ROLE = registry_mod.CircuitRoleV4
    .ethereum_incremental_leaf_wrapper_v4;
pub const SERIALIZABLE_FRESH_CAPTURE = false;
pub const DIGEST_ONLY_CONSTRUCTION = false;

pub const Error = error{
    EthereumIncrementalColdCompositionCaptureMismatchV4,
};

/// `ColdOwner` must be the actual role-0 cold wrapper proof owner. Its
/// View types and its checked projection method are checked below.
pub fn ColdCompositionCaptureV4(comptime ColdOwner: type) type {
    assertColdOwnerContract(ColdOwner);
    return struct {
        owner: *const ColdOwner,
        registry: *const registry_mod.RecursiveCircuitRegistryV1,
        wrapper: common_authority.FreshWrapperViewV2,
        ingress: ColdOwner.Ingress,
        graph: ColdOwner.Graph,

        const Self = @This();

        pub fn init(
            owner: *const ColdOwner,
            registry: *const registry_mod.RecursiveCircuitRegistryV1,
        ) !Self {
            const views = try owner.borrowedViews();
            const result = Self{
                .owner = owner,
                .registry = registry,
                .wrapper = views.wrapper,
                .ingress = views.ingress,
                .graph = views.graph,
            };
            try result.validateProjection(views);
            return result;
        }

        pub fn validateBorrowed(self: Self) !void {
            const views = try self.owner.borrowedViews();
            try self.validateProjection(views);
        }

        // No public method accepts a caller-supplied projection as authority.
        // Both callers obtain these views freshly from the owner above.
        fn validateProjection(self: Self, expected: ColdOwner.BorrowedViews) !void {
            // std.meta.eql compares every metadata field and checks borrowed
            // slices by pointer and length, without walking immutable buffers.
            if (!std.meta.eql(self.wrapper, expected.wrapper) or
                !std.meta.eql(self.ingress, expected.ingress) or
                !std.meta.eql(self.graph, expected.graph))
            {
                return error.EthereumIncrementalColdCompositionCaptureMismatchV4;
            }
            try self.registry.validate();
            try self.wrapper.validateAgainst(self.registry);
            try self.ingress.validate();
            // The cold owner admitted this graph before taking private
            // ownership. Exact alias checks above bind its deeply const view;
            // rebuilding the graph digest here would repeat that admission.
            if (try self.wrapper.role() != ROLE or
                self.wrapper.nodePublic() != self.ingress.node_public or
                self.wrapper.geometry != self.ingress.geometry or
                self.wrapper.capture != self.ingress.capture or
                self.ingress.query_words != self.graph.query_words or
                self.ingress.query_log_size != self.graph.query_log_size or
                self.ingress.final_transcript_digest !=
                    self.graph.final_transcript_digest or
                self.ingress.final_transcript_draw_count !=
                    self.graph.final_transcript_draw_count or
                self.ingress.query_words_identity_sha256 !=
                    self.graph.query_words_identity_sha256)
            {
                return error.EthereumIncrementalColdCompositionCaptureMismatchV4;
            }
        }
    };
}

fn assertColdOwnerContract(comptime ColdOwner: type) void {
    if (!@hasDecl(ColdOwner, "Ingress"))
        @compileError("role-0 cold owner missing Ingress type");
    if (!@hasDecl(ColdOwner, "Graph"))
        @compileError("role-0 cold owner missing Graph type");
    if (!@hasDecl(ColdOwner, "BorrowedViews") or !@hasDecl(ColdOwner, "borrowedViews"))
        @compileError("role-0 cold owner missing checked borrowed views");
    inline for (.{
        "node_public",
        "claims",
        "session",
        "statement",
        "geometry",
        "capture",
        "query_words",
        "query_log_size",
        "final_transcript_digest",
        "final_transcript_draw_count",
        "query_words_identity_sha256",
    }) |name| if (!@hasField(ColdOwner.Ingress, name))
        @compileError("role-0 cold ingress missing field: " ++ name);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or
        @intFromEnum(ROLE) != 0 or SERIALIZABLE_FRESH_CAPTURE or
        DIGEST_ONLY_CONSTRUCTION)
    {
        @compileError("role-0 cold composition capture V4 drifted");
    }
    _ = std;
}

test "Ethereum cold composition admission rejects altered borrowed graph and ingress" {
    const core = @import("stwo_core");
    const frontend = @import("stwo_riscv_frontend");
    const capture_owner = @import("recursive_common_ethereum_incremental_leaf_composition_capture_owner_v4.zig");
    const composition = frontend.recursion.air.composition_circuit;
    const M31 = core.fields.m31.M31;
    const QM31 = core.fields.qm31.QM31;
    const FreshGraphViewV4 = capture_owner.FreshGraphViewV4;
    const QUERY_WORD_COUNT = capture_owner.QUERY_WORD_COUNT;
    const CIRCUIT_ID = capture_owner.CIRCUIT_ID;
    const allocator = std.testing.allocator;
    const identity_words = [_]u8{1} ** 32;
    const query_words = [_]M31{M31.zero()} ** QUERY_WORD_COUNT;
    const final_digest = [_]u32{2} ** 8;
    const nodes = [_]composition.Node{.{ .op = .input }};
    const outputs = [_]u32{0};
    const bindings = [_]composition.RecursionInputBinding{.{ .node_id = 0, .source = .{ .statement_word = 0 } }};
    const values = [_]QM31{QM31.zero()};
    const original: FreshGraphViewV4 = .{
        .capture_identity_sha256 = &identity_words,
        .layout_identity_sha256 = &identity_words,
        .query_words = &query_words,
        .query_log_size = 4,
        .final_transcript_digest = &final_digest,
        .final_transcript_draw_count = 17,
        .query_words_identity_sha256 = &identity_words,
        .lane = .{
            .verifier_id = 1,
            .circuit_id = CIRCUIT_ID,
            .statement_scope = 2,
            .graph = .{ .nodes = &nodes, .outputs = &outputs, .identity_digest = composition.computeGraphDigest(&nodes, &outputs) },
            .profile = .{ .sampled_value_count = 1, .claimed_sum_count = 1, .relation_challenge_count = 1 },
            .bindings = &bindings,
        },
        .evaluation = .{ .circuit_identity = identity_words, .values = &values },
    };
    // This fixture isolates real adapter ingress admission. Its deliberately
    // invalid registry is a sentinel after alias admission; pointees used only
    // for pointer custody are never read, and no proof validity is asserted.
    const TestOwner = struct {
        pub const Graph = FreshGraphViewV4;
        pub const Ingress = struct {
            node_public: *const common_authority.NodePublic,
            claims: *const u8,
            session: *const u8,
            statement: *const u8,
            geometry: *const common_authority.Geometry,
            capture: *const common_authority.ProofCapture,
            query_words: *const [QUERY_WORD_COUNT]M31,
            query_log_size: u32,
            final_transcript_digest: *const capture_owner.TranscriptDigestV4,
            final_transcript_draw_count: u32,
            query_words_identity_sha256: *const [32]u8,
            manifest: *const u8,

            pub fn validate(_: @This()) !void {}
        };
        pub const BorrowedViews = struct {
            wrapper: common_authority.FreshWrapperViewV2,
            ingress: Ingress,
            graph: Graph,
        };
        wrapper: common_authority.FreshWrapperViewV2,
        ingress: Ingress,
        graph: Graph,
        acceptance_calls: *usize,
        reject_source: *bool,

        pub fn borrowedViews(self: *const @This()) !BorrowedViews {
            self.acceptance_calls.* += 1;
            if (self.reject_source.*) return error.ChangedBorrowedSource;
            return .{ .wrapper = self.wrapper, .ingress = self.ingress, .graph = self.graph };
        }
    };
    const artifact: common_authority.RecursiveNodeArtifact = undefined;
    const geometry: common_authority.Geometry = undefined;
    const capture: common_authority.ProofCapture = undefined;
    var authorities = [_]u8{0} ** 5;
    var acceptance_calls: usize = 0;
    var reject_source = false;
    const owner: TestOwner = .{
        .acceptance_calls = &acceptance_calls,
        .reject_source = &reject_source,
        .wrapper = .{ .artifact = &artifact, .geometry = &geometry, .capture = &capture },
        .ingress = .{
            .node_public = &artifact.node_public,
            .claims = &authorities[0],
            .session = &authorities[1],
            .statement = &authorities[2],
            .manifest = &authorities[3],
            .geometry = &geometry,
            .capture = &capture,
            .query_words = &query_words,
            .query_log_size = original.query_log_size,
            .final_transcript_digest = &final_digest,
            .final_transcript_draw_count = original.final_transcript_draw_count,
            .query_words_identity_sha256 = &identity_words,
        },
        .graph = original,
    };
    const invalid_registry: registry_mod.RecursiveCircuitRegistryV1 = .{
        .format_version = 0,
        .entries = undefined,
        .identity_sha256 = undefined,
    };
    const Adapter = ColdCompositionCaptureV4(TestOwner);
    const admitted: Adapter = .{
        .owner = &owner,
        .registry = &invalid_registry,
        .wrapper = owner.wrapper,
        .ingress = owner.ingress,
        .graph = owner.graph,
    };
    try std.testing.expectError(error.InvalidCircuitRegistry, admitted.validateBorrowed());
    try std.testing.expectEqual(@as(usize, 1), acceptance_calls);
    acceptance_calls = 0;
    try std.testing.expectError(error.InvalidCircuitRegistry, Adapter.init(&owner, &invalid_registry));
    try std.testing.expectEqual(@as(usize, 1), acceptance_calls);
    // A previous successful source acquisition cannot authorize changed sources.
    reject_source = true;
    acceptance_calls = 0;
    try std.testing.expectError(error.ChangedBorrowedSource, admitted.validateBorrowed());
    try std.testing.expectEqual(@as(usize, 1), acceptance_calls);
    reject_source = false;

    var candidate = admitted;
    candidate.ingress.manifest = &authorities[4];
    try std.testing.expectError(error.EthereumIncrementalColdCompositionCaptureMismatchV4, candidate.validateBorrowed());
    const other_artifact = try allocator.create(common_authority.RecursiveNodeArtifact);
    defer allocator.destroy(other_artifact);
    candidate = admitted;
    candidate.wrapper.artifact = other_artifact;
    try std.testing.expectError(error.EthereumIncrementalColdCompositionCaptureMismatchV4, candidate.validateBorrowed());
    // Metadata changes preserve every buffer alias and every pointed-to hash.
    // The former partial alias predicate accepted these altered authorities.
    inline for (.{ "verifier_id", "circuit_id", "statement_scope" }) |name| {
        var changed = original;
        @field(changed.lane, name) += 1;
        candidate = admitted;
        candidate.graph = changed;
        try std.testing.expectError(error.EthereumIncrementalColdCompositionCaptureMismatchV4, candidate.validateBorrowed());
    }
    inline for (@typeInfo(composition.InputProfile).@"struct".fields) |field| {
        var changed = original;
        if (field.type == bool)
            @field(changed.lane.profile, field.name) = !@field(changed.lane.profile, field.name)
        else
            @field(changed.lane.profile, field.name) += 1;
        candidate = admitted;
        candidate.graph = changed;
        try std.testing.expectError(error.EthereumIncrementalColdCompositionCaptureMismatchV4, candidate.validateBorrowed());
    }
    var changed = original;
    changed.lane.graph.identity_digest[0] ^= 1;
    candidate = admitted;
    candidate.graph = changed;
    try std.testing.expectError(error.EthereumIncrementalColdCompositionCaptureMismatchV4, candidate.validateBorrowed());
    changed = original;
    changed.evaluation.circuit_identity[0] ^= 1;
    candidate = admitted;
    candidate.graph = changed;
    try std.testing.expectError(error.EthereumIncrementalColdCompositionCaptureMismatchV4, candidate.validateBorrowed());

    // Equal contents and matching hashes do not authenticate foreign storage.
    const other_outputs = try allocator.dupe(u32, &outputs);
    defer allocator.free(other_outputs);
    changed = original;
    changed.lane.graph.outputs = other_outputs;
    candidate = admitted;
    candidate.graph = changed;
    try std.testing.expectError(error.EthereumIncrementalColdCompositionCaptureMismatchV4, candidate.validateBorrowed());
    changed.lane.graph.outputs = original.lane.graph.outputs[0..0];
    candidate = admitted;
    candidate.graph = changed;
    try std.testing.expectError(error.EthereumIncrementalColdCompositionCaptureMismatchV4, candidate.validateBorrowed());
    const other_nodes = try allocator.dupe(composition.Node, &nodes);
    defer allocator.free(other_nodes);
    changed = original;
    changed.lane.graph.nodes = other_nodes;
    candidate = admitted;
    candidate.graph = changed;
    try std.testing.expectError(error.EthereumIncrementalColdCompositionCaptureMismatchV4, candidate.validateBorrowed());
    const other_bindings = try allocator.dupe(composition.RecursionInputBinding, &bindings);
    defer allocator.free(other_bindings);
    changed = original;
    changed.lane.bindings = other_bindings;
    candidate = admitted;
    candidate.graph = changed;
    try std.testing.expectError(error.EthereumIncrementalColdCompositionCaptureMismatchV4, candidate.validateBorrowed());
    const other_values = try allocator.dupe(QM31, &values);
    defer allocator.free(other_values);
    changed = original;
    changed.evaluation.values = other_values;
    candidate = admitted;
    candidate.graph = changed;
    try std.testing.expectError(error.EthereumIncrementalColdCompositionCaptureMismatchV4, candidate.validateBorrowed());
    const other_identity = try allocator.create([32]u8);
    defer allocator.destroy(other_identity);
    other_identity.* = identity_words;
    changed = original;
    changed.capture_identity_sha256 = other_identity;
    candidate = admitted;
    candidate.graph = changed;
    try std.testing.expectError(error.EthereumIncrementalColdCompositionCaptureMismatchV4, candidate.validateBorrowed());
}
