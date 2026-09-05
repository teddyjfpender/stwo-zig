//! Role-0 cold composition-capture boundary.
//!
//! The concrete owner is supplied by the future universal-36 cold verifier.
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
/// `Ingress` type and four methods are checked at compile time below.
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
            try owner.validateBorrowed();
            const result = Self{
                .owner = owner,
                .registry = registry,
                .wrapper = try owner.wrapperView(),
                .ingress = try owner.ingressView(),
                .graph = try owner.foldGraphView(),
            };
            try result.validateBorrowed();
            return result;
        }

        pub fn validateBorrowed(self: Self) !void {
            try self.owner.validateBorrowed();
            try self.registry.validate();
            try self.wrapper.validateAgainst(self.registry);
            try self.ingress.validate();
            try self.graph.lane.graph.validate();
            const expected_wrapper = try self.owner.wrapperView();
            const expected_ingress = try self.owner.ingressView();
            const expected_graph = try self.owner.foldGraphView();
            if (try self.wrapper.role() != ROLE or
                !wrapperAliases(self.wrapper, expected_wrapper) or
                !ingressAliases(self.ingress, expected_ingress) or
                !graphAliases(self.graph, expected_graph) or
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

fn wrapperAliases(
    left: common_authority.FreshWrapperViewV2,
    right: common_authority.FreshWrapperViewV2,
) bool {
    return left.artifact == right.artifact and
        left.geometry == right.geometry and left.capture == right.capture;
}

fn ingressAliases(left: anytype, right: @TypeOf(left)) bool {
    return left.node_public == right.node_public and
        left.claims == right.claims and left.session == right.session and
        left.statement == right.statement and left.geometry == right.geometry and
        left.capture == right.capture and
        left.query_words == right.query_words and
        left.query_log_size == right.query_log_size and
        left.final_transcript_digest == right.final_transcript_digest and
        left.final_transcript_draw_count == right.final_transcript_draw_count and
        left.query_words_identity_sha256 == right.query_words_identity_sha256;
}

fn graphAliases(left: anytype, right: @TypeOf(left)) bool {
    return left.capture_identity_sha256 == right.capture_identity_sha256 and
        left.layout_identity_sha256 == right.layout_identity_sha256 and
        left.query_words == right.query_words and
        left.query_log_size == right.query_log_size and
        left.final_transcript_digest == right.final_transcript_digest and
        left.final_transcript_draw_count == right.final_transcript_draw_count and
        left.query_words_identity_sha256 == right.query_words_identity_sha256 and
        left.lane.graph.nodes.ptr == right.lane.graph.nodes.ptr and
        left.lane.graph.nodes.len == right.lane.graph.nodes.len and
        left.lane.graph.outputs.ptr == right.lane.graph.outputs.ptr and
        left.lane.graph.outputs.len == right.lane.graph.outputs.len and
        left.lane.bindings.ptr == right.lane.bindings.ptr and
        left.lane.bindings.len == right.lane.bindings.len and
        left.evaluation.values.ptr == right.evaluation.values.ptr and
        left.evaluation.values.len == right.evaluation.values.len;
}

fn assertColdOwnerContract(comptime ColdOwner: type) void {
    if (!@hasDecl(ColdOwner, "Ingress"))
        @compileError("role-0 cold owner missing Ingress type");
    if (!@hasDecl(ColdOwner, "Graph"))
        @compileError("role-0 cold owner missing Graph type");
    inline for (.{
        "validateBorrowed",
        "wrapperView",
        "ingressView",
        "foldGraphView",
    }) |name| if (!@hasDecl(ColdOwner, name))
        @compileError("role-0 cold owner missing declaration: " ++ name);
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
