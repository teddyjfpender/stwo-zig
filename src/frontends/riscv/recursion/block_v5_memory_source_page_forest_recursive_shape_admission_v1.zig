//! PAGE leaf expected setup from original typed native/fixed family. No Fresh,
//! MAIN, caller-supplied fixed rows or received geometry nominates expectation.
const std = @import("std");
const core = @import("stwo_core");
const Base = @import("blake3_execution_parent_protocol.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Term = @import("block_v5_open_child_frames_v2.zig").Term;
const Span = @import("block_v5_pc_clock_span_v1.zig").Span;
const Semantic = @import("../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const Leaves = @import("block_v5_memory_source_page_forest_leaf_v1.zig");
const Fixed = @import("block_v5_memory_source_page_recursive_fixed_roster_v1.zig");
const Norm = @import("block_v5_memory_source_page_forest_normalizer_v1.zig");
const Algebra = @import("block_v5_memory_source_page_forest_algebra_v1.zig");
fn baseKey(k: anytype) Base.Key {
    return .{ .profile = k.profile, .config = k.config, .context = k.context, .log_sizes = k.log_sizes, .preprocessed_root = k.preprocessed_root };
}
pub fn ForKind(comptime kind: Semantic.Kind) type {
    const Original = Leaves.ForKind(kind);
    const Family = Fixed.ForKind(kind);
    const Bus = @import("block_v5_memory_source_page_recursive_public_bus_v1.zig").ForKind(kind);
    const Protocol = @import("block_v5_reusable_memory_source_page_parent_protocol_v1.zig").ForKind(kind);
    return struct {
        pub const PUBLIC_CIRCUIT = Original.PUBLIC_CIRCUIT;
        pub const Source = struct {
            const Self = @This();
            allocator: std.mem.Allocator,
            lease: ?*Budget,
            policy: Original.Policy,
            expected_claims: Semantic.Claims,
            normal: Norm.Normalized,
            terms: []Term,
            pub fn derive(comptime Backend: type, a: std.mem.Allocator, policy: Original.Policy, independently_expected_claims: Semantic.Claims, capacity: u32, profile: Base.Profile, limits: Fixed.Limits) !Self {
                if (!std.meta.eql(policy.claims.semantic.claims, independently_expected_claims)) return error.UntrustedPageForestExpectedSemanticClaims;
                var fixed = try Family.Owned.derive(a, policy.admitted, policy.admitted.template_id, independently_expected_claims, capacity, profile, limits);
                defer fixed.deinit();
                // Internally constructed original fixed owner, consumed here;
                // ONE root-only commitment before any proposed key comparison.
                const geometry = try Parent.ForBackend(Backend).deriveKeyFromFixed(a, fixed.fixed, fixed.context, profile);
                const key = try Protocol.Key.fromGeometry(geometry, fixed.wires);
                try policy.admitted.validate(policy.admitted.template_id);
                if (!std.meta.eql(key, policy.key) or !std.meta.eql(try key.identity(), policy.expected_id) or fixed.wires.len != policy.schedule.len) return error.UntrustedPageForestFixedLeafSetup;
                for (fixed.wires, policy.schedule) |expected, proposed| if (!std.meta.eql(expected, proposed)) return error.UntrustedPageForestFixedLeafSetup;
                const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
                errdefer if (lease) |owner| owner.destroy();
                var values = try Bus.Values.init(a, policy.admitted, policy.claims);
                defer values.deinit();
                const authority = try Protocol.Admission.init(key, policy.expected_id, policy.schedule, values);
                var normal = try Norm.Normalized.initWithWords(a, &authority, values.statement.felts, try Algebra.semanticClaimOffset(values.statement.component_claim_first), values.statement.words, policy.normalization);
                errdefer normal.deinit();
                const terms = try a.alloc(Term, policy.schedule.len);
                errdefer a.free(terms);
                for (terms, policy.schedule) |*term, wire| term.* = .{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .coordinates = try values.at(wire.source, wire.coordinate) };
                return .{ .allocator = a, .lease = lease, .policy = policy, .expected_claims = independently_expected_claims, .normal = normal, .terms = terms };
            }
            pub fn validate(self: *const Self) !void {
                if (!std.meta.eql(self.policy.claims.semantic.claims, self.expected_claims)) return error.UntrustedPageForestExpectedSemanticClaims;
                try self.policy.validate();
                var values = try Bus.Values.init(self.allocator, self.policy.admitted, self.policy.claims);
                defer values.deinit();
                const authority = try Protocol.Admission.init(self.policy.key, self.policy.expected_id, self.policy.schedule, values);
                try self.normal.requireWithWords(self.allocator, &authority, values.statement.felts, try Algebra.semanticClaimOffset(values.statement.component_claim_first), values.statement.words, self.policy.normalization);
                if (self.terms.len != self.policy.schedule.len) return error.UntrustedPageForestFixedLeafSetup;
                for (self.terms, self.policy.schedule) |term, wire| if (term.circuit != wire.circuit or term.wire != wire.wire or term.uses != wire.uses or term.negative or !std.meta.eql(term.coordinates, try values.at(wire.source, wire.coordinate))) return error.UntrustedPageForestFixedLeafSetup;
            }
            pub fn replayPublic(self: *const Self, recorder: anytype) void {
                self.normal.frame.recordAt(recorder, self.normal.frame.first, PUBLIC_CIRCUIT) catch |failure| {
                    recorder.failure = failure;
                };
            }
            pub fn deinit(self: *Self) void {
                const lease = self.lease;
                self.allocator.free(self.terms);
                self.normal.deinit();
                self.* = undefined;
                if (lease) |owner| owner.destroy();
            }
        };
        pub const Admission = struct {
            pub const fixed_setup_only = true;
            source: *const Source,
            key: Base.Key,
            pc_clock_children: []const Span = &.{},
            pub fn init(source: *const Source) !@This() {
                try source.validate();
                return .{ .source = source, .key = baseKey(source.policy.key) };
            }
            pub fn validate(self: *const @This()) !void {
                try self.source.validate();
                if (self.pc_clock_children.len != 0 or !std.meta.eql(self.key, baseKey(self.source.policy.key))) return error.UntrustedPageForestFixedLeafSetup;
            }
            pub fn config(self: *const @This()) !core.pcs.PcsConfig {
                try self.validate();
                return self.key.config;
            }
        };
    };
}
pub const Node = @import("block_v5_ram_range_forest_recursive_shape_admission_v1.zig").ForSummary(@import("block_v5_memory_source_page_forest_summary_bus_v1.zig"), @import("block_v5_memory_source_page_forest_summary_protocol_v1.zig"), @import("block_v5_memory_source_page_forest_summary_source_v1.zig").PUBLIC_CIRCUIT, true);
