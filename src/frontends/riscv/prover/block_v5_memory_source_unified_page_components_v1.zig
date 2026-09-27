//! Original SHA/BLAKE, table, capture and semantic arithmetic equations in one
//! PAGE composition. All input suppliers read original trees1/5; arithmetic
//! inputs live in tree7 and both sides precede the dedicated wire challenge.
//! This component construction is not a verified PAGE or aggregate receipt.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Canonical = @import("block_v5_memory_source_page_canonical_component_v1.zig");
const Input = @import("block_v5_memory_source_page_input_component_v1.zig");
const Composition = @import("block_v5_memory_source_page_composition_v1.zig");
const SHA = @import("block_v5_memory_source_packed_sha_columns_v1.zig");
const Blake = @import("block_v5_memory_source_packed_blake_columns_v1.zig");
const Raw = @import("block_v5_memory_source_batch_raw_schema_v1.zig");
const ShaCaptureAir = @import("block_v5_memory_source_sha_connector_air_v1.zig");
const ShaCapture = @import("block_v5_memory_source_sha_connector_component_v1.zig").ForSourceFixed(Raw.FIXED_COUNT);
const ShaClaim = @import("block_v5_memory_source_sha_connector_interaction_v1.zig").Claim;
const BlakeCapture = @import("block_v5_memory_source_blake_capture_component_v1.zig");
const BlakeCaptureAir = @import("block_v5_memory_source_blake_capture_air_v1.zig");
const BlakeClaim = @import("block_v5_memory_source_blake_capture_interaction_v1.zig").Claim;
const Universal = @import("../recursion/air/universal_challenges.zig");
const Providers = @import("../recursion/air/universal_provider_relations.zig");
const RosterFactory = @import("../recursion/air/universal_component_roster.zig");
const OwnerFactory = @import("../recursion/air/universal_component_owner.zig");
const GeometryFactory = @import("../recursion/air/roster_composition_geometry.zig");
const Lower = @import("../recursion/air/verifier_arithmetic_lowering.zig");
const ArithFixed = @import("../recursion/air/arithmetic_fusion_fixed_columns_v1.zig");
const ArithAirs = ArithFixed.Airs;
const ProofKind = @import("../recursion/air/proof_kind.zig").ProofKind;
/// Original inverse/linear AIR proof-kind selectors are shared by interaction
/// generation and component evaluation; dot4 and FMA have no parameters.
pub const ARITHMETIC_PARAMETERS = .{
    [0]M{}, [0]M{}, ProofKind.segment_leaf.selectors(), ProofKind.segment_leaf.selectors(),
};
const ArithRoster = RosterFactory.ForAirs(ArithAirs, &.{ "dot4", "fma", "inverse", "linear" });
const ArithOwner = OwnerFactory.ForRoster(ArithRoster);
pub const ArithmeticSetup = @import("block_v5_packed_hash_setup_v1.zig").ForAirs(ArithAirs);
const Tables = @import("../air/lookups/tables/schema.zig");
const Table = @import("../air/lookups/tables/component.zig").LookupTableComponent;
const TableInteraction = @import("../air/lookups/tables/interaction.zig");
const KINDS = [_]Tables.Kind{ .bitwise, .range_check_8_8 };
fn total(comptime Airs: anytype, comptime field: []const u8) usize {
    var n: usize = 0;
    inline for (Airs) |Air| n += @field(Air, field);
    return n;
}
pub fn ForKind(comptime kind: Semantic.Kind) type {
    return struct {
        const Self = @This();
        pub const CoreColumns = if (kind == .raw) SHA else Blake;
        pub const CoreAirs = CoreColumns.Airs;
        pub const CoreRoster = RosterFactory.ForAirs(CoreAirs, if (kind == .raw) &.{ "sha_source", "sha_schedule", "sha_round", "sha_feed" } else &.{ "blake_g", "blake_xor" });
        const CoreOwner = OwnerFactory.ForRoster(CoreRoster);
        const CoreGeometry = GeometryFactory.ForAirs(CoreAirs);
        const ArithmeticGeometry = GeometryFactory.ForAirs(ArithAirs);
        pub const SourceInput = Input.ForWidth(if (kind == .raw) 960 else 1859);
        pub const CaptureInput = Input.ForWidth(if (kind == .raw) 256 else 192);
        const Canon = Canonical.ForKind(kind);
        const Capture = if (kind == .raw) ShaCapture else BlakeCapture.Component;
        pub const CaptureClaim = if (kind == .raw) ShaClaim else BlakeClaim;
        pub const SOURCE_FIXED: usize = if (kind == .raw) Raw.FIXED_COUNT else 4;
        pub const SOURCE_MAIN: usize = Canon.MAIN_COUNT;
        pub const CAPTURE_FIXED: usize = if (kind == .raw) ShaCaptureAir.EXPANDED_FIXED_COUNT else BlakeCaptureAir.FIXED_COUNT;
        pub const CAPTURE_MAIN: usize = CaptureInput.MAIN_COUNT;
        pub const CORE_FIXED: usize = total(CoreAirs, "PREPROCESSED_COLUMN_COUNT") + 2 + Tables.arity(.bitwise) + Tables.arity(.range_check_8_8);
        pub const CORE_MAIN: usize = total(CoreAirs, "PHYSICAL_MAIN_COLUMN_COUNT") + 2;
        pub const CORE_INTERACTION: usize = total(CoreAirs, "INTERACTION_COLUMN_COUNT") + 2 * TableInteraction.N_COLUMNS;
        pub const CAPTURE_INTERACTION: usize = if (kind == .raw) ShaCaptureAir.INTERACTION_COUNT else BlakeCaptureAir.INTERACTION_COUNT;
        pub const ARITHMETIC_FIXED: usize = total(ArithAirs, "PREPROCESSED_COLUMN_COUNT");
        pub const ARITHMETIC_MAIN: usize = total(ArithAirs, "PHYSICAL_MAIN_COLUMN_COUNT");
        pub const ARITHMETIC_INTERACTION: usize = total(ArithAirs, "INTERACTION_COLUMN_COUNT");
        pub const ARITHMETIC_FIXED_OFFSET: usize = Canonical.CANONICAL_FIXED_COUNT + SourceInput.FIXED_COUNT + CaptureInput.FIXED_COUNT;
        pub const ARITHMETIC_INTERACTION_OFFSET: usize = CORE_INTERACTION + CAPTURE_INTERACTION + SourceInput.INTERACTION_COUNT + CaptureInput.INTERACTION_COUNT;
        pub const CHILD_COUNT: usize = CoreAirs.len + 2 + 1 + 3 + ArithAirs.len;
        pub const SPLIT: u32 = @max(2, @max(CoreGeometry.quotient_log_blowup, ArithmeticGeometry.quotient_log_blowup));
        pub const Geometry = struct {
            source_log: u32,
            capture_log: u32,
            core_logs: [CoreAirs.len]u32,
            arithmetic_logs: [4]u32,
            capture_requests: u64,
        };
        pub const Claims = struct {
            core: [CoreAirs.len + 2]Q,
            capture: Self.CaptureClaim,
            source_inputs: SourceInput.Claim,
            capture_inputs: CaptureInput.Claim,
            arithmetic: [4]Q,
        };
        pub const PlacementRoster = struct {
            placements: [CHILD_COUNT][5]Composition.Placement,
            lengths: [CHILD_COUNT]usize,
        };
        /// Original placement order shared by live handles and shape-only masks.
        pub fn placementRoster() PlacementRoster {
            var result: PlacementRoster = undefined;
            var next: usize = 0;
            var offsets: [3]usize = @splat(0);
            inline for (CoreAirs) |Air| {
                result.lengths[next] = 3;
                result.placements[next][0..3].* = .{
                    .{ .tree = 2, .view_count = CORE_FIXED, .used_first = offsets[0], .used_count = Air.PREPROCESSED_COLUMN_COUNT },
                    .{ .tree = 3, .view_count = CORE_MAIN, .used_first = offsets[1], .used_count = Air.PHYSICAL_MAIN_COLUMN_COUNT },
                    .{ .tree = 8, .view_count = CORE_INTERACTION, .used_first = offsets[2], .used_count = Air.INTERACTION_COLUMN_COUNT },
                };
                next += 1;
                offsets[0] += Air.PREPROCESSED_COLUMN_COUNT;
                offsets[1] += Air.PHYSICAL_MAIN_COLUMN_COUNT;
                offsets[2] += Air.INTERACTION_COLUMN_COUNT;
            }
            for (KINDS) |table_kind| {
                result.lengths[next] = 3;
                result.placements[next][0..3].* = .{
                    .{ .tree = 2, .view_count = CORE_FIXED, .used_first = offsets[0], .used_count = Tables.arity(table_kind) + 1 },
                    .{ .tree = 3, .view_count = CORE_MAIN, .used_first = offsets[1], .used_count = 1 },
                    .{ .tree = 8, .view_count = CORE_INTERACTION, .used_first = offsets[2], .used_count = TableInteraction.N_COLUMNS },
                };
                next += 1;
                offsets[0] += Tables.arity(table_kind) + 1;
                offsets[1] += 1;
                offsets[2] += TableInteraction.N_COLUMNS;
            }
            if (kind == .raw) {
                result.lengths[next] = 5;
                result.placements[next] = .{
                    .{ .tree = 0, .view_count = SOURCE_FIXED, .used_count = SOURCE_FIXED },                                           .{ .tree = 1, .view_count = SOURCE_MAIN, .used_count = SOURCE_MAIN },
                    .{ .tree = 4, .view_count = CAPTURE_FIXED, .used_count = CAPTURE_FIXED },                                         .{ .tree = 5, .view_count = CAPTURE_MAIN, .used_count = CAPTURE_MAIN },
                    .{ .tree = 8, .offset = CORE_INTERACTION, .view_count = CAPTURE_INTERACTION, .used_count = CAPTURE_INTERACTION },
                };
            } else {
                result.lengths[next] = 3;
                result.placements[next][0..3].* = .{ .{ .tree = 4, .view_count = CAPTURE_FIXED, .used_count = CAPTURE_FIXED }, .{ .tree = 5, .view_count = CAPTURE_MAIN, .used_count = CAPTURE_MAIN }, .{ .tree = 8, .offset = CORE_INTERACTION, .view_count = CAPTURE_INTERACTION, .used_count = CAPTURE_INTERACTION } };
            }
            next += 1;
            result.lengths[next] = 3;
            result.placements[next][0..3].* = .{ .{ .tree = 6, .view_count = Canonical.CANONICAL_FIXED_COUNT, .used_count = Canonical.CANONICAL_FIXED_COUNT }, .{ .tree = 1, .view_count = SOURCE_MAIN, .used_count = SOURCE_MAIN }, .{ .tree = 8, .view_count = 0, .used_count = 0 } };
            next += 1;
            result.lengths[next] = 3;
            result.placements[next][0..3].* = .{ .{ .tree = 6, .offset = Canonical.CANONICAL_FIXED_COUNT, .view_count = SourceInput.FIXED_COUNT, .used_count = SourceInput.FIXED_COUNT }, .{ .tree = 1, .view_count = SourceInput.MAIN_COUNT, .used_count = SourceInput.MAIN_COUNT }, .{ .tree = 8, .offset = CORE_INTERACTION + CAPTURE_INTERACTION, .view_count = SourceInput.INTERACTION_COUNT, .used_count = SourceInput.INTERACTION_COUNT } };
            next += 1;
            result.lengths[next] = 3;
            result.placements[next][0..3].* = .{ .{ .tree = 6, .offset = Canonical.CANONICAL_FIXED_COUNT + SourceInput.FIXED_COUNT, .view_count = CaptureInput.FIXED_COUNT, .used_count = CaptureInput.FIXED_COUNT }, .{ .tree = 5, .view_count = CaptureInput.MAIN_COUNT, .used_count = CaptureInput.MAIN_COUNT }, .{ .tree = 8, .offset = CORE_INTERACTION + CAPTURE_INTERACTION + SourceInput.INTERACTION_COUNT, .view_count = CaptureInput.INTERACTION_COUNT, .used_count = CaptureInput.INTERACTION_COUNT } };
            next += 1;
            offsets = @splat(0);
            inline for (ArithAirs) |Air| {
                result.lengths[next] = 3;
                result.placements[next][0..3].* = .{
                    .{ .tree = 6, .offset = ARITHMETIC_FIXED_OFFSET, .view_count = ARITHMETIC_FIXED, .used_first = offsets[0], .used_count = Air.PREPROCESSED_COLUMN_COUNT },
                    .{ .tree = 7, .view_count = ARITHMETIC_MAIN, .used_first = offsets[1], .used_count = Air.PHYSICAL_MAIN_COLUMN_COUNT },
                    .{ .tree = 8, .offset = ARITHMETIC_INTERACTION_OFFSET, .view_count = ARITHMETIC_INTERACTION, .used_first = offsets[2], .used_count = Air.INTERACTION_COLUMN_COUNT },
                };
                next += 1;
                offsets[0] += Air.PREPROCESSED_COLUMN_COUNT;
                offsets[1] += Air.PHYSICAL_MAIN_COLUMN_COUNT;
                offsets[2] += Air.INTERACTION_COLUMN_COUNT;
            }
            std.debug.assert(next == CHILD_COUNT);
            return result;
        }
        pub const Owner = struct {
            a: std.mem.Allocator,
            cores: *CoreOwner,
            arithmetic: *ArithOwner,
            providers: Providers.SharedProviderRelations,
            tables: [2]Table = undefined,
            capture: Capture = undefined,
            canonical: Canon.Component = undefined,
            source_input: SourceInput.Component = undefined,
            capture_input: CaptureInput.Component = undefined,
            composition: ?*Composition.Owner = null,
            pub fn deinit(self: *@This()) void {
                if (self.composition) |owner| owner.deinit();
                self.arithmetic.deinit();
                self.cores.deinit();
                self.a.destroy(self);
            }
            /// Inputs/plan/fixed must be independently generated from exactly
            /// the admitted graph; a fresh receiver calls this same method
            /// without private source values or arithmetic evaluations.
            pub fn init(a: std.mem.Allocator, graph: *const Semantic.Prepared, plan: *const Lower.Plan, fixed: *const ArithFixed.Fixed, source_input: *const SourceInput.Plan, capture_input: *const CaptureInput.Plan, geometry: Self.Geometry, relations: Universal.UniversalRelations, claims: Self.Claims, core_setup: *const CoreColumns.Setup, arithmetic_setup: *const ArithmeticSetup, limits: Composition.Limits) !*@This() {
                if (geometry.source_log < 1 or geometry.source_log > 12 or geometry.capture_log < 1 or geometry.capture_log > 14 or
                    (kind == .raw and geometry.capture_log != geometry.source_log) or geometry.capture_requests >= core.fields.m31.Modulus)
                    return error.InvalidSourceUnifiedPageComponents;
                for (geometry.core_logs ++ geometry.arithmetic_logs) |log| if (log < 1 or log > 24) return error.InvalidSourceUnifiedPageComponents;
                if (graph.kind != kind or graph.circuit == null or geometry.source_log != source_input.row_log or geometry.capture_log != capture_input.row_log or
                    source_input.group != .source or capture_input.group != .capture or !std.meta.eql(source_input.graph_identity, graph.identity) or !std.meta.eql(capture_input.graph_identity, graph.identity) or
                    !std.mem.eql(u32, &geometry.arithmetic_logs, &fixed.logs) or try std.math.add(u64, source_input.requests, capture_input.requests) != graph.input_requests)
                    return error.InvalidSourceUnifiedPageComponents;
                var lanes: [2]Lower.Lane = undefined;
                const reference = try graph.reference(&lanes);
                try plan.validateAgainst(reference);
                // Full kernel and full semantic closures are distinct, not
                // one freely cancelling aggregate claim.
                var kernel_sum = Q.zero();
                for (claims.core) |sum| kernel_sum = kernel_sum.add(sum);
                for (claims.capture.sums) |sum| kernel_sum = kernel_sum.add(sum);
                if (!kernel_sum.isZero()) return error.UnclosedSourcePageHashKernel;
                _ = try SourceInput.normalize(claims.source_inputs, @as(usize, 1) << @intCast(geometry.source_log), source_input.requests);
                _ = try CaptureInput.normalize(claims.capture_inputs, @as(usize, 1) << @intCast(geometry.capture_log), capture_input.requests);
                if (kind == .fold) _ = try @import("block_v5_memory_source_blake_capture_interaction_v1.zig").normalize(claims.capture, @as(usize, 1) << @intCast(geometry.capture_log), geometry.capture_requests);
                var semantic_sum = try plan.publicBoundaryClaim(.segment_leaf, &relations);
                for (claims.arithmetic) |sum| semantic_sum = semantic_sum.add(sum);
                for (claims.source_inputs.sums) |sum| semantic_sum = semantic_sum.add(sum);
                for (claims.capture_inputs.sums) |sum| semantic_sum = semantic_sum.add(sum);
                if (!semantic_sum.isZero()) return error.UnclosedSourcePageSemanticWires;
                var core_lease = try core_setup.lease();
                defer core_lease.deinit();
                var arithmetic_lease = try arithmetic_setup.lease();
                defer arithmetic_lease.deinit();
                const cores = try CoreOwner.initPrepared(a, &.{ .log_sizes = geometry.core_logs }, &core_setup.definitions, &core_setup.plans, @as([CoreAirs.len][0]M, @splat(.{})), relations, claims.core[0..CoreAirs.len].*);
                errdefer cores.deinit();
                const arithmetic = try ArithOwner.initPrepared(a, &.{ .log_sizes = geometry.arithmetic_logs }, &arithmetic_setup.definitions, &arithmetic_setup.plans, ARITHMETIC_PARAMETERS, relations, claims.arithmetic);
                errdefer arithmetic.deinit();
                const providers = try Providers.SharedProviderRelations.init(&relations);
                const self = try a.create(@This());
                self.* = .{ .a = a, .cores = cores, .arithmetic = arithmetic, .providers = providers };
                errdefer {
                    if (self.composition) |owner| owner.deinit();
                    a.destroy(self);
                }
                const wire = relations.get(.recursion_wire);
                const challenge = SourceInput.Algebra(Q).Challenge{ .z = wire.z, .powers = wire.alpha_powers[0..6].* };
                self.source_input = .{ .log_size = geometry.source_log, .spec = .{ .rows = @as(u32, 1) << @intCast(geometry.source_log), .requests = source_input.requests, .claim = claims.source_inputs, .challenge = challenge } };
                self.capture_input = .{ .log_size = geometry.capture_log, .spec = .{ .rows = @as(u32, 1) << @intCast(geometry.capture_log), .requests = capture_input.requests, .claim = claims.capture_inputs, .challenge = .{ .z = challenge.z, .powers = challenge.powers } } };
                self.canonical = .{ .log_size = geometry.source_log, .spec = .{ .rows = @as(u32, 1) << @intCast(geometry.source_log) } };
                self.capture = if (kind == .raw)
                    try ShaCapture.init(geometry.source_log, geometry.capture_requests, claims.capture, .{ .z = wire.z, .powers = wire.alpha_powers[0..6].* })
                else
                    .{ .log_size = geometry.capture_log, .spec = .{ .rows = @as(u32, 1) << @intCast(geometry.capture_log), .expected_requests = geometry.capture_requests, .claim = claims.capture, .challenge = .{ .z = wire.z, .powers = wire.alpha_powers[0..6].* } } };
                var fixed_offset: usize = total(CoreAirs, "PREPROCESSED_COLUMN_COUNT");
                for (KINDS, 0..) |table_kind, i| {
                    var tuple_indices: [Tables.MAX_ARITY]usize = undefined;
                    for (tuple_indices[0..Tables.arity(table_kind)], 0..) |*index, ordinal| index.* = fixed_offset + 1 + ordinal;
                    self.tables[i] = try Table.initProver(table_kind, fixed_offset, tuple_indices[0..Tables.arity(table_kind)], CORE_MAIN - 2 + i, CORE_INTERACTION - 2 * TableInteraction.N_COLUMNS + i * TableInteraction.N_COLUMNS, &self.providers.native, claims.core[CoreAirs.len + i]);
                    fixed_offset += Tables.arity(table_kind) + 1;
                }
                var logs: [Composition.TREE_COUNT]std.ArrayList(u32) = @splat(.empty);
                defer for (&logs) |*tree| tree.deinit(a);
                try appendLogs(a, &logs[0], SOURCE_FIXED, geometry.source_log);
                try appendLogs(a, &logs[1], SOURCE_MAIN, geometry.source_log);
                inline for (CoreAirs, 0..) |Air, i| {
                    try appendLogs(a, &logs[2], Air.PREPROCESSED_COLUMN_COUNT, geometry.core_logs[i]);
                    try appendLogs(a, &logs[3], Air.PHYSICAL_MAIN_COLUMN_COUNT, geometry.core_logs[i]);
                    try appendLogs(a, &logs[8], Air.INTERACTION_COLUMN_COUNT, geometry.core_logs[i]);
                }
                for (KINDS) |table_kind| {
                    const log = Tables.logSize(table_kind);
                    try appendLogs(a, &logs[2], Tables.arity(table_kind) + 1, log);
                    try appendLogs(a, &logs[3], 1, log);
                    try appendLogs(a, &logs[8], TableInteraction.N_COLUMNS, log);
                }
                try appendLogs(a, &logs[4], CAPTURE_FIXED, geometry.capture_log);
                try appendLogs(a, &logs[5], CAPTURE_MAIN, geometry.capture_log);
                try appendLogs(a, &logs[6], Canonical.CANONICAL_FIXED_COUNT + SourceInput.FIXED_COUNT, geometry.source_log);
                try appendLogs(a, &logs[6], CaptureInput.FIXED_COUNT, geometry.capture_log);
                try appendLogs(a, &logs[8], CAPTURE_INTERACTION, geometry.capture_log);
                try appendLogs(a, &logs[8], SourceInput.INTERACTION_COUNT, geometry.source_log);
                try appendLogs(a, &logs[8], CaptureInput.INTERACTION_COUNT, geometry.capture_log);
                inline for (ArithAirs, 0..) |Air, i| {
                    try appendLogs(a, &logs[6], Air.PREPROCESSED_COLUMN_COUNT, geometry.arithmetic_logs[i]);
                    try appendLogs(a, &logs[7], Air.PHYSICAL_MAIN_COLUMN_COUNT, geometry.arithmetic_logs[i]);
                    try appendLogs(a, &logs[8], Air.INTERACTION_COLUMN_COUNT, geometry.arithmetic_logs[i]);
                }
                var views: [Composition.TREE_COUNT][]const u32 = undefined;
                for (&views, logs) |*view, tree| view.* = tree.items;
                var children: [CHILD_COUNT]Composition.Child = undefined;
                var placements: [CHILD_COUNT][5]Composition.Placement = undefined;
                const placement_roster = placementRoster();
                var next: usize = 0;
                const core_provers = try cores.proverHandles();
                const core_verifiers = try cores.verifierHandles();
                inline for (CoreAirs, 0..) |_, i| {
                    @memcpy(placements[next][0..placement_roster.lengths[next]], placement_roster.placements[next][0..placement_roster.lengths[next]]);
                    children[next] = .{ .prover = core_provers[i], .verifier = core_verifiers[i], .placements = placements[next][0..3] };
                    next += 1;
                }
                for (KINDS, 0..) |_, i| {
                    @memcpy(placements[next][0..placement_roster.lengths[next]], placement_roster.placements[next][0..placement_roster.lengths[next]]);
                    children[next] = .{ .prover = try CoreGeometry.table(self.tables[i].asProverComponent()), .verifier = try CoreGeometry.table(self.tables[i].asVerifierComponent()), .placements = placements[next][0..3] };
                    next += 1;
                }
                if (kind == .raw) {
                    @memcpy(placements[next][0..placement_roster.lengths[next]], placement_roster.placements[next][0..placement_roster.lengths[next]]);
                    children[next] = Composition.Child.from(&self.capture, &placements[next]);
                } else {
                    @memcpy(placements[next][0..placement_roster.lengths[next]], placement_roster.placements[next][0..placement_roster.lengths[next]]);
                    children[next] = Composition.Child.from(&self.capture, placements[next][0..3]);
                }
                next += 1;
                @memcpy(placements[next][0..placement_roster.lengths[next]], placement_roster.placements[next][0..placement_roster.lengths[next]]);
                children[next] = Composition.Child.from(&self.canonical, placements[next][0..3]);
                next += 1;
                @memcpy(placements[next][0..placement_roster.lengths[next]], placement_roster.placements[next][0..placement_roster.lengths[next]]);
                children[next] = Composition.Child.from(&self.source_input, placements[next][0..3]);
                next += 1;
                @memcpy(placements[next][0..placement_roster.lengths[next]], placement_roster.placements[next][0..placement_roster.lengths[next]]);
                children[next] = Composition.Child.from(&self.capture_input, placements[next][0..3]);
                next += 1;
                const arithmetic_provers = try arithmetic.proverHandles();
                const arithmetic_verifiers = try arithmetic.verifierHandles();
                inline for (ArithAirs, 0..) |_, i| {
                    @memcpy(placements[next][0..placement_roster.lengths[next]], placement_roster.placements[next][0..placement_roster.lengths[next]]);
                    children[next] = .{ .prover = arithmetic_provers[i], .verifier = arithmetic_verifiers[i], .placements = placements[next][0..3] };
                    next += 1;
                }
                std.debug.assert(next == CHILD_COUNT);
                self.composition = try Composition.Owner.init(a, &children, views, SPLIT, limits);
                return self;
            }
            pub fn asProverComponent(self: *const @This()) engine.air.component_prover.ComponentProver {
                return self.composition.?.asProverComponent();
            }
            pub fn asVerifierComponent(self: *const @This()) core.air.components.Component {
                return self.composition.?.asVerifierComponent();
            }
        };
    };
}
fn appendLogs(a: std.mem.Allocator, out: *std.ArrayList(u32), count: usize, log: u32) !void {
    if (log == 0 or log >= core.circle.M31_CIRCLE_LOG_ORDER) return error.InvalidSourceUnifiedPageComponents;
    try out.appendNTimes(a, log, count);
}
