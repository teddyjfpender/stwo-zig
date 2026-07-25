const std = @import("std");
const adapter = @import("adapter/mod.zig");
const opcodes = @import("adapter/opcodes.zig");
const semantic_authority = @import("proof_plan/semantic_authority.zig");
const witness_bundle = @import("witness/bundle.zig");
const composition_bundle = @import("witness/composition_bundle.zig");
const feed_bundle = @import("witness/feed_bundle.zig");
const fixed_table_bundle = @import("witness/fixed_table_bundle.zig");

pub const TracePartId = union(enum) {
    main,
    memory_big: u32,
    memory_small,
};

pub const RowExtent = struct {
    /// Runtime writer cardinality. Feed-derived gather/compact writers leave
    /// this unresolved until execution; their padded domain is still exact.
    real_rows: ?u32,
    padded_rows: u32,

    pub fn validate(self: RowExtent) Error!void {
        if (self.padded_rows < 16 or !std.math.isPowerOfTwo(self.padded_rows))
            return Error.InvalidRowExtent;
        if (self.real_rows) |real_rows| {
            if (real_rows == 0 or real_rows > self.padded_rows)
                return Error.InvalidRowExtent;
        }
    }
};

pub const TracePart = struct {
    id: TracePartId,
    rows: RowExtent,
};

pub const ProducerEdge = struct {
    producer: []const u8,
    word_base: u32,
    words_per_instance: u32,
    instances: u32,
};

pub const CapacityFeed = struct {
    producer: []const u8,
    instances: u32,
};

pub const WriterKind = enum {
    recorded_aot,
    native_backend,
    fixed_table,
    memory_trace,
};

/// Lookup slabs whose base writer is cheaper than replaying the same witness
/// program during interaction and whose retained footprint fits the SN2 arena.
pub fn retainsLookupInputs(component: []const u8) bool {
    if (std.process.hasEnvVarConstant("STWO_ZIG_METAL_REPLAY_RETAINED_LOOKUPS")) return false;
    return retainsLookupInputsByPolicy(component, true);
}

fn retainsLookupInputsByPolicy(component: []const u8, retain: bool) bool {
    if (!retain) return false;
    return std.mem.eql(u8, component, "partial_ec_mul_window_bits_18") or
        std.mem.eql(u8, component, "cube_252") or
        std.mem.eql(u8, component, "poseidon_3_partial_rounds_chain");
}

/// Retained lookup producers still replay only their interaction subwords so
/// downstream gathers observe the interaction-epoch producer slab.
pub fn retainedLookupReplaysSubwords(component: []const u8) bool {
    return retainsLookupInputs(component) and
        std.mem.eql(u8, component, "poseidon_3_partial_rounds_chain");
}

test "retained lookup policy is narrow and explicit" {
    for ([_][]const u8{
        "partial_ec_mul_window_bits_18",
        "cube_252",
        "poseidon_3_partial_rounds_chain",
    }) |component| try std.testing.expect(retainsLookupInputs(component));
    try std.testing.expect(retainedLookupReplaysSubwords("poseidon_3_partial_rounds_chain"));
    for ([_][]const u8{
        "partial_ec_mul_generic",
        "blake_g",
        "add_opcode",
        "verify_instruction",
    }) |component| {
        try std.testing.expect(!retainsLookupInputs(component));
        try std.testing.expect(!retainedLookupReplaysSubwords(component));
    }
    try std.testing.expect(!retainsLookupInputsByPolicy("partial_ec_mul_window_bits_18", false));
    try std.testing.expect(!retainsLookupInputsByPolicy("cube_252", false));
    try std.testing.expect(!retainsLookupInputsByPolicy("poseidon_3_partial_rounds_chain", false));
}

pub const Component = struct {
    name: []const u8,
    instance: u32 = 0,
    canonical_ordinal: u32,
    writer: WriterKind,
    trace_parts: []const TracePart,
    producer_edges: []const ProducerEdge,
    capacity_feeds: []const CapacityFeed,
};

pub const Level = struct {
    component_indices: []u32,
};

const ComponentSeed = struct {
    name: []const u8,
    instance: u32,
    writer: WriterKind,
    padded_rows: u32,
    real_rows: ?u32,
};

pub const Error = error{
    DuplicateComponent,
    DuplicateCanonicalOrdinal,
    MissingComponent,
    DanglingProducer,
    InvalidProducerEdge,
    InvalidCapacityFeed,
    InvalidRowExtent,
    InvalidTraceParts,
    CyclicDependency,
    NonCanonicalOrder,
};

/// Exact per-proof Cairo component graph. It deliberately owns ordinary
/// runtime slices: a PIE determines presence and row geometry at runtime, and
/// none of those facts benefit from comptime specialization.
pub const CairoProofPlan = struct {
    allocator: std.mem.Allocator,
    components: []Component,
    levels: []Level,
    level_storage: []u32,
    canonical_order: []u32,

    pub fn init(allocator: std.mem.Allocator, components: []const Component) !CairoProofPlan {
        if (components.len == 0) return Error.MissingComponent;
        const owned_components = try allocator.alloc(Component, components.len);
        var initialized: usize = 0;
        errdefer {
            for (owned_components[0..initialized]) |component| freeComponent(allocator, component);
            allocator.free(owned_components);
        }
        while (initialized < components.len) : (initialized += 1) {
            const source = components[initialized];
            const name = try allocator.dupe(u8, source.name);
            errdefer allocator.free(name);
            const trace_parts = try allocator.dupe(TracePart, source.trace_parts);
            errdefer allocator.free(trace_parts);
            const producer_edges = try allocator.alloc(ProducerEdge, source.producer_edges.len);
            var edges_initialized: usize = 0;
            errdefer {
                for (producer_edges[0..edges_initialized]) |edge| allocator.free(edge.producer);
                allocator.free(producer_edges);
            }
            while (edges_initialized < producer_edges.len) : (edges_initialized += 1) {
                producer_edges[edges_initialized] = source.producer_edges[edges_initialized];
                producer_edges[edges_initialized].producer = try allocator.dupe(u8, source.producer_edges[edges_initialized].producer);
            }
            const capacity_feeds = try allocator.alloc(CapacityFeed, source.capacity_feeds.len);
            var feeds_initialized: usize = 0;
            errdefer {
                for (capacity_feeds[0..feeds_initialized]) |feed| allocator.free(feed.producer);
                allocator.free(capacity_feeds);
            }
            while (feeds_initialized < capacity_feeds.len) : (feeds_initialized += 1) {
                capacity_feeds[feeds_initialized] = source.capacity_feeds[feeds_initialized];
                capacity_feeds[feeds_initialized].producer = try allocator.dupe(u8, source.capacity_feeds[feeds_initialized].producer);
            }
            owned_components[initialized] = .{
                .name = name,
                .instance = source.instance,
                .canonical_ordinal = source.canonical_ordinal,
                .writer = source.writer,
                .trace_parts = trace_parts,
                .producer_edges = producer_edges,
                .capacity_feeds = capacity_feeds,
            };
        }
        try validateComponents(owned_components);

        const canonical_order = try allocator.alloc(u32, owned_components.len);
        errdefer allocator.free(canonical_order);
        for (canonical_order, 0..) |*index, value| index.* = @intCast(value);
        std.mem.sortUnstable(u32, canonical_order, owned_components, struct {
            fn lessThan(items: []Component, lhs: u32, rhs: u32) bool {
                return items[lhs].canonical_ordinal < items[rhs].canonical_ordinal;
            }
        }.lessThan);
        for (canonical_order, 0..) |component_index, ordinal| {
            if (owned_components[component_index].canonical_ordinal != ordinal)
                return Error.NonCanonicalOrder;
        }

        const topology = try buildLevels(allocator, owned_components);
        errdefer {
            allocator.free(topology.levels);
            allocator.free(topology.storage);
        }
        return .{
            .allocator = allocator,
            .components = owned_components,
            .levels = topology.levels,
            .level_storage = topology.storage,
            .canonical_order = canonical_order,
        };
    }

    /// Builds the recorded-witness portion used by the legacy Metal schedule.
    pub fn fromWitnessSchedule(
        allocator: std.mem.Allocator,
        schedule: []const std.json.Value,
        row_overrides: []const std.json.Value,
        bundle: witness_bundle.Bundle,
        input: ?*const adapter.ProverInput,
    ) !CairoProofPlan {
        const seeds = try allocator.alloc(ComponentSeed, bundle.entries.len);
        defer allocator.free(seeds);
        for (bundle.entries, seeds) |entry, *seed| {
            const padded_rows = try scheduledMainRows(schedule, entry.label);
            seed.* = .{
                .name = entry.label,
                .instance = 0,
                .writer = if (std.mem.eql(u8, entry.label, "partial_ec_mul_generic"))
                    .native_backend
                else
                    .recorded_aot,
                .padded_rows = padded_rows,
                .real_rows = try exactRowOverride(row_overrides, entry.label) orelse
                    if (input) |adapted|
                        directRealRows(adapted, entry.label, padded_rows)
                    else
                        padded_rows,
            };
        }
        return fromSeeds(allocator, seeds, null, true);
    }

    /// Joins every active component with its proof-independent writer
    /// authority. No Metal schedule, arena offset, or backend handle enters
    /// this plan.
    pub fn fromSemanticArtifacts(
        allocator: std.mem.Allocator,
        witnesses: witness_bundle.Bundle,
        feeds: feed_bundle.Bundle,
        fixed_tables: fixed_table_bundle.Bundle,
        composition: composition_bundle.Bundle,
        input: *const adapter.ProverInput,
    ) !CairoProofPlan {
        const facts = try allocator.alloc(
            semantic_authority.ComponentFacts,
            composition.components.len,
        );
        defer allocator.free(facts);
        try semantic_authority.validateAndClassify(
            allocator,
            witnesses,
            fixed_tables,
            composition,
            input,
            facts,
        );
        const seeds = try allocator.alloc(ComponentSeed, composition.components.len);
        defer allocator.free(seeds);
        for (composition.components, facts, seeds) |component, fact, *seed| {
            const padded_rows = @as(u32, 1) << @intCast(component.trace_log_size);
            seed.* = .{
                .name = component.label,
                .instance = component.instance,
                .writer = switch (fact.writer) {
                    .recorded_aot => .recorded_aot,
                    .native_backend => .native_backend,
                    .fixed_table => .fixed_table,
                    .memory_trace => .memory_trace,
                },
                .padded_rows = padded_rows,
                .real_rows = fact.real_rows,
            };
        }
        try validateFeedClosure(seeds, feeds);
        return fromSeeds(allocator, seeds, feeds, false);
    }

    fn fromSeeds(
        allocator: std.mem.Allocator,
        seeds: []const ComponentSeed,
        authenticated_feeds: ?feed_bundle.Bundle,
        resolve_real_rows: bool,
    ) !CairoProofPlan {
        const components = try allocator.alloc(Component, seeds.len);
        defer allocator.free(components);
        const parts = try allocator.alloc(TracePart, seeds.len);
        defer allocator.free(parts);
        const real_rows = try allocator.alloc(?u32, seeds.len);
        defer allocator.free(real_rows);
        const edge_lists = try allocator.alloc([]ProducerEdge, seeds.len);
        var edge_lists_initialized: usize = 0;
        defer {
            for (edge_lists[0..edge_lists_initialized]) |edges| allocator.free(edges);
            allocator.free(edge_lists);
        }
        const capacity_lists = try allocator.alloc([]CapacityFeed, seeds.len);
        var capacity_lists_initialized: usize = 0;
        defer {
            for (capacity_lists[0..capacity_lists_initialized]) |feeds| allocator.free(feeds);
            allocator.free(capacity_lists);
        }

        for (seeds, real_rows, 0..) |seed, *rows, index| {
            rows.* = seed.real_rows;
            const canonical_edges = canonicalProducerEdges(seed.name);
            var edge_count: usize = 0;
            for (canonical_edges) |edge| {
                if (seedIndex(seeds, edge.producer) != null) edge_count += 1;
            }
            edge_lists[index] = try allocator.alloc(ProducerEdge, edge_count);
            edge_lists_initialized += 1;
            var edge_index: usize = 0;
            for (canonical_edges) |edge| {
                if (seedIndex(seeds, edge.producer) == null) continue;
                edge_lists[index][edge_index] = edge;
                edge_index += 1;
            }
            const canonical_feeds = canonicalCapacityFeeds(seed.name);
            var feed_count: usize = 0;
            for (canonical_feeds) |feed| {
                if (seedIndex(seeds, feed.producer) != null) feed_count += 1;
            }
            if (authenticated_feeds) |feeds| {
                for (feeds.feeds) |feed| {
                    if (feedTargets(seed, feed) and
                        !capacityContains(canonical_feeds, feed.producer))
                        feed_count += 1;
                }
            }
            capacity_lists[index] = try allocator.alloc(CapacityFeed, feed_count);
            capacity_lists_initialized += 1;
            var feed_index: usize = 0;
            for (canonical_feeds) |feed| {
                if (seedIndex(seeds, feed.producer) == null) continue;
                capacity_lists[index][feed_index] = feed;
                feed_index += 1;
            }
            if (authenticated_feeds) |feeds| {
                for (feeds.feeds) |feed| {
                    if (!feedTargets(seed, feed) or
                        capacityContains(canonical_feeds, feed.producer))
                        continue;
                    capacity_lists[index][feed_index] = .{
                        .producer = feed.producer,
                        .instances = 1,
                    };
                    feed_index += 1;
                }
            }
        }

        var unresolved = if (resolve_real_rows) seeds.len else 0;
        while (unresolved > 0) {
            var progress = false;
            unresolved = 0;
            for (seeds, 0..) |seed, index| {
                if (real_rows[index] != null) continue;
                unresolved += 1;
                const edges = edge_lists[index];
                if (edges.len == 0) return Error.InvalidRowExtent;
                var total: u32 = 0;
                var ready = true;
                const compact = isCompactConsumer(seed.name);
                for (edges) |edge| {
                    const producer_index = seedIndex(seeds, edge.producer) orelse
                        return Error.DanglingProducer;
                    const producer_real = real_rows[producer_index] orelse {
                        ready = false;
                        break;
                    };
                    const producer_rows = if (compact)
                        producer_real
                    else
                        seeds[producer_index].padded_rows;
                    const contribution = std.math.mul(u32, producer_rows, edge.instances) catch
                        return Error.InvalidRowExtent;
                    total = std.math.add(u32, total, contribution) catch
                        return Error.InvalidRowExtent;
                }
                if (!ready) continue;
                if (total == 0 or total > seed.padded_rows) {
                    std.log.err(
                        "Cairo proof-plan rows exceed padding: component={s} real={} padded={}",
                        .{ seed.name, total, seed.padded_rows },
                    );
                    return Error.InvalidRowExtent;
                }
                real_rows[index] = total;
                unresolved -= 1;
                progress = true;
            }
            if (unresolved > 0 and !progress) return Error.CyclicDependency;
        }

        for (seeds, 0..) |seed, index| {
            parts[index] = .{
                .id = .main,
                .rows = .{
                    .real_rows = real_rows[index],
                    .padded_rows = seed.padded_rows,
                },
            };
            components[index] = .{
                .name = seed.name,
                .instance = seed.instance,
                .canonical_ordinal = @intCast(index),
                .writer = seed.writer,
                .trace_parts = parts[index .. index + 1],
                .producer_edges = edge_lists[index],
                .capacity_feeds = capacity_lists[index],
            };
        }
        return init(allocator, components);
    }

    pub fn deinit(self: *CairoProofPlan) void {
        self.allocator.free(self.canonical_order);
        self.allocator.free(self.level_storage);
        self.allocator.free(self.levels);
        for (self.components) |component| freeComponent(self.allocator, component);
        self.allocator.free(self.components);
        self.* = undefined;
    }

    pub fn find(self: CairoProofPlan, name: []const u8) ?*const Component {
        for (self.components) |*component| if (std.mem.eql(u8, component.name, name)) return component;
        return null;
    }

    pub fn findInstance(
        self: CairoProofPlan,
        name: []const u8,
        instance: u32,
    ) ?*const Component {
        for (self.components) |*component| {
            if (component.instance == instance and std.mem.eql(u8, component.name, name))
                return component;
        }
        return null;
    }

    pub fn componentIndex(self: CairoProofPlan, name: []const u8) ?u32 {
        for (self.components, 0..) |component, index| {
            if (std.mem.eql(u8, component.name, name)) return @intCast(index);
        }
        return null;
    }
};

const edge_blake_round = [_]ProducerEdge{.{ .producer = "blake_compress_opcode", .word_base = 110, .words_per_instance = 19, .instances = 10 }};
const edge_blake_g = [_]ProducerEdge{.{ .producer = "blake_round", .word_base = 81, .words_per_instance = 6, .instances = 8 }};
const edge_triple_xor = [_]ProducerEdge{.{ .producer = "blake_compress_opcode", .word_base = 300, .words_per_instance = 3, .instances = 8 }};
const edge_partial_w18 = [_]ProducerEdge{.{ .producer = "pedersen_aggregator_window_bits_18", .word_base = 7, .words_per_instance = 72, .instances = 28 }};
const edge_cube = [_]ProducerEdge{
    .{ .producer = "poseidon_aggregator", .word_base = 282, .words_per_instance = 10, .instances = 2 },
    .{ .producer = "poseidon_3_partial_rounds_chain", .word_base = 1, .words_per_instance = 10, .instances = 3 },
    .{ .producer = "poseidon_full_round_chain", .word_base = 0, .words_per_instance = 10, .instances = 3 },
};
const edge_range_252 = [_]ProducerEdge{
    .{ .producer = "poseidon_aggregator", .word_base = 262, .words_per_instance = 10, .instances = 2 },
    .{ .producer = "poseidon_3_partial_rounds_chain", .word_base = 61, .words_per_instance = 10, .instances = 3 },
};
const edge_poseidon_full = [_]ProducerEdge{.{ .producer = "poseidon_aggregator", .word_base = 6, .words_per_instance = 32, .instances = 8 }};
const edge_poseidon_partial = [_]ProducerEdge{.{ .producer = "poseidon_aggregator", .word_base = 342, .words_per_instance = 42, .instances = 27 }};
const compact_verify_edges = [_]ProducerEdge{
    .{ .producer = "add_opcode", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "add_opcode_small", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "add_ap_opcode", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "assert_eq_opcode", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "assert_eq_opcode_imm", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "assert_eq_opcode_double_deref", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "blake_compress_opcode", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "call_opcode_abs", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "call_opcode_rel_imm", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "generic_opcode", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "jnz_opcode_non_taken", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "jnz_opcode_taken", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "jump_opcode_abs", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "jump_opcode_double_deref", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "jump_opcode_rel", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "jump_opcode_rel_imm", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "mul_opcode", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "mul_opcode_small", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "qm_31_add_mul_opcode", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "ret_opcode", .word_base = 0, .words_per_instance = 7, .instances = 1 },
};
const compact_pedersen_edges = [_]ProducerEdge{.{ .producer = "pedersen_builtin", .word_base = 3, .words_per_instance = 3, .instances = 1 }};
const compact_poseidon_edges = [_]ProducerEdge{.{ .producer = "poseidon_builtin", .word_base = 6, .words_per_instance = 6, .instances = 1 }};
const capacity_blake_round = [_]CapacityFeed{.{ .producer = "blake_compress_opcode", .instances = 10 }};
const capacity_blake_g = [_]CapacityFeed{.{ .producer = "blake_round", .instances = 8 }};
const capacity_triple_xor = [_]CapacityFeed{.{ .producer = "blake_compress_opcode", .instances = 8 }};
const capacity_partial_w18 = [_]CapacityFeed{.{ .producer = "pedersen_aggregator_window_bits_18", .instances = 28 }};
const capacity_cube = [_]CapacityFeed{
    .{ .producer = "poseidon_aggregator", .instances = 2 },
    .{ .producer = "poseidon_3_partial_rounds_chain", .instances = 3 },
    .{ .producer = "poseidon_full_round_chain", .instances = 3 },
};
const capacity_range_252 = [_]CapacityFeed{
    .{ .producer = "poseidon_aggregator", .instances = 2 },
    .{ .producer = "poseidon_3_partial_rounds_chain", .instances = 3 },
};
const capacity_poseidon_full = [_]CapacityFeed{.{ .producer = "poseidon_aggregator", .instances = 8 }};
const capacity_poseidon_partial = [_]CapacityFeed{.{ .producer = "poseidon_aggregator", .instances = 27 }};
const capacity_verify = [_]CapacityFeed{
    .{ .producer = "add_opcode", .instances = 1 },
    .{ .producer = "add_opcode_small", .instances = 1 },
    .{ .producer = "add_ap_opcode", .instances = 1 },
    .{ .producer = "assert_eq_opcode", .instances = 1 },
    .{ .producer = "assert_eq_opcode_imm", .instances = 1 },
    .{ .producer = "assert_eq_opcode_double_deref", .instances = 1 },
    .{ .producer = "blake_compress_opcode", .instances = 1 },
    .{ .producer = "call_opcode_abs", .instances = 1 },
    .{ .producer = "call_opcode_rel_imm", .instances = 1 },
    .{ .producer = "generic_opcode", .instances = 1 },
    .{ .producer = "jnz_opcode_non_taken", .instances = 1 },
    .{ .producer = "jnz_opcode_taken", .instances = 1 },
    .{ .producer = "jump_opcode_abs", .instances = 1 },
    .{ .producer = "jump_opcode_double_deref", .instances = 1 },
    .{ .producer = "jump_opcode_rel", .instances = 1 },
    .{ .producer = "jump_opcode_rel_imm", .instances = 1 },
    .{ .producer = "mul_opcode", .instances = 1 },
    .{ .producer = "mul_opcode_small", .instances = 1 },
    .{ .producer = "qm_31_add_mul_opcode", .instances = 1 },
    .{ .producer = "ret_opcode", .instances = 1 },
};
const capacity_pedersen = [_]CapacityFeed{.{ .producer = "pedersen_builtin", .instances = 1 }};
const capacity_poseidon = [_]CapacityFeed{.{ .producer = "poseidon_builtin", .instances = 1 }};

/// Producer slabs gathered without sorting into one consumer witness input.
pub fn gatheredProducerEdges(component: []const u8) ?[]const ProducerEdge {
    if (std.mem.eql(u8, component, "blake_round")) return &edge_blake_round;
    if (std.mem.eql(u8, component, "blake_g")) return &edge_blake_g;
    if (std.mem.eql(u8, component, "triple_xor_32")) return &edge_triple_xor;
    if (std.mem.eql(u8, component, "partial_ec_mul_window_bits_18")) return &edge_partial_w18;
    if (std.mem.eql(u8, component, "cube_252")) return &edge_cube;
    if (std.mem.eql(u8, component, "range_check_252_width_27")) return &edge_range_252;
    if (std.mem.eql(u8, component, "poseidon_full_round_chain")) return &edge_poseidon_full;
    if (std.mem.eql(u8, component, "poseidon_3_partial_rounds_chain")) return &edge_poseidon_partial;
    return null;
}

/// Geometry for producer tuples that must be gathered, sorted, and compacted.
pub const CompactGeometry = struct {
    edges: []const ProducerEdge,
    tuple_words: u32,
    key_words: u32,
    enabler_slot: u32,
    iota_slot: u32,
    multiplicity_slot: u32,
};

pub fn compactGeometry(component: []const u8) ?CompactGeometry {
    if (std.mem.eql(u8, component, "verify_instruction")) return .{ .edges = &compact_verify_edges, .tuple_words = 7, .key_words = 1, .enabler_slot = 7, .iota_slot = 8, .multiplicity_slot = 9 };
    if (std.mem.eql(u8, component, "pedersen_aggregator_window_bits_18")) return .{ .edges = &compact_pedersen_edges, .tuple_words = 3, .key_words = 2, .enabler_slot = 3, .iota_slot = 4, .multiplicity_slot = 5 };
    if (std.mem.eql(u8, component, "poseidon_aggregator")) return .{ .edges = &compact_poseidon_edges, .tuple_words = 6, .key_words = 3, .enabler_slot = 6, .iota_slot = 7, .multiplicity_slot = 8 };
    return null;
}

pub fn canonicalProducerEdges(component: []const u8) []const ProducerEdge {
    if (gatheredProducerEdges(component)) |edges| return edges;
    if (compactGeometry(component)) |geometry| return geometry.edges;
    return &.{};
}

fn canonicalCapacityFeeds(component: []const u8) []const CapacityFeed {
    if (std.mem.eql(u8, component, "blake_round")) return &capacity_blake_round;
    if (std.mem.eql(u8, component, "blake_g")) return &capacity_blake_g;
    if (std.mem.eql(u8, component, "triple_xor_32")) return &capacity_triple_xor;
    if (std.mem.eql(u8, component, "partial_ec_mul_window_bits_18")) return &capacity_partial_w18;
    if (std.mem.eql(u8, component, "cube_252")) return &capacity_cube;
    if (std.mem.eql(u8, component, "range_check_252_width_27")) return &capacity_range_252;
    if (std.mem.eql(u8, component, "poseidon_full_round_chain")) return &capacity_poseidon_full;
    if (std.mem.eql(u8, component, "poseidon_3_partial_rounds_chain")) return &capacity_poseidon_partial;
    if (std.mem.eql(u8, component, "verify_instruction")) return &capacity_verify;
    if (std.mem.eql(u8, component, "pedersen_aggregator_window_bits_18")) return &capacity_pedersen;
    if (std.mem.eql(u8, component, "poseidon_aggregator")) return &capacity_poseidon;
    return &.{};
}

fn scheduledMainRows(schedule: []const std.json.Value, component: []const u8) !u32 {
    for (schedule) |entry| {
        if (entry != .object) continue;
        const object = entry.object;
        const purpose = object.get("purpose") orelse continue;
        const name = object.get("component") orelse continue;
        const ordinal = object.get("ordinal") orelse continue;
        if (purpose != .string or name != .string or ordinal != .integer or ordinal.integer != 0 or
            !std.mem.eql(u8, purpose.string, "BaseTrace") or !std.mem.eql(u8, name.string, component))
            continue;
        const words = object.get("len_words") orelse return Error.InvalidRowExtent;
        if (words != .integer or words.integer <= 0 or words.integer > std.math.maxInt(u32)) return Error.InvalidRowExtent;
        return @intCast(words.integer);
    }
    return Error.MissingComponent;
}

fn exactRowOverride(overrides: []const std.json.Value, component: []const u8) !?u32 {
    for (overrides) |entry| {
        if (entry != .object) return Error.InvalidRowExtent;
        const name = entry.object.get("component") orelse return Error.InvalidRowExtent;
        const rows = entry.object.get("n_real_rows") orelse return Error.InvalidRowExtent;
        if (name != .string or rows != .integer or rows.integer <= 0 or rows.integer > std.math.maxInt(u32))
            return Error.InvalidRowExtent;
        if (std.mem.eql(u8, name.string, component)) return @intCast(rows.integer);
    }
    return null;
}

fn directRealRows(input: *const adapter.ProverInput, component: []const u8, padded_rows: u32) ?u32 {
    if (std.meta.stringToEnum(opcodes.OpcodeTag, component)) |tag| {
        return @intCast(input.state_transitions.casm_states_by_opcode.getConst(tag).len);
    }
    const Builtin = struct { name: []const u8, segment: ?adapter.MemorySegmentAddresses, cells: u32 };
    const builtins = [_]Builtin{
        .{ .name = "bitwise_builtin", .segment = input.builtin_segments.bitwise_builtin, .cells = 5 },
        .{ .name = "range_check_builtin", .segment = input.builtin_segments.range_check_builtin, .cells = 1 },
        .{ .name = "pedersen_builtin", .segment = input.builtin_segments.pedersen_builtin, .cells = 3 },
        .{ .name = "poseidon_builtin", .segment = input.builtin_segments.poseidon_builtin, .cells = 6 },
    };
    for (builtins) |builtin| {
        if (!std.mem.eql(u8, component, builtin.name)) continue;
        const segment = builtin.segment orelse return null;
        if (segment.stop_ptr < segment.begin_addr) return null;
        const instances = (segment.stop_ptr - segment.begin_addr) / builtin.cells;
        return @intCast(@min(instances, padded_rows));
    }
    if (std.mem.eql(u8, component, "partial_ec_mul_generic")) return padded_rows;
    return null;
}

fn seedIndex(seeds: []const ComponentSeed, name: []const u8) ?usize {
    for (seeds, 0..) |seed, index| if (std.mem.eql(u8, seed.name, name)) return index;
    return null;
}

fn validateFeedClosure(seeds: []const ComponentSeed, feeds: feed_bundle.Bundle) !void {
    for (feeds.feeds, 0..) |feed, feed_index| {
        for (feeds.feeds[0..feed_index]) |previous| {
            if (std.mem.eql(u8, previous.producer, feed.producer))
                return error.DuplicateMultiplicityProducer;
        }
        const producer_index = seedIndex(seeds, feed.producer) orelse
            return error.MissingMultiplicityProducer;
        if (feed.row_count != seeds[producer_index].padded_rows)
            return error.MultiplicityProducerGeometryMismatch;
        for (feed.destinations) |destination| {
            if (destination.words == 0) return error.InvalidMultiplicityDestination;
            var found = false;
            for (seeds) |seed| found = found or destinationTargets(seed, destination.name);
            if (!found) return error.MissingMultiplicityDestination;
        }
    }
}

fn feedTargets(seed: ComponentSeed, feed: feed_bundle.Feed) bool {
    for (feed.destinations) |destination| {
        if (destinationTargets(seed, destination.name)) return true;
    }
    return false;
}

fn destinationTargets(seed: ComponentSeed, destination: []const u8) bool {
    if (std.mem.eql(u8, destination, "memory_id_to_big#small"))
        return std.mem.eql(u8, seed.name, "memory_id_to_small");
    return std.mem.eql(u8, seed.name, destination);
}

fn capacityContains(feeds: []const CapacityFeed, producer: []const u8) bool {
    for (feeds) |feed| {
        if (std.mem.eql(u8, feed.producer, producer)) return true;
    }
    return false;
}

fn isCompactConsumer(component: []const u8) bool {
    return compactGeometry(component) != null;
}

fn freeComponent(allocator: std.mem.Allocator, component: Component) void {
    allocator.free(component.name);
    allocator.free(component.trace_parts);
    for (component.producer_edges) |edge| allocator.free(edge.producer);
    allocator.free(component.producer_edges);
    for (component.capacity_feeds) |feed| allocator.free(feed.producer);
    allocator.free(component.capacity_feeds);
}

fn validateComponents(components: []const Component) Error!void {
    for (components, 0..) |component, index| {
        if (component.name.len == 0 or component.trace_parts.len == 0)
            return Error.InvalidTraceParts;
        for (components[0..index]) |previous| {
            if (previous.instance == component.instance and
                std.mem.eql(u8, previous.name, component.name))
                return Error.DuplicateComponent;
            if (previous.canonical_ordinal == component.canonical_ordinal) return Error.DuplicateCanonicalOrdinal;
        }
        for (component.trace_parts, 0..) |part, part_index| {
            try part.rows.validate();
            for (component.trace_parts[0..part_index]) |previous| {
                if (std.meta.eql(previous.id, part.id)) return Error.InvalidTraceParts;
            }
        }
        for (component.producer_edges) |edge| {
            if (edge.producer.len == 0 or edge.words_per_instance == 0 or edge.instances == 0)
                return Error.InvalidProducerEdge;
            if (findIndex(components, edge.producer) == null) return Error.DanglingProducer;
        }
        for (component.capacity_feeds) |feed| {
            if (feed.producer.len == 0 or feed.instances == 0) return Error.InvalidCapacityFeed;
            if (findIndex(components, feed.producer) == null) return Error.DanglingProducer;
        }
    }
}

fn buildLevels(
    allocator: std.mem.Allocator,
    components: []const Component,
) !struct { levels: []Level, storage: []u32 } {
    const placed = try allocator.alloc(bool, components.len);
    defer allocator.free(placed);
    @memset(placed, false);
    var storage = std.ArrayList(u32).empty;
    errdefer storage.deinit(allocator);
    var ranges = std.ArrayList(struct { start: usize, end: usize }).empty;
    defer ranges.deinit(allocator);

    var placed_count: usize = 0;
    while (placed_count < components.len) {
        const start = storage.items.len;
        for (components, 0..) |component, index| {
            if (placed[index] or !dependenciesPlaced(components, placed, component)) continue;
            try storage.append(allocator, @intCast(index));
        }
        if (storage.items.len == start) return Error.CyclicDependency;
        const end = storage.items.len;
        for (storage.items[start..end]) |index| {
            placed[index] = true;
            placed_count += 1;
        }
        try ranges.append(allocator, .{ .start = start, .end = end });
    }

    const owned_storage = try storage.toOwnedSlice(allocator);
    errdefer allocator.free(owned_storage);
    const levels = try allocator.alloc(Level, ranges.items.len);
    for (ranges.items, levels) |range, *level| level.* = .{
        .component_indices = owned_storage[range.start..range.end],
    };
    return .{ .levels = levels, .storage = owned_storage };
}

fn dependenciesPlaced(components: []const Component, placed: []const bool, component: Component) bool {
    for (component.producer_edges) |edge| {
        const index = findIndex(components, edge.producer) orelse return false;
        if (!placed[index]) return false;
    }
    for (component.capacity_feeds) |feed| {
        const index = findIndex(components, feed.producer) orelse return false;
        if (!placed[index]) return false;
    }
    return true;
}

fn findIndex(components: []const Component, name: []const u8) ?usize {
    for (components, 0..) |component, index| if (std.mem.eql(u8, component.name, name)) return index;
    return null;
}

test "Cairo proof plan computes canonical producer levels" {
    const rows = [_]TracePart{.{ .id = .main, .rows = .{ .real_rows = 17, .padded_rows = 32 } }};
    const edge = [_]ProducerEdge{.{
        .producer = "producer",
        .word_base = 7,
        .words_per_instance = 72,
        .instances = 28,
    }};
    const capacity = [_]CapacityFeed{.{ .producer = "producer", .instances = 28 }};
    const components = [_]Component{
        .{
            .name = "producer",
            .canonical_ordinal = 0,
            .writer = .recorded_aot,
            .trace_parts = &rows,
            .producer_edges = &.{},
            .capacity_feeds = &.{},
        },
        .{
            .name = "consumer",
            .canonical_ordinal = 1,
            .writer = .recorded_aot,
            .trace_parts = &rows,
            .producer_edges = &edge,
            .capacity_feeds = &capacity,
        },
    };
    var plan = try CairoProofPlan.init(std.testing.allocator, &components);
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 2), plan.levels.len);
    try std.testing.expectEqualSlices(u32, &.{0}, plan.levels[0].component_indices);
    try std.testing.expectEqualSlices(u32, &.{1}, plan.levels[1].component_indices);
}

test "Cairo proof plan rejects dangling producers" {
    const rows = [_]TracePart{.{ .id = .main, .rows = .{ .real_rows = 16, .padded_rows = 16 } }};
    const edge = [_]ProducerEdge{.{
        .producer = "missing",
        .word_base = 0,
        .words_per_instance = 1,
        .instances = 1,
    }};
    const components = [_]Component{.{
        .name = "consumer",
        .canonical_ordinal = 0,
        .writer = .recorded_aot,
        .trace_parts = &rows,
        .producer_edges = &edge,
        .capacity_feeds = &.{},
    }};
    try std.testing.expectError(Error.DanglingProducer, CairoProofPlan.init(std.testing.allocator, &components));
}

test "Cairo proof plan classifies gather and compact geometry" {
    const gather = gatheredProducerEdges("cube_252") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 3), gather.len);
    try std.testing.expectEqualStrings("poseidon_aggregator", gather[0].producer);
    try std.testing.expect(compactGeometry("cube_252") == null);

    const compact = compactGeometry("verify_instruction") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 7), compact.tuple_words);
    try std.testing.expectEqual(@as(u32, 9), compact.multiplicity_slot);
    try std.testing.expectEqual(@as(usize, 20), compact.edges.len);
    try std.testing.expect(gatheredProducerEdges("verify_instruction") == null);
    try std.testing.expectEqual(compact.edges.len, canonicalProducerEdges("verify_instruction").len);
}
