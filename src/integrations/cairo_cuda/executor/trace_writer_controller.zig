//! Allocation-free dispatch of authenticated Cairo CUDA trace writers.
//!
//! Ingress owns pointer-table construction and resident buffer binding. This
//! controller checks that every launch owner matches the semantic schedule,
//! then invokes the real strict-AOT/native stage API in dependency order.

const std = @import("std");
const fixed_tables = @import(
    "../../../backends/cuda/runtime/stages/cairo_base/fixed_tables.zig",
);
const memory = @import(
    "../../../backends/cuda/runtime/stages/cairo_base/memory.zig",
);
const multiplicity_feed = @import(
    "../../../backends/cuda/runtime/stages/cairo_base/multiplicity_feed.zig",
);
const cairo_witness = @import(
    "../../../backends/cuda/runtime/stages/cairo_witness.zig",
);
const cairo_witness_plan = @import(
    "../../../backends/cuda/runtime/stages/cairo_witness_plan.zig",
);
const native_ec = @import("../native_ec.zig");
const recorded_witness = @import("../recorded_witness.zig");
const base_binding = @import("base_writer_binding.zig");
const trace_schedule = @import("trace_schedule.zig");
const controller_identity = @import("trace_writer_controller/identity.zig");

pub const production_ready = false;

const NativeOps = struct {
    pub fn recorded(
        prepared: *recorded_witness.PreparedLaunch,
        session: anytype,
    ) !void {
        try prepared.launch(session);
    }

    pub fn fixed(
        binding: FixedBinding,
        session: anytype,
    ) !void {
        try fixed_tables.Native.materialize(
            session,
            binding.geometry,
            binding.buffers,
        );
    }

    pub fn memoryAddress(
        binding: MemoryAddressBinding,
        session: anytype,
    ) !void {
        try memory.Native.addressBase(
            session,
            binding.geometry,
            binding.buffers,
        );
    }

    pub fn memoryValue(
        binding: MemoryValueBinding,
        session: anytype,
    ) !void {
        try memory.Native.valueBase(
            session,
            binding.geometry,
            binding.buffers,
        );
    }

    pub fn nativeEc(
        prepared: *native_ec.Prepared,
        session: anytype,
    ) !void {
        try prepared.launch(session);
    }

    pub fn clearFeeds(
        binding: multiplicity_feed.Clear,
        session: anytype,
    ) !void {
        try multiplicity_feed.Native.clear(session, binding);
    }

    pub fn feed(
        binding: multiplicity_feed.Feed,
        session: anytype,
    ) !void {
        try multiplicity_feed.Native.counts(session, binding);
    }

    pub fn gather(
        binding: GatherBinding,
        session: anytype,
    ) !void {
        try cairo_witness.Native.gatherEdges(
            session,
            binding.topology,
            binding.producer_arena,
            binding.outputs,
        );
    }

    pub fn compact(
        binding: cairo_witness.Compact,
        session: anytype,
    ) !void {
        try cairo_witness.Native.compact(session, binding);
    }
};

pub const FixedBinding = base_binding.Fixed;
pub const MemoryAddressBinding = base_binding.MemoryAddress;
pub const MemoryValueBinding = base_binding.MemoryValue;
pub const FixedResident = base_binding.FixedResident;
pub const FixedSource = base_binding.FixedSource;
pub const MemorySource = base_binding.MemorySource;
pub const DependencyCapability = base_binding.DependencyCapability;
pub const prepareFixed = base_binding.prepareFixed;
pub const prepareMemoryAddress = base_binding.prepareMemoryAddress;
pub const prepareMemoryValue = base_binding.prepareMemoryValue;
pub const dependencyIdentity = base_binding.dependencyIdentity;
pub const dependencyBindingIdentity =
    base_binding.dependencyBindingIdentity;
pub const fixedBindingIdentity = base_binding.fixedBindingIdentity;
pub const memoryAddressBindingIdentity =
    base_binding.memoryAddressBindingIdentity;
pub const memoryValueBindingIdentity =
    base_binding.memoryValueBindingIdentity;

pub const NativeEcBinding = struct {
    prepared: *native_ec.Prepared,
    member_component_index: u32,
    member_catalog_identity: [32]u8,
};

pub const Body = union(enum) {
    recorded: *recorded_witness.PreparedLaunch,
    fixed: FixedBinding,
    memory_address: MemoryAddressBinding,
    memory_value_big: MemoryValueBinding,
    memory_value_small: MemoryValueBinding,
    native_ec: NativeEcBinding,
};

pub const Binding = struct {
    component_index: u32,
    catalog_identity: [32]u8,
    body: Body,
    gather: ?GatherBinding = null,
    compact: ?cairo_witness.Compact = null,
};

pub const GatherBinding = struct {
    topology: cairo_witness_plan.MultiEdgeTopology,
    producer_arena: @import(
        "../../../backends/cuda/runtime/stages/common.zig",
    ).Words,
    outputs: @import(
        "../../../backends/cuda/runtime/stages/common.zig",
    ).WordMatrix,
};

pub const PostFeed = struct {
    component_index: u32,
    binding: multiplicity_feed.Feed,
};

pub const FeedGraph = struct {
    clear: multiplicity_feed.Clear,
    post_feeds: []const PostFeed,
};

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    bindings: []Binding,
    schedule_identity: [32]u8,
    identity: [32]u8,
    feed_graph: ?FeedGraph = null,

    pub fn init(
        allocator: std.mem.Allocator,
        schedule: trace_schedule.Schedule,
        supplied: []const Binding,
    ) !Prepared {
        return initWithFeeds(allocator, schedule, supplied, null);
    }

    pub fn initWithFeeds(
        allocator: std.mem.Allocator,
        schedule: trace_schedule.Schedule,
        supplied: []const Binding,
        feed_graph: ?FeedGraph,
    ) !Prepared {
        if (std.mem.allEqual(u8, &schedule.identity, 0) or
            supplied.len != schedule.launch_order.len)
        {
            std.debug.print(
                "cairo-cuda trace binding inventory failed: " ++
                    "supplied={} scheduled={} zero_identity={}\n",
                .{
                    supplied.len,
                    schedule.launch_order.len,
                    std.mem.allEqual(u8, &schedule.identity, 0),
                },
            );
            return error.TraceWriterBindingMismatch;
        }
        validateScheduleAuthority(schedule) catch |err| {
            std.debug.print(
                "cairo-cuda trace schedule authority failed: {s}\n",
                .{@errorName(err)},
            );
            return err;
        };
        const bindings = try allocator.alloc(Binding, supplied.len);
        errdefer allocator.free(bindings);
        for (schedule.launch_order, bindings, 0..) |
            component_index,
            *binding,
            launch_ordinal,
        | {
            const entry = uniqueEntry(
                schedule.entries,
                component_index,
            ) orelse {
                std.debug.print(
                    "cairo-cuda trace schedule entry missing/duplicate " ++
                        "component={} launch={}\n",
                    .{ component_index, launch_ordinal },
                );
                return error.TraceWriterBindingMismatch;
            };
            const candidate = uniqueBinding(
                supplied,
                component_index,
            ) orelse {
                std.debug.print(
                    "cairo-cuda trace supplied binding missing/duplicate " ++
                        "{s}#{} component={} launch={}\n",
                    .{
                        entry.name,
                        entry.instance,
                        component_index,
                        launch_ordinal,
                    },
                );
                return error.TraceWriterBindingMismatch;
            };
            validateBinding(schedule, entry, candidate) catch |err| {
                std.debug.print(
                    "cairo-cuda trace binding {s}#{} ordinal={} " ++
                        "launch={} failed: {s}\n",
                    .{
                        entry.name,
                        entry.instance,
                        entry.canonical_ordinal,
                        launch_ordinal,
                        @errorName(err),
                    },
                );
                return err;
            };
            binding.* = candidate;
        }
        if (feed_graph) |graph| {
            validateFeedGraph(schedule, graph) catch |err| {
                std.debug.print(
                    "cairo-cuda trace feed graph failed: {s}\n",
                    .{@errorName(err)},
                );
                return err;
            };
        }
        return .{
            .allocator = allocator,
            .bindings = bindings,
            .schedule_identity = schedule.identity,
            .identity = controller_identity.compute(
                schedule.identity,
                bindings,
                feed_graph,
            ),
            .feed_graph = feed_graph,
        };
    }

    pub fn deinit(self: *Prepared) void {
        self.allocator.free(self.bindings);
        self.* = undefined;
    }

    pub fn execute(
        self: Prepared,
        session: anytype,
    ) !void {
        return self.executeWith(NativeOps, session);
    }

    pub fn executeWith(
        self: Prepared,
        comptime Ops: type,
        session: anytype,
    ) !void {
        if (std.mem.allEqual(u8, &self.identity, 0))
            return error.TraceWriterBindingMismatch;
        if (self.feed_graph) |graph| {
            Ops.clearFeeds(graph.clear, session) catch |err| {
                std.debug.print(
                    "cairo-cuda trace clear-feeds failed: {s}\n",
                    .{@errorName(err)},
                );
                return err;
            };
        }
        for (self.bindings, 0..) |binding, launch_ordinal| {
            if (binding.gather != null and binding.compact != null)
                return error.TraceWriterBindingMismatch;
            if (binding.gather) |gather| {
                Ops.gather(gather, session) catch |err| {
                    std.debug.print(
                        "cairo-cuda trace gather launch={d} component={d} " ++
                            "failed: {s}\n",
                        .{
                            launch_ordinal,
                            binding.component_index,
                            @errorName(err),
                        },
                    );
                    return err;
                };
            }
            if (binding.compact) |compact| {
                Ops.compact(compact, session) catch |err| {
                    std.debug.print(
                        "cairo-cuda trace compact launch={d} component={d} " ++
                            "failed: {s}\n",
                        .{
                            launch_ordinal,
                            binding.component_index,
                            @errorName(err),
                        },
                    );
                    return err;
                };
            }
            validatePreparedBody(binding) catch |err| {
                std.debug.print(
                    "cairo-cuda trace body validation launch={d} " ++
                        "component={d} failed: {s}\n",
                    .{
                        launch_ordinal,
                        binding.component_index,
                        @errorName(err),
                    },
                );
                return err;
            };
            const body_result = switch (binding.body) {
                .recorded => |prepared| Ops.recorded(
                    prepared,
                    session,
                ),
                .fixed => |fixed| Ops.fixed(fixed, session),
                .memory_address => |address| Ops.memoryAddress(
                    address,
                    session,
                ),
                .memory_value_big,
                .memory_value_small,
                => |value| Ops.memoryValue(value, session),
                .native_ec => |native| Ops.nativeEc(
                    native.prepared,
                    session,
                ),
            };
            body_result catch |err| {
                std.debug.print(
                    "cairo-cuda trace body launch={d} component={d} " ++
                        "kind={s} failed: {s}\n",
                    .{
                        launch_ordinal,
                        binding.component_index,
                        @tagName(binding.body),
                        @errorName(err),
                    },
                );
                return err;
            };
            if (self.feed_graph) |graph| {
                for (graph.post_feeds) |feed| {
                    const owns_feed = feed.component_index ==
                        binding.component_index or switch (binding.body) {
                        .native_ec => |native| feed.component_index ==
                            native.member_component_index,
                        else => false,
                    };
                    if (owns_feed) {
                        Ops.feed(feed.binding, session) catch |err| {
                            std.debug.print(
                                "cairo-cuda trace feed launch={d} " ++
                                    "component={d} feed_component={d} " ++
                                    "failed: {s}\n",
                                .{
                                    launch_ordinal,
                                    binding.component_index,
                                    feed.component_index,
                                    @errorName(err),
                                },
                            );
                            return err;
                        };
                    }
                }
            }
        }
    }
};

fn validateFeedGraph(
    schedule: trace_schedule.Schedule,
    graph: FeedGraph,
) !void {
    if (graph.post_feeds.len == 0)
        return error.TraceWriterBindingMismatch;
    for (graph.post_feeds, 0..) |feed, index| {
        if (uniqueEntry(
            schedule.entries,
            feed.component_index,
        ) == null)
            return error.TraceWriterBindingMismatch;
        for (graph.post_feeds[0..index]) |previous| {
            if (previous.component_index == feed.component_index)
                return error.TraceWriterBindingMismatch;
        }
    }
}

fn validateBinding(
    schedule: trace_schedule.Schedule,
    entry: trace_schedule.Entry,
    binding: Binding,
) !void {
    if (entry.execution == .composite_member or
        binding.component_index != entry.component_index or
        !std.mem.eql(
            u8,
            &binding.catalog_identity,
            &entry.catalog_identity,
        ))
    {
        return error.TraceWriterBindingMismatch;
    }
    const matches = switch (binding.body) {
        .recorded => |prepared| entry.prepare_api ==
            .recorded_witness_prepare and
            entry.execution == .standalone and
            std.mem.eql(
                u8,
                &prepared.catalog_identity,
                &entry.catalog_identity,
            ) and
            !std.mem.allEqual(u8, &prepared.binding_identity, 0),
        .fixed => |fixed| entry.prepare_api ==
            .fixed_table_materialize and
            validateBaseSeal(entry, fixed) and
            base_binding.fixedSealValid(fixed),
        .memory_address => |memory_address| entry.prepare_api ==
            .memory_address_base and
            validateBaseSeal(entry, memory_address) and
            base_binding.memoryAddressSealValid(memory_address),
        .memory_value_big => |memory_value| entry.prepare_api ==
            .memory_value_base_big and
            validateBaseSeal(entry, memory_value) and
            base_binding.memoryValueSealValid(memory_value),
        .memory_value_small => |memory_value| entry.prepare_api ==
            .memory_value_base_small and
            validateBaseSeal(entry, memory_value) and
            base_binding.memoryValueSealValid(memory_value),
        .native_ec => |native| try validateNativeMember(
            schedule,
            entry,
            native,
        ),
    };
    if (!matches) return error.TraceWriterBindingMismatch;
}

fn validateNativeMember(
    schedule: trace_schedule.Schedule,
    root: trace_schedule.Entry,
    native: NativeEcBinding,
) !bool {
    const root_shape = root.prepare_api == .native_ec_prepare and
        root.execution == .composite_root and
        root.launch_owner == root.component_index;
    if (!root_shape) {
        std.debug.print(
            "cairo-cuda native trace seal root shape failed\n",
            .{},
        );
        return false;
    }
    const member = uniqueEntry(
        schedule.entries,
        native.member_component_index,
    ) orelse {
        std.debug.print(
            "cairo-cuda native trace seal member missing/duplicate\n",
            .{},
        );
        return false;
    };
    const member_shape = member.prepare_api == .native_ec_member and
        member.execution == .composite_member and
        member.launch_owner == root.component_index;
    const member_binding_catalog = std.mem.eql(
        u8,
        &native.member_catalog_identity,
        &member.catalog_identity,
    );
    const root_prepared_catalog = std.mem.eql(
        u8,
        &native.prepared.catalog_identity,
        &root.catalog_identity,
    );
    const member_prepared_catalog = std.mem.eql(
        u8,
        &native.prepared.partial_ec_mul.catalog_identity,
        &member.catalog_identity,
    );
    const root_binding_nonzero = !std.mem.allEqual(
        u8,
        &native.prepared.binding_identity,
        0,
    );
    const member_binding_nonzero = !std.mem.allEqual(
        u8,
        &native.prepared.partial_ec_mul.binding_identity,
        0,
    );
    const valid = member_shape and
        member_binding_catalog and
        root_prepared_catalog and
        member_prepared_catalog and
        root_binding_nonzero and
        member_binding_nonzero;
    if (!valid) {
        std.debug.print(
            "cairo-cuda native trace seal failed: " ++
                "member_shape={} member_binding_catalog={} " ++
                "root_prepared_catalog={} member_prepared_catalog={} " ++
                "root_binding_nonzero={} member_binding_nonzero={}\n",
            .{
                member_shape,
                member_binding_catalog,
                root_prepared_catalog,
                member_prepared_catalog,
                root_binding_nonzero,
                member_binding_nonzero,
            },
        );
    }
    return valid;
}

fn validatePreparedBody(binding: Binding) !void {
    const valid = switch (binding.body) {
        .recorded => |prepared| std.mem.eql(
            u8,
            &prepared.catalog_identity,
            &binding.catalog_identity,
        ) and !std.mem.allEqual(u8, &prepared.binding_identity, 0),
        .native_ec => |native| std.mem.eql(
            u8,
            &native.prepared.catalog_identity,
            &binding.catalog_identity,
        ) and !std.mem.allEqual(
            u8,
            &native.prepared.binding_identity,
            0,
        ),
        .fixed => |fixed| bodySealMatches(
            binding.catalog_identity,
            fixed,
        ) and base_binding.fixedSealValid(fixed),
        .memory_address => |memory_address| bodySealMatches(
            binding.catalog_identity,
            memory_address,
        ) and base_binding.memoryAddressSealValid(memory_address),
        .memory_value_big,
        .memory_value_small,
        => |memory_value| bodySealMatches(
            binding.catalog_identity,
            memory_value,
        ) and base_binding.memoryValueSealValid(memory_value),
    };
    if (!valid) return error.TraceWriterBindingMismatch;
}

fn validateBaseSeal(entry: trace_schedule.Entry, body: anytype) bool {
    return entry.execution == .standalone and
        bodySealMatches(entry.catalog_identity, body) and
        std.meta.eql(body.ownership, entry.buffers) and
        std.mem.eql(
            u8,
            &body.dependency_identity,
            &base_binding.dependencyIdentity(entry),
        ) and
        body.capability.owner != 0 and body.capability.generation != 0;
}

fn bodySealMatches(catalog_identity: [32]u8, body: anytype) bool {
    return std.mem.eql(
        u8,
        &body.catalog_identity,
        &catalog_identity,
    ) and !std.mem.allEqual(u8, &body.binding_identity, 0);
}

fn validateScheduleAuthority(schedule: trace_schedule.Schedule) !void {
    var dependency_count: usize = 0;
    var launch_count: usize = 0;
    for (schedule.entries) |entry| {
        if (!validOwnership(entry))
            return error.TraceWriterBindingMismatch;
        if (entry.execution != .composite_member) launch_count += 1;
        dependency_count = std.math.add(
            usize,
            dependency_count,
            entry.dependencies.len,
        ) catch return error.TraceWriterBindingMismatch;
        for (entry.dependencies, 0..) |dependency, index| {
            if (!validDependencyShape(entry, dependency))
                return error.TraceWriterBindingMismatch;
            for (entry.dependencies[0..index]) |prior| {
                if (std.meta.eql(prior, dependency))
                    return error.TraceWriterBindingMismatch;
            }
            const producer = uniqueEntry(
                schedule.entries,
                dependency.producer_component_index,
            ) orelse return error.TraceWriterBindingMismatch;
            try validateDependencyOrder(
                schedule,
                producer,
                entry,
                dependency,
            );
        }
    }
    if (dependency_count != schedule.dependency_storage.len or
        launch_count != schedule.launch_order.len)
    {
        return error.TraceWriterBindingMismatch;
    }
    var dependency_cursor: usize = 0;
    for (schedule.entries) |entry| {
        const end = dependency_cursor + entry.dependencies.len;
        if (end > schedule.dependency_storage.len or
            !std.mem.eql(
                u8,
                std.mem.sliceAsBytes(entry.dependencies),
                std.mem.sliceAsBytes(
                    schedule.dependency_storage[dependency_cursor..end],
                ),
            ))
        {
            return error.TraceWriterBindingMismatch;
        }
        dependency_cursor = end;
    }
    for (schedule.launch_order, 0..) |component_index, index| {
        const entry = uniqueEntry(
            schedule.entries,
            component_index,
        ) orelse return error.TraceWriterBindingMismatch;
        if (entry.execution == .composite_member or
            entry.launch_owner != component_index)
        {
            return error.TraceWriterBindingMismatch;
        }
        for (schedule.launch_order[0..index]) |prior| {
            if (prior == component_index)
                return error.TraceWriterBindingMismatch;
        }
    }
}

fn validOwnership(entry: trace_schedule.Entry) bool {
    const own = entry.buffers;
    const common = own.trace_outputs == entry.component_index and
        own.lookup_outputs == entry.component_index and
        own.subword_outputs == entry.component_index and
        own.multiplicity_outputs == entry.component_index;
    if (!common) return false;
    return switch (entry.execution) {
        .standalone => entry.launch_owner == entry.component_index and
            own.native_partial_workspace == null and
            own.native_partial_inputs == null,
        .composite_root => entry.prepare_api == .native_ec_prepare and
            entry.launch_owner == entry.component_index and
            own.native_partial_workspace == entry.component_index and
            own.native_partial_inputs == null,
        .composite_member => entry.prepare_api == .native_ec_member and
            entry.launch_owner != entry.component_index and
            own.native_partial_workspace == null and
            own.native_partial_inputs == entry.launch_owner,
    };
}

fn validDependencyShape(
    entry: trace_schedule.Entry,
    dependency: trace_schedule.Dependency,
) bool {
    if (dependency.producer_component_index == entry.component_index or
        dependency.instances == 0)
    {
        return false;
    }
    return switch (dependency.kind) {
        .producer_words => dependency.words_per_instance != 0,
        .capacity => dependency.word_base == 0 and
            dependency.words_per_instance == 0,
        .native_ec_workspace => entry.execution == .composite_member and
            dependency.producer_component_index == entry.launch_owner and
            dependency.word_base == 0 and
            dependency.words_per_instance == 0 and
            dependency.instances == 1,
    };
}

fn validateDependencyOrder(
    schedule: trace_schedule.Schedule,
    producer: trace_schedule.Entry,
    consumer: trace_schedule.Entry,
    dependency: trace_schedule.Dependency,
) !void {
    if (dependency.kind == .native_ec_workspace) {
        if (producer.execution != .composite_root or
            producer.launch_owner != consumer.launch_owner)
        {
            return error.TraceWriterBindingMismatch;
        }
        return;
    }
    const producer_position = launchPosition(
        schedule.launch_order,
        producer.launch_owner,
    ) orelse return error.TraceWriterBindingMismatch;
    const consumer_position = launchPosition(
        schedule.launch_order,
        consumer.launch_owner,
    ) orelse return error.TraceWriterBindingMismatch;
    if (producer_position >= consumer_position)
        return error.TraceWriterBindingMismatch;
}

fn launchPosition(order: []const u32, component_index: u32) ?usize {
    for (order, 0..) |candidate, index| {
        if (candidate == component_index) return index;
    }
    return null;
}

fn uniqueBinding(
    bindings: []const Binding,
    component_index: u32,
) ?Binding {
    var found: ?Binding = null;
    for (bindings) |binding| {
        if (binding.component_index != component_index) continue;
        if (found != null) return null;
        found = binding;
    }
    return found;
}

fn uniqueEntry(
    entries: []const trace_schedule.Entry,
    component_index: u32,
) ?trace_schedule.Entry {
    var found: ?trace_schedule.Entry = null;
    for (entries) |entry| {
        if (entry.component_index != component_index) continue;
        if (found != null) return null;
        found = entry;
    }
    return found;
}
