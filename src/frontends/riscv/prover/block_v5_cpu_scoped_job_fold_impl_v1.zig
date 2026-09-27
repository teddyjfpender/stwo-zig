//! Real late-bound CPU fold. At most four original/lower fresh captures live
//! per node. Original proof bytes are reloaded from their actual durable stores;
//! expected keys are derived from genuine verifier+merge rows, never a file.
//! Normative setup is built once, then transferred to the immutable owner.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Sources = @import("block_v5_cpu_scoped_job_sources_v1.zig");
const Setup = @import("../recursion/block_v5_heterogeneous_scoped_owner_v1.zig");
const Source = @import("../recursion/block_v5_heterogeneous_scoped_source_v1.zig");
const Bus = @import("../recursion/block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Protocol = @import("../recursion/block_v5_reusable_heterogeneous_scoped_protocol_v1.zig");
const Rows = @import("../recursion/block_v5_heterogeneous_scoped_preparation_v1.zig");
const Fresh = @import("../recursion/block_v5_heterogeneous_scoped_receiver_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const Publication = @import("block_v5_cpu_scoped_publication_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const Recipe = @import("../recursion/block_v5_heterogeneous_scoped_plan_v1.zig").Recipe;
pub const Pin = struct { byte_len: u64, sha256: [32]u8 };
pub const Limits = struct {
    setup: Setup.Limits = .{},
    max_metadata_bytes: usize = 256 << 20,
    max_live_bytes: usize = 4 << 30,
    max_child_bytes: usize = 512 << 20,
    max_parent_bytes: usize = 512 << 20,
    max_total_parent_bytes: u64 = 64 << 30,
    rows: Rows.Limits = .{},
    transcript_capacity: u32 = 2,
    pub fn validate(self: Limits) !void {
        if (self.max_metadata_bytes == 0 or self.max_live_bytes == 0 or self.max_child_bytes == 0 or self.max_parent_bytes == 0 or self.max_total_parent_bytes == 0 or self.transcript_capacity == 0)
            return error.CpuScopedFoldResourceLimit;
    }
};
pub const Sink = struct {
    context: *anyopaque,
    /// Called only after actual freshly checked parent publication. All fields
    /// borrow for this call, and remain setup/transport proposals for receivers.
    /// Prior successful callbacks remain provisional until run succeeds; any
    /// later failure rolls back this invocation's newly published node files.
    put_open: *const fn (*anyopaque, u32, Pin, *const Setup.NodeSpec) anyerror!void,
};
pub const Result = struct {
    a: std.mem.Allocator,
    owner: *Setup.Owner,
    files: []Pin,
    /// Only the requester specialization retains the ALREADY fresh root.
    /// This same budget owns its Source plus original verifier capture.
    root_fresh: ?Fresh.Fresh = null,
    root_budget: ?*Budget = null,
    pub const complete_block_authority = false;
    pub const pending_source_authorities = @import("block_v5_recursive_coverage_plan_v1.zig").SOURCE_COUNT;
    pub fn rootFresh(self: *const Result) !*const Fresh.Fresh {
        return if (self.root_fresh) |*value| value else error.CpuRequesterRootCaptureReleased;
    }
    pub fn releaseRootCapture(self: *Result) void {
        if (self.root_fresh) |*value| value.deinit();
        self.root_fresh = null;
        if (self.root_budget) |value| value.destroy();
        self.root_budget = null;
    }
    pub fn deinit(self: *Result) void {
        self.releaseRootCapture();
        self.owner.deinit();
        self.a.free(self.files);
        self.* = undefined;
    }
};
const Record = struct { authority: Protocol.Admission, source: Source.Source, spec: Setup.NodeSpec };
/// Reconstruct mode reads genuine proposed node bytes, independently derives
/// their exact expected key/schedule from fresh children, then freshly verifies
/// each parent. No received key, constructor capture or host flag is authority.
pub const Action = union(enum) { publish: Sink, reconstruct: []const Pin };
fn nodePath(comptime recipe: Recipe, buffer: []u8, index: u32) ![]const u8 {
    return Publication.path(recipe, buffer, index);
}
pub const path = ForRecipe(.complete).path;
pub const ForBackend = ForRecipe(.complete).ForBackend;
pub fn ForRecipe(comptime recipe: Recipe) type {
    return struct {
        pub const RECIPE = recipe;
        pub fn path(buffer: []u8, index: u32) ![]const u8 {
            return nodePath(recipe, buffer, index);
        }
        pub fn ForBackend(comptime Backend: type) type {
            return struct {
                pub fn run(backing: std.mem.Allocator, dir: std.fs.Dir, source: *const Sources.Owner, profile: @import("../recursion/blake3_execution_parent_protocol.zig").Profile, limits: Limits, action: Action) !Result {
                    try limits.validate();
                    if (!std.meta.eql(profile.config(), source.coverage.meta.security.recursive)) return error.UntrustedCpuScopedFoldSecurity;
                    var setup = try Setup.ForRecipe(recipe).prepareJob(backing, source.policy(), .{ .job = source.publication.sources.roster.pins.job_id, .coverage = source.coverage.pinned_digest, .source = source.coverage.meta.seal_digest, .recipe = source.coverage.meta.recipe }, limits.setup);
                    defer setup.deinit();
                    const routes = try setup.routes();
                    const count = routes.nodes.len;
                    if (action == .reconstruct and action.reconstruct.len != count) return error.IncompleteCpuScopedNodeFiles;
                    var publication = try Publication.ForRecipe(recipe).Tracker.init(dir, count, limits.setup.cohorts.max_nodes);
                    errdefer publication.rollback();
                    const budget = try Budget.create(backing, limits.max_metadata_bytes);
                    defer budget.destroy();
                    var arena = std.heap.ArenaAllocator.init(budget.allocator());
                    defer arena.deinit();
                    const meta = arena.allocator();
                    const records = try meta.alloc(Record, count);
                    var initialized: usize = 0;
                    defer for (records[0..initialized]) |*record| record.source.deinit();
                    const specs = try meta.alloc(Setup.NodeSpec, count);
                    const ids = try meta.alloc([32]u8, count);
                    const pins = try backing.alloc(Pin, count);
                    errdefer backing.free(pins);
                    var root_fresh: ?Fresh.Fresh = null;
                    var root_budget: ?*Budget = null;
                    errdefer {
                        if (root_fresh) |*value| value.deinit();
                        if (root_budget) |value| value.destroy();
                    }
                    var total: u64 = 0;
                    for (routes.cohorts.nodes, 0..) |cohort, index| {
                        const live_budget = try Budget.createRetainingParent(backing, limits.max_live_bytes);
                        defer live_budget.destroy();
                        const a = live_budget.allocator();
                        var children: [4]Fresh.Fresh = undefined;
                        var child_count: usize = 0;
                        defer for (children[0..child_count]) |*child| child.deinit();
                        var actual: [4]Source.Source = undefined;
                        var captures: [4]*const @import("../recursion/blake3_native_parent_verifier.zig").Verified = undefined;
                        const expected_children = try meta.alloc(Source.Source, cohort.child_count);
                        const child_pins = try meta.alloc(Bus.ChildPin, cohort.child_count);
                        for (cohort.children[0..cohort.child_count], 0..) |ref, slot| {
                            const bytes = switch (ref) {
                                .leaf => |ordinal| try source.readLeaf(a, ordinal),
                                .node => |ordinal| block: {
                                    if (ordinal >= initialized) return error.InvalidCpuScopedFoldOrder;
                                    var buffer: [128]u8 = undefined;
                                    break :block try Files.readPinned(a, dir, try nodePath(recipe, &buffer, ordinal), pins[ordinal].byte_len, pins[ordinal].sha256, limits.max_child_bytes);
                                },
                            };
                            defer a.free(bytes);
                            if (bytes.len == 0 or bytes.len > limits.max_child_bytes) return error.CpuScopedFoldResourceLimit;
                            children[slot] = switch (ref) {
                                .leaf => |ordinal| try Fresh.verifyLeaf(a, bytes, routes, ordinal),
                                .node => |ordinal| try Fresh.verify(a, bytes, records[ordinal].authority),
                            };
                            child_count += 1;
                            actual[slot] = children[slot].source;
                            captures[slot] = &children[slot].equation;
                            expected_children[slot] = switch (ref) {
                                .leaf => |ordinal| try setup.source(ordinal),
                                .node => |ordinal| records[ordinal].source,
                            };
                            if (!std.meta.eql(actual[slot].seal, expected_children[slot].seal)) return error.ChangedCpuScopedChildSource;
                            child_pins[slot] = .{ .key = expected_children[slot].key, .id = expected_children[slot].expected_id, .public_input = expected_children[slot].public_input_digest, .source_seal = expected_children[slot].seal };
                        }
                        const outputs = try deriveOutputs(meta, routes, @intCast(index), expected_children);
                        const values = Bus.Values{ .routes = routes, .index = @intCast(index), .children = actual[0..child_count], .pins = child_pins, .outputs = outputs };
                        var rows = try Rows.prepareVerifierRows(a, values, captures[0..child_count], limits.transcript_capacity, limits.rows);
                        var owns_rows = true;
                        defer if (owns_rows) rows.deinit();
                        // Prepared rows own every child verifier/equation cell.
                        // The genuine child seals were checked against these deep
                        // independent metadata Sources before row materialization.
                        // Keep later admissions on that stable policy, rather than
                        // retaining any original child proof/capture for proving.
                        const stable_values = Bus.Values{ .routes = routes, .index = @intCast(index), .children = expected_children, .pins = child_pins, .outputs = outputs };
                        rows.values = stable_values;
                        for (children[0..child_count]) |*child| child.deinit();
                        child_count = 0;
                        const unbound = rows.recursive.context;
                        const derived_pins = try setup.derivedPins();
                        Setup.bindIndependentContext(&rows.recursive.context, derived_pins.contextIdentity());
                        const geometry = try Parent.ForBackend(Backend).deriveKeyWithProfile(a, &rows.recursive, profile);
                        const key = try Protocol.Key.fromGeometry(geometry, rows.wires);
                        const id = try key.identity();
                        const wires = try meta.dupe(Bus.Wire, rows.wires);
                        const authority = try Protocol.Admission.init(key, id, wires, .{ .routes = routes, .index = @intCast(index), .children = expected_children, .pins = child_pins, .outputs = outputs });
                        const live = try Protocol.Admission.init(key, id, rows.wires, stable_values);
                        if (!std.meta.eql(try live.publicInputIdentity(), try authority.publicInputIdentity())) return error.ChangedCpuScopedChildSource;
                        var buffer: [128]u8 = undefined;
                        const file_path = try nodePath(recipe, &buffer, @intCast(index));
                        const bytes = switch (action) {
                            .publish => block: {
                                const Producer = @import("../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Backend, Protocol);
                                const producer = try Producer.init(a, &rows.recursive.rows, live);
                                defer producer.deinit();
                                var workspace = @import("../recursion/blake3_native_parent_producer.zig").Workspace.init(a, 0);
                                defer workspace.deinit();
                                var proof = try producer.proveConsumingWithWorkspace(a, &rows.recursive.rows, &workspace);
                                defer proof.deinit();
                                break :block try Parent.codec.encode(a, &proof, &live);
                            },
                            .reconstruct => |received| try Files.readPinned(a, dir, file_path, received[index].byte_len, received[index].sha256, limits.max_parent_bytes),
                        };
                        defer a.free(bytes);
                        // Encoded bytes and the independently owned authority
                        // suffice for the original fresh verifier. Release PCS,
                        // producer, workspace and all transient rows beforehand.
                        rows.deinit();
                        owns_rows = false;
                        if (bytes.len == 0 or bytes.len > limits.max_parent_bytes) return error.CpuScopedFoldResourceLimit;
                        var checked = try Fresh.verify(a, bytes, authority);
                        var owns_checked = true;
                        defer if (owns_checked) checked.deinit();
                        var expected_source = try Source.fromNode(meta, authority);
                        errdefer expected_source.deinit();
                        if (!std.meta.eql(checked.source.seal, expected_source.seal)) return error.ChangedCpuScopedChildSource;
                        const pin = Pin{ .byte_len = bytes.len, .sha256 = Files.hash(bytes) };
                        total = try std.math.add(u64, total, pin.byte_len);
                        if (total > limits.max_total_parent_bytes) return error.CpuScopedFoldResourceLimit;
                        const spec = Setup.NodeSpec{ .unbound_context = unbound, .key = key, .expected_id = id, .wires = wires, .children = child_pins, .outputs = outputs, .public_input = try authority.publicInputIdentity(), .source_seal = expected_source.seal };
                        if (action == .publish) {
                            try publication.publish(@intCast(index), bytes);
                            try action.publish.put_open(action.publish.context, @intCast(index), pin, &spec);
                        }
                        // Complete every fallible guard before transferring
                        // expected_source into records' destructor inventory.
                        if (comptime recipe == .requesters) {
                            if (routes.cohorts.root == .node and routes.cohorts.root.node == index and
                                (root_fresh != null or root_budget != null))
                                return error.InvalidCpuRequesterRootCapture;
                        }
                        records[index] = .{ .authority = authority, .source = expected_source, .spec = spec };
                        initialized += 1;
                        specs[index] = spec;
                        ids[index] = id;
                        pins[index] = pin;
                        if (comptime recipe == .requesters) {
                            if (routes.cohorts.root == .node and routes.cohorts.root.node == index) {
                                root_budget = live_budget.retain();
                                root_fresh = checked;
                                owns_checked = false;
                            }
                        }
                    }
                    if (comptime recipe == .requesters) {
                        if (root_fresh == null or root_budget == null) return error.InvalidCpuRequesterRootCapture;
                    }
                    var pinned = try setup.derivedPins();
                    pinned.node_ids = ids;
                    const owner = try setup.finish(pinned, specs);
                    publication.commit();
                    // Same stable normative plans transfer; no second full-job setup.
                    return .{ .a = backing, .owner = owner, .files = pins, .root_fresh = root_fresh, .root_budget = root_budget };
                }
            };
        }
    };
}
pub fn slotValue(source: *const Source.Source, requirement: u32) !Q {
    const slot = try source.findSlot(requirement);
    if (slot.first > source.cells.len or source.cells.len - slot.first < 4) return error.InvalidScopedSource;
    var limbs: [4]M = undefined;
    for (&limbs, 0..) |*limb, i| {
        var word: u32 = 0;
        for (source.cells[slot.first + i], 0..) |byte, part| {
            if (byte.v > 255) return error.NoncanonicalScopedSummary;
            word |= byte.v << @as(u5, @intCast(8 * part));
        }
        if (word >= core.fields.m31.Modulus) return error.NoncanonicalScopedSummary;
        limb.* = M.fromCanonical(word);
    }
    return Q.fromM31Array(limbs);
}
fn deriveOutputs(a: std.mem.Allocator, routes: *const @import("../recursion/block_v5_heterogeneous_scoped_routes_v1.zig").Plan, index: u32, children: []const Source.Source) ![]Q {
    const outputs = try a.alloc(Q, routes.nodes[index].exports.len);
    for (outputs, routes.nodes[index].exports) |*output, requirement| {
        var sum = Q.zero();
        for (children) |*child| switch (child.ref) {
            .leaf => |ordinal| {
                const terms = @import("../recursion/block_v5_heterogeneous_scoped_plan_v1.zig").Plan.termsFor(routes.scoped.requirements[requirement], ordinal);
                for (terms) |term| {
                    const value = try routes.scoped.value(term.selection);
                    sum = if (term.negative) sum.sub(value) else sum.add(value);
                }
            },
            .node => {
                // A child without this keyed contribution contributes zero.
                for (child.slots) |slot| if (slot.requirement == requirement) {
                    sum = sum.add(try slotValue(child, requirement));
                    break;
                };
            },
        };
        output.* = sum;
    }
    return outputs;
}
