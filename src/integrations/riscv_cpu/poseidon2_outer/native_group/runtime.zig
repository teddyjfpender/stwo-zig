//! Experimental complete grouped-root orchestration. Native members are
//! verified directly in canonical groups; only group boundaries need folds.
//! Receiver reconstructs all authority from pinned code/input and declarations,
//! never from native proof bytes or a proposed root verifier key.
const std = @import("std");
const E = @import("stwo_prover_engine");
const C = @import("../../rv64_recursion/om31_poseidon/common.zig");
const Runtime = @import("../sponge_cpu/runtime.zig");
const Receiver = @import("../sponge_cpu/receiver.zig");
const Captured = @import("../sponge_cpu/captured_source.zig");
const A = @import("../sponge_cpu/root_admission.zig");
const Planner = @import("plan.zig");
const Topology = @import("topology.zig");
const Adapter = @import("native_adapter.zig");
const Walk = @import("source_walk.zig");
const Keys = @import("keys.zig");
const Cost = Keys.Cost;
const Fold = @import("../native_omul/fold.zig");
const Profile = @import("../op_profile.zig").Profile;
const Templates = @import("../pure_p2_gkr_templates_wire.zig");
const Write = @import("../../rv64_ethereum_batch_receipt.zig").writeExclusive;
const Config = @import("../../rv64_ethereum_request.zig").Config;
pub const Metadata = struct {
    schema: u32 = 1,
    format: []const u8 = "op-direct-native-group-root/v1",
    profile: Profile,
    maximum_group: u32,
    statement: A.Metadata,
    terminal_outer_profile: ?Profile = null,
    arithmetization: ?Keys.Format = null,
};
pub const Options = struct {
    arithmetization: Keys.Format = .r6,
    terminal_outer_profile: ?Profile = null,
    pub fn resolve(self: Options, native: Profile) !Profile {
        const terminal = self.terminal_outer_profile orelse native;
        try Topology.requireTerminalProfile(native, terminal);
        return terminal;
    }
};
fn metadataJson(a: std.mem.Allocator, value: Metadata) ![]u8 {
    // Default R6 B4/B2 metadata keeps its exact existing bytes. New arithmetic
    // is explicit metadata AND independently receiver-pinned source policy.
    if (value.arithmetization == null) {
        if (value.terminal_outer_profile == null) return std.json.Stringify.valueAlloc(a, .{ .schema = value.schema, .format = value.format, .profile = value.profile, .maximum_group = value.maximum_group, .statement = value.statement }, .{ .whitespace = .indent_2 });
        return std.json.Stringify.valueAlloc(a, .{ .schema = value.schema, .format = value.format, .profile = value.profile, .maximum_group = value.maximum_group, .statement = value.statement, .terminal_outer_profile = value.terminal_outer_profile }, .{ .whitespace = .indent_2 });
    }
    return std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
}
fn requireReceiverHeader(a: std.mem.Allocator, path: []const u8, profile: Profile, maximum: u32, terminal: Profile, format: Keys.Format) !void {
    if (!E.host_budget_allocator.SharedHostBudget.isAllocator(a)) return error.OpNativeRequiresSharedHostBudget;
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    const raw = try dir.readFileAlloc(a, "root.json", 4 << 20);
    defer a.free(raw);
    const Header = struct { schema: u32, format: []const u8, profile: Profile, maximum_group: u32, terminal_outer_profile: ?Profile = null, arithmetization: ?Keys.Format = null };
    const parsed = try std.json.parseFromSlice(Header, a, raw, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const h = parsed.value;
    if (h.schema != 1 or !std.mem.eql(u8, h.format, "op-direct-native-group-root/v1") or h.profile != profile or h.maximum_group != maximum or (h.terminal_outer_profile orelse h.profile) != terminal or (h.arithmetization orelse .r6) != format) return error.NativeGroupReceiverPolicy;
}
fn authority(source: Runtime.SourceDirectory) A.Authority {
    return .{ .inventory = source.inventory, .cpus = source.authority.cpu, .detached = source.authority.detached, .catalog = source.authority.catalogs, .towers = source.authority.catalog.miller, .image = source.image };
}
const Node = struct {
    key: Keys.Ref,
    output: Fold.Digest,
    bytes: []u8,
    captured: Keys.Captured,
    fn deinit(self: *Node, a: std.mem.Allocator) void {
        self.captured.deinit(a);
        a.free(self.bytes);
    }
};
const Collector = struct {
    a: std.mem.Allocator,
    directory: std.fs.Dir,
    maximum: u32,
    profile: Profile,
    terminal_outer_profile: Profile,
    arithmetization: Keys.Format,
    plan: ?Planner.Plan = null,
    group_node: usize = 0,
    seen: u32 = 0,
    manifest: ?[36]u8 = null,
    source: ?Keys.Stream = null,
    numeric: ?Keys.Stream = null,
    groups: std.ArrayList(*Topology.Group) = .empty,
    nodes: [Planner.MAX_NODES]?Node = @splat(null),
    leaves: std.ArrayList(Adapter.Leaf) = .empty,
    templates: std.ArrayList([]const u8) = .empty,
    topology: ?Topology.Topology = null,
    completed: bool = false,
    prove_groups: bool,
    fn deinit(self: *Collector) void {
        for (&self.nodes) |*node| if (node.*) |*value| value.deinit(self.a);
        if (self.topology) |*t| t.deinit();
        for (self.groups.items) |group| {
            group.deinit();
            self.a.destroy(group);
        }
        self.groups.deinit(self.a);
        for (self.leaves.items) |leaf| self.a.free(leaf.claims);
        self.leaves.deinit(self.a);
        for (self.templates.items) |shape| self.a.free(shape);
        self.templates.deinit(self.a);
        if (self.source) |*source| source.deinit();
        if (self.numeric) |*numeric| numeric.deinit();
        self.directory.close();
    }
    fn persistNode(self: *Collector, index: usize, owner: *const C.PoseidonContext, key: Keys.Ref, output: Fold.Digest) !Node {
        var recorder = E.stage_profile.Recorder.initWithOptions(self.a, "cpu", "op_direct_native_group_root", .{ .capture_tasks = false, .capture_process_usage = true });
        defer recorder.deinit();
        var timer = try std.time.Timer.start();
        const bytes = try key.prove(self.a, owner, &output, &recorder);
        errdefer self.a.free(bytes);
        const name = try std.fmt.allocPrint(self.a, "node-{d}.bin", .{index});
        defer self.a.free(name);
        try Write(self.directory, name, bytes);
        var stages = try recorder.snapshot(self.a);
        defer stages.deinit(self.a);
        const json = try std.json.Stringify.valueAlloc(self.a, stages, .{});
        defer self.a.free(json);
        const stage_name = try std.fmt.allocPrint(self.a, "node-{d}-stages.json", .{index});
        defer self.a.free(stage_name);
        try Write(self.directory, stage_name, json);
        var captured = try key.verifyCaptured(self.a, &output, bytes);
        errdefer captured.deinit(self.a);
        std.debug.print("OP_NATIVE_GROUP_NODE index={} span={any} bytes={} prove_persist_verify_ns={}\n", .{ index, self.plan.?.nodes[index].span, bytes.len, timer.read() });
        return .{ .key = key, .output = output, .bytes = bytes, .captured = captured };
    }
    fn fragment(raw: ?*anyopaque, a: std.mem.Allocator, value: Receiver.Verified) !void {
        const self: *Collector = @ptrCast(@alignCast(raw.?));
        if (self.plan == null) self.plan = try Planner.Plan.init(@intCast(value.manifest.entries.len), self.maximum);
        if (self.seen != value.ordinal) return error.NativeGroupSourceCoverage;
        try Adapter.visit(a, value, .{ .context = self, .visit = append });
    }
    fn append(raw: *anyopaque, _: std.mem.Allocator, member: Captured.View) !void {
        const self: *Collector = @ptrCast(@alignCast(raw));
        if (member.ordinal() != self.seen or member.profile() != self.profile) return error.NativeGroupSourceAuthority;
        if (self.manifest) |manifest| {
            if (!std.mem.eql(u8, &manifest, &member.manifest())) return error.NativeGroupSourceAuthority;
        } else self.manifest = member.manifest();
        const plan = &self.plan.?;
        if (self.source == null) {
            while (self.group_node < plan.node_count and plan.nodes[self.group_node].operation != .group) self.group_node += 1;
            if (self.group_node >= plan.node_count) return error.NativeGroupSourceCoverage;
            const span = plan.nodes[self.group_node].span;
            if (span.first != self.seen) return error.NativeGroupSourceCoverage;
            self.source = try Keys.Stream.init(self.a, true, span.first, span.count, self.profile, self.manifest.?, self.arithmetization);
            if (self.prove_groups) self.numeric = try Keys.Stream.init(self.a, false, span.first, span.count, self.profile, self.manifest.?, self.arithmetization);
        }
        try self.leaves.ensureUnusedCapacity(self.a, 1);
        self.leaves.appendAssumeCapacity(try Adapter.metadata(self.a, member));
        if (try Adapter.template(self.a, member)) |shape| {
            errdefer self.a.free(shape);
            try self.templates.append(self.a, shape);
        }
        try self.source.?.append(member);
        if (self.numeric) |*numeric| try numeric.append(member);
        self.seen += 1;
        if (self.source.?.base().appended == self.source.?.base().count) {
            try self.groups.ensureUnusedCapacity(self.a, 1);
            const group = try self.a.create(Topology.Group);
            var transferred = false;
            errdefer if (!transferred) self.a.destroy(group);
            const header = self.source.?.base();
            const bindings = header.bindings;
            var model: Cost = undefined;
            group.* = .{ .key = try Keys.Owner.fromSelectedStreamWithCost(self.a, &self.source.?, if (self.group_node == plan.root) self.terminal_outer_profile else self.profile, &model), .span = plan.nodes[self.group_node].span, .profile = self.profile, .manifest = self.manifest.?, .bindings = bindings };
            std.debug.print("OP_NATIVE_GROUP_SOURCE span={any} model={any}\n", .{ plan.nodes[self.group_node].span, model });
            self.groups.appendAssumeCapacity(group);
            transferred = true;
            if (self.numeric) |*numeric| {
                const output = try numeric.expectedOutput();
                var owner = try numeric.finish();
                defer owner.deinit();
                if (!std.meta.eql(model, try Cost.derive(&owner, self.arithmetization))) return error.NativeGroupSourceAuthority;
                self.nodes[self.group_node] = try self.persistNode(self.group_node, &owner, group.key.ref(), output);
                numeric.deinit();
                self.numeric = null;
            }
            group.retireProverData();
            self.source.?.deinit();
            self.source = null;
            self.group_node += 1;
        }
    }
    fn complete(raw: ?*anyopaque, _: std.mem.Allocator, source: Runtime.SourceDirectory, closed: *const Receiver.Closed) !void {
        const self: *Collector = @ptrCast(@alignCast(raw.?));
        if (self.completed or self.seen != source.inventory.workers.len or self.source != null or self.numeric != null or self.manifest == null or !std.mem.eql(u8, &closed.pending.digest, &self.manifest.?)) return error.NativeGroupSourceCoverage;
        const metadata = Metadata{ .arithmetization = if (self.arithmetization == .r6) null else self.arithmetization, .terminal_outer_profile = if (self.terminal_outer_profile == self.profile) null else self.terminal_outer_profile, .profile = self.profile, .maximum_group = self.maximum, .statement = .{ .execution = source.inventory.execution, .manifest = self.manifest.?, .leaves = self.leaves.items } };
        var prepared = try A.prepare(self.a, authority(source), metadata.statement);
        defer prepared.deinit();
        const json = try metadataJson(self.a, metadata);
        defer self.a.free(json);
        const templates = try Templates.encode(self.a, self.templates.items);
        defer self.a.free(templates);
        try Write(self.directory, "root.json", json);
        try Write(self.directory, "templates.bin", templates);
        if (!self.prove_groups) {
            self.completed = true;
            return;
        }
        self.topology = try Topology.Topology.beginWithPolicy(self.a, source.inventory, &prepared, self.maximum, self.groups.items, self.terminal_outer_profile, self.arithmetization);
        for (self.plan.?.ordered(), 0..) |node, index| if (node.operation == .fold) {
            const edge = node.operation.fold;
            const left = if (self.nodes[edge.left]) |*value| value else return error.NativeGroupSourceCoverage;
            const right = if (self.nodes[edge.right]) |*value| value else return error.NativeGroupSourceCoverage;
            var owner = switch (self.arithmetization) {
                .r6 => blk: {
                    if (left.key != .r6 or right.key != .r6 or left.captured != .r6 or right.captured != .r6) return error.NativeGroupArithmetizationPolicy;
                    break :blk try (Fold.Source{ .children = .{ .{ .key = left.key.r6, .verified = &left.captured.r6, .output = left.output }, .{ .key = right.key.r6, .verified = &right.captured.r6, .output = right.output } } }).buildForProving(self.a);
                },
                .r7 => try (@import("../native_dot/fold.zig").Source{ .children = .{ .{ .key = left.key, .verified = left.captured.borrow(), .output = left.output }, .{ .key = right.key, .verified = right.captured.borrow(), .output = right.output } } }).buildCanonicalTreeForProving(self.a),
            };
            defer owner.deinit();
            const key = try self.topology.?.deriveFold(index, true);
            self.nodes[index] = try self.persistNode(index, &owner, key.ref(), try Fold.digest(left.output, right.output));
            key.retireProverData();
        };
        try self.topology.?.requireComplete();
        const root = self.nodes[self.plan.?.root] orelse return error.NativeGroupSourceCoverage;
        if (!std.meta.eql(root.output, try prepared.expectedRoot())) return error.NativeGroupOutputMismatch;
        try self.topology.?.verify(source.inventory, &prepared, root.bytes);
        // The complete root is published only after native/global/terminal
        // closure, independent source obligations and physical root acceptance.
        try Write(self.directory, "root.bin", root.bytes);
        try std.posix.fsync(self.directory.fd);
        self.completed = true;
    }
};
pub fn produce(a: std.mem.Allocator, config: Config, native_path: []const u8, out: []const u8, profile: Profile, resources: Runtime.Resources, maximum_group: u32, physical: bool) !void {
    return produceWithOptions(a, config, native_path, out, profile, resources, maximum_group, physical, .{});
}
pub fn produceWithOptions(a: std.mem.Allocator, config: Config, native_path: []const u8, out: []const u8, profile: Profile, resources: Runtime.Resources, maximum_group: u32, physical: bool, options: Options) !void {
    const terminal_outer_profile = try options.resolve(profile);
    _ = try Planner.Plan.init(1, maximum_group);
    if (!E.host_budget_allocator.SharedHostBudget.isAllocator(a)) return error.OpNativeRequiresSharedHostBudget;
    try std.fs.cwd().makeDir(out);
    var state = Collector{ .arithmetization = options.arithmetization, .terminal_outer_profile = terminal_outer_profile, .a = a, .directory = try std.fs.cwd().openDir(out, .{}), .maximum = maximum_group, .profile = profile, .prove_groups = physical };
    defer state.deinit();
    try Runtime.verifyDirectoryWithHooks(a, config, native_path, profile, resources, .{ .context = &state, .complete = Collector.complete, .fragments = .{ .context = &state, .fragment = Collector.fragment } });
    if (!state.completed) return error.NativeGroupSourceCoverage;
}
const SourceCollector = struct {
    a: std.mem.Allocator,
    plan: Planner.Plan,
    profile: Profile,
    manifest: [36]u8,
    terminal_outer_profile: Profile,
    arithmetization: Keys.Format,
    next_node: usize = 0,
    seen: u32 = 0,
    stream: ?Keys.Stream = null,
    groups: std.ArrayList(*Topology.Group) = .empty,
    fn deinit(self: *SourceCollector) void {
        if (self.stream) |*stream| stream.deinit();
        for (self.groups.items) |group| {
            group.deinit();
            self.a.destroy(group);
        }
        self.groups.deinit(self.a);
    }
    fn append(raw: *anyopaque, _: std.mem.Allocator, member: Captured.View) !void {
        const self: *SourceCollector = @ptrCast(@alignCast(raw));
        if (member.ordinal() != self.seen) return error.NativeGroupSourceCoverage;
        if (self.stream == null) {
            while (self.next_node < self.plan.node_count and self.plan.nodes[self.next_node].operation != .group) self.next_node += 1;
            if (self.next_node >= self.plan.node_count) return error.NativeGroupSourceCoverage;
            const span = self.plan.nodes[self.next_node].span;
            self.stream = try Keys.Stream.init(self.a, true, span.first, span.count, self.profile, self.manifest, self.arithmetization);
        }
        try self.stream.?.append(member);
        self.seen += 1;
        if (self.stream.?.base().appended == self.stream.?.base().count) {
            try self.groups.ensureUnusedCapacity(self.a, 1);
            const group = try self.a.create(Topology.Group);
            var transferred = false;
            errdefer if (!transferred) self.a.destroy(group);
            group.* = try Topology.Group.initSelectedWithOuterProfile(self.a, &self.stream.?, if (self.next_node == self.plan.root) self.terminal_outer_profile else self.profile);
            group.retireProverData();
            self.groups.appendAssumeCapacity(group);
            transferred = true;
            self.stream.?.deinit();
            self.stream = null;
            self.next_node += 1;
        }
    }
};
const Reception = struct {
    path: []const u8,
    maximum: u32,
    profile: Profile,
    terminal_outer_profile: Profile,
    arithmetization: Keys.Format,
    passed: bool = false,
    adversarial: bool = false,
    controls: u32 = 0,
    fn run(raw: ?*anyopaque, a: std.mem.Allocator, source: Runtime.SourceDirectory) !void {
        const self: *Reception = @ptrCast(@alignCast(raw.?));
        var dir = try std.fs.cwd().openDir(self.path, .{});
        defer dir.close();
        const json = try dir.readFileAlloc(a, "root.json", 4 << 20);
        defer a.free(json);
        const parsed = try std.json.parseFromSlice(Metadata, a, json, .{});
        defer parsed.deinit();
        const metadata = parsed.value;
        if (metadata.schema != 1 or !std.mem.eql(u8, metadata.format, "op-direct-native-group-root/v1") or metadata.profile != self.profile or metadata.maximum_group != self.maximum or (metadata.terminal_outer_profile orelse metadata.profile) != self.terminal_outer_profile or (metadata.arithmetization orelse .r6) != self.arithmetization) return error.NativeGroupReceiverPolicy;
        var timer = try std.time.Timer.start();
        var prepared = try A.prepare(a, authority(source), metadata.statement);
        defer prepared.deinit();
        const shape_bytes = try dir.readFileAlloc(a, "templates.bin", Templates.MAX_BYTES);
        defer a.free(shape_bytes);
        var templates = try Walk.decodeTemplates(a, authority(source), shape_bytes);
        defer templates.deinit(a);
        var collector = SourceCollector{ .arithmetization = self.arithmetization, .terminal_outer_profile = self.terminal_outer_profile, .a = a, .plan = try Planner.Plan.init(@intCast(source.inventory.workers.len), self.maximum), .profile = self.profile, .manifest = prepared.manifest };
        defer collector.deinit();
        try Walk.visit(a, authority(source), &prepared, metadata.statement, &templates, .{ .context = &collector, .visit = SourceCollector.append });
        if (collector.seen != source.inventory.workers.len or collector.stream != null) return error.NativeGroupSourceCoverage;
        var topology = try Topology.Topology.initWithPolicy(a, source.inventory, &prepared, self.maximum, collector.groups.items, self.terminal_outer_profile, self.arithmetization);
        defer topology.deinit();
        const source_ns = timer.lap();
        const bytes = try dir.readFileAlloc(a, "root.bin", 2 << 20);
        defer a.free(bytes);
        try topology.verify(source.inventory, &prepared, bytes);
        const physical_ns = timer.lap();
        if (self.adversarial) self.controls = try @import("root_attacks.zig").run(a, &topology, authority(source), &prepared, metadata.statement, bytes);
        self.passed = true;
        var public_root: [36]u8 = undefined;
        for (try prepared.expectedRoot(), 0..) |word, i| std.mem.writeInt(u32, public_root[4 * i ..][0..4], word.toM31Array()[0].v, .little);
        std.debug.print("OP_NATIVE_GROUP_TERMINAL native={s} outer={s} source_identity={s} canonical_root={s}\n", .{ @tagName(self.profile), @tagName(self.terminal_outer_profile), std.fmt.bytesToHex(topology.rootKey().identity(), .lower), std.fmt.bytesToHex(public_root, .lower) });
        std.debug.print("OP_NATIVE_GROUP_RECEIVER accepted=true execution_only=true leaves={} groups={} folds={} bytes={} source_group_and_fold_key_ns={} physical_root_read_verify_ns={} native_proof_bytes_read=0 production_admission=false\n", .{ collector.seen, collector.groups.items.len, topology.owned.items.len, bytes.len, source_ns, physical_ns });
    }
};
pub fn verify(a: std.mem.Allocator, config: Config, native_source: []const u8, root_path: []const u8, profile: Profile, resources: Runtime.Resources, maximum_group: u32) !void {
    return verifyWithOptions(a, config, native_source, root_path, profile, resources, maximum_group, .{});
}
pub fn verifyWithOptions(a: std.mem.Allocator, config: Config, native_source: []const u8, root_path: []const u8, profile: Profile, resources: Runtime.Resources, maximum_group: u32, options: Options) !void {
    const terminal_outer_profile = try options.resolve(profile);
    _ = try Planner.Plan.init(1, maximum_group);
    try requireReceiverHeader(a, root_path, profile, maximum_group, terminal_outer_profile, options.arithmetization);
    var reception = Reception{ .arithmetization = options.arithmetization, .terminal_outer_profile = terminal_outer_profile, .path = root_path, .maximum = maximum_group, .profile = profile };
    try Runtime.withSourceDirectory(a, config, native_source, profile, resources, &reception, Reception.run);
    if (!reception.passed) return error.NativeGroupSourceCoverage;
}

/// Explicit qualification path; normal verify performs exactly one root check.
pub fn qualify(a: std.mem.Allocator, config: Config, native_source: []const u8, root_path: []const u8, profile: Profile, resources: Runtime.Resources, maximum_group: u32) !u32 {
    return qualifyWithOptions(a, config, native_source, root_path, profile, resources, maximum_group, .{});
}
pub fn qualifyWithOptions(a: std.mem.Allocator, config: Config, native_source: []const u8, root_path: []const u8, profile: Profile, resources: Runtime.Resources, maximum_group: u32, options: Options) !u32 {
    const terminal_outer_profile = try options.resolve(profile);
    _ = try Planner.Plan.init(1, maximum_group);
    try requireReceiverHeader(a, root_path, profile, maximum_group, terminal_outer_profile, options.arithmetization);
    var reception = Reception{ .arithmetization = options.arithmetization, .terminal_outer_profile = terminal_outer_profile, .path = root_path, .maximum = maximum_group, .profile = profile, .adversarial = true };
    try Runtime.withSourceDirectory(a, config, native_source, profile, resources, &reception, Reception.run);
    if (!reception.passed or reception.controls < 6) return error.NativeGroupSourceCoverage;
    return reception.controls;
}

test "native grouped default metadata keeps exact bytes and R7 policy is explicit" {
    const a = std.testing.allocator;
    var metadata = Metadata{ .profile = .op_target_b4_q72_p0_fold4_v1, .maximum_group = 4, .statement = .{ .execution = @splat(0), .manifest = @splat(0), .leaves = &.{} } };
    const legacy = try metadataJson(a, metadata);
    defer a.free(legacy);
    const expected = try std.json.Stringify.valueAlloc(a, .{ .schema = metadata.schema, .format = metadata.format, .profile = metadata.profile, .maximum_group = metadata.maximum_group, .statement = metadata.statement }, .{ .whitespace = .indent_2 });
    defer a.free(expected);
    try std.testing.expectEqualSlices(u8, expected, legacy);
    metadata.terminal_outer_profile = .op_control_b2_q144_p0_fold4_v1;
    const b2 = try metadataJson(a, metadata);
    defer a.free(b2);
    const expected_b2 = try std.json.Stringify.valueAlloc(a, .{ .schema = metadata.schema, .format = metadata.format, .profile = metadata.profile, .maximum_group = metadata.maximum_group, .statement = metadata.statement, .terminal_outer_profile = metadata.terminal_outer_profile }, .{ .whitespace = .indent_2 });
    defer a.free(expected_b2);
    try std.testing.expectEqualSlices(u8, expected_b2, b2);
    metadata.arithmetization = .r7;
    const r7 = try metadataJson(a, metadata);
    defer a.free(r7);
    const parsed = try std.json.parseFromSlice(Metadata, a, r7, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(Keys.Format.r7, parsed.value.arithmetization.?);
}
