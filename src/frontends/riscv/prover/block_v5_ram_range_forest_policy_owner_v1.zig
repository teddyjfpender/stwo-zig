//! Durable actual RAM/range recursive leaves -> minimum closed shard forest
//! -> PAGE+memory join. Native leaf keys come from independent fixed admission;
//! Forest node keys also come from independent compact fixed setup. Receiving
//! staged leaves/nodes constructs no private witness solely to recover a key.
//! The final transition is OPEN for native/caller and remaining global joins.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Catalogue = @import("block_v5_ram_range_forest_catalogue_v1.zig");
const Manifest = @import("block_v5_ram_range_forest_manifest_v1.zig");
const Page = @import("block_v5_memory_source_page_forest_policy_owner_v1.zig");
const PageSource = @import("../recursion/block_v5_memory_source_page_forest_summary_source_v1.zig");
const LiveBudget = @import("block_v5_memory_source_page_forest_live_budget_v1.zig");
const Bundle = @import("block_v5_cpu_bundle_store_v1.zig").ForCapacity(true);
const Lane = @import("block_v5_ram_lanes_receiver_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const A = @import("../recursion/block_v5_ram_range_forest_authority_v1.zig");
const Plan = @import("../recursion/block_v5_ram_range_forest_plan_v1.zig");
const Bus = @import("../recursion/block_v5_ram_range_forest_bus_v1.zig");
const Protocol = @import("../recursion/block_v5_ram_range_forest_protocol_v1.zig");
const Receive = @import("../recursion/block_v5_ram_range_forest_summary_receiver_v1.zig");
const Source = @import("../recursion/block_v5_ram_range_forest_source_v1.zig");
const RowsModule = @import("../recursion/block_v5_ram_range_forest_preparation_v1.zig");
const Rows = RowsModule.ForNode(Receive, Source);
const JoinPublic = @import("../recursion/block_v5_source_ram_forest_join_public_v1.zig");
const JoinRows = @import("../recursion/block_v5_source_ram_forest_join_preparation_v1.zig");
const JoinProtocol = @import("../recursion/block_v5_source_ram_forest_join_protocol_v1.zig");
const JoinReceiver = @import("../recursion/block_v5_source_ram_forest_join_receiver_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
const Templates = @import("block_v5_cpu_recursive_template_derivation_v1.zig");
const WordCache = @import("block_v5_word_expected_setup_cache_v1.zig");
const FixedForest = @import("../recursion/block_v5_ram_range_forest_fixed_assembly_v1.zig");
const FixedKey = @import("../recursion/blake3_parent_fixed_key_v1.zig");
const FixedJoin = @import("../recursion/block_v5_source_ram_forest_join_fixed_assembly_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
pub const Action = union(enum) { publish, reconstruct: Manifest.FilePin };
pub const FileKind = enum { ram, range, node, join };
pub const Limits = struct {
    catalogue: Catalogue.Limits = .{},
    plan: Plan.Limits = .{},
    public: Bus.Limits = .{},
    rows: RowsModule.Limits = .{},
    join_public: JoinPublic.Limits = .{},
    join_rows: JoinRows.Limits = .{},
    manifest: Manifest.Limits = .{},
    max_metadata_bytes: usize = 1 << 30,
    max_live_bytes: usize = 8 << 30,
    max_word_template_metadata_bytes: usize = 64 << 20,
    fixed_memory: FixedForest.Limits = .{},
    fixed_join: FixedJoin.Limits = .{},
    transcript_capacity: u32 = 1 << 24,
    provider: @import("../recursion/block_v5_memory_recursive_provider_source_v1.zig").Limits = .{},
    pub fn validate(self: Limits) !void {
        try self.fixed_memory.validate(self.transcript_capacity);
        try self.fixed_join.validate(self.transcript_capacity);
        if (self.max_metadata_bytes == 0 or self.max_live_bytes == 0 or self.max_word_template_metadata_bytes == 0 or self.transcript_capacity == 0 or self.catalogue.max_leaves == 0 or self.manifest.max_records == 0 or self.manifest.max_bytes == 0 or self.manifest.max_proof_bytes == 0 or self.manifest.max_total_proof_bytes == 0 or self.rows.max_owned_bytes == 0 or self.join_rows.max_owned_bytes == 0 or self.provider.max_words == 0 or self.provider.max_felts == 0 or self.provider.max_steps == 0 or self.provider.max_terms == 0 or self.provider.max_proof_bytes != self.manifest.max_proof_bytes) return error.InvalidRamForestOwnerLimits;
    }
    fn fixedMemoryLimits(self: Limits) FixedForest.Limits {
        var limits = self.fixed_memory;
        limits.max_metadata_bytes = @min(limits.max_metadata_bytes, self.max_metadata_bytes);
        limits.max_live_bytes = @min(limits.max_live_bytes, self.max_live_bytes);
        // One normative supplier recipe serves expected setup and live rows.
        limits.public = self.public;
        limits.public_supply = self.rows.public_supply;
        return limits;
    }
};
/// Structural parity only; original producer admission still checks the live
/// preprocessed commitment against the independently derived expected root.
pub fn requireNodePreparedMetadata(expected: Bus.Spec, context: Base.Context, log_sizes: [@import("../recursion/air/blake3_parent_row_storage.zig").Airs.len]u32, wire_count: usize, profile: Base.Profile) !void {
    if (wire_count != 0 or !std.meta.eql(expected.geometry.profile, profile) or
        !std.meta.eql(expected.geometry.config, profile.config()) or
        !std.meta.eql(expected.geometry.context, context) or
        !std.meta.eql(expected.geometry.log_sizes, log_sizes)) return error.UntrustedRamRangeFixedAssembly;
    const key = try Protocol.Key.fromGeometry(expected.geometry, &.{});
    if (!std.meta.eql(try key.identity(), expected.expected_id)) return error.UntrustedRamRangeFixedAssembly;
}
pub fn filename(buffer: []u8, kind: FileKind, index: u32) ![]const u8 {
    return std.fmt.bufPrint(buffer, "source-memory-recursive-{s}-{d}.b5rmp", .{ @tagName(kind), index });
}
/// Counts advance only after successful exclusive publication. This removes
/// no original/PAGE inputs, pre-existing destination or failed private inode.
pub fn removePublished(dir: std.fs.Dir, ram: usize, range: usize, nodes: usize, joined: bool) void {
    inline for ([_]FileKind{ .ram, .range, .node }, [_]usize{ ram, range, nodes }) |kind, n| {
        for (0..n) |index| {
            var path: [96]u8 = undefined;
            dir.deleteFile(filename(&path, kind, @intCast(index)) catch continue) catch {};
        }
    }
    if (joined) {
        var path: [96]u8 = undefined;
        dir.deleteFile(filename(&path, .join, 0) catch return) catch {};
    }
}
pub const Owner = struct {
    budget: *Budget,
    catalogue: Catalogue.Owned,
    forest: ?A.Owned = null,
    fixed_memory: ?FixedForest.Catalogue = null,
    join_setup: ?*FixedJoin.Owned = null,
    ram: []A.Ram.Policy,
    range: []A.Range.Policy,
    ram_made: usize = 0,
    range_made: usize = 0,
    specs: []Bus.Spec,
    records: []Manifest.Record,
    header: Manifest.Header,
    expected_plan: [32]u8 = @splat(0),
    limits: Limits,
    profile: Base.Profile,
    page: ?Page.Built = null,
    page_source: ?PageSource.Source = null,
    memory_root: ?*Receive.Fresh = null,
    memory_source: ?Source.Source = null,
    join_key: ?JoinProtocol.Key = null,
    manifest_pin: ?Manifest.FilePin = null,
    pub const complete_block_authority = false;
    pub fn nodePolicy(self: *const Owner, index: u32) Receive.Policy {
        return .{ .public = .{ .forest = &self.forest.?, .expected_plan = self.expected_plan, .specs = self.specs, .index = index }, .public_limits = self.limits.public, .max_proof_bytes = self.limits.manifest.max_proof_bytes };
    }
    pub fn joinPolicy(self: *const Owner) JoinReceiver.Policy {
        return .{ .public = .{ .source = &self.page_source.?, .memory = &self.forest.?, .expected_memory_plan = self.expected_plan, .aggregate = if (self.memory_source) |*s| s else null }, .key = self.join_key.?, .expected_id = self.records[self.records.len - 1].expected_id, .schedule = &.{}, .public_limits = self.limits.join_public, .max_proof_bytes = self.limits.manifest.max_proof_bytes };
    }
    pub fn deinit(self: *Owner) void {
        const budget = self.budget;
        const a = budget.allocator();
        if (self.join_setup) |fixed| fixed.deinit();
        if (self.memory_source) |*s| s.deinit();
        if (self.page_source) |*s| s.deinit();
        if (self.memory_root) |fresh| fresh.deinit();
        if (self.fixed_memory) |*fixed| fixed.deinit();
        if (self.forest) |*f| f.deinit();
        for (self.ram[0..self.ram_made]) |p| a.free(p.schedule);
        for (self.range[0..self.range_made]) |p| a.free(p.schedule);
        a.free(self.ram);
        a.free(self.range);
        a.free(self.specs);
        a.free(self.records);
        self.catalogue.deinit();
        if (self.page) |*page| page.deinit();
        a.destroy(self);
        budget.destroy();
    }
};
pub const Built = struct {
    owner: *Owner,
    join: *JoinReceiver.Fresh,
    pub const complete_block_authority = false;
    pub fn deinit(self: *Built) void {
        self.join.deinit();
        self.owner.deinit();
        self.* = undefined;
    }
};
fn create(backing: std.mem.Allocator, memory: Lane.Pins, sealed: Seal.Sealed, page: *const Page.Built, profile: Base.Profile, limits: Limits) !*Owner {
    try limits.validate();
    try page.owner.require(page.owner.expected_policy);
    if (page.root == null) return error.AbsentPageForestSourceRoot;
    if (!std.meta.eql(profile.config(), memory.seal.config)) return error.UntrustedRamForestOwnerSecurity;
    if (!std.meta.eql(limits.catalogue.ram.proof, memory.limits.proof) or !std.meta.eql(limits.plan.lane, memory.limits.plan)) return error.UntrustedRamForestOwnerLimits;
    const budget = try Budget.createRetainingParent(backing, limits.max_metadata_bytes);
    errdefer budget.destroy();
    const a = budget.allocator();
    var catalogue = try Catalogue.Owned.init(a, memory, sealed, limits.catalogue);
    errdefer catalogue.deinit();
    var ranges = try @import("block_v5_ram_lanes_plan_v1.zig").rangePlan(a, catalogue.memory.pins, memory.expected_total_events, limits.plan.lane);
    defer ranges.deinit(a);
    var geometry = try Plan.derive(a, catalogue.memory.pins, &ranges, limits.plan);
    defer geometry.deinit();
    const ram = try a.alloc(A.Ram.Policy, catalogue.ram.len);
    errdefer a.free(ram);
    const range = try a.alloc(A.Range.Policy, catalogue.range.len);
    errdefer a.free(range);
    const specs = try a.alloc(Bus.Spec, geometry.nodes.len);
    errdefer a.free(specs);
    const record_count = try std.math.add(usize, try std.math.add(usize, try std.math.add(usize, ram.len, range.len), specs.len), 1);
    const header = Manifest.Header{ .ram = @intCast(ram.len), .range = @intCast(range.len), .nodes = @intCast(specs.len), .seal = sealed.digest, .memory_plan = memory.seal.memory_plan_digest, .page_owner = page.owner.identity };
    if (record_count > limits.manifest.max_records or try Manifest.requiredBytes(header) > limits.manifest.max_bytes) return error.RamForestManifestLimit;
    const records = try a.alloc(Manifest.Record, record_count);
    errdefer a.free(records);
    const self = try a.create(Owner);
    self.* = .{ .budget = budget, .catalogue = catalogue, .ram = ram, .range = range, .specs = specs, .records = records, .header = header, .limits = limits, .profile = profile };
    return self;
}
fn bytesFor(comptime Backend: type, comptime ProtocolType: type, a: std.mem.Allocator, dir: std.fs.Dir, path: []const u8, proposed: ?Manifest.Record, prepared: anytype, admission: anytype, maximum: usize) ![]u8 {
    // Independent metadata/key derivation has completed. Both publication and
    // reconstruction release one-shot source columns before fresh verification.
    defer prepared.rows.releaseRows();
    if (proposed) |received| {
        try Manifest.requireDerived(received, try admission.key.identity());
        return Files.readPinned(a, dir, path, received.file.byte_len, received.file.sha256, maximum);
    }
    const Producer = @import("../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Backend, ProtocolType);
    const producer = try Producer.init(a, &prepared.rows, admission);
    defer producer.deinit();
    var workspace = @import("../recursion/blake3_native_parent_producer.zig").Workspace.init(a, 0);
    defer workspace.deinit();
    var proof = try producer.proveConsumingWithWorkspace(a, &prepared.rows, &workspace);
    defer proof.deinit();
    const encoded = try Parent.codec.encode(a, &proof, &admission);
    errdefer a.free(encoded);
    if (encoded.len == 0 or encoded.len > maximum) return error.RamForestOwnerProofLimit;
    return encoded;
}
fn acceptRecord(self: *Owner, position: usize, bytes: []const u8, expected_id: [32]u8, total: *u64) !void {
    total.* = try std.math.add(u64, total.*, bytes.len);
    if (total.* > self.limits.manifest.max_total_proof_bytes) return error.RamForestOwnerProofLimit;
    self.records[position] = .{ .file = .{ .byte_len = bytes.len, .sha256 = Files.hash(bytes) }, .expected_id = expected_id };
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        /// original_store is a fresh strict capacity Bundle reader. The one-shot
        /// reader consumes originals once; retry uses a newly admitted reader.
        /// page transfers only on success. Original files are never removed.
        pub fn build(backing: std.mem.Allocator, dir: std.fs.Dir, original_store: *Bundle.Store, memory: Lane.Pins, sealed: Seal.Sealed, page: *Page.Built, profile: Base.Profile, limits: Limits, action: Action) !Built {
            try limits.validate();
            if (original_store.mode != .reader or !std.meta.eql(original_store.config, memory.seal.config)) return error.UntrustedRamForestBaseReader;
            const self = try create(backing, memory, sealed, page, profile, limits);
            errdefer self.deinit();
            const a = self.budget.allocator();
            var received: ?Manifest.Owned = null;
            defer if (received) |*manifest| manifest.deinit();
            if (action == .reconstruct) {
                received = try Manifest.read(a, dir, action.reconstruct, limits.manifest);
                if (!std.meta.eql(received.?.header, self.header)) return error.UntrustedRamForestManifest;
            }
            var published_ram: usize = 0;
            var published_range: usize = 0;
            var published_node: usize = 0;
            var published_join = false;
            errdefer if (action == .publish) removePublished(dir, published_ram, published_range, published_node, published_join);
            var total: u64 = 0;
            inline for ([_]@import("../recursion/block_v5_memory_recursive_provider_source_v1.zig").Kind{ .ram, .range }) |kind| {
                const Capture = if (kind == .ram) @import("block_v5_ram_lanes_recursive_capture_v1.zig") else @import("block_v5_range16_recursive_capture_v1.zig");
                const LeafBus = if (kind == .ram) @import("../recursion/block_v5_ram_lanes_recursive_public_bus_v1.zig") else @import("../recursion/block_v5_range16_recursive_public_bus_v1.zig");
                const LeafProtocol = if (kind == .ram) @import("../recursion/block_v5_reusable_ram_lanes_parent_protocol_v1.zig") else @import("../recursion/block_v5_reusable_range16_parent_protocol_v1.zig");
                const Providers = @import("../recursion/block_v5_memory_recursive_provider_source_v1.zig").ForKind(kind);
                const admissions = if (kind == .ram) self.catalogue.ram else self.catalogue.range;
                const policies = if (kind == .ram) self.ram else self.range;
                var expected_cache = try WordCache.ForFamily(if (kind == .ram) .ram_lanes else .range16, Backend).init(a, limits.max_word_template_metadata_bytes);
                defer expected_cache.deinit();
                for (admissions, policies, 0..) |*admitted, *policy, index| {
                    const live = try LiveBudget.create(backing, self.budget, limits.max_live_bytes);
                    defer live.destroy();
                    const scratch = live.allocator();
                    // No original proof, private capture or MAIN witness can
                    // select this expected key. Fixed setup is released here
                    // before decoding and verifying the original proof below.
                    const expected = try expected_cache.get(scratch, admitted, profile, limits.transcript_capacity);
                    var reader = Bundle.ProofReader{ .store = original_store, .a = scratch };
                    var original = try reader.take(if (kind == .ram) .ram_lanes else .range16, @intCast(index));
                    var owns_original = true;
                    defer if (owns_original) original.deinit(scratch);
                    var capture = try Capture.ForBackend(Backend).verifyBorrowed(scratch, &original, admitted);
                    var owns_capture = true;
                    defer if (owns_capture) capture.deinit();
                    // Real capture owns the original opened PCS verifier data;
                    // the decoded original proof allocation is no longer held.
                    original.deinit(scratch);
                    owns_original = false;
                    const receipt = capture.receipt;
                    const key = expected.key;
                    const id = expected.key_id;
                    const schedule = try a.dupe(LeafBus.Wire, expected.schedule);
                    errdefer a.free(schedule);
                    const proposed = Providers.Policy{ .admitted = admitted, .proposal = receipt, .key = key, .expected_id = id, .schedule = schedule, .limits = limits.provider };
                    const authority = try proposed.authority();
                    const position = if (kind == .ram) index else self.ram.len + index;
                    var path: [96]u8 = undefined;
                    const name = try filename(&path, if (kind == .ram) .ram else .range, @intCast(index));
                    if (action == .reconstruct) {
                        // Independent setup and genuine original receipt are
                        // sufficient for fresh recursive verification. There
                        // is no reason to construct a private verifier witness
                        // when this process is not producing another proof.
                        capture.deinit();
                        owns_capture = false;
                        const record = received.?.records[position];
                        try Manifest.requireDerived(record, id);
                        const bytes = try Files.readPinned(scratch, dir, name, record.file.byte_len, record.file.sha256, limits.manifest.max_proof_bytes);
                        defer scratch.free(bytes);
                        const fresh = try Providers.verify(scratch, proposed, bytes);
                        defer fresh.deinit();
                        try acceptRecord(self, position, bytes, id, &total);
                        policy.* = proposed;
                        if (kind == .ram) self.ram_made += 1 else self.range_made += 1;
                        continue;
                    }
                    var rows = try LeafBus.prepare(scratch, admitted, &capture, limits.transcript_capacity);
                    var owns_rows = true;
                    defer if (owns_rows) rows.deinit();
                    capture.deinit();
                    owns_capture = false;
                    try Templates.requirePolicyRows(if (kind == .ram) .ram_lanes else .range16, expected.*, &rows, profile);
                    const bytes = try bytesFor(Backend, LeafProtocol, scratch, dir, name, if (received) |r| r.records[position] else null, &rows.recursive, authority, limits.manifest.max_proof_bytes);
                    defer scratch.free(bytes);
                    rows.deinit();
                    owns_rows = false;
                    const fresh = try Providers.verify(scratch, proposed, bytes);
                    defer fresh.deinit();
                    try acceptRecord(self, position, bytes, id, &total);
                    if (action == .publish) {
                        try Files.publish(dir, name, bytes);
                        if (kind == .ram) published_ram += 1 else published_range += 1;
                    }
                    policy.* = proposed;
                    if (kind == .ram) self.ram_made += 1 else self.range_made += 1;
                }
            }
            self.forest = try A.Owned.init(a, self.catalogue.memory, sealed, self.ram, self.range, limits.plan);
            self.expected_plan = self.forest.?.identity;
            if (self.forest.?.geometry.nodes.len != self.specs.len) return error.UntrustedRamForestRoster;
            // Fixed setup metadata/live lanes are siblings under the caller's
            // aggregate budget. Large fixed columns must not consume Owner's
            // much smaller metadata-only cap.
            self.fixed_memory = try FixedForest.ForBackend(Backend).derive(backing, &self.forest.?, self.expected_plan, limits.transcript_capacity, profile, limits.fixedMemoryLimits());
            const fixed_forest = &self.fixed_memory.?;
            const expected_fixed_forest = fixed_forest.independently_expected;
            @memcpy(self.specs, fixed_forest.specs);
            for (self.forest.?.geometry.nodes, 0..) |node, index| {
                const live = try LiveBudget.create(backing, self.budget, limits.max_live_bytes);
                defer live.destroy();
                const scratch = live.allocator();
                try fixed_forest.requireSelected(@intCast(index), expected_fixed_forest);
                const expected = fixed_forest.specs[index];
                const position = self.ram.len + self.range.len + index;
                var node_path: [96]u8 = undefined;
                const node_name = try filename(&node_path, .node, @intCast(index));
                if (action == .reconstruct) {
                    const record = received.?.records[position];
                    try Manifest.requireDerived(record, expected.expected_id);
                    const bytes = try Files.readPinned(scratch, dir, node_name, record.file.byte_len, record.file.sha256, limits.manifest.max_proof_bytes);
                    defer scratch.free(bytes);
                    const fresh = try Receive.verify(scratch, self.nodePolicy(@intCast(index)), bytes);
                    var transfer = false;
                    defer if (!transfer) fresh.deinit();
                    try acceptRecord(self, position, bytes, expected.expected_id, &total);
                    if (self.forest.?.geometry.root == @as(u32, @intCast(index))) {
                        self.memory_root = fresh;
                        transfer = true;
                    }
                    continue;
                }
                var captures: [4]Rows.Capture = undefined;
                var made: usize = 0;
                defer for (captures[0..made]) |capture| switch (capture) {
                    .ram => |v| @constCast(v).deinit(),
                    .range => |v| @constCast(v).deinit(),
                    .node => |v| @constCast(v).deinit(),
                };
                for (node.children[0..node.child_count], 0..) |ref, ordinal| {
                    const child_position = switch (ref) {
                        .ram => |i| i,
                        .range => |i| self.ram.len + i,
                        .node => |i| self.ram.len + self.range.len + i,
                    };
                    var path: [96]u8 = undefined;
                    const name = switch (ref) {
                        .ram => |i| try filename(&path, .ram, i),
                        .range => |i| try filename(&path, .range, i),
                        .node => |i| try filename(&path, .node, i),
                    };
                    const pin = self.records[child_position].file;
                    const bytes = try Files.readPinned(scratch, dir, name, pin.byte_len, pin.sha256, limits.manifest.max_proof_bytes);
                    defer scratch.free(bytes);
                    captures[ordinal] = switch (ref) {
                        .ram => |i| .{ .ram = try A.Ram.verify(scratch, self.forest.?.ram[i], bytes) },
                        .range => |i| .{ .range = try A.Range.verify(scratch, self.forest.?.range[i], bytes) },
                        .node => |i| .{ .node = try Receive.verify(scratch, self.nodePolicy(i), bytes) },
                    };
                    made += 1;
                }
                var public = try Bus.Owner.prepareSources(scratch, self.nodePolicy(@intCast(index)).public, limits.public);
                var owns_public = true;
                defer if (owns_public) public.deinit();
                var rows = try Rows.prepare(scratch, &public, captures[0..made], limits.transcript_capacity, limits.rows);
                var owns_rows = true;
                defer if (owns_rows) rows.deinit();
                // Public owns independently normalized policy frames. The
                // emitted rows/context retain no pointers to these captures.
                for (captures[0..made]) |capture| switch (capture) {
                    .ram => |v| @constCast(v).deinit(),
                    .range => |v| @constCast(v).deinit(),
                    .node => |v| @constCast(v).deinit(),
                };
                made = 0;
                try rows.recursive.rows.partitionHashRows();
                try requireNodePreparedMetadata(expected, rows.recursive.context, try FixedKey.rowLogs(rows.recursive.rows.fixed), rows.wires.len, profile);
                const key = try Protocol.Key.fromGeometry(expected.geometry, &.{});
                const authority = try Protocol.Admission.init(key, self.specs[index].expected_id, &.{}, .{ .public = &public });
                const bytes = try bytesFor(Backend, Protocol, scratch, dir, node_name, null, &rows.recursive, authority, limits.manifest.max_proof_bytes);
                defer scratch.free(bytes);
                rows.deinit();
                owns_rows = false;
                public.deinit();
                owns_public = false;
                const fresh = try Receive.verify(scratch, self.nodePolicy(@intCast(index)), bytes);
                var transfer = false;
                defer if (!transfer) fresh.deinit();
                try acceptRecord(self, position, bytes, self.specs[index].expected_id, &total);
                if (action == .publish) {
                    try Files.publish(dir, node_name, bytes);
                    published_node += 1;
                }
                if (self.forest.?.geometry.root == @as(u32, @intCast(index))) {
                    self.memory_root = fresh;
                    transfer = true;
                }
            }
            self.page_source = try PageSource.Source.init(a, page.root.?);
            if (self.memory_root) |fresh| self.memory_source = try Source.Source.init(a, fresh);
            const page_fixed = if (page.owner.fixed_catalogue) |*fixed| fixed else return error.MissingIndependentPageForestFixedSetup;
            var join_limits = limits.fixed_join;
            join_limits.max_metadata_bytes = @min(join_limits.max_metadata_bytes, limits.max_metadata_bytes);
            join_limits.max_live_bytes = @min(join_limits.max_live_bytes, limits.max_live_bytes);
            join_limits.page = page_fixed.limits;
            join_limits.memory = fixed_forest.limits;
            join_limits.public = limits.join_public;
            join_limits.public_supply = limits.join_rows.public_supply;
            self.join_setup = try FixedJoin.ForBackend(Backend).deriveFromCatalogues(backing, page_fixed, page.owner.independently_expected_catalogue, fixed_forest, expected_fixed_forest, limits.transcript_capacity, profile, join_limits);
            // The expected key/frame and authentic lower catalogue custody are
            // retained for FINAL22; no lower fixed columns overlap live rows.
            try self.join_setup.?.releaseFixedRows();
            const live = try LiveBudget.create(backing, self.budget, limits.max_live_bytes);
            defer live.destroy();
            const scratch = live.allocator();
            const public_policy = JoinPublic.Policy{ .source = &self.page_source.?, .memory = &self.forest.?, .expected_memory_plan = self.expected_plan, .aggregate = if (self.memory_source) |*s| s else null };
            var public = try JoinPublic.Owner.init(scratch, public_policy, limits.join_public);
            var owns_public = true;
            defer if (owns_public) public.deinit();
            const key = self.join_setup.?.key;
            self.join_key = key;
            const id = try key.identity();
            const authority = try JoinProtocol.Admission.init(key, id, &.{}, .{ .public = &public });
            const position = self.records.len - 1;
            var path: [96]u8 = undefined;
            const name = try filename(&path, .join, 0);
            const bytes = prepared: {
                if (received) |proposal| {
                    const record = proposal.records[position];
                    try Manifest.requireDerived(record, id);
                    break :prepared try Files.readPinned(scratch, dir, name, record.file.byte_len, record.file.sha256, limits.manifest.max_proof_bytes);
                }
                var rows = try JoinRows.prepare(scratch, &public, limits.transcript_capacity, limits.join_rows);
                defer rows.deinit();
                try rows.recursive.rows.partitionHashRows();
                if (rows.wires.len != 0 or !std.meta.eql(key.context, rows.recursive.context) or
                    !std.meta.eql(key.log_sizes, try FixedKey.rowLogs(rows.recursive.rows.fixed))) return error.UntrustedSourceRamFixedSetup;
                break :prepared try bytesFor(Backend, JoinProtocol, scratch, dir, name, null, &rows.recursive, authority, limits.manifest.max_proof_bytes);
            };
            defer scratch.free(bytes);
            try acceptRecord(self, position, bytes, id, &total);
            public.deinit();
            owns_public = false;
            const fresh = try JoinReceiver.verify(scratch, self.joinPolicy(), bytes);
            errdefer fresh.deinit();
            if (action == .publish) {
                try Files.publish(dir, name, bytes);
                published_join = true;
            }
            try Manifest.require(self.header, self.records, limits.manifest);
            const manifest_bytes = try Manifest.encode(a, self.header, self.records, limits.manifest);
            defer a.free(manifest_bytes);
            self.manifest_pin = .{ .byte_len = manifest_bytes.len, .sha256 = Files.hash(manifest_bytes) };
            if (action == .publish) try Files.publish(dir, Manifest.NAME, manifest_bytes) else if (!std.meta.eql(self.manifest_pin.?, action.reconstruct)) return error.UntrustedRamForestManifest;
            // All escaped captures retain their scratch budget. Sources borrow
            // only stable heap owners; final join dies before these originals.
            self.page = page.*;
            page.* = undefined;
            return .{ .owner = self, .join = fresh };
        }
    };
}
