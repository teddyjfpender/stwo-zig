//! Actual requester PUBLIC21 -> source, durable PAGE+RAM VERSION20 -> source,
//! genuine two-child FINAL22 publisher and standalone fresh verifier. No file
//! selects a verifier key and no ClosedBlock token/default activation exists.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Live = @import("block_v5_memory_source_page_forest_live_budget_v1.zig");
const Memory = @import("block_v5_ram_range_forest_policy_owner_v1.zig");
const Manifest = @import("block_v5_cpu_final_job_manifest_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const Scoped = @import("../recursion/block_v5_heterogeneous_scoped_owner_v1.zig");
const Compact = @import("../recursion/block_v5_heterogeneous_scoped_source_v1.zig");
const Requester = @import("../recursion/block_v5_requester_summary_source_v1.zig");
const Public = @import("../recursion/block_v5_requester_public_compensation_v1.zig");
const PublicBus = @import("../recursion/block_v5_requester_public_bus_v1.zig");
const PublicRows = @import("../recursion/block_v5_requester_public_preparation_v1.zig");
const PublicProtocol = @import("../recursion/block_v5_requester_public_protocol_v1.zig");
const PublicReceive = @import("../recursion/block_v5_requester_public_receiver_v1.zig");
const PublicSource = @import("../recursion/block_v5_requester_public_source_v1.zig");
const MemorySource = @import("../recursion/block_v5_source_ram_forest_join_source_v1.zig");
const FinalPublic = @import("../recursion/block_v5_requester_memory_public_v1.zig");
const FinalRows = @import("../recursion/block_v5_requester_memory_preparation_v1.zig");
const FinalProtocol = @import("../recursion/block_v5_requester_memory_protocol_v1.zig");
const FinalReceive = @import("../recursion/block_v5_requester_memory_receiver_v1.zig");
const Windows = @import("block_v5_register_windows_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
const PublicFixed = @import("../recursion/block_v5_requester_public_fixed_assembly_v1.zig");
const FixedKey = @import("../recursion/blake3_parent_fixed_key_v1.zig");
const FinalFixed = @import("../recursion/block_v5_requester_memory_fixed_assembly_v1.zig");
pub const complete_block_authority = false;
pub const Release = struct { context: *anyopaque, call: *const fn (*anyopaque) void };
/// Resource lifecycle only. This gate grants no source or equation authority.
pub const CaptureRelease = struct {
    callback: ?Release,
    released: bool = false,
    pub fn afterPreparation(self: *CaptureRelease) !void {
        if (self.released) return error.RequesterCaptureAlreadyReleased;
        self.released = true;
        if (self.callback) |callback| callback.call(callback.context);
    }
};
/// Lifecycle only: no key/admission/value enters from this callback. Called
/// exactly once, only after actual original verifier/tuple rows are owned.
pub const RequesterInput = struct { source: *const Requester.Source, after_preparation: ?Release = null };
pub const Action = union(enum) { publish, reconstruct: Manifest.FilePin };
pub const Limits = struct {
    max_metadata_bytes: usize = 1 << 30,
    max_live_bytes: usize = 8 << 30,
    transcript_capacity: u32 = 1 << 24,
    max_schedule_terms: usize = 16 << 20,
    public_fields: @import("../recursion/block_v5_global_public_fields_v1.zig").Limits = .{},
    public_rows: PublicRows.Limits = .{},
    public_fixed: PublicFixed.Limits = .{},
    public_source: PublicSource.Limits = .{},
    memory_source: MemorySource.Limits = .{},
    final_public: FinalPublic.Limits = .{},
    final_rows: FinalRows.Limits = .{},
    final_fixed: FinalFixed.Limits = .{},
    files: Manifest.Limits = .{},
    pub fn validate(self: Limits) !void {
        if (self.public_fixed.max_bytes == 0 or self.public_fixed.max_rows_per_cohort == 0 or self.public_fixed.max_rows_per_cohort > 1 << 24) return error.FinalJobResourceLimit;
        if (self.final_fixed.max_owned_bytes == 0 or self.final_fixed.max_setup_bytes == 0 or self.final_fixed.max_rows_per_cohort == 0 or self.final_fixed.max_rows_per_cohort > 1 << 24) return error.FinalJobResourceLimit;
        if (self.max_metadata_bytes == 0 or self.max_live_bytes == 0 or self.transcript_capacity == 0 or self.max_schedule_terms == 0 or self.files.max_manifest_bytes < Manifest.BYTE_LEN or self.files.max_proof_bytes == 0 or self.files.max_total_proof_bytes == 0 or self.public_rows.max_preparation_bytes == 0 or self.public_rows.max_graph_bytes == 0 or self.final_rows.max_owned_bytes == 0 or self.final_public.max_children != 2 or self.public_source.max_terms < self.max_schedule_terms) return error.FinalJobResourceLimit;
    }
};
pub const Selection = struct {
    requester: RequesterInput,
    memory: *Memory.Built,
    windows: Windows.Plan,
    profile: Base.Profile,
    limits: Limits = .{},
};
pub const Owner = struct {
    budget: *Budget,
    requester: Scoped.Borrow,
    /// Borrowed arena facade from stable Scoped.Owner. Never deinit this copy.
    compact: Compact.Source,
    windows: Windows.Plan,
    public: ?Public.Owner = null,
    public_key: ?PublicProtocol.Key = null,
    public_wires: []PublicBus.Wire = &.{},
    public_fresh: ?*PublicReceive.Fresh = null,
    public_source: ?PublicSource.Source = null,
    memory_source: ?MemorySource.Source = null,
    memory: ?Memory.Built = null,
    final_key: ?FinalProtocol.Key = null,
    proposal: Manifest.Proposal,
    manifest_pin: ?Manifest.FilePin = null,
    profile: Base.Profile,
    limits: Limits,
    pub const complete_block_authority = false;
    pub fn finalPolicy(self: *const Owner) FinalReceive.Policy {
        return .{ .public = .{ .expected_requester = self.requester.owner, .requester = &self.public_source.?, .memory = &self.memory_source.? }, .key = self.final_key.?, .expected_id = self.proposal.records[1].expected_id, .schedule = &.{}, .public_limits = self.limits.final_public, .max_proof_bytes = self.limits.files.max_proof_bytes };
    }
    pub fn deinit(self: *Owner) void {
        const budget = self.budget;
        const a = budget.allocator();
        if (self.public_source) |*source| source.deinit();
        if (self.memory_source) |*source| source.deinit();
        if (self.public_fresh) |fresh| fresh.deinit();
        if (self.public) |*public| public.deinit();
        a.free(self.public_wires);
        a.free(self.windows.windows);
        if (self.memory) |*memory| memory.deinit();
        self.requester.deinit();
        a.destroy(self);
        budget.destroy();
    }
};
pub const Built = struct {
    owner: *Owner,
    final: *FinalReceive.Fresh,
    pub const complete_block_authority = false;
    pub fn deinit(self: *Built) void {
        self.final.deinit();
        self.owner.deinit();
        self.* = undefined;
    }
};
fn bindings(requester: *const Scoped.Owner, memory: *const Memory.Built, windows: Windows.Plan) !Manifest.Bindings {
    const original_memory = try memory.join.authority();
    return .{ .requester_context = requester.pinned_context, .source_seal = requester.pins.source, .memory_plan = memory.join.public.policy.expected_memory_plan, .memory_public = try original_memory.publicInputIdentity(), .register_windows = try windows.digest() };
}
fn requireMemoryCustody(memory: *const Memory.Built) !void {
    try memory.join.validate();
    const owner = memory.owner;
    const forest = if (owner.forest) |*value| value else return error.UnpairedFinalJobMemoryCustody;
    const page = if (owner.page_source) |*value| value else return error.UnpairedFinalJobMemoryCustody;
    const policy = memory.join.public.policy;
    const aggregate = if (owner.memory_source) |*value| value else null;
    if (policy.memory != forest or policy.source != page or policy.aggregate != aggregate or
        !std.meta.eql(policy.expected_memory_plan, owner.expected_plan) or owner.records.len == 0 or
        !std.meta.eql(memory.join.policy.expected_id, owner.records[owner.records.len - 1].expected_id) or
        !std.meta.eql(memory.join.policy.key, owner.join_key orelse return error.UnpairedFinalJobMemoryCustody)) return error.UnpairedFinalJobMemoryCustody;
}
/// Copies original validated public endpoints, never reconstructs an endpoint
/// from claims or a received manifest. The caller frees result.windows.
pub fn cloneWindows(a: std.mem.Allocator, original: Windows.Plan) !Windows.Plan {
    try original.validate();
    var result = original;
    result.windows = try a.dupe(Windows.Window, original.windows);
    return result;
}
/// Stable descriptors only. Actual public values and the independently derived
/// template still undergo the original Admission/Parent receiver validation.
pub fn cloneSchedule(a: std.mem.Allocator, original: []const PublicBus.Wire, max_terms: usize) ![]PublicBus.Wire {
    if (max_terms == 0 or original.len > max_terms) return error.FinalJobResourceLimit;
    _ = try PublicBus.scheduleDigest(original);
    return a.dupe(PublicBus.Wire, original);
}
fn create(backing: std.mem.Allocator, selection: Selection) !*Owner {
    try selection.limits.validate();
    try selection.requester.source.validate();
    try requireMemoryCustody(selection.memory);
    const requester = selection.requester.source.owner;
    if (!std.meta.eql(selection.profile.config(), requester.coverage.meta.security.recursive)) return error.UntrustedFinalJobSecurity;
    var lease = try requester.borrow();
    errdefer lease.deinit();
    const budget = try Budget.createRetainingParent(backing, selection.limits.max_metadata_bytes);
    errdefer budget.destroy();
    const a = budget.allocator();
    const windows = try cloneWindows(a, selection.windows);
    errdefer a.free(windows.windows);
    const compact = try requester.source(requester.cohorts.root);
    const independent = try bindings(requester, selection.memory, windows);
    const self = try a.create(Owner);
    self.* = .{ .budget = budget, .requester = lease, .compact = compact, .windows = windows, .proposal = .{ .bindings = independent, .records = undefined }, .profile = selection.profile, .limits = selection.limits };
    return self;
}
fn bytesFor(comptime Backend: type, comptime Protocol: type, a: std.mem.Allocator, dir: std.fs.Dir, path: []const u8, proposed: ?Manifest.Record, prepared: anytype, authority: anytype, cap: usize) ![]u8 {
    defer prepared.rows.releaseRows();
    if (proposed) |record| {
        try Manifest.requireKey(record, try authority.key.identity());
        return Files.readPinned(a, dir, path, record.file.byte_len, record.file.sha256, cap);
    }
    const Factory = @import("../recursion/blake3_native_parent_producer.zig");
    const Producer = Factory.PlanForProtocol(Backend, Protocol);
    const producer = try Producer.init(a, &prepared.rows, authority);
    defer producer.deinit();
    var workspace = Factory.Workspace.init(a, 0);
    defer workspace.deinit();
    var proof = try producer.proveConsumingWithWorkspace(a, &prepared.rows, &workspace);
    defer proof.deinit();
    const bytes = try Parent.codec.encode(a, &proof, &authority);
    errdefer a.free(bytes);
    if (bytes.len == 0 or bytes.len > cap) return error.FinalJobResourceLimit;
    return bytes;
}
fn proofRecord(bytes: []const u8, key_id: [32]u8) Manifest.Record {
    return .{ .file = .{ .byte_len = bytes.len, .sha256 = Files.hash(bytes) }, .expected_id = key_id };
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        /// Scoped catalogue/Assembly/Publication original admission owners stay
        /// external under the checked borrow. memory transfers ONLY success.
        /// A released original requester capture is not restored on failure.
        pub fn build(backing: std.mem.Allocator, dir: std.fs.Dir, selection: Selection, action: Action) !Built {
            try selection.limits.validate();
            // Transport bounds/framing reject before any source capability.
            const received = if (action == .reconstruct) try Manifest.read(backing, dir, action.reconstruct, selection.limits.files) else null;
            const self = try create(backing, selection);
            errdefer self.deinit();
            const meta = self.budget.allocator();
            if (received) |proposal| try Manifest.requireBindings(proposal, self.proposal.bindings);
            var release = CaptureRelease{ .callback = selection.requester.after_preparation };
            var published_public = false;
            var published_final = false;
            errdefer if (action == .publish) Manifest.removePublished(dir, published_public, published_final);
            self.public = try Public.init(meta, self.requester.owner, &self.compact, self.windows, self.limits.public_fields);
            {
                const live = try Live.create(backing, self.budget, self.limits.max_live_bytes);
                defer live.destroy();
                const a = live.allocator();
                // Expected setup consumes independent requester policy and
                // public endpoints, not a received PUBLIC21 proof or capture.
                // Its fixed scratch dies before any private witness is built.
                const key = expected: {
                    var fixed_limits = self.limits.public_fixed;
                    fixed_limits.max_bytes = @min(fixed_limits.max_bytes, self.limits.max_live_bytes);
                    var fixed = try PublicFixed.ForBackend(Backend).deriveKeyAndScheduleForPolicy(a, &self.public.?, self.limits.transcript_capacity, self.profile, fixed_limits);
                    defer fixed.deinit();
                    self.public_wires = try cloneSchedule(meta, fixed.wires, self.limits.max_schedule_terms);
                    break :expected fixed.key;
                };
                const id = try key.identity();
                self.public_key = key;
                const authority = try PublicProtocol.Admission.init(key, id, self.public_wires, .{ .public = &self.public.? });
                const bytes = prepared: {
                    if (received) |proposal| {
                        const record = proposal.records[0];
                        try Manifest.requireKey(record, id);
                        break :prepared try Files.readPinned(a, dir, Manifest.PUBLIC_PROOF, record.file.byte_len, record.file.sha256, self.limits.files.max_proof_bytes);
                    }
                    var rows = try PublicRows.prepare(a, &self.public.?, selection.requester.source, self.limits.transcript_capacity, self.limits.public_rows);
                    defer rows.deinit();
                    // All source/Fresh accesses are complete before releasing
                    // the optional external requester capture.
                    try release.afterPreparation();
                    try rows.recursive.rows.partitionHashRows();
                    if (!std.meta.eql(key.context, rows.recursive.context) or
                        !std.meta.eql(key.log_sizes, try FixedKey.rowLogs(rows.recursive.rows.fixed)) or
                        rows.wires.len != self.public_wires.len) return error.UntrustedRequesterPublicFixedAssembly;
                    for (self.public_wires, rows.wires) |expected, actual| if (!std.meta.eql(expected, actual)) return error.UntrustedRequesterPublicFixedAssembly;
                    // Original producer commits these live columns and admits
                    // exactly the independently derived preprocessed root.
                    break :prepared try bytesFor(Backend, PublicProtocol, a, dir, Manifest.PUBLIC_PROOF, null, &rows.recursive, authority, self.limits.files.max_proof_bytes);
                };
                defer a.free(bytes);
                self.public_fresh = try PublicReceive.verify(a, bytes, .{ .public = &self.public.?, .key = key, .expected_id = id, .wires = self.public_wires, .max_proof_bytes = self.limits.files.max_proof_bytes });
                self.proposal.records[0] = proofRecord(bytes, id);
                if (action == .publish) {
                    try Files.publish(dir, Manifest.PUBLIC_PROOF, bytes);
                    published_public = true;
                }
            }
            self.public_source = try PublicSource.Source.init(meta, self.public_fresh.?, self.limits.public_source);
            self.memory_source = try MemorySource.Source.init(meta, selection.memory.join, self.limits.memory_source);
            const live = try Live.create(backing, self.budget, self.limits.max_live_bytes);
            defer live.destroy();
            const a = live.allocator();
            const policy = FinalPublic.Policy{ .expected_requester = self.requester.owner, .requester = &self.public_source.?, .memory = &self.memory_source.? };
            var public = try FinalPublic.Owner.init(a, policy, self.limits.final_public);
            var owns_public = true;
            defer if (owns_public) public.deinit();
            const memory_setup = selection.memory.owner.join_setup orelse return error.MissingIndependentMemoryRootFixedSetup;
            const key = expected: {
                var fixed_limits = self.limits.final_fixed;
                fixed_limits.max_owned_bytes = @min(fixed_limits.max_owned_bytes, self.limits.max_live_bytes);
                fixed_limits.max_setup_bytes = @min(fixed_limits.max_setup_bytes, self.limits.max_live_bytes);
                fixed_limits.public_setup = self.limits.public_fixed;
                fixed_limits.independent_memory_setup = memory_setup.limits;
                fixed_limits.public_supply = self.limits.final_rows.public_supply;
                var fixed = try FinalFixed.ForBackend(Backend).deriveKeyAndScheduleForAuthenticatedMemory(a, &public, self.limits.transcript_capacity, self.profile, fixed_limits, memory_setup);
                defer fixed.deinit();
                if (fixed.wires.len != 0) return error.ClosedRequesterMemoryHasNoPublicTerms;
                break :expected fixed.key;
            };
            const id = try key.identity();
            self.final_key = key;
            const authority = try FinalProtocol.Admission.init(key, id, &.{}, .{ .public = &public });
            const bytes = prepared: {
                if (received) |proposal| {
                    const record = proposal.records[1];
                    try Manifest.requireKey(record, id);
                    break :prepared try Files.readPinned(a, dir, Manifest.FINAL_PROOF, record.file.byte_len, record.file.sha256, self.limits.files.max_proof_bytes);
                }
                var rows = try FinalRows.prepare(a, &public, self.limits.transcript_capacity, self.limits.final_rows);
                defer rows.deinit();
                try rows.recursive.rows.partitionHashRows();
                if (rows.wires.len != 0 or !std.meta.eql(key.context, rows.recursive.context) or
                    !std.meta.eql(key.log_sizes, try FixedKey.rowLogs(rows.recursive.rows.fixed))) return error.UntrustedRequesterMemoryFixedAssembly;
                break :prepared try bytesFor(Backend, FinalProtocol, a, dir, Manifest.FINAL_PROOF, null, &rows.recursive, authority, self.limits.files.max_proof_bytes);
            };
            defer a.free(bytes);
            public.deinit();
            owns_public = false;
            self.proposal.records[1] = proofRecord(bytes, id);
            try Manifest.validate(self.proposal, self.limits.files);
            const fresh = try FinalReceive.verify(a, self.finalPolicy(), bytes);
            errdefer fresh.deinit();
            if (action == .publish) {
                try Files.publish(dir, Manifest.FINAL_PROOF, bytes);
                published_final = true;
            }
            const encoded = try Manifest.encode(self.proposal, self.limits.files);
            self.manifest_pin = .{ .byte_len = encoded.len, .sha256 = Files.hash(&encoded) };
            if (action == .publish) try Files.publish(dir, Manifest.NAME, &encoded) else if (!std.meta.eql(self.manifest_pin.?, action.reconstruct)) return error.UntrustedFinalJobManifest;
            self.memory = selection.memory.*;
            selection.memory.* = undefined;
            return .{ .owner = self, .final = fresh };
        }
    };
}
pub fn publish(a: std.mem.Allocator, dir: std.fs.Dir, selection: Selection) !Built {
    return ForBackend(Cpu).build(a, dir, selection, .publish);
}
pub fn reconstruct(a: std.mem.Allocator, dir: std.fs.Dir, selection: Selection, manifest: Manifest.FilePin) !Built {
    return ForBackend(Cpu).build(a, dir, selection, .{ .reconstruct = manifest });
}
