//! Full execution acceptance for the new field-explicit services profile.
//! Request/geometry declarations are checked against receiver-owned setup,
//! image/program authority, exact coverage and endpoints before stage-one use.
//! No prefix-derived expected endpoint or producer-selected security claim.
const std = @import("std");
const core = @import("stwo_core");
const O = core.fields.om31.OM31;
const Config = core.pcs.ForField(O).PcsConfig;
const P = @import("../protocol.zig");
const R = @import("../roster.zig");
const Manifest = @import("manifest.zig");
const ManifestWire = @import("manifest_wire.zig");
const Frame = @import("frame.zig");
const Roster = @import("roster.zig");
const CPU = @import("cpu_worker.zig");
const Truth = @import("truth_worker.zig");
const Scope = @import("service_scope.zig");
const V3 = @import("truth_v3_worker.zig");
pub fn extendedTruth(t: R.Truth) bool {
    return t != .keccak and t != .secp;
}
const FixedSet = @import("fixed_authority_set.zig").Set;

/// Entirely receiver-derived context. Instances and first IDs are constructed
/// once, used for both manifest admission and fresh physical verification.
pub const Inventory = struct {
    allocator: std.mem.Allocator,
    execution_identity: [32]u8,
    workers: []Manifest.ExpectedWorker,
    instances: [][]Frame.Instance,
    first_ids: [][@import("../types.zig").FAMILIES]u32,
    pub fn deinit(self: *Inventory) void {
        const a = self.allocator;
        for (self.instances) |instances| a.free(instances);
        a.free(self.instances);
        a.free(self.first_ids);
        a.free(self.workers);
        self.* = undefined;
    }
    pub fn init(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, requests: []const P.Request, expected: P.Expected, config: Config) !Inventory {
        return initWithAuthority(a, setups, truths, requests, expected, config, null);
    }
    pub fn initWithAuthority(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, requests: []const P.Request, expected: P.Expected, config: Config, fixed: ?*const FixedSet) !Inventory {
        // Reuse the existing independent image, sorted/unique public cells,
        // RAM rights, epoch, call spans, program, register/PC adjacency and
        // exact total/final endpoint authority. It does not verify proofs.
        if (fixed) |authority| try authority.require(setups, truths, config) else try validateConfig(config);
        // Admit only service_scope-qualified families and representations; unsupported routes remain closed.
        for (setups) |setup| try Scope.setup(setup);
        for (requests) |request| try Scope.request(request);
        for (truths) |truth| try Scope.truth(truth);
        _ = try P.admit(a, setups, truths, requests, expected);
        if (fixed != null) {
            const Wire = @import("../wire.zig");
            const declarations = try a.alloc(Wire.CpuDeclaration, setups.len);
            defer a.free(declarations);
            const truth_declarations = try a.alloc(Wire.TruthDeclaration, truths.len);
            defer a.free(truth_declarations);
            for (setups, declarations) |setup, *d| d.* = .{ .geometry = setup.materials.geometry, .bridges = setup.bridges };
            for (truths, truth_declarations) |truth, *d| d.* = Wire.TruthDeclaration.from(truth);
            var source_bounds = try @import("source_bounds.zig").derive(a, setups[0].materials.program.log_size, declarations, truth_declarations, requests);
            defer source_bounds.deinit();
            if (@import("worker_protocol.zig").candidateProfile(config) == .d2_native_b4_q54_p20_fold4) {
                const Candidate = @import("../../../word16_execution/om31_security_candidate.zig");
                // Source derivation above enforces the receiver caps and signed
                // characteristic bounds. The conservative whole-cap D2 ledger
                // also charges its actual LDE domain factor before any worker.
                try Candidate.requireProfileAlgebraicRomBudget(.d2_native_b4_q54_p20_fold4, Candidate.Facts.caps(), Candidate.MAX_AUDITED_LOG_WORK);
            }
        }
        const count = try std.math.add(usize, setups.len, truths.len);
        const workers = try a.alloc(Manifest.ExpectedWorker, count);
        errdefer a.free(workers);
        const instances = try a.alloc([]Frame.Instance, setups.len);
        errdefer a.free(instances);
        var done: usize = 0;
        errdefer for (instances[0..done]) |values| a.free(values);
        const first_ids = try a.alloc([@import("../types.zig").FAMILIES]u32, setups.len);
        errdefer a.free(first_ids);
        var next: [@import("../types.zig").FAMILIES]u64 = @splat(1);
        for (setups, requests, 0..) |setup, request, i| {
            for (next, &first_ids[i]) |id, *out| out.* = std.math.cast(u32, id) orelse return error.GlobalGkrManifestOrdinal;
            const binding = if (fixed) |authority| authority.at(i) else null;
            workers[i] = try localCpuExpected(a, setup, request, @intCast(i), first_ids[i], config, binding);
            instances[i] = @constCast(workers[i].local_instances.?);
            done += 1;
            for (&next, request.calls) |*id, calls| id.* = try std.math.add(u64, id.*, calls);
        }
        const base_identity = executionIdentity(config, expected);
        const identity = if (fixed) |authority| (if ((try @import("../../../word16_execution/native_policy.zig").current()) == .m6_v2_gkr) try authority.executionIdentityForGkr(base_identity) else authority.executionIdentity(base_identity)) else base_identity;
        for (truths, 0..) |truth, i| {
            const kind: Manifest.Kind = if (extendedTruth(truth)) .delegation else switch (truth.family()) {
                .keccak => .keccak,
                .add => .secp_add,
                .double => .secp_double,
                else => return error.GkrV3ServiceUnsupported,
            };
            const binding = if (fixed) |authority| authority.at(setups.len + i) else null;
            workers[setups.len + i] = .{
                .kind = kind,
                .ordinal = @intCast(setups.len + i),
                .statement = if (extendedTruth(truth)) try V3.truthStatementWithAuthority(truth, config, identity, binding) else try Truth.truthStatementWithAuthority(truth, config, identity, binding),
                .fixed = if (binding) |authority| authority.root() else truth.key().root,
                .local_instances = null,
                .global_relations = .{ .ram = false, .kio = kind == .keccak, .wire = kind != .keccak },
                .mass = if (extendedTruth(truth)) try V3.truthMass(truth) else try Truth.truthMass(truth),
            };
        }
        try Manifest.validateRoster(workers);
        if (try @import("chain.zig").enabled()) try @import("chain.zig").assign(setups, truths, requests, first_ids, workers, config, fixed);
        return .{ .allocator = a, .execution_identity = identity, .workers = workers, .instances = instances, .first_ids = first_ids };
    }
};
/// Initial profile supports the two qualified fold schedules and the fixed
/// trees' blowup. Numeric parameters are receiver inputs, never proof hydration.
/// One worker's exact source-local expectation. Whole Inventory and early
/// MAIN construction share this authority; this is not global acceptance.
/// Caller owns `local_instances` and must free it after constructing a worker.
pub fn localCpuExpected(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, ordinal: u32, first: [@import("../types.zig").FAMILIES]u32, config: Config, binding: ?*const @import("fixed_authority.zig").Binding) !Manifest.ExpectedWorker {
    if (ordinal >= 256) return error.GlobalGkrManifestOrdinal;
    try Scope.setup(setup);
    try Scope.request(request);
    const instances = try Roster.fromSetup(a, setup);
    errdefer a.free(instances);
    return .{
        .kind = .cpu,
        .ordinal = ordinal,
        .statement = CPU.cpuStatementWithAuthority(setup, request, first, config, binding),
        .fixed = if (binding) |authority| authority.root() else setup.key.root,
        .local_instances = instances,
        .global_relations = .{ .ram = true, .kio = setup.bridges.keccak != null or setup.bridges.sponge.any(), .wire = CPU.wirePresent(setup.bridges) },
        .mass = try CPU.cpuMass(request),
    };
}
/// Global-inventory handoff checks exact expected class/public/protocol and
/// roster, before an early worker or its MAIN tree can enter stage two.
pub fn requireSameCpuExpected(local: Manifest.ExpectedWorker, admitted: Manifest.ExpectedWorker) !void {
    if (local.kind != .cpu or admitted.kind != .cpu or local.ordinal != admitted.ordinal or
        !std.mem.eql(u8, &local.statement, &admitted.statement) or !std.mem.eql(u8, &local.fixed, &admitted.fixed) or
        !std.meta.eql(local.mass, admitted.mass) or !std.meta.eql(local.global_relations, admitted.global_relations)) return error.EarlyCpuInventoryMismatch;
    const x = local.local_instances orelse return error.EarlyCpuInventoryMismatch;
    const y = admitted.local_instances orelse return error.EarlyCpuInventoryMismatch;
    if (x.len != y.len) return error.EarlyCpuInventoryMismatch;
    for (x, y) |left, right| if (!std.meta.eql(left, right)) return error.EarlyCpuInventoryMismatch;
}

pub fn validateConfig(config: Config) !void {
    return @import("worker_protocol.zig").validateConfig(config);
}

pub const Limits = struct {
    /// Explicitly selected only with a thread-safe allocator and a bound pool.
    physical_verify_workers: usize = 1,
    max_proof_bytes: usize = 128 << 20,
    max_total_proof_bytes: usize = 2 << 30,
    max_claims_per_worker: usize = 256,
};
fn admitEncoded(cpus: []const CPU.CpuEncoded, truths: []const Truth.TruthEncoded, limits: Limits) !void {
    if (limits.max_proof_bytes == 0 or limits.max_total_proof_bytes == 0 or limits.max_claims_per_worker == 0) return error.WideServicesProofBudgetExceeded;
    var total: usize = 0;
    for (cpus) |proof| {
        if (proof.bytes.len == 0 or proof.bytes.len > limits.max_proof_bytes or proof.claims.len > limits.max_claims_per_worker) return error.WideServicesProofBudgetExceeded;
        total = std.math.add(usize, total, proof.bytes.len) catch return error.WideServicesProofBudgetExceeded;
        if (total > limits.max_total_proof_bytes) return error.WideServicesProofBudgetExceeded;
    }
    for (truths) |proof| {
        if (proof.bytes.len == 0 or proof.bytes.len > limits.max_proof_bytes or proof.claims.len > limits.max_claims_per_worker) return error.WideServicesProofBudgetExceeded;
        total = std.math.add(usize, total, proof.bytes.len) catch return error.WideServicesProofBudgetExceeded;
        if (total > limits.max_total_proof_bytes) return error.WideServicesProofBudgetExceeded;
    }
}
fn digest(channel: anytype, bytes: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}
/// Raw256-bit transcript identity, with the implemented eight-coordinate
/// sampler identity. This is request binding, not a security certificate.
pub fn executionIdentity(config: Config, expected: P.Expected) [32]u8 {
    var writer = ExecutionIdentityWriter{ .channel = core.channel.raw_mod_m31.Om31Channel.init() };
    emitExecutionIdentity(config, expected, &writer);
    return writer.channel.digestBytes();
}
const ExecutionIdentityWriter = struct {
    channel: core.channel.raw_mod_m31.Om31Channel,
    pub fn header(self: *@This(), words: []const u32) void {
        self.channel.mixU32s(words);
    }
    pub fn configuration(self: *@This(), config: Config) void {
        config.mixInto(&self.channel);
    }
    pub fn constantDigest(self: *@This(), value: [32]u8) void {
        digest(&self.channel, value);
    }
    pub fn publicDigest(self: *@This(), value: [32]u8) void {
        digest(&self.channel, value);
    }
    pub fn int64(self: *@This(), value: u64) void {
        self.channel.mixU64(value);
    }
};
/// Single native/circuit authority for this frozen transcript order. The
/// circuit writer uses raw u32 pairs for u64 values and propagates its errors.
pub fn emitExecutionIdentity(config: Config, expected: anytype, writer: anytype) void {
    writer.header(&.{ 0x45584731, 1, 8 });
    writer.configuration(config);
    writer.constantDigest(core.channel.raw_mod_m31.om31_profile.identity());
    writer.publicDigest(expected.program_identity);
    writer.publicDigest(expected.admission.image_identity);
    writer.int64(expected.total_steps);
    writer.int64(expected.max_total_steps);
    writer.int64(expected.admission.max_prefix_steps);
    writer.int64(expected.admission.initial_pc);
    for (expected.admission.initial_registers) |value| writer.int64(value);
    writer.int64(expected.final_pc);
    for (expected.final_registers) |value| writer.int64(value);
}
pub const Verified = struct {
    completed: bool,
    total_steps: u64,
    physical_proofs: usize,
    execution_identity: [32]u8,
    manifest_identity: [32]u8,
    // Deliberately no whole-protocol security claim from successful arithmetic.
};
/// All arguments are borrowed. Each worker decoder creates independently owned
/// native proof storage and consumes it through its fresh verifier.
pub fn verify(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, requests: []const P.Request, expected: P.Expected, config: Config, stage_one_bytes: []const u8, cpus: []const CPU.CpuEncoded, truth_proofs: []const Truth.TruthEncoded) !Verified {
    return verifyWithLimits(a, setups, truths, requests, expected, config, stage_one_bytes, cpus, truth_proofs, .{});
}
pub fn verifyWithLimits(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, requests: []const P.Request, expected: P.Expected, config: Config, stage_one_bytes: []const u8, cpus: []const CPU.CpuEncoded, truth_proofs: []const Truth.TruthEncoded, limits: Limits) !Verified {
    return verifyWithAuthorityAndLimits(a, setups, truths, requests, expected, config, stage_one_bytes, cpus, truth_proofs, limits, null);
}
pub fn verifyWithAuthority(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, requests: []const P.Request, expected: P.Expected, config: Config, stage_one_bytes: []const u8, cpus: []const CPU.CpuEncoded, truth_proofs: []const Truth.TruthEncoded, fixed: *const FixedSet) !Verified {
    return verifyWithAuthorityAndLimits(a, setups, truths, requests, expected, config, stage_one_bytes, cpus, truth_proofs, .{}, fixed);
}
pub fn verifyWithAuthorityAndLimits(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, requests: []const P.Request, expected: P.Expected, config: Config, stage_one_bytes: []const u8, cpus: []const CPU.CpuEncoded, truth_proofs: []const Truth.TruthEncoded, limits: Limits, fixed: ?*const FixedSet) !Verified {
    if (cpus.len != setups.len or truth_proofs.len != truths.len) return error.InvalidWideServicesProofInventory;
    try admitEncoded(cpus, truth_proofs, limits);
    var inventory = try Inventory.initWithAuthority(a, setups, truths, requests, expected, config, fixed);
    defer inventory.deinit();
    var decoded = try ManifestWire.decode(a, inventory.execution_identity, inventory.workers, stage_one_bytes);
    defer decoded.deinit();
    var pending = try decoded.verifyAndSeal(a, inventory.execution_identity, inventory.workers);
    defer pending.deinit(a);
    const verified_claims = try a.alloc(Manifest.Claims, inventory.workers.len);
    defer a.free(verified_claims);
    const RowWork = @import("stwo_prover_engine").lookups.row_work;
    const Job = struct {
        ordinal: usize,
        bytes: usize,
        failure: ?anyerror = null,

        fn largerFirst(_: void, lhs: @This(), rhs: @This()) bool {
            return lhs.bytes > rhs.bytes;
        }
    };
    const Physical = struct {
        allocator: std.mem.Allocator,
        setups: []const *const R.CpuSetup,
        truths: []const R.Truth,
        requests: []const P.Request,
        cpus: []const CPU.CpuEncoded,
        truth_proofs: []const Truth.TruthEncoded,
        inventory: *const Inventory,
        pending: *const Manifest.PendingManifest,
        config: Config,
        fixed: ?*const FixedSet,
        claims: []Manifest.Claims,
        jobs: []Job,
        next: std.atomic.Value(usize) = .init(0),

        fn verifyAt(self: *const @This(), ordinal: usize) !Manifest.Claims {
            const binding = if (self.fixed) |authority| authority.at(ordinal) else null;
            const worker = self.inventory.workers[ordinal];
            if (ordinal < self.setups.len) {
                return CPU.verifyCpuWithAuthority(self.allocator, self.setups[ordinal], self.requests[ordinal], worker, self.inventory.first_ids[ordinal], self.pending, ordinal, self.config, &self.cpus[ordinal], binding);
            }
            const i = ordinal - self.setups.len;
            const truth = self.truths[i];
            return if (extendedTruth(truth))
                V3.verifyTruthWithAuthority(self.allocator, truth, worker, self.pending, ordinal, self.config, &self.truth_proofs[i], binding)
            else
                Truth.verifyTruthWithAuthority(self.allocator, truth, worker, self.pending, ordinal, self.config, &self.truth_proofs[i], binding);
        }
        pub fn runRange(self: *@This(), _: usize, _: usize, _: usize) void {
            while (true) {
                const index = self.next.fetchAdd(1, .monotonic);
                if (index >= self.jobs.len) return;
                const job = &self.jobs[index];
                self.claims[job.ordinal] = self.verifyAt(job.ordinal) catch |err| {
                    job.failure = err;
                    continue;
                };
            }
        }
    };
    const jobs = try a.alloc(Job, verified_claims.len);
    defer a.free(jobs);
    for (cpus, jobs[0..cpus.len], 0..) |proof, *job, i| job.* = .{ .ordinal = i, .bytes = proof.bytes.len };
    for (truth_proofs, jobs[cpus.len..], cpus.len..) |proof, *job, i| job.* = .{ .ordinal = i, .bytes = proof.bytes.len };
    var physical = Physical{
        .allocator = a,
        .setups = setups,
        .truths = truths,
        .requests = requests,
        .cpus = cpus,
        .truth_proofs = truth_proofs,
        .inventory = &inventory,
        .pending = &pending,
        .config = config,
        .fixed = fixed,
        .claims = verified_claims,
        .jobs = jobs,
    };
    if (limits.physical_verify_workers <= 1) {
        for (verified_claims, 0..) |*claim, ordinal| claim.* = try physical.verifyAt(ordinal);
    } else {
        // Pull the largest encodings first. A worker that finishes a small
        // proof can immediately pick up another without waiting for a shard.
        std.mem.sort(Job, jobs, {}, Job.largerFirst);
        _ = RowWork.forEachRange(jobs.len, &physical, .{ .max_shards = limits.physical_verify_workers, .min_rows_per_shard = 1 });
        // Preserve the lowest failing proof ordinal across all workers.
        var first_failure: ?Job = null;
        for (jobs) |job| {
            if (job.failure != null and (first_failure == null or job.ordinal < first_failure.?.ordinal)) first_failure = job;
        }
        if (first_failure) |job| return job.failure.?;
    }
    try pending.checkGlobalClosure(verified_claims);
    return .{ .completed = true, .total_steps = expected.total_steps, .physical_proofs = inventory.workers.len, .execution_identity = inventory.execution_identity, .manifest_identity = pending.digest };
}
