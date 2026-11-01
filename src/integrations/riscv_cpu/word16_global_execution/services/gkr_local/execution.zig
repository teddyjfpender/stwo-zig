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
const FixedSet = @import("fixed_authority_set.zig").Set;

/// Entirely receiver-derived context. Instances and first IDs are constructed
/// once, used for both manifest admission and fresh physical verification.
pub const Inventory = struct {
    allocator: std.mem.Allocator,
    execution_identity: [32]u8,
    workers: []Manifest.ExpectedWorker,
    instances: [][]Frame.Instance,
    first_ids: [][3]u32,
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
        _ = try P.admit(a, setups, truths, requests, expected);
        const count = try std.math.add(usize, setups.len, truths.len);
        const workers = try a.alloc(Manifest.ExpectedWorker, count);
        errdefer a.free(workers);
        const instances = try a.alloc([]Frame.Instance, setups.len);
        errdefer a.free(instances);
        var done: usize = 0;
        errdefer for (instances[0..done]) |values| a.free(values);
        const first_ids = try a.alloc([3]u32, setups.len);
        errdefer a.free(first_ids);
        var next: [3]u64 = @splat(1);
        for (setups, requests, 0..) |setup, request, i| {
            for (next, &first_ids[i]) |id, *out| out.* = std.math.cast(u32, id) orelse return error.GlobalGkrManifestOrdinal;
            instances[i] = try Roster.fromSetup(a, setup);
            done += 1;
            const binding = if (fixed) |authority| authority.at(i) else null;
            workers[i] = .{
                .kind = .cpu,
                .ordinal = @intCast(i),
                .statement = CPU.cpuStatementWithAuthority(setup, request, first_ids[i], config, binding),
                .fixed = if (binding) |authority| authority.root() else setup.key.root,
                .local_instances = instances[i],
                .global_relations = .{ .ram = true, .kio = setup.bridges.keccak != null, .wire = setup.bridges.add != null or setup.bridges.double != null },
                .mass = try CPU.cpuMass(request),
            };
            for (&next, request.calls) |*id, calls| id.* = try std.math.add(u64, id.*, calls);
        }
        const base_identity = executionIdentity(config, expected);
        const identity = if (fixed) |authority| authority.executionIdentity(base_identity) else base_identity;
        for (truths, 0..) |truth, i| {
            const kind: Manifest.Kind = switch (truth.family()) {
                .keccak => .keccak,
                .add => .secp_add,
                .double => .secp_double,
            };
            const binding = if (fixed) |authority| authority.at(setups.len + i) else null;
            workers[setups.len + i] = .{
                .kind = kind,
                .ordinal = @intCast(setups.len + i),
                .statement = Truth.truthStatementWithAuthority(truth, config, identity, binding),
                .fixed = if (binding) |authority| authority.root() else truth.key().root,
                .local_instances = null,
                .global_relations = .{ .ram = false, .kio = kind == .keccak, .wire = kind != .keccak },
                .mass = try Truth.truthMass(truth),
            };
        }
        try Manifest.validateRoster(workers);
        return .{ .allocator = a, .execution_identity = identity, .workers = workers, .instances = instances, .first_ids = first_ids };
    }
};
/// Initial profile supports the two qualified fold schedules and the fixed
/// trees' blowup. Numeric parameters are receiver inputs, never proof hydration.
pub fn validateConfig(config: Config) !void {
    return @import("worker_protocol.zig").validateConfig(config);
}

pub const Limits = struct {
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
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    channel.mixU32s(&.{ 0x45584731, 1, 8 });
    config.mixInto(&channel);
    digest(&channel, core.channel.raw_mod_m31.om31_profile.identity());
    digest(&channel, expected.program_identity);
    digest(&channel, expected.admission.image_identity);
    channel.mixU64(expected.total_steps);
    channel.mixU64(expected.max_total_steps);
    channel.mixU64(expected.admission.max_prefix_steps);
    channel.mixU64(expected.admission.initial_pc);
    for (expected.admission.initial_registers) |value| channel.mixU64(value);
    channel.mixU64(expected.final_pc);
    for (expected.final_registers) |value| channel.mixU64(value);
    return channel.digestBytes();
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
    for (setups, requests, cpus, 0..) |setup, request, *proof, i| {
        verified_claims[i] = try CPU.verifyCpuWithAuthority(a, setup, request, inventory.workers[i], inventory.first_ids[i], &pending, i, config, proof, if (fixed) |authority| authority.at(i) else null);
    }
    for (truths, truth_proofs, 0..) |truth, *proof, i| {
        const ordinal = setups.len + i;
        verified_claims[ordinal] = try Truth.verifyTruthWithAuthority(a, truth, inventory.workers[ordinal], &pending, ordinal, config, proof, if (fixed) |authority| authority.at(ordinal) else null);
    }
    try pending.checkGlobalClosure(verified_claims);
    return .{ .completed = true, .total_steps = expected.total_steps, .physical_proofs = inventory.workers.len, .execution_identity = inventory.execution_identity, .manifest_identity = pending.digest };
}
