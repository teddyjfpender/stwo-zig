//! Receiver-owned complete OP native inventory. No producer declaration is
//! sufficient authority: program/image/endpoints and source keys are supplied
//! independently, then admission and source bounds precede the manifest.
const std = @import("std");
const P = @import("../word16_global_execution/services/protocol.zig");
const R = @import("../word16_global_execution/services/roster.zig");
const T = @import("../word16_global_execution/services/types.zig");
const Wire = @import("../word16_global_execution/services/wire.zig");
const Bounds = @import("../word16_global_execution/services/gkr_local/source_bounds.zig");
const Roster = @import("../word16_global_execution/services/gkr_local/roster.zig");
const Legacy = @import("../word16_global_execution/services/gkr_local/cpu_worker.zig");
const Manifest = @import("pure_p2_manifest.zig");
const CPU = @import("pure_p2_cpu_worker.zig");
const Key = @import("pure_p2_fixed_key.zig").Key;
const Truth = @import("pure_p2_truth_worker.zig");
const TruthLocal = @import("truth_local_gkr/worker.zig");
const Miller = @import("pure_p2_tower_worker.zig");
const MillerLocal = @import("miller_local_gkr/worker.zig");
const Suite = @import("pure_p2_source_suite.zig").Suite;
const SuiteSecurity = @import("pure_p2_source_suite_security.zig");
const Profile = @import("pure_p2_worker_protocol.zig").Profile;
pub const MillerDeclaration = struct { key: *const Miller.Key, span: Miller.Span, local_key: ?*const MillerLocal.Key = null };
pub const Inventory = struct {
    allocator: std.mem.Allocator,
    workers: []Manifest.Expected,
    first_ids: [][T.FAMILIES]u32,
    bounds: Bounds.OpReport,
    execution: [32]u8,
    cpu_count: usize,
    truth_count: usize,
    /// Borrowed source keys. Empty is the original classic truth protocol.
    truth_local_keys: []const ?*const TruthLocal.Key = &.{},
    source_suite: ?Suite = null,
    source_security: ?SuiteSecurity.Checked = null,
    pub fn deinit(self: *Inventory) void {
        for (self.workers) |worker| if (worker.local_instances) |instances| self.allocator.free(instances);
        self.allocator.free(self.workers);
        self.allocator.free(self.first_ids);
        self.bounds.deinit();
        self.* = undefined;
    }
    pub fn init(a: std.mem.Allocator, profile: Profile, setups: []const *const R.CpuSetup, requests: []const P.Request, spans: []const T.OpTowerSpan, cpu_keys: []const *const Key, truths: []const R.Truth, truth_keys: []const *const Truth.Key, miller: []const MillerDeclaration, expected: P.Expected) !Inventory {
        return initForTruthLocal(a, profile, setups, requests, spans, cpu_keys, truths, truth_keys, miller, expected, &.{});
    }
    /// A nonempty parallel vector is an explicit new truth protocol selection;
    /// it is supplied by independently rebuilt source authority, not the bundle.
    pub fn initForTruthLocal(a: std.mem.Allocator, profile: Profile, setups: []const *const R.CpuSetup, requests: []const P.Request, spans: []const T.OpTowerSpan, cpu_keys: []const *const Key, truths: []const R.Truth, truth_keys: []const *const Truth.Key, miller: []const MillerDeclaration, expected: P.Expected, truth_local_keys: []const ?*const TruthLocal.Key) !Inventory {
        return initForSourceSuite(a, profile, setups, requests, spans, cpu_keys, truths, truth_keys, miller, expected, truth_local_keys, null);
    }
    /// Explicit independently selected source suite. Legacy constructors never
    /// infer a new flavor from an incoming key, proof or metadata declaration.
    pub fn initForSourceSuite(a: std.mem.Allocator, profile: Profile, setups: []const *const R.CpuSetup, requests: []const P.Request, spans: []const T.OpTowerSpan, cpu_keys: []const *const Key, truths: []const R.Truth, truth_keys: []const *const Truth.Key, miller: []const MillerDeclaration, expected: P.Expected, truth_local_keys: []const ?*const TruthLocal.Key, source_suite: ?Suite) !Inventory {
        if (source_suite) |suite| {
            try suite.validate();
            if (suite.truth == .local_gkr and truth_local_keys.len != truths.len) return error.InvalidOpTruthLocalInventory;
            if (suite.truth == .classic and truth_local_keys.len != 0) return error.InvalidOpTruthLocalInventory;
        }
        for (miller) |item| {
            const wants_local = if (source_suite) |suite| suite.miller == .local_gkr else false;
            if (wants_local != (item.local_key != null)) return error.OpMillerSourceSuitePolicy;
            if (item.local_key) |key| {
                _ = try key.geometry(item.span);
                if (key.base.profile != profile or !std.mem.eql(u8, &key.base.identity, &item.key.identity) or !std.mem.eql(u8, &key.base.root, &item.key.root)) return error.OpMillerSourceSuitePolicy;
            }
        }
        if (truth_local_keys.len != 0 and truth_local_keys.len != truths.len) return error.InvalidOpTruthLocalInventory;
        if (profile == .reference_b2_q24_p0 or setups.len == 0 or setups.len != cpu_keys.len or setups.len != spans.len or setups.len != requests.len or truths.len != truth_keys.len or setups.len + truths.len + miller.len > Manifest.MAX_WORKERS) return error.InvalidOpNativeInventory;
        _ = try P.admitForOp(a, setups, truths, requests, expected, spans);
        const declarations = try a.alloc(Wire.CpuDeclaration, setups.len);
        defer a.free(declarations);
        for (setups, declarations) |setup, *out| out.* = .{ .geometry = setup.materials.geometry, .bridges = setup.bridges };
        const truth_declarations = try a.alloc(Wire.TruthDeclaration, truths.len);
        defer a.free(truth_declarations);
        for (truths, truth_declarations) |truth, *out| out.* = Wire.TruthDeclaration.from(truth);
        const tower_declarations = try a.alloc(Bounds.OpTowerTruthDeclaration, miller.len);
        defer a.free(tower_declarations);
        for (miller, tower_declarations) |item, *out| {
            if (item.key.profile != profile) return error.InvalidOpNativeProfile;
            out.* = .{ .calls = item.span.calls, .first_id = item.span.first_id, .frontier_log = item.key.frontier_log, .arithmetic_log = item.key.arithmetic_log };
        }
        var bounds = try Bounds.deriveForOp(a, setups[0].materials.program.log_size, declarations, truth_declarations, requests, spans, tower_declarations);
        errdefer bounds.deinit();
        const source_security = if (source_suite) |suite| try SuiteSecurity.check(profile, &bounds, truth_declarations, tower_declarations, suite) else null;
        const workers = try a.alloc(Manifest.Expected, setups.len + truths.len + miller.len);
        errdefer a.free(workers);
        var done: usize = 0;
        errdefer for (workers[0..done]) |worker| if (worker.local_instances) |instances| a.free(instances);
        const ids = try a.alloc([T.FAMILIES]u32, setups.len);
        errdefer a.free(ids);
        for (setups, requests, spans, cpu_keys, 0..) |setup, request, span, key, i| {
            try key.requireForOp(setup, profile);
            ids[i] = try P.firstIds(requests, i);
            const instances = try Roster.fromOpSetup(a, setup);
            errdefer a.free(instances);
            workers[i] = .{ .kind = .cpu, .ordinal = @intCast(i), .profile = profile, .statement = try key.statementForOp(setup, request, ids[i], span), .fixed_identity = key.identity, .fixed = key.scope(), .local_instances = instances, .mass = try CPU.cpuMass(setup, request, span), .global_relations = .{ .ram = true, .kio = setup.bridges.keccak != null or setup.bridges.sponge.any(), .wire = Legacy.wirePresent(setup.bridges) or span.calls != 0 } };
            done += 1;
        }
        for (truths, truth_keys, 0..) |truth, key, i| {
            if (key.profile != profile) return error.InvalidOpNativeProfile;
            try key.require(truth);
            if (source_suite) |suite| if (suite.truth == .local_gkr and (truth == .keccak or truth == .secp) and truth_local_keys[i] == null) return error.InvalidOpTruthLocalInventory;
            if (if (truth_local_keys.len == 0) null else truth_local_keys[i]) |local| {
                if (truth != .keccak and truth != .secp) return error.InvalidOpTruthLocalInventory;
                try local.require(truth);
                if (local.base.profile != profile or !std.mem.eql(u8, &local.base.identity, &key.identity) or !std.mem.eql(u8, &local.base.root, &key.root)) return error.InvalidOpTruthLocalInventory;
                workers[done] = try local.expected(truth, @intCast(setups.len + i));
            } else workers[done] = try key.expected(truth, @intCast(setups.len + i));
            done += 1;
        }
        for (miller) |item| {
            workers[done] = if (item.local_key) |key| try key.expected(item.span, @intCast(done)) else try item.key.expected(item.span, @intCast(done));
            done += 1;
        }
        try Manifest.validateExpected(workers);
        // Every request statement and key is already framed by Manifest. This
        // domain additionally binds receiver-selected genesis/terminal authority.
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        if (source_suite) |suite| {
            h.update("op-native-pure-p2-complete-execution/source-suite/v1\x00");
            h.update(&try suite.encode());
        } else h.update("op-native-pure-p2-complete-execution/v1\x00");
        h.update(&profile.identity());
        h.update(&expected.program_identity);
        h.update(&expected.admission.image_identity);
        for ([_]u64{ expected.admission.initial_pc, expected.total_steps, expected.final_pc }) |word| mix(&h, word);
        for (expected.admission.initial_registers) |word| mix(&h, word);
        for (expected.final_registers) |word| mix(&h, word);
        for (workers) |worker| {
            h.update(&worker.statement);
            h.update(&worker.fixed_identity);
            h.update(&worker.fixed);
        }
        return .{ .allocator = a, .workers = workers, .first_ids = ids, .bounds = bounds, .execution = h.finalResult(), .cpu_count = setups.len, .truth_count = truths.len, .truth_local_keys = truth_local_keys, .source_suite = source_suite, .source_security = source_security };
    }
};
fn mix(h: *std.crypto.hash.sha2.Sha256, word: u64) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, word, .little);
    h.update(&bytes);
}

test "OP inventory source suite is explicit and legacy constructors fail closed" {
    const a = std.testing.allocator;
    const profile = Profile.op_target_b4_q72_p0_fold4_v1;
    var local = try MillerLocal.Key.init(a, profile, 8, 15);
    defer local.deinit();
    const declarations = [_]MillerDeclaration{.{ .key = &local.base, .local_key = &local, .span = .{ .calls = 1, .first_id = 1 } }};
    // Empty CPU roster prevents any proof admission. These controls exercise
    // protocol-policy selection before source keys can enter an inventory.
    try std.testing.expectError(error.OpMillerSourceSuitePolicy, Inventory.initForTruthLocal(a, profile, &.{}, &.{}, &.{}, &.{}, &.{}, &.{}, &declarations, undefined, &.{}));
    try std.testing.expectError(error.OpMillerSourceSuitePolicy, Inventory.initForSourceSuite(a, profile, &.{}, &.{}, &.{}, &.{}, &.{}, &.{}, &declarations, undefined, &.{}, Suite{}));
    try std.testing.expectError(error.InvalidOpNativeInventory, Inventory.initForSourceSuite(a, profile, &.{}, &.{}, &.{}, &.{}, &.{}, &.{}, &declarations, undefined, &.{}, Suite.millerGkr()));
}
