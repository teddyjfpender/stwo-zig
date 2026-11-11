//! Independent expected endpoint/source admission for the OP pure-P2 CPU gate.
const std = @import("std");
const core = @import("stwo_core");
const P = @import("../word16_global_execution/services/protocol.zig");
const R = @import("../word16_global_execution/services/roster.zig");
const T = @import("../word16_global_execution/services/types.zig");
const M = @import("pure_p2_manifest.zig");
const Frame = @import("../word16_global_execution/services/gkr_local/frame.zig");
const Protocol = @import("pure_p2_worker_protocol.zig");
const Key = @import("pure_p2_fixed_key.zig").Key;
pub const Inventory = struct {
    allocator: std.mem.Allocator,
    execution_identity: [32]u8,
    workers: []M.Expected,
    instances: [][]Frame.Instance,
    first_ids: [][T.FAMILIES]u32,
    pub fn init(a: std.mem.Allocator, setups: []const *const R.CpuSetup, requests: []const P.Request, expected: P.Expected, keys: []const Key, profile: Protocol.Profile) !Inventory {
        if (setups.len == 0 or setups.len != requests.len or setups.len != keys.len or setups.len > 256) return error.PoseidonNativeInventory;
        _ = try P.admit(a, setups, &.{}, requests, expected);
        const Scope = @import("../word16_global_execution/services/gkr_local/service_scope.zig");
        for (setups, requests, keys) |setup, request, key| {
            try Scope.setup(setup);
            try Scope.request(request);
            try key.require(setup, profile);
        }
        const workers = try a.alloc(M.Expected, setups.len);
        errdefer a.free(workers);
        const instances = try a.alloc([]Frame.Instance, setups.len);
        errdefer a.free(instances);
        var done: usize = 0;
        errdefer for (instances[0..done]) |instance| a.free(instance);
        const ids = try a.alloc([T.FAMILIES]u32, setups.len);
        errdefer a.free(ids);
        var next: [T.FAMILIES]u64 = @splat(1);
        for (setups, requests, keys, workers, instances, ids, 0..) |setup, request, *key, *worker, *instance, *first, i| {
            for (next, first) |id, *v| v.* = std.math.cast(u32, id) orelse return error.PoseidonNativeInventory;
            instance.* = try @import("../word16_global_execution/services/gkr_local/roster.zig").fromSetup(a, setup);
            done += 1;
            worker.* = .{ .kind = .cpu, .ordinal = @intCast(i), .statement = key.statement(setup, request, first.*), .fixed = key.scope(), .fixed_identity = key.identity, .profile = profile, .local_instances = instance.*, .mass = try @import("../word16_global_execution/services/gkr_local/cpu_worker.zig").cpuMass(request), .global_relations = .{ .ram = true, .kio = setup.bridges.keccak != null or setup.bridges.sponge.any(), .wire = @import("../word16_global_execution/services/gkr_local/cpu_worker.zig").wirePresent(setup.bridges) } };
            for (&next, request.calls) |*v, count| v.* = try std.math.add(u64, v.*, count);
        }
        try M.validateExpected(workers);
        // Source-derived signed/absolute characteristic and roster bounds.
        const Wire = @import("../word16_global_execution/services/wire.zig");
        const declarations = try a.alloc(Wire.CpuDeclaration, setups.len);
        defer a.free(declarations);
        for (setups, declarations) |setup, *d| d.* = .{ .geometry = setup.materials.geometry, .bridges = setup.bridges };
        var bounds = try @import("../word16_global_execution/services/gkr_local/source_bounds.zig").derive(a, setups[0].materials.program.log_size, declarations, &.{}, requests);
        defer bounds.deinit();
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("opstack-pure-p2/source-execution-admission/v1\x00");
        h.update(&profile.identity());
        h.update(&@import("../word16_global_execution/services/gkr_local/execution.zig").executionIdentity(profile.config(), expected));
        for (keys) |key| {
            h.update(&key.identity);
            h.update(&key.root);
        }
        var execution_id: [32]u8 = undefined;
        h.final(&execution_id);
        return .{ .allocator = a, .execution_identity = execution_id, .workers = workers, .instances = instances, .first_ids = ids };
    }
    pub fn deinit(self: *Inventory) void {
        for (self.instances) |instances| self.allocator.free(instances);
        self.allocator.free(self.instances);
        self.allocator.free(self.workers);
        self.allocator.free(self.first_ids);
        self.* = undefined;
    }
};
