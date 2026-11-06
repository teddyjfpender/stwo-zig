//! NativeStage1 device transcript (spec §3.5 item 1) up to the local GKR:
//!
//!   seed      = worker_protocol.begin(config, expected) checkpoint (pure host,
//!               challenge free: computed in pre-stage, staged as 9 words)
//!   FIXED     = class-persistent tree (Stager.persistent, keyed by the
//!               class's FIXED identity): committed on device by the FIRST job
//!               of the class on this worker, then only its root is mixed
//!               (legacy appendFixed -> appendCommittedTree mixes the root)
//!   MAIN      = native_commit, root mixed on device
//!
//! The FIXED root the device computed is copied to a slab field; finish must
//! compare it with the setup key root (the legacy appendFixed authority check).
//! Not here yet: the witness source producer of the MAIN inputs and the local
//! GKR (its own child channel; spec: channel kept on device, section into the
//! slab). MAIN inputs are device buffers produced before `enqueue`, or staged
//! host columns.
const std = @import("std");
const api = @import("api.zig");
const C = @import("native_commit.zig");
const G = @import("native_gkr.zig");

pub const FixedTree = struct {
    plan: *C.CommitPlan,
    /// Class FIXED identity (e.g. the setup key root). Two classes with equal
    /// keys must have identical FIXED trees.
    key: [32]u8,
    persistent: ?api.Persistent = null,

    pub fn words(self: *const FixedTree) usize {
        return self.plan.coefficient_cells + 8;
    }
    pub fn stage(self: *FixedTree, s: *api.Stager, inputs: []const C.Input) !void {
        const p = try s.persistent(self.key, self.words());
        if (p.fresh) try self.plan.stage(s, inputs);
        self.persistent = p;
    }
    /// Returns persistent coefficient views: never free them.
    pub fn enqueue(self: *const FixedTree, sym: C.Symbols, e: *api.Enqueue, inputs: []const C.Input, root_out: api.DeviceBuffer) !C.Committed {
        const p = self.persistent orelse return error.FixedTreeNotStaged;
        const coefficients = try p.buffer.slice(0, self.plan.coefficient_cells);
        const root = try p.buffer.slice(self.plan.coefficient_cells, 8);
        if (p.fresh) _ = try self.plan.enqueueInto(sym, e, inputs, coefficients, root, false);
        if (sym.copy_d2d(e.ctx(), root_out.ptr, root.ptr, 32) != 0) return error.CudaEnqueueFailed;
        try e.channel.mixRootFromTree(root);
        return .{ .coefficients = coefficients, .root = root.ptr };
    }
};

pub const Stage1 = struct {
    fixed: *FixedTree,
    main: *C.CommitPlan,
    csym: C.Symbols,
    seed: [9]u32,
    staged_seed: ?api.DeviceBuffer = null,
    /// Local GKR of the segment, fed by this job's FIXED/MAIN commitments and
    /// the device MAIN root (spec §3.5 item 1); null stops after MAIN.
    gkr: ?*G.Gkr = null,

    pub fn stage(self: *Stage1, s: *api.Stager, fixed_inputs: []const C.Input, main_inputs: []const C.Input) !void {
        const b = try s.alloc(9);
        try s.upload(b, &self.seed);
        self.staged_seed = b;
        try self.fixed.stage(s, fixed_inputs);
        try self.main.stage(s, main_inputs);
        if (self.gkr) |gkr| try gkr.stageCommitted(s);
    }
    pub const Committed = struct { fixed: C.Committed, main: C.Committed };
    /// `roots`: slab field of 16 words (FIXED root, MAIN root). MAIN
    /// coefficients are job-arena memory owned by the caller after return.
    pub fn enqueue(self: *Stage1, e: *api.Enqueue, fixed_inputs: []const C.Input, main_inputs: []const C.Input, roots: api.DeviceBuffer) !Committed {
        try e.channel.initFromCheckpoint(self.staged_seed orelse return error.Stage1NotStaged);
        const fixed = try self.fixed.enqueue(self.csym, e, fixed_inputs, try roots.slice(0, 8));
        const main = try self.main.enqueue(self.csym, e, main_inputs, try roots.slice(8, 8), true);
        if (self.gkr) |gkr| try gkr.enqueueCommitted(e, self.fixed.plan, fixed, self.main, main, try roots.slice(8, 8));
        return .{ .fixed = fixed, .main = main };
    }
};

/// The 9-word staged seed of a host channel checkpoint (digest[8], draws).
pub fn seedOf(channel: anytype) [9]u32 {
    var seed: [9]u32 = undefined;
    for (seed[0..8], 0..) |*w, i| w.* = std.mem.readInt(u32, channel.inner.digest[i * 4 ..][0..4], .little);
    seed[8] = channel.inner.n_draws;
    return seed;
}
