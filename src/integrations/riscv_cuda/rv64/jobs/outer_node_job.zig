//! GPU-native recursion request jobs and their custody.
//! Installed class registration lives in outer_device.zig. This owner takes
//! borrowed immutable NodeClass products, constructs node jobs, and retains
//! them until completion/publication without owning or releasing class pins.
const std = @import("std");
const api = @import("api.zig");
const G = @import("gpu_native.zig");
const Seed = @import("outer_seed_device.zig");
const O = @import("ops.zig");
pub const Copy = *const fn (*anyopaque, *anyopaque, *const anyopaque, usize) callconv(.c) c_int;
const lane: u32 = 0;
pub const lookup_field_index: u32 = 0x4348_4b31; // outer_checks.field_index ("CHK1")

/// Device products of one warmed recursion node class (built once at warm).
pub const NodeClass = struct {
    /// Seed program words (outer_seed_device.buildFold / buildLeaf) with
    /// each child's image at the END of its class's encoded region.
    program: []const u32,
    prog_key: [32]u8,
    n_children: u32,
    /// Output words of the node (4 per output).
    output_words: u32,
    require_warm: bool = false,
    compressed: bool = false,
    ctx: *anyopaque,
    /// The whole-node job of this class, its encoder targeting `target`
    /// (image tail on, outputs from device memory). Type-erased: the
    /// builder lives outside rv64/jobs/ (legacy host types).
    make: *const fn (ctx: *anyopaque, a: std.mem.Allocator, target: Target) anyerror!Made,
};
pub const Target = struct {
    /// GPU the node runs on (its whole-node graph cache is per device).
    device: u32 = 0,
    region: api.DeviceBuffer,
    pcs_status: api.DeviceBuffer,
    encode_status: api.DeviceBuffer,
    oods_status: api.DeviceBuffer,
    class_unpack_status: ?api.DeviceBuffer = null,
};
pub const Made = struct {
    job: api.Job,
    ctx: *anyopaque,
    /// After `job`'s stage: the node-region ranges the seed fill writes.
    inputs: *const fn (*anyopaque) anyerror!Inputs,
    destroy: *const fn (*anyopaque) void,
};
pub const max_graph_devices = G.max_devices;
pub const Inputs = struct { seeds: api.DeviceBuffer, channel_seed: api.DeviceBuffer, outputs: api.DeviceBuffer };
/// Device entry points the node job needs (bound by the service).
pub const DeviceOps = struct {
    seed: Seed.Symbols,
    d2d: Copy,
    peer: O.Peer,
};

/// Owns request jobs until publication, or an observed finish/abort settles
/// them. The caller serializes make/end/reclaim (the registry mutex does so
/// in production); workers only publish the atomic settled latch. Teardown
/// requires quiescence and runs before installed class pins are released.
pub const Requests = struct {
    jobs: std.ArrayListUnmanaged(*NodeJob) = .empty,

    pub fn deinit(self: *Requests, a: std.mem.Allocator) void {
        self.releaseWhere(a, null, false);
        self.jobs.deinit(a);
        self.* = .{};
    }
    pub fn end(self: *Requests, a: std.mem.Allocator, request: u64) void {
        self.releaseWhere(a, request, false);
    }
    pub fn reclaimSettled(self: *Requests, a: std.mem.Allocator) void {
        self.releaseWhere(a, null, true);
    }
    pub fn count(self: *const Requests) usize {
        return self.jobs.items.len;
    }
    /// Success transfers job/body ownership. On allocation failure the
    /// caller still owns both and no partially retained job is visible.
    pub fn adopt(self: *Requests, a: std.mem.Allocator, job: *NodeJob) !api.Job {
        try self.jobs.append(a, job);
        return job.job();
    }
    /// Free the jobs of `request` (null: every job), or with `settled_only`
    /// only the jobs that settled. Caller holds the mutex (or tears down).
    fn releaseWhere(self: *Requests, a: std.mem.Allocator, request: ?u64, settled_only: bool) void {
        var keep: usize = 0;
        for (self.jobs.items) |j| {
            const mine = if (request) |r| j.request == r else true;
            if (mine and (!settled_only or j.settled.load(.acquire))) {
                j.deinit();
                a.destroy(j);
            } else {
                self.jobs.items[keep] = j;
                keep += 1;
            }
        }
        self.jobs.shrinkRetainingCapacity(keep);
    }

    pub fn make(self: *Requests, a: std.mem.Allocator, ops: DeviceOps, nc: *const NodeClass, rc: *const G.RequestContext, id: G.ProofId, children: []const G.ProofId, device: u32) !api.Job {
        if (children.len != nc.n_children or children.len > Seed.max_children) return error.GpuNativeNodeChildCount;
        if (device >= rc.segments.len or device >= rc.layout.segments.len) return error.GpuNativeProofDeviceOutOfRange;
        const seg = &rc.layout.segments[device];
        const buf = rc.segments[device];
        const target = Target{ .device = device, .region = try seg.encodedBuffer(buf, id), .pcs_status = try seg.statusBuffer(buf, id, .node_pcs_status), .encode_status = try seg.statusBuffer(buf, id, .encode_bounds), .oods_status = try seg.statusBuffer(buf, id, .node_oods_constraint), .class_unpack_status = if (nc.compressed) try seg.statusBuffer(buf, id, .class_unpack) else null };
        const job = try a.create(NodeJob);
        errdefer a.destroy(job);
        job.* = .{ .a = a, .request = rc.request, .proof_id = id, .ops = ops, .class = nc, .device = device, .verdicts = .{
            .seed_tape = try seg.statusBuffer(buf, id, .seed_tape),
            .child_binding = try seg.statusBuffer(buf, id, .child_binding),
            .lookup_sum = try seg.statusBuffer(buf, id, .lookup_sum),
            .channel_order = try seg.statusBuffer(buf, id, .channel_order),
        }, .made = undefined };
        for (children, 0..) |c, k| job.children[k] = try childRegion(rc, c);
        job.n_children = @intCast(children.len);
        job.made = try nc.make(nc.ctx, a, target);
        errdefer job.made.destroy(job.made.ctx);
        return self.adopt(a, job);
    }
    /// A child's encoded region: the segment of the GPU that produced it.
    fn childRegion(rc: *const G.RequestContext, id: G.ProofId) !NodeJob.Child {
        for (rc.layout.segments, 0..) |*s, d| if (s.find(id) != null) return .{ .device = @intCast(d), .region = try s.encodedBuffer(rc.segments[d], id) };
        return error.GpuNativeUnknownProof;
    }
};

/// The GPU-native node job: seed fill + statement (device), then the class's
/// whole-node job, then the lookup_sum / channel_order words. Children on
/// the other GPU are peer-copied into node-local memory first (the batch
/// already waits on their producers' done events).
pub const NodeJob = struct {
    pub const Child = struct { device: u32, region: api.DeviceBuffer };
    pub const Verdicts = struct { seed_tape: api.DeviceBuffer, child_binding: api.DeviceBuffer, lookup_sum: api.DeviceBuffer, channel_order: api.DeviceBuffer };
    a: std.mem.Allocator,
    /// Request that made the job (Recursion.node); 0 for a standalone job.
    request: u64 = 0,
    proof_id: G.ProofId = .{ .kind = .leaf, .ordinal = 0 },
    /// Set (release) after `finish` / `abort` returned; Recursion frees the
    /// job only then (or at `end` / `deinit`).
    settled: std.atomic.Value(bool) = .init(false),
    ops: DeviceOps,
    class: *const NodeClass,
    device: u32,
    verdicts: Verdicts,
    made: Made,
    children: [Seed.max_children]Child = undefined,
    n_children: u32 = 0,
    local: [Seed.max_children]?api.DeviceBuffer = @splat(null),
    d_prog: api.DeviceBuffer = undefined,
    scratch: api.DeviceBuffer = undefined,
    /// Host-side time of stage + enqueue of the seed fill and verdicts (ns).
    host_ns: u64 = 0,
    launches: u32 = 0,

    pub fn deinit(self: *NodeJob) void {
        self.made.destroy(self.made.ctx);
    }
    pub fn job(self: *NodeJob) api.Job {
        return api.Job.from(NodeJob, self);
    }
    pub fn classKey(self: *NodeJob) [32]u8 {
        return self.made.job.classKey();
    }
    fn g(words: u64) u64 {
        return std.mem.alignForward(u64, @max(words, 1), 64);
    }
    fn extra(self: *const NodeJob) u64 {
        var n = g(@as(u64, self.class.program[Seed.P.scratch_words]) + 8);
        for (self.children[0..self.n_children]) |c| if (c.device != self.device) {
            n += g(c.region.words);
        };
        return n;
    }
    pub fn footprint(self: *NodeJob) api.Footprint {
        var fp = self.made.job.footprint();
        const x = self.extra();
        fp.device_words += @intCast(x);
        fp.staged_words += @intCast(x);
        fp.pinned_words += self.class.program.len;
        return fp;
    }
    pub fn stage(self: *NodeJob, s: *api.Stager) !void {
        try self.made.job.vtable.stage(self.made.job.ctx, s);
        var t = try std.time.Timer.start();
        defer self.host_ns += t.read();
        const p = try s.persistent(self.class.prog_key, self.class.program.len);
        self.d_prog = p.buffer;
        if (self.class.require_warm and p.fresh) return error.GpuNativeRecursionSeedProgramCold;
        if (p.fresh) {
            const pinned = try s.pinned(self.class.program.len);
            @memcpy(pinned, self.class.program);
            try s.upload(p.buffer, pinned);
        }
        for (self.children[0..self.n_children], 0..) |c, k| if (c.device != self.device) {
            self.local[k] = try s.alloc(c.region.words);
        };
        self.scratch = try s.alloc(@as(usize, self.class.program[Seed.P.scratch_words]) + 8);
    }
    pub fn enqueue(self: *NodeJob, e: *api.Enqueue) !void {
        const trace_stage: O.Trace.Stage = switch (self.proof_id.kind) {
            .leaf => .leaf,
            .fold => .fold,
            .root => .root,
            else => return error.GpuNativeNotARecursionProof,
        };
        var trace_label: [80]u8 = undefined;
        var trace_range = try e.trace(trace_stage, self.proof_id.ordinal, &trace_label);
        defer trace_range.deinit();
        var t = try std.time.Timer.start();
        try e.waitStaged();
        const in = try self.made.inputs(self.made.ctx);
        var io = Seed.Io{
            .program = self.d_prog.ptr,
            .program_words = self.class.program.len,
            .children = @splat(null),
            .children_words = @splat(0),
            .seeds = in.seeds.ptr,
            .seeds_words = in.seeds.words,
            .scratch = self.scratch.ptr,
            .scratch_words = self.scratch.words,
            .seed_status = &self.verdicts.seed_tape.ptr[0],
            .bind_status = &self.verdicts.child_binding.ptr[0],
            .outputs = in.outputs.ptr,
            .checkpoint = in.channel_seed.ptr,
            .outputs_words = @intCast(in.outputs.words),
            .n_children = self.n_children,
            .n_ops = self.class.program[Seed.P.n_ops],
            .n_caps = self.class.program[Seed.P.n_caps],
        };
        self.launches = 0;
        for (self.children[0..self.n_children], 0..) |c, k| {
            var region = c.region;
            if (self.local[k]) |l| {
                try O.check(self.ops.peer.peer_copy_async(l.ptr, self.device, c.region.ptr, c.device, c.region.words * 4, e.stream()));
                region = l;
                self.launches += 1;
            }
            io.children[k] = region.ptr;
            io.children_words[k] = region.words;
        }
        if (self.ops.seed.fill(e.ctx(), lane, &io) != 0) return error.GnNodeSeedFillEnqueueFailed;
        self.launches += 3 + @as(u32, @intFromBool(io.n_caps != 0));
        self.host_ns += t.lap();
        try self.made.job.vtable.enqueue(self.made.job.ctx, e);
        t.reset();
        // lookup_sum: the body's device check word (job slab) -> request slab.
        const chk = try e.slab.field(.opaque_words, lookup_field_index);
        if (self.ops.d2d(e.ctx(), @ptrCast(self.verdicts.lookup_sum.ptr), @ptrCast(chk.ptr), 4) != 0) return error.GnNodeVerdictCopyFailed;
        // channel_order: the device channel's status latch is 0.
        const state = e.channel.stateBuffer();
        if (self.ops.peer.flags_verdict(state.ptr + 10, 1, 0, self.verdicts.channel_order.ptr, G.Verdict.reject(.channel_order, 1), e.stream()) != 0) return error.GnNodeVerdictEnqueueFailed;
        self.launches += 2;
        self.host_ns += t.read();
    }
    pub fn finish(self: *NodeJob, view: api.SlabView) !void {
        defer self.settled.store(true, .release);
        // GPU-native: publish() reads the request slab's status words.
        return self.made.job.vtable.finish(self.made.job.ctx, view);
    }
    pub fn abort(self: *NodeJob) void {
        defer self.settled.store(true, .release);
        self.made.job.vtable.abort(self.made.job.ctx);
    }
};

test "request custody allocation failure leaves the body owned by its caller" {
    const t = std.testing;
    const Body = struct {
        destroys: u32 = 0,
        fn destroy(raw: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.destroys += 1;
        }
    };
    var body = Body{};
    const job = try t.allocator.create(NodeJob);
    defer t.allocator.destroy(job);
    job.* = undefined;
    job.made = .{ .ctx = &body, .destroy = Body.destroy, .job = undefined, .inputs = undefined };
    var requests = Requests{};
    var failing = std.testing.FailingAllocator.init(t.allocator, .{ .fail_index = 0 });
    try t.expectError(error.OutOfMemory, requests.adopt(failing.allocator(), job));
    try t.expectEqual(@as(usize, 0), requests.count());
    try t.expectEqual(@as(u32, 0), body.destroys);
    requests.deinit(failing.allocator());
    // Custody did not transfer: exactly one explicit caller cleanup remains.
    job.deinit();
    try t.expectEqual(@as(u32, 1), body.destroys);
}
