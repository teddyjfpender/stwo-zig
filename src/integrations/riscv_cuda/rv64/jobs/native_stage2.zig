//! NativeStage2 device transcript (spec §3.5 item 2), from the global χ to the
//! end of the proof, on the job's DeviceChannel. The order is exactly the
//! legacy CpuWorker.complete + generic engine order:
//!
//!   mixManifestAndClaims  (worker_protocol.zig: u32 header {0x57474b32, 1, n},
//!                          manifest digest words, claims as OM31 felts)
//!   INTER commit          (native_commit, root mixed on device)
//!   composition coefficient = drawSecureFelt          (on device)
//!   composition commit    (producer seam, root mixed on device)
//!   OODS + base point + enqueue-only PCS             (native_pcs.enqueueOpening)
//!
//! The composition producer is `NativeComposition` (native_composition.zig:
//! the legacy native composition kernels, powers from the DEVICE
//! coefficient). The INTER columns and claims come from the global
//! interaction producer (native_global.zig) and the binding producer; claims
//! and INTER inputs are device buffers enqueued before `enqueue` is called.
//! A producer may not read the coefficient on the host; the lint covers
//! every file a job imports.
const std = @import("std");
const api = @import("api.zig");
const C = @import("native_commit.zig");
const N = @import("native_pcs.zig");
const NC = @import("native_composition.zig");

pub const manifest_header = [2]u32{ 0x57474b32, 1 };

/// Composition producer seam: enqueue the composition from the device
/// coefficient `alpha` (8 words) over the committed FIXED/MAIN/INTER
/// coefficient views and commit it (root into `root_out`, NOT mixed: Stage2
/// mixes it). Returns the committed tree (coefficient views for the PCS).
/// `NativeComposition` (native_composition.zig) is the native producer.
pub const Composition = struct {
    ctx: *anyopaque,
    enqueue: *const fn (*anyopaque, *api.Enqueue, alpha: api.DeviceBuffer, root_out: api.DeviceBuffer, trees: [3]Committed) anyerror!Committed,
    /// Coefficient views by original column: `tree.coefficients.ptr + offsets[i]`.
    pub const Committed = struct {
        offsets: []const usize,
        tree: C.Committed,
        pub fn of(plan: *const C.CommitPlan, tree: C.Committed) Committed {
            return .{ .offsets = plan.offsets, .tree = tree };
        }
        pub fn columns(self: Committed) NC.Columns {
            return .{ .base = self.tree.coefficients.ptr, .offsets = self.offsets };
        }
    };
};

/// The native composition producer behind the seam: a staged
/// native_composition.Plan, its symbols and a status word (noncanonical alpha).
pub const NativeComposition = struct {
    plan: *const NC.Plan,
    sym: NC.Symbols,
    status: api.DeviceBuffer,
    pub fn producer(self: *NativeComposition) Composition {
        return .{ .ctx = self, .enqueue = enqueueOf };
    }
    fn enqueueOf(raw: *anyopaque, e: *api.Enqueue, alpha: api.DeviceBuffer, root_out: api.DeviceBuffer, trees: [3]Composition.Committed) anyerror!Composition.Committed {
        const self: *NativeComposition = @ptrCast(@alignCast(raw));
        const tree = try self.plan.enqueue(self.sym, e, .{ trees[0].columns(), trees[1].columns(), trees[2].columns() }, alpha.ptr, root_out, self.status.ptr);
        return .{ .offsets = self.plan.offsets, .tree = tree };
    }
};

/// Slab fields (word offsets inside the job slab) for this stage's outputs.
pub const Fields = struct {
    roots: api.DeviceBuffer, // 8 words per tree, FIXED/MAIN first (written by stage 1), INTER at [2], composition at [3]
    alpha: api.DeviceBuffer, // 8 words
    oods: api.DeviceBuffer, // N.oods_field_words
    pcs: api.DeviceBuffer, // PcsJob.outputWords()
};

pub const Stage2 = struct {
    inter: *C.CommitPlan,
    pcs: *N.PcsJob,
    csym: C.Symbols,
    nsym: N.Symbols,
    /// Staged by `stage`: header words and the manifest digest words.
    staged: ?api.DeviceBuffer = null,
    pinned: []u32 = &.{},
    claim_count: u32,

    pub fn stage(self: *Stage2, s: *api.Stager, manifest: [32]u8, inter_inputs: []const C.Input) !void {
        var words: [11]u32 = undefined;
        words[0] = manifest_header[0];
        words[1] = manifest_header[1];
        words[2] = self.claim_count;
        for (words[3..], 0..) |*w, i| w.* = std.mem.readInt(u32, manifest[4 * i ..][0..4], .little);
        const b = try s.alloc(words.len);
        try s.upload(b, &words);
        self.staged = b;
        try self.inter.stage(s, inter_inputs);
        self.pinned = try s.pinned(@intCast(self.pcs.ingressWords()));
    }

    /// `prior`: trees committed before stage 2 (FIXED, MAIN), already mixed;
    /// bound into the PCS as trees 0 and 1. `claims`: device OM31 claims
    /// (8 words each, `claim_count` of them).
    pub fn enqueue(self: *Stage2, e: *api.Enqueue, prior: [2]Composition.Committed, claims: api.DeviceBuffer, inter_inputs: []const C.Input, composition: Composition, fields: Fields) !void {
        const staged = self.staged orelse return error.Stage2NotStaged;
        if (claims.words < @as(usize, self.claim_count) * 8 or fields.roots.words < 32 or fields.alpha.words < 8) return error.InvalidStage2Fields;
        // mixManifestAndClaims: three mixes, exactly as worker_protocol.zig.
        try e.channel.mixWords(.{ .ptr = staged.ptr, .words = 3 });
        try e.channel.mixWords(.{ .ptr = staged.ptr + 3, .words = 8 });
        try e.channel.mixFelts(.{ .ptr = claims.ptr, .words = @as(usize, self.claim_count) * 8 });
        // INTER commit, root mixed on device.
        const inter = try self.inter.enqueue(self.csym, e, inter_inputs, try fields.roots.slice(16, 8), true);
        // Composition coefficient on device; the producer never sees it on the host.
        try e.channel.drawSecureFelts(1, fields.alpha);
        const inter_views = Composition.Committed.of(self.inter, inter);
        const comp = try composition.enqueue(composition.ctx, e, fields.alpha, try fields.roots.slice(24, 8), .{ prior[0], prior[1], inter_views });
        try e.channel.mixRootFromTree(try fields.roots.slice(24, 8));
        // Bind all four trees into the stage-time PCS framing, then the tail.
        const trees = [4]Composition.Committed{ prior[0], prior[1], inter_views, comp };
        for (trees, 0..) |t, index| for (t.offsets, 0..) |offset, original| try self.pcs.bindColumn(index, original, t.tree.coefficients.ptr + offset);
        try self.pcs.enqueueOpening(self.nsym, e, self.pinned, fields.oods, fields.pcs);
        e.free(comp.tree.coefficients);
        e.free(inter.coefficients);
    }
};
