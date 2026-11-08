//! A whole outer node with its proof bytes encoded on the device
//! (outer_encode.zig / NAT/rv64/jobs/outer_encode.cu), as one api.Job.
//!
//! The wrapper adds, after the node body on the same exec stream, ONE
//! encoder launch that reads the node's own device results (the PCS image
//! field, the outer section's claims / status latches / MAIN, INTER and
//! composition roots) plus two staged inputs (the class descriptor, kept in
//! a worker-persistent region per class, and the expected outputs) and writes
//! [length | om31 wire bytes] and the node_pcs_status / encode_bounds Verdict
//! words into a field of the node's slab. Nothing is read back early: the
//! bytes come home with the node's single slab D2H.
//!
//! STWO_RV64_M8_OUTER_DEVICE_ENCODE=check (outer_job_factory.zig) requires
//! the device bytes, the host mirror (outer_encode.encodeHost over the same
//! PCS image) and the host serialisation of the assembled proof
//! (om31 wire.encode) to be identical, node by node; any difference fails
//! the node closed (OuterDeviceEncodeMismatch). The proof bytes the request
//! publishes stay the host's in check mode.
const std = @import("std");
const api = @import("api.zig");
const Slab = @import("slab.zig");
const Job = @import("outer_job.zig");
const Plan = @import("outer_plan.zig");
const K = @import("outer_kernels.zig");
const E = @import("outer_encode.zig");
const G = @import("gpu_native.zig");
const OO = @import("outer_encode_oods.zig");
const Pcs = @import("native_pcs.zig");
const Outer = @import("stwo_circuit_cpu_integration").om31;

/// Slab field: [length word | payload (max_payload_words)] then the two
/// Verdict words [node_pcs_status, encode_bounds].
pub const field_index: u32 = 0x454e_4331; // "ENC1"
/// Slab field of the OODS check: [verdict | evaluated(8) | extracted(8)].
pub const oods_field_index: u32 = 0x4f4f_4331; // "OOC1"
pub const oods_field_words: usize = 17;

/// The device node_oods_constraint check, run after the encoder.
pub const Oods = struct {
    symbols: OO.Symbols,
    program: []const u32,
    key: [32]u8 = undefined,
    buf: api.DeviceBuffer = undefined,
    scratch: api.DeviceBuffer = undefined,
    /// Results (job-slab mode): verdict and [evaluated | extracted].
    verdict: u32 = G.Verdict.unset,
    diag: [16]u32 = @splat(0),
    /// Request-slab status word (GPU-native target); null: job slab field.
    status: ?api.DeviceBuffer = null,
    fn scratchWords(self: *const Oods) usize {
        return @as(usize, self.program[OO.H.scratch_words]) + 9 * @as(usize, self.program[OO.H.parts]);
    }
};

/// om31 wire envelope prefix of an authority: "STWOCOM1" + sha256(domain
/// name of the active profile) + the authority identity (wire.zig encode).
pub fn envelopeFor(identity: [32]u8, n_outputs: usize) !E.Envelope {
    var e = E.Envelope{ .prefix = undefined, .n_outputs = @intCast(n_outputs), .n_claims = Plan.n_components, .latches = Plan.Section.status_words };
    @memcpy(e.prefix[0..8], "STWOCOM1");
    std.crypto.hash.sha2.Sha256.hash(Outer.protocol.domainName(), e.prefix[8..40], .{});
    @memcpy(e.prefix[40..72], &identity);
    if (n_outputs > Outer.wire.MAX_OUTPUTS) return error.Om31CircuitWireLimit;
    return e;
}

/// Descriptor of a node class from its PCS framing (pcs_assembly.Shape).
pub fn descriptorFor(a: std.mem.Allocator, shape: anytype, envelope: ?E.Envelope, fixed_root: ?[32]u8) ![]u32 {
    const trees = try a.alloc(E.TreeShape, shape.trees.len);
    defer a.free(trees);
    for (trees, shape.trees) |*out, t| out.* = .{ .coefficient_logs = t.coefficient_logs, .sorted_to_original = t.sorted_to_original, .sample_counts = t.sample_counts };
    const c = shape.config;
    const config = E.Config{
        .pow_bits = c.pow_bits,
        .log_blowup = c.fri_config.log_blowup_factor,
        .log_last_layer = c.fri_config.log_last_layer_degree_bound,
        .n_queries = std.math.cast(u32, c.fri_config.n_queries) orelse return error.InvalidPcsShape,
        .fold_step = c.fri_config.fold_step,
        .lifting = c.lifting_log_size,
    };
    var root_words: ?[8]u32 = null;
    if (fixed_root) |r| {
        var w: [8]u32 = undefined;
        for (&w, 0..) |*x, i| x.* = std.mem.readInt(u32, r[4 * i ..][0..4], .little);
        root_words = w;
    }
    return E.buildDescriptor(a, .{ .config = config, .degree_log = shape.degree_log, .trees = trees }, envelope, root_words);
}

pub const EncodedNode = struct {
    inner: *Job.OuterNodeJob,
    symbols: E.Symbols,
    /// Class descriptor (host copy; staged into a persistent region keyed by
    /// its content, so every node of a class on a worker shares one upload).
    desc: []const u32,
    desc_key: [32]u8,
    /// Copy of the encoded bytes and verdicts from finish (caller frees with `allocator`).
    allocator: std.mem.Allocator,
    bytes: ?[]u8 = null,
    pcs_verdict: u32 = G.Verdict.unset,
    bounds_verdict: u32 = G.Verdict.unset,
    desc_buf: api.DeviceBuffer = undefined,
    outputs_buf: ?api.DeviceBuffer = null,
    scratch: api.DeviceBuffer = undefined,
    field_words: usize = 0,
    launches: u32 = 0,
    /// CUDA events around the encoder launch only (GPU time; never a sync).
    timing: ?K.Timing = null,
    /// Negative test (outer_encode.faultOrdinal): the PCS image's terminal
    /// value word is set to 0xffffffff on the device before the encoder runs;
    /// node_pcs_status must refuse it (detail noncanonical).
    fault: bool = false,
    /// node_oods_constraint on the device (null: not run).
    oods: ?Oods = null,
    /// CUDA events around the OODS check launch only.
    oods_timing: ?K.Timing = null,
    /// Negative test (outer_encode.oodsFaultOrdinal): composition sample 0's
    /// first coordinate is zeroed on the device (still canonical, so the PCS
    /// checks pass and node_oods_constraint must refuse the node).
    oods_fault: bool = false,
    /// Negative test (outer_encode.oodsPointFaultOrdinal): the OODS field's
    /// status word is set nonzero on the device; node_oods_constraint must
    /// refuse it (detail point).
    oods_point_fault: bool = false,

    /// GPU-native publication target (gpu_native.RequestLayout): the node's
    /// encoded region (length word + capacity) and its two status words in
    /// the request slab segment of its GPU. Null: a field of the node's own
    /// job slab (check mode, read back in finish).
    target: ?Target = null,
    /// GPU-native (gn-node): the node's outputs are device data (the seed
    /// fill's statement kernel wrote them); the encoder reads them here and
    /// no host outputs are uploaded.
    outputs_device: ?api.DeviceBuffer = null,
    /// With `outputs_device` bound after stage: never upload host outputs.
    outputs_on_device: bool = false,
    /// GPU-native (gn-node child seed source): after the bytes, copy the
    /// node's PCS readback image into the LAST image words of the target
    /// region (a parent's seed fill reads it there; publish slices only the
    /// length-word bytes). Needs `target` and `copy` (d2d).
    image_tail: bool = false,
    /// GPU-native publication (gn-node NodeJob): the request slab's device
    /// verdict words are the authority, so finish runs no host decode at all
    /// (no section decode / host lookupSum / PCS image copy): publish() checks
    /// node_pcs_status, encode_bounds, node_oods_constraint, lookup_sum,
    /// seed_tape, child_binding and channel_order on the mirror.
    device_publish: bool = false,
    pub const Target = struct { region: api.DeviceBuffer, pcs_status: api.DeviceBuffer, encode_status: api.DeviceBuffer, layout_status_oods: ?api.DeviceBuffer = null };
    /// The request-slab target of proof `id` (layout of its GPU's segment).
    pub fn targetOf(layout: *const G.SegmentLayout, segment: api.DeviceBuffer, id: G.ProofId) !Target {
        return .{ .region = try layout.encodedBuffer(segment, id), .pcs_status = try layout.statusBuffer(segment, id, .node_pcs_status), .encode_status = try layout.statusBuffer(segment, id, .encode_bounds), .layout_status_oods = try layout.statusBuffer(segment, id, .node_oods_constraint) };
    }

    pub fn init(a: std.mem.Allocator, inner: *Job.OuterNodeJob, symbols: E.Symbols, desc: []const u32) !EncodedNode {
        return initTarget(a, inner, symbols, desc, null);
    }
    pub fn initTarget(a: std.mem.Allocator, inner: *Job.OuterNodeJob, symbols: E.Symbols, desc: []const u32, target: ?Target) !EncodedNode {
        if (inner.whole == null) return error.OuterEncodeNeedsWholeNode;
        var key: [32]u8 = undefined;
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64/m8/outer-encode/descriptor/v1\x00");
        h.update(std.mem.sliceAsBytes(desc));
        key = h.finalResult();
        var self = EncodedNode{ .inner = inner, .symbols = symbols, .desc = desc, .desc_key = key, .allocator = a, .target = target };
        if (target) |t| {
            // The slab entry's capacity must hold the class bound.
            if (t.region.words < 1 + @as(usize, desc[E.D.max_payload_words]) or t.pcs_status.words < 1 or t.encode_status.words < 1) return error.OuterEncodeRegionTooSmall;
            return self;
        }
        self.field_words = 1 + @as(usize, desc[E.D.max_payload_words]) + 2;
        _ = try inner.layout.add(.opaque_words, field_index, self.field_words);
        return self;
    }
    /// Adds the device OODS check (before submission).
    pub fn withOods(self: *EncodedNode, symbols: OO.Symbols, program: []const u32) !void {
        try OO.validate(program);
        var o = Oods{ .symbols = symbols, .program = program };
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64/m8/outer-oods/program/v1\x00");
        h.update(std.mem.sliceAsBytes(program));
        o.key = h.finalResult();
        if (self.target) |t| {
            o.status = t.layout_status_oods orelse return error.OuterOodsTargetMissing;
        } else _ = try self.inner.layout.add(.opaque_words, oods_field_index, oods_field_words);
        self.oods = o;
    }
    pub fn deinit(self: *EncodedNode) void {
        if (self.bytes) |b| self.allocator.free(b);
        self.bytes = null;
    }
    pub fn job(self: *EncodedNode) api.Job {
        return api.Job.from(EncodedNode, self);
    }
    pub fn classKey(self: *EncodedNode) [32]u8 {
        return self.inner.classKey();
    }
    fn g(words: u64) u64 {
        return std.mem.alignForward(u64, @max(words, 1), 64);
    }
    fn extraStaged(self: *const EncodedNode) u64 {
        var n = g(self.desc[E.D.scratch_words]) + g(self.inner.staged.expected.len);
        if (self.oods) |*o| n += g(o.scratchWords());
        return n;
    }
    pub fn footprint(self: *EncodedNode) api.Footprint {
        var fp = self.inner.footprint();
        if (self.target != null and self.device_publish) fp.readback = .request_slab;
        const extra = self.extraStaged();
        fp.device_words += @intCast(extra);
        fp.staged_words += @intCast(extra);
        // Descriptor (persistent, outside the window) and outputs come from pinned memory.
        fp.pinned_words += self.desc.len + self.inner.staged.expected.len;
        if (self.oods) |*o| fp.pinned_words += o.program.len;
        return fp;
    }
    pub fn stage(self: *EncodedNode, s: *api.Stager) !void {
        try self.inner.stage(s);
        const p = try s.persistent(self.desc_key, self.desc.len);
        self.desc_buf = p.buffer;
        if (self.inner.require_warm and p.fresh) return error.GpuNativeRecursionEncoderCold;
        if (p.fresh) {
            const pinned = try s.pinned(self.desc.len);
            @memcpy(pinned, self.desc);
            try s.upload(p.buffer, pinned);
        }
        const outputs = self.inner.staged.expected;
        if (self.outputs_device != null or self.outputs_on_device) {} else if (outputs.len != 0) {
            const b = try s.alloc(outputs.len);
            const pinned = try s.pinned(outputs.len);
            @memcpy(pinned, outputs);
            try s.upload(b, pinned);
            self.outputs_buf = b;
        }
        self.scratch = try s.alloc(self.desc[E.D.scratch_words]);
        if (self.oods) |*o| {
            const q = try s.persistent(o.key, o.program.len);
            o.buf = q.buffer;
            if (self.inner.require_warm and q.fresh) return error.GpuNativeRecursionEncoderCold;
            if (q.fresh) {
                const pinned = try s.pinned(o.program.len);
                @memcpy(pinned, o.program);
                try s.upload(q.buffer, pinned);
            }
            o.scratch = try s.alloc(o.scratchWords());
        }
    }
    pub fn enqueue(self: *EncodedNode, e: *api.Enqueue) !void {
        try self.inner.enqueue(e);
        const S = Plan.Section;
        const section = try e.slab.field(.opaque_words, Job.section_index);
        const pcs = try e.slab.field(.opaque_words, Job.pcs_index);
        // Region [length | payload] and the two status words: the request
        // slab (GPU-native) or the job slab field (check mode).
        var region: [*]u32 = undefined;
        var region_words: usize = 0;
        var pcs_status: [*]u32 = undefined;
        var encode_status: [*]u32 = undefined;
        if (self.target) |t| {
            region = t.region.ptr;
            region_words = t.region.words;
            pcs_status = t.pcs_status.ptr;
            encode_status = t.encode_status.ptr;
        } else {
            const out = try e.slab.field(.opaque_words, field_index);
            region = out.ptr;
            region_words = out.words - 2;
            pcs_status = out.ptr + region_words;
            encode_status = out.ptr + region_words + 1;
        }
        // Tree 0's expected root: when the node commits FIXED itself, the root
        // it mixed into the transcript (section), which the encoder also
        // requires to equal the class root (D.flag_fixed_root, host check
        // InvalidOm31DeviceFixedRoot); otherwise the class root.
        const fixed_root: [*]const u32 = if (self.inner.fixed_commit != null) section.ptr + S.fixed_root else self.desc_buf.ptr + E.D.fixed_root;
        if (self.desc[E.D.flags] & E.D.flag_fixed_root == 0) return error.OuterEncodeFixedRootMissing;
        const io = E.Io{
            .desc = self.desc_buf.ptr,
            .desc_words = self.desc.len,
            .image = pcs.ptr,
            .image_words = pcs.words,
            .roots = .{ fixed_root, section.ptr + S.main_root, section.ptr + S.inter_root, section.ptr + S.composition_root },
            .claims = section.ptr + S.claims,
            .latches = section.ptr + S.status,
            .outputs = if (self.outputs_device) |b| b.ptr else if (self.outputs_on_device) return error.OuterEncodeOutputsUnbound else if (self.outputs_buf) |b| b.ptr else null,
            .claims_words = 8 * Plan.n_components,
            .latches_words = S.status_words,
            .outputs_words = @intCast(self.inner.staged.expected.len),
            .region = region,
            .region_words = region_words,
            .pcs_status = pcs_status,
            .encode_status = encode_status,
            .scratch = self.scratch.ptr,
            .scratch_words = self.scratch.words,
        };
        if (self.fault) {
            const im = E.Image.of(self.desc);
            if (im.terminal >= pcs.words) return error.OuterEncodeFaultOutOfRange;
            if (self.inner.kernels.memset(e.ctx(), @ptrCast(pcs.ptr + im.terminal), 0xff, 4) != 0) return error.OuterEncodeEnqueueFailed;
        }
        if (self.timing) |t| t.mark(t.ctx, false, e.stream());
        const rc = self.symbols.encode(e.ctx(), K.lane, &io);
        if (self.timing) |t| t.mark(t.ctx, true, e.stream());
        if (rc != 0) {
            std.log.err("OUTER_ENCODE enqueue failed rc={d}", .{rc});
            return error.OuterEncodeEnqueueFailed;
        }
        self.launches = 1;
        if (self.image_tail) {
            const t = self.target orelse return error.OuterEncodeImageTailNeedsTarget;
            if (t.region.words < 1 + @as(usize, self.desc[E.D.max_payload_words]) + pcs.words) return error.OuterEncodeRegionTooSmall;
            const at = t.region.words - pcs.words;
            if (self.inner.kernels.d2d(e.ctx(), @ptrCast(t.region.ptr + at), @ptrCast(pcs.ptr), pcs.words * 4) != 0) return error.OuterEncodeEnqueueFailed;
            self.launches += 1;
        }
        if (self.oods) |*o| {
            const im = E.Image.of(self.desc);
            if (self.oods_fault) {
                const at = im.samples + 8 * @as(u64, o.program[OO.H.composition_sample]);
                if (at >= pcs.words) return error.OuterEncodeFaultOutOfRange;
                // Corrupt before the encoder would also change the bytes; the
                // check reads the same image, so order relative to it is moot.
                if (self.inner.kernels.memset(e.ctx(), @ptrCast(pcs.ptr + at), 0, 4) != 0) return error.OuterEncodeEnqueueFailed;
            }
            const point = try e.slab.field(.opaque_words, Job.oods_index);
            // The kernel reads the whole field (point + its status word).
            if (point.words < Pcs.oods_field_words) return error.OuterOodsPointFieldTooSmall;
            if (self.oods_point_fault) {
                if (self.inner.kernels.memset(e.ctx(), @ptrCast(point.ptr + Pcs.oods_field_words - 1), 0x01, 4) != 0) return error.OuterEncodeEnqueueFailed;
            }
            var verdict: [*]u32 = undefined;
            var diag: ?[*]u32 = null;
            if (o.status) |st| verdict = st.ptr else {
                const f = try e.slab.field(.opaque_words, oods_field_index);
                verdict = f.ptr;
                diag = f.ptr + 1;
            }
            const oio = OO.Io{
                .desc = o.buf.ptr,
                .desc_words = o.program.len,
                .samples = pcs.ptr + im.samples,
                .sample_words = @as(u64, self.desc[E.D.samples]) * 8,
                .claims = section.ptr + S.claims,
                .challenges = section.ptr + S.challenges,
                .point = point.ptr,
                .scratch = o.scratch.ptr,
                .scratch_words = o.scratch.words,
                .verdict = verdict,
                .diag = diag,
            };
            if (self.oods_timing) |t| t.mark(t.ctx, false, e.stream());
            const orc = o.symbols.check(e.ctx(), K.lane, &oio);
            if (self.oods_timing) |t| t.mark(t.ctx, true, e.stream());
            if (orc != 0) {
                std.log.err("OUTER_OODS enqueue failed rc={d}", .{orc});
                return error.OuterOodsEnqueueFailed;
            }
            self.launches += 1;
        }
    }
    pub fn finish(self: *EncodedNode, view: api.SlabView) !void {
        if (self.timing) |t| t.resolve(t.ctx);
        if (self.oods_timing) |t| t.resolve(t.ctx);
        // GPU-native: gpu_native.publish reads the request slab mirror.
        if (self.target != null) {
            if (!self.device_publish) return self.inner.finish(view);
            self.inner.finished = true;
            self.inner.report.receipt = view.receipt;
            if (self.inner.timing) |t| t.resolve(t.ctx);
            return;
        }
        // Device verdicts first (the authority on the GPU-native path), then
        // the host reference in inner.finish: a device refusal is reported
        // as the device's, even where a host check would also refuse.
        if (self.oods) |*o| {
            const w = try Slab.read(view, .opaque_words, oods_field_index);
            o.verdict = w[0];
            @memcpy(&o.diag, w[1..17]);
        }
        const words = try Slab.read(view, .opaque_words, field_index);
        const payload_words = words.len - 2;
        self.pcs_verdict = words[payload_words];
        self.bounds_verdict = words[payload_words + 1];
        if (self.pcs_verdict != G.Verdict.accepted or self.bounds_verdict != G.Verdict.accepted) {
            std.debug.print("GPU_M8_OUTER_ENCODE rejected ordinal={d} pcs=0x{x} bounds=0x{x}\n", .{ self.inner.staged.ordinal, self.pcs_verdict, self.bounds_verdict });
            return error.OuterDeviceEncodeRejected;
        }
        if (self.oods) |o| if (o.verdict != G.Verdict.accepted) {
            std.debug.print("GPU_M8_OUTER_OODS rejected ordinal={d} verdict=0x{x}\n", .{ self.inner.staged.ordinal, o.verdict });
            return error.OuterDeviceOodsRejected;
        };
        try self.inner.finish(view);
        const n = words[0];
        if (n % 4 != 0 or n / 4 > payload_words - 1) return error.OuterEncodeLengthOutOfRange;
        const bytes = try self.allocator.alloc(u8, n);
        for (0..n / 4) |i| std.mem.writeInt(u32, bytes[4 * i ..][0..4], words[1 + i], .little);
        self.bytes = bytes;
    }
    pub fn abort(self: *EncodedNode) void {
        self.inner.abort();
    }
};
