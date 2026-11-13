//! Producer diagnostics owner: native encoder mirror, seed binding and optional captures.
const Timer = @import("outer_gpu_timer.zig");
const Schema = @import("outer_job_factory.zig");
const std = @import("std");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const Prestage = @import("outer_job_prestage.zig");
const K = @import("jobs/outer_kernels.zig");
const Job = @import("jobs/outer_job.zig");
const api = @import("jobs/api.zig");
const Events = @import("cuda_events.zig");
const Enc = @import("jobs/outer_encode.zig");
const EncJob = @import("jobs/outer_encode_job.zig");
const OodsAbi = @import("jobs/outer_encode_oods.zig");
const Seed = @import("jobs/outer_seed_device.zig");
const GnRecord = @import("outer_seed_record.zig");

pub const Recorder = struct {
    const Rec = @import("outer_seed_record.zig");
    pub const magic = Rec.node_magic;
    pub const dir = Rec.dir;
    pub fn words8(bytes: [32]u8) [8]u32 {
        var w: [8]u32 = undefined;
        for (&w, 0..) |*x, i| x.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
        return w;
    }
    pub fn write(a: std.mem.Allocator, input: Prestage.Input, staged: *const @import("jobs/outer_staged.zig").Staged, job: *Job.OuterNodeJob, produced: *const Outer.prove.Produced, image: []const u32) !void {
        const path = dir() orelse return;
        const wire = try Outer.wire.encode(a, input.key.identity, produced.outputs, produced.claims, &produced.proof.proof);
        defer a.free(wire);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(wire, &digest, .{});
        var out: std.ArrayListUnmanaged(u32) = .empty;
        defer out.deinit(a);
        try out.appendSlice(a, &.{ magic, 2, input.ordinal, @intFromBool(input.is_leaf) });
        try out.appendSlice(a, &words8(input.key.identity));
        try out.appendSlice(a, &words8(staged.fixed_root));
        try out.appendSlice(a, &words8(input.class orelse @splat(0)));
        try out.appendSlice(a, &staged.checkpoint);
        try out.append(a, @intCast(staged.expected.len));
        try out.appendSlice(a, staged.expected);
        try out.append(a, @intCast(staged.assignment.seeds.len));
        try out.appendSlice(a, staged.assignment.seeds);
        try Rec.appendShape(a, &out, job.pcs.?.prepared.metadata.shape);
        try out.append(a, @intCast(image.len));
        try out.appendSlice(a, image);
        const claims = produced.claims.toArray();
        try out.append(a, @intCast(claims.len * 8));
        for (claims) |cl| for (cl.toM31Array()) |m| try out.append(a, m.v);
        try out.append(a, @intCast(wire.len));
        const at = out.items.len;
        try out.appendNTimes(a, 0, (wire.len + 3) / 4);
        @memcpy(std.mem.sliceAsBytes(out.items[at..])[0..wire.len], wire);
        // Class transcript prefix (om31 prove.begin before the statement
        // words): the digest after the config and profile mixes, draws.
        {
            var channel = Outer.protocol.Channel.init();
            (try Outer.protocol.targetConfig()).mixInto(&channel);
            Outer.protocol.mixProfile(&channel);
            const cp = @import("stwo_core").channel.raw_mod_m31.om31Checkpoint(&channel);
            for (0..8) |i| try out.append(a, std.mem.readInt(u32, cp.digest[4 * i ..][0..4], .little));
            try out.append(a, cp.draws);
        }
        var name_buf: [96]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "node-{d:0>4}-{x}.gnr", .{ input.ordinal, digest[0..8].* });
        if (try Rec.writeOnce(path, name, out.items)) std.debug.print("GN_NODE_RECORD ordinal={d} leaf={} seeds={d} image_words={d} wire_bytes={d} file={s}\n", .{ input.ordinal, input.is_leaf, staged.assignment.seeds.len / 5, image.len, wire.len, name });
    }
};

/// STWO_RV64_M8_OUTER_DEVICE_ENCODE=check: one node's device encoding next
/// to the host bytes. Three byte strings must be identical: the device
/// encoder's (outer_encode.cu, in-stream after the body), the host mirror's
/// (outer_encode.encodeHost over the same PCS image words) and the host
/// serialisation of the assembled proof (om31 wire.encode, the bytes the
/// request publishes and the pipeline writes as the node file). Any
/// difference or a non-accepted device verdict fails the node closed.
pub const EncodeCheck = struct {
    desc: []u32,
    program: ?[]u32 = null,
    oods_timer: ?Timer.GpuTimer = null,
    host_oods: [16]u32 = @splat(0),
    node: EncJob.EncodedNode,
    timer: ?Timer.GpuTimer = null,
    mirror_bytes: ?[]u8 = null,
    mirror_ns: u64 = 0,
    host_bytes: u64 = 0,
    pub fn init(a: std.mem.Allocator, job: *Job.OuterNodeJob, shared: *const Schema.Shared, key: *const Prestage.Authority, staged: *const @import("jobs/outer_staged.zig").Staged) !EncodeCheck {
        const shape = job.pcs.?.prepared.metadata.shape;
        const desc = try EncJob.descriptorFor(a, shape, try EncJob.envelopeFor(key.identity, staged.expected.len / 4), staged.fixed_root);
        errdefer a.free(desc);
        var out = EncodeCheck{ .desc = desc, .node = try EncJob.EncodedNode.init(a, job, shared.encode.?, desc), .timer = if (shared.events) |*ev| Timer.GpuTimer{ .api = ev } else null, .oods_timer = if (shared.events) |*ev| Timer.GpuTimer{ .api = ev } else null };
        errdefer out.node.deinit();
        if (shared.oods) |sym| {
            const counts = try a.alloc([]const u32, shape.trees.len);
            defer a.free(counts);
            for (counts, shape.trees) |*c, t| c.* = t.sample_counts;
            const program = try Prestage.oodsProgram(a, key, counts);
            errdefer a.free(program);
            try out.node.withOods(sym, program);
            out.program = program;
        }
        return out;
    }
    /// After init has been moved to its final address (the timer pointer).
    pub fn arm(self: *EncodeCheck) void {
        if (self.timer) |*t| self.node.timing = t.timing();
        if (self.oods_timer) |*t| self.node.oods_timing = t.timing();
    }
    pub fn deinit(self: *EncodeCheck, a: std.mem.Allocator) void {
        self.node.deinit();
        if (self.timer) |*t| t.deinit();
        if (self.oods_timer) |*t| t.deinit();
        if (self.program) |p| a.free(p);
        if (self.mirror_bytes) |b| a.free(b);
        a.free(self.desc);
    }
    fn words8(root: [32]u8) [8]u32 {
        var w: [8]u32 = undefined;
        for (&w, 0..) |*x, i| x.* = std.mem.readInt(u32, root[4 * i ..][0..4], .little);
        return w;
    }
    pub fn mirror(self: *EncodeCheck, a: std.mem.Allocator, job: *Job.OuterNodeJob, staged: anytype) !void {
        if (self.node.pcs_verdict != 0 or self.node.bounds_verdict != 0) {
            std.debug.print("GPU_M8_OUTER_ENCODE rejected ordinal={d} pcs=0x{x} bounds=0x{x}\n", .{ staged.ordinal, self.node.pcs_verdict, self.node.bounds_verdict });
            return error.OuterDeviceEncodeRejected;
        }
        if (self.node.oods) |o| if (o.verdict != 0) {
            std.debug.print("GPU_M8_OUTER_OODS rejected ordinal={d} verdict=0x{x}\n", .{ staged.ordinal, o.verdict });
            return error.OuterDeviceOodsRejected;
        };
        var timer = try std.time.Timer.start();
        const d = job.decoded orelse return error.OuterJobNotDecoded;
        const fixed = words8(staged.fixed_root);
        const main = words8(d.main_root);
        const inter = words8(d.inter_root);
        const comp = words8(job.composition_root);
        var claims: [8 * @import("jobs/outer_plan.zig").n_components]u32 = undefined;
        for (d.claims.toArray(), 0..) |c, i| for (c.toM31Array(), 0..) |m, k| {
            claims[8 * i + k] = m.v;
        };
        const latches: [4]u32 = @splat(0);
        const out = try a.alloc(u32, self.desc[Enc.D.max_payload_words] + 1);
        defer a.free(out);
        const v = try Enc.encodeHost(a, self.desc, job.pcs_words, .{ .roots = .{ &fixed, &main, &inter, &comp }, .claims = &claims, .latches = &latches, .outputs = staged.expected }, out);
        if (v.pcs != 0 or v.bounds != 0) {
            std.debug.print("GPU_M8_OUTER_ENCODE mirror_rejected ordinal={d} pcs=0x{x} bounds=0x{x}\n", .{ staged.ordinal, v.pcs, v.bounds });
            return error.OuterHostEncodeRejected;
        }
        const bytes = try a.alloc(u8, out[0]);
        for (0..out[0] / 4) |i| std.mem.writeInt(u32, bytes[4 * i ..][0..4], out[1 + i], .little);
        self.mirror_bytes = bytes;
        self.mirror_ns = timer.read();
    }
    pub fn compare(self: *EncodeCheck, a: std.mem.Allocator, key: *const Prestage.Authority, produced: *const Outer.prove.Produced, ordinal: u32) !void {
        const host = try Outer.wire.encode(a, key.identity, produced.outputs, produced.claims, &produced.proof.proof);
        defer a.free(host);
        self.host_bytes = host.len;
        const device = self.node.bytes orelse return error.OuterDeviceEncodeMissing;
        const mirror_bytes = self.mirror_bytes orelse return error.OuterDeviceEncodeMissing;
        const dev_eq = std.mem.eql(u8, device, host);
        const mir_eq = std.mem.eql(u8, mirror_bytes, host);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(host, &digest, .{});
        std.debug.print("GPU_M8_OUTER_ENCODE ordinal={d} host_bytes={d} device_bytes={d} mirror_bytes={d} device_identical={} mirror_identical={} sha256={x} encode_gpu_ns={d} mirror_ns={d} launches={d}\n", .{ ordinal, host.len, device.len, mirror_bytes.len, dev_eq, mir_eq, digest[0..8].*, if (self.timer) |t| t.ns else 0, self.mirror_ns, self.node.launches });
        if (self.node.oods) |o| {
            const values_eq = std.mem.eql(u32, &o.diag, &self.host_oods);
            std.debug.print("GPU_M8_OUTER_OODS ordinal={d} verdict=0x{x} values_identical={} oods_gpu_ns={d} parts={d}\n", .{ ordinal, o.verdict, values_eq, if (self.oods_timer) |t| t.ns else 0, if (self.program) |p| p[OodsAbi.H.parts] else 0 });
            if (o.verdict != 0 or !values_eq) return error.OuterDeviceOodsMismatch;
        }
        if (!dev_eq or !mir_eq) {
            const n = @min(@min(device.len, host.len), mirror_bytes.len);
            var first: usize = n;
            for (0..n) |i| if (device[i] != host[i] or mirror_bytes[i] != host[i]) {
                first = i;
                break;
            };
            std.debug.print("GPU_M8_OUTER_ENCODE mismatch ordinal={d} first_byte={d}\n", .{ ordinal, first });
            return error.OuterDeviceEncodeMismatch;
        }
    }
};

/// STWO_RV64_M8_GN_NODE=check (default off): the node's assignment seeds,
/// transcript checkpoint and (with device checks) expected outputs come from
/// the DEVICE seed fill + statement kernel (jobs/outer_seed_device.zig,
/// NAT/rv64/jobs/outer_seed.cu) over its children's seed sources, not from
/// the host. The host values are erased before staging (seed limbs and the
/// checkpoint are zeroed), so a node proof that passes the gate's byte
/// identity was proved from device-filled inputs. Children are found in
/// GnRecord.Live (stand-in for the request slab: their wire bytes + PCS
/// image are uploaded as this node's child regions). A leaf's native child
/// supplies its PCS image; its statement tail (ordinal, digests, GKR values,
/// request words) and outputs are the native producer's words, taken here
/// from the host seeds / expected outputs before they are erased.
/// Verdicts seed_tape / child_binding and the device outputs/checkpoint copy
/// are read back from the node's job slab and must match the host values.
fn gnFaultOrdinal() !?u32 {
    const two = std.posix.getenv("STWO_RV64_M8_FAULT_INJECTION") orelse return null;
    if (!std.mem.eql(u8, two, "1")) return null;
    const v = std.posix.getenv("STWO_RV64_M8_GN_NODE_FAULT_ORDINAL") orelse return null;
    return std.fmt.parseInt(u32, v, 10) catch error.InvalidGnNodeFaultOrdinal;
}
pub const GnCheck = struct {
    pub const field_index: u32 = 0x474e_4f44; // "GNOD"
    /// Fold children: om31 node proofs under the diet-wire profile (fold
    /// Merkle cap 2^3); leaf children: native proofs with full paths.
    pub const cap_log: u32 = 3;
    pub const leaf_cap_log: u32 = 0;
    const fold_domain: u32 = 0x4f464c31;
    /// >= 1 + the largest om31 node wire in words: 759,512 B on 24628607 /
    /// 26235156 [M] (189,879 words); 2^18 words = 1 MiB of bytes.
    pub const wire_words: u32 = 1 << 18;
    outer: *Job.OuterNodeJob,
    next: api.Job = undefined,
    encoder: ?*EncJob.EncodedNode = null,
    symbols: Seed.Symbols,
    program: Seed.Program,
    prog_key: [32]u8,
    regions: [][]u32,
    expected: []u32, // host copy (comparison; restored before host assembly)
    checkpoint: [9]u32, // host copy (comparison)
    field_words: usize,
    d_prog: api.DeviceBuffer = undefined,
    d_regions: [Seed.max_children]api.DeviceBuffer = undefined,
    d_scratch: api.DeviceBuffer = undefined,
    d_outputs: ?api.DeviceBuffer = null,
    timer: ?Timer.GpuTimer = null,
    report: Schema.GnReport = .{},
    host_timer_ns: u64 = 0,
    seed_status: u32 = 0xffff_ffff,
    bind_status: u32 = 0xffff_ffff,
    dev_outputs: [64]u32 = @splat(0),
    dev_checkpoint: [9]u32 = @splat(0),
    /// What NodeClasses.harvest keeps of this node's class (owned).
    harvest: Harvest = .{},
    const Harvest = struct {
        vars: []u32 = &.{},
        constants: [][4]u32 = &.{},
        shapes: [Seed.max_children][]u32 = @splat(&.{}),
        identities: [Seed.max_children][8]u32 = undefined,
        fixed_roots: [Seed.max_children][8]u32 = undefined,
        n_outputs: [Seed.max_children]u32 = @splat(0),
        n: usize = 0,
        tail: u32 = 0,
        statement: Seed.Statement = undefined,
        fn deinit(self: *Harvest, a: std.mem.Allocator) void {
            a.free(self.vars);
            a.free(self.constants);
            for (self.shapes[0..self.n]) |x| a.free(x);
        }
    };

    pub fn init(a: std.mem.Allocator, input: Prestage.Input, staged: *@import("jobs/outer_staged.zig").Staged, node_job: *Job.OuterNodeJob, symbols: Seed.Symbols, events: ?*const Events.Api) !GnCheck {
        var warm = try std.time.Timer.start();
        const seeds = staged.assignment.seeds;
        const n = seeds.len / 5;
        const vars = try a.alloc(u32, n);
        defer a.free(vars);
        for (vars, 0..) |*v, i| v.* = seeds[5 * i];
        var found: std.ArrayListUnmanaged(GnRecord.Live.Found) = .empty;
        defer {
            for (found.items) |*f| f.deinit(a);
            found.deinit(a);
        }
        try GnRecord.Live.find(a, seeds, !input.is_leaf, &found);
        if (found.items.len == 0 or (input.is_leaf and found.items.len != 1) or found.items.len > Seed.max_children) {
            std.debug.print("GN_NODE ordinal={d} error=GnNodeChildrenNotFound found={d} leaf={}\n", .{ input.ordinal, found.items.len, input.is_leaf });
            return error.GnNodeChildrenNotFound;
        }
        const n_out = staged.expected.len;
        var prefix: [8]u32 = undefined;
        {
            var channel = Outer.protocol.Channel.init();
            (try Outer.protocol.targetConfig()).mixInto(&channel);
            Outer.protocol.mixProfile(&channel);
            const cp = @import("stwo_core").channel.raw_mod_m31.om31Checkpoint(&channel);
            if (cp.draws != 0) return error.GnNodePrefixDraws;
            for (&prefix, 0..) |*w, i| w.* = std.mem.readInt(u32, cp.digest[4 * i ..][0..4], .little);
        }
        const identity = Recorder.words8(input.key.identity);
        const fixed_root = Recorder.words8(staged.fixed_root);
        var classes: [Seed.max_children]Seed.ChildClass = undefined;
        var shapes: [Seed.max_children]Seed.Shape = undefined;
        var shaped: usize = 0;
        defer for (shapes[0..shaped]) |sh| a.free(sh.trees);
        for (found.items, 0..) |f, k| {
            var at: usize = 0;
            shapes[k] = try Seed.Shape.parse(a, f.entry.shape, &at);
            shaped += 1;
            classes[k] = .{ .shape = shapes[k], .wire_words = wire_words, .n_outputs = f.entry.n_outputs, .identity = f.entry.identity, .fixed_root = f.entry.fixed_root };
        }
        const regions = try a.alloc([]u32, found.items.len);
        var made: usize = 0;
        errdefer {
            for (regions[0..made]) |x| a.free(x);
            a.free(regions);
        }
        var program: Seed.Program = undefined;
        if (input.is_leaf) {
            const f = found.items[0];
            const s0 = f.at;
            const proof_len = try Seed.leafTapeLength(a, classes[0], leaf_cap_log);
            if (s0 + proof_len > n) return error.GnNodeLeafTapeTooLong;
            const tail: u32 = @intCast(n - s0 - proof_len);
            const outputs_at: u32 = @intCast(wire_words + f.entry.image.len + 4 * tail);
            const constants = try a.alloc([4]u32, s0);
            defer a.free(constants);
            for (constants, 0..) |*c, j| c.* = seeds[5 * j + 1 ..][0..4].*;
            program = try Seed.buildLeaf(a, classes[0], leaf_cap_log, tail, vars, constants, .{ .kind = 2, .outputs_at = outputs_at, .domain = 0, .version_word = 0, .n_outputs = @intCast(n_out / 4), .prefix = prefix, .identity = identity, .fixed_root = fixed_root, .profile = @splat(0) });
            errdefer program.deinit(a);
            // [len][wire placeholder][image][statement tail][outputs]: the
            // native producer's words (from the host values, erased below).
            const region = try a.alloc(u32, outputs_at + n_out);
            @memset(region, 0);
            region[0] = 1;
            @memcpy(region[wire_words..][0..f.entry.image.len], f.entry.image);
            for (0..tail) |j| @memcpy(region[wire_words + f.entry.image.len + 4 * j ..][0..4], seeds[5 * (s0 + proof_len + j) + 1 ..][0..4]);
            @memcpy(region[outputs_at..][0..n_out], staged.expected);
            regions[0] = region;
            made = 1;
        } else {
            const tape = try Seed.tapeLength(classes[0..found.items.len], cap_log, a);
            if (tape > n) return error.GnNodeFoldTapeTooLong;
            const constants = try a.alloc([4]u32, n - tape);
            defer a.free(constants);
            for (constants, 0..) |*c, j| c.* = seeds[5 * j + 1 ..][0..4].*;
            for (found.items, 0..) |f, k| {
                const L = try Seed.Layout.of(shapes[k]);
                const need = (f.entry.wire.len + 3) / 4 + 1;
                if (need > wire_words or f.entry.image.len != L.words) return error.GnNodeChildRegion;
                const region = try a.alloc(u32, wire_words + f.entry.image.len);
                @memset(region, 0);
                region[0] = @intCast(f.entry.wire.len);
                @memcpy(std.mem.sliceAsBytes(region[1..need])[0..f.entry.wire.len], f.entry.wire);
                @memcpy(region[wire_words..], f.entry.image);
                regions[k] = region;
                made += 1;
            }
            var profile: [8]u32 = undefined;
            @memcpy(&profile, regions[0][3..11]);
            const arity = found.items.len;
            program = try Seed.buildFold(a, classes[0..arity], cap_log, vars, constants, .{ .domain = fold_domain, .version_word = if (arity == 2) 2 else (@as(u32, @intCast(arity)) << 8) | 2, .n_outputs = @intCast(n_out / 4), .prefix = prefix, .identity = identity, .fixed_root = fixed_root, .profile = profile });
        }
        errdefer program.deinit(a);
        var harvest = Harvest{ .vars = try a.dupe(u32, vars), .n = found.items.len };
        errdefer harvest.deinit(a);
        {
            const n_const: usize = program.header(Seed.P.n_constants);
            harvest.constants = try a.alloc([4]u32, n_const);
            for (harvest.constants, 0..) |*c, j| c.* = seeds[5 * j + 1 ..][0..4].*;
        }
        for (found.items, 0..) |f, k| {
            harvest.shapes[k] = try a.dupe(u32, f.entry.shape);
            harvest.identities[k] = f.entry.identity;
            harvest.fixed_roots[k] = f.entry.fixed_root;
            harvest.n_outputs[k] = f.entry.n_outputs;
        }
        harvest.tail = if (input.is_leaf) @intCast(n - found.items[0].at - try Seed.leafTapeLength(a, classes[0], leaf_cap_log)) else 0;
        harvest.statement = .{ .kind = program.header(Seed.P.statement), .outputs_at = program.header(Seed.P.outputs_at), .domain = program.header(Seed.P.domain), .version_word = program.header(Seed.P.version_word), .n_outputs = program.header(Seed.P.n_outputs), .prefix = prefix, .identity = identity, .fixed_root = fixed_root, .profile = program.words[program.header(Seed.P.profile)..][0..8].* };
        // Negative test (two-key: STWO_RV64_M8_FAULT_INJECTION=1 and
        // STWO_RV64_M8_GN_NODE_FAULT_ORDINAL=n): one MAIN-tree Merkle path
        // word of child 0's image flips; seed_tape must refuse the node.
        if (try gnFaultOrdinal()) |f| if (f == input.ordinal) {
            const L = try Seed.Layout.of(shapes[0]);
            regions[0][wire_words + L.trees[1].paths] ^= 1;
            std.debug.print("GN_NODE fault_injected ordinal={d}\n", .{input.ordinal});
        };
        var key: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(std.mem.sliceAsBytes(program.words), &key, .{});
        // Erase the host values: the node can only be proved from the device's.
        const host_expected = try a.dupe(u32, staged.expected);
        errdefer a.free(host_expected);
        const host_checkpoint = staged.checkpoint;
        const writable: []u32 = @constCast(staged.assignment.seeds);
        for (0..n) |i| @memset(writable[5 * i + 1 ..][0..4], 0);
        staged.checkpoint = @splat(0);
        if (staged.image.expected.words != 0) @memset(@constCast(staged.expected), 0);
        var self = GnCheck{ .outer = node_job, .symbols = symbols, .program = program, .prog_key = key, .regions = regions, .expected = host_expected, .checkpoint = host_checkpoint, .field_words = 32 + n_out, .harvest = harvest };
        _ = try node_job.layout.add(.opaque_words, field_index, self.field_words);
        self.timer = if (events) |ev| Timer.GpuTimer{ .api = ev } else null;
        self.report = .{ .ran = true, .children = @intCast(found.items.len), .seeds = n, .warm_ns = warm.read(), .launches = 4 };
        for (regions) |x| self.report.source_words += x.len;
        return self;
    }
    pub fn arm(self: *GnCheck) void {
        _ = self;
    }
    pub fn deinit(self: *GnCheck, a: std.mem.Allocator) void {
        self.harvest.deinit(a);
        if (self.timer) |*t| t.deinit();
        self.program.deinit(a);
        for (self.regions) |x| a.free(x);
        a.free(self.regions);
        a.free(self.expected);
    }
    pub fn job(self: *GnCheck) api.Job {
        return api.Job.from(GnCheck, self);
    }
    pub fn classKey(self: *GnCheck) [32]u8 {
        return self.next.classKey();
    }
    fn g(words: u64) u64 {
        return std.mem.alignForward(u64, @max(words, 1), 64);
    }
    fn extra(self: *const GnCheck) u64 {
        var n = g(@as(u64, self.program.header(Seed.P.scratch_words)) + 8) + g(self.expected.len);
        for (self.regions) |x| n += g(x.len);
        return n;
    }
    pub fn footprint(self: *GnCheck) api.Footprint {
        var fp = self.next.footprint();
        const x = self.extra();
        fp.device_words += @intCast(x);
        fp.staged_words += @intCast(x);
        fp.pinned_words += self.program.words.len;
        for (self.regions) |r| fp.pinned_words += r.len;
        return fp;
    }
    pub fn stage(self: *GnCheck, s: *api.Stager) !void {
        try self.next.vtable.stage(self.next.ctx, s);
        var t = try std.time.Timer.start();
        const p = try s.persistent(self.prog_key, self.program.words.len);
        self.d_prog = p.buffer;
        if (p.fresh) {
            const pinned = try s.pinned(self.program.words.len);
            @memcpy(pinned, self.program.words);
            try s.upload(p.buffer, pinned);
        }
        // Check mode only: the children's seed sources (GPU-native: their
        // request-slab regions, already on the device).
        for (self.regions, 0..) |x, k| {
            self.d_regions[k] = try s.alloc(x.len);
            const pinned = try s.pinned(x.len);
            @memcpy(pinned, x);
            try s.upload(self.d_regions[k], pinned);
        }
        self.d_scratch = try s.alloc(@as(usize, self.program.header(Seed.P.scratch_words)) + 8);
        if (self.outer.staged.image.expected.words == 0) self.d_outputs = try s.alloc(@max(self.expected.len, 1));
        self.host_timer_ns += t.read();
    }
    pub fn enqueue(self: *GnCheck, e: *api.Enqueue) !void {
        var t = try std.time.Timer.start();
        try e.waitStaged();
        try e.slab.bind(&self.outer.layout);
        const field = try e.slab.field(.opaque_words, field_index);
        const st = self.outer.staged;
        const bases = self.outer.bases;
        const seeds: [*]u32 = @constCast(bases.at(st.image.seeds));
        const channel_seed: [*]u32 = @constCast(bases.at(st.image.channel_seed));
        const outputs: [*]u32 = if (st.image.expected.words != 0) @constCast(bases.at(st.image.expected)) else self.d_outputs.?.ptr;
        if (self.encoder) |encoder| encoder.outputs_device = .{ .ptr = outputs, .words = self.expected.len };
        var io = Seed.Io{
            .program = self.d_prog.ptr,
            .program_words = self.program.words.len,
            .children = @splat(null),
            .children_words = @splat(0),
            .seeds = seeds,
            .seeds_words = st.assignment.seeds.len,
            .scratch = self.d_scratch.ptr,
            .scratch_words = self.d_scratch.words,
            .seed_status = &field.ptr[0],
            .bind_status = &field.ptr[1],
            .outputs = outputs,
            .checkpoint = channel_seed,
            .outputs_copy = field.ptr + 32,
            .checkpoint_copy = field.ptr + 16,
            .outputs_words = @intCast(self.expected.len),
            .n_children = @intCast(self.regions.len),
            .n_ops = self.program.header(Seed.P.n_ops),
            .n_caps = self.program.header(Seed.P.n_caps),
        };
        for (self.regions, 0..) |_, k| {
            io.children[k] = self.d_regions[k].ptr;
            io.children_words[k] = self.d_regions[k].words;
        }
        if (self.timer) |*tm| Timer.GpuTimer.mark(@ptrCast(tm), false, e.stream());
        const rc = self.symbols.fill(e.ctx(), K.lane, &io);
        if (self.timer) |*tm| Timer.GpuTimer.mark(@ptrCast(tm), true, e.stream());
        if (rc != 0) {
            std.log.err("GN_NODE seed fill enqueue failed rc={d}", .{rc});
            return error.GnNodeSeedFillEnqueueFailed;
        }
        self.host_timer_ns += t.read();
        try self.next.vtable.enqueue(self.next.ctx, e);
    }
    pub fn finish(self: *GnCheck, view: api.SlabView) !void {
        if (self.timer) |*tm| Timer.GpuTimer.resolve(@ptrCast(tm));
        // Host assembly publishes the host outputs (verified == device below).
        if (self.outer.staged.image.expected.words != 0) @memcpy(@constCast(self.outer.staged.expected), self.expected);
        const w = try @import("jobs/slab.zig").read(view, .opaque_words, field_index);
        self.seed_status = w[0];
        self.bind_status = w[1];
        @memcpy(&self.dev_checkpoint, w[16..25]);
        @memcpy(self.dev_outputs[0..self.expected.len], w[32..][0..self.expected.len]);
        if (self.seed_status != 0 or self.bind_status != 0) {
            std.debug.print("GN_NODE rejected ordinal={d} seed_tape=0x{x} child_binding=0x{x}\n", .{ self.outer.staged.ordinal, self.seed_status, self.bind_status });
            return error.GnNodeDeviceRejected;
        }
        try self.next.vtable.finish(self.next.ctx, view);
    }
    pub fn abort(self: *GnCheck) void {
        self.next.vtable.abort(self.next.ctx);
    }
    /// After the node proved: the device outputs and checkpoint equal the
    /// legacy host values (the proof bytes themselves are the gate's check).
    pub fn verify(self: *GnCheck, ordinal: u32, staged: anytype) !void {
        _ = staged;
        const out_eq = std.mem.eql(u32, self.dev_outputs[0..self.expected.len], self.expected);
        const cp_eq = std.mem.eql(u32, &self.dev_checkpoint, &self.checkpoint);
        self.report.gpu_ns = if (self.timer) |tm| tm.ns else 0;
        self.report.host_ns = self.host_timer_ns;
        std.debug.print("GN_NODE ordinal={d} children={d} seeds={d} seed_tape=0x{x} child_binding=0x{x} outputs_identical={} checkpoint_identical={} seed_gpu_ns={d} seed_host_ns={d} warm_ns={d} launches={d} source_words={d}\n", .{ ordinal, self.report.children, self.report.seeds, self.seed_status, self.bind_status, out_eq, cp_eq, self.report.gpu_ns, self.report.host_ns, self.report.warm_ns, self.report.launches, self.report.source_words });
        if (!out_eq or !cp_eq) return error.GnNodeStatementMismatch;
    }
};
