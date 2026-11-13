//! Exact class fields, request masks and fingerprint comparison.
const NB = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_binding;
const NG = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_gkr;
const Plan = @import("native_class_inventory.zig").Plan;
const Class = @import("native_class_build.zig").Class;
const FC = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_framing_cache;
const G = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.gpu_native;
const M = core.fields.m31.M31;
const S2 = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_device_stage2;
const core = @import("stwo_core");
const std = @import("std");

pub const Field = struct {
    name: []const u8,
    /// true: part of the class (must be equal for equal classes);
    /// false: per-request value (rebound / patched; reported only).
    class: bool,
    digest: [32]u8,
};

pub const Fingerprint = struct {
    a: std.mem.Allocator,
    fields: std.ArrayListUnmanaged(Field) = .empty,

    pub fn deinit(self: *Fingerprint) void {
        self.fields.deinit(self.a);
    }
    pub fn key(self: *const Fingerprint) G.ClassKey {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64-m8-gn-shape-class/v1");
        for (self.fields.items) |f| if (f.class) {
            h.update(f.name);
            h.update(&f.digest);
        };
        return h.finalResult();
    }
    fn put(self: *Fingerprint, name: []const u8, class: bool, k: *FC.Key) !void {
        try self.fields.append(self.a, .{ .name = name, .class = class, .digest = k.final() });
    }
    fn value(self: *Fingerprint, name: []const u8, class: bool, v: anytype) !void {
        var k = FC.Key.init(name);
        k.value(v);
        try self.put(name, class, &k);
    }
    fn words(self: *Fingerprint, name: []const u8, class: bool, w: []const u32) !void {
        var k = FC.Key.init(name);
        k.bytes(std.mem.sliceAsBytes(w));
        try self.put(name, class, &k);
    }
    /// `w` with the 8-word felts at `masked` dst offsets zeroed (class part)
    /// and the masked words alone (request part).
    fn maskedWords(self: *Fingerprint, name: []const u8, request_name: []const u8, w: []const u32, masked: []const u32) !void {
        const copy = try self.a.dupe(u32, w);
        defer self.a.free(copy);
        var req = FC.Key.init(request_name);
        for (masked) |d| {
            const n = @min(8, copy.len -| d);
            req.bytes(std.mem.sliceAsBytes(copy[d..][0..n]));
            @memset(copy[d..][0..n], 0);
        }
        try self.words(name, true, copy);
        try self.put(request_name, false, &req);
    }

    pub fn of(a: std.mem.Allocator, cl: *const Class) !Fingerprint {
        var fp = try ofStage1(a, cl);
        errdefer fp.deinit();
        try fp.addStage2(cl);
        return fp;
    }
    /// Stage-1 fields only (the Spec + binding plan).
    pub fn ofStage1(a: std.mem.Allocator, cl: *const Class) !Fingerprint {
        var fp = Fingerprint{ .a = a };
        errdefer fp.deinit();
        try fp.addStage1(cl);
        return fp;
    }
    fn addStage1(fp: *Fingerprint, cl: *const Class) !void {
        // ---- Stage 1: Spec ----
        const g = &cl.gkr;
        try fp.value("s1.gkr.variables", true, g.variables);
        try fp.value("s1.gkr.traversal", true, g.traversal);
        try fp.value("s1.gkr.v3", true, g.v3);
        try fp.value("s1.gkr.relation_count", true, g.relation_count);
        try fp.value("s1.gkr.byte_cap", true, g.byte_cap);
        try fp.value("s1.gkr.fixed_count", true, g.fixed_count);
        try fp.value("s1.gkr.constants", true, g.constants);
        try fp.value("s1.gkr.instances", true, g.instances);
        try fp.value("s1.gkr.order", true, g.order);
        try fp.value("s1.gkr.logs", true, g.logs);
        try fp.value("s1.gkr.instance_mixes", true, g.instance_mixes);
        try fp.value("s1.gkr.child_steps", true, g.child_steps);
        try fp.value("s1.gkr.staged_words", true, g.staged_words);
        try fp.value("s1.gkr.item_offsets", true, g.item_offsets);
        try fp.value("s1.gkr.twiddle_words", true, g.twiddle_words);
        try fp.value("s1.gkr.host_column_words", true, g.host_column_words);
        try fp.value("s1.gkr.fields", true, g.fields);
        {
            var k = FC.Key.init("s1.gkr.source");
            const s = &g.source;
            for (s.columns) |c| k.int(c.log_size);
            k.value(s.groups);
            k.value(s.offsets);
            k.int(s.fixed_count);
            k.int(s.cells);
            k.int(s.max_log);
            for (s.items) |it| {
                k.int(it.kernel);
                k.value(it.offsets);
                k.int(it.log);
                k.int(it.terms);
                k.int(it.lanes);
                k.int(it.facts);
            }
            try fp.put("s1.gkr.source", true, &k);
            var p = FC.Key.init("s1.request.publics");
            for (s.items) |it| p.value(it.public);
            try fp.put("s1.request.publics", false, &p);
        }
        try fp.value("s1.request.prefix", false, g.prefix);
        try fp.value("s1.instances", true, cl.instances);
        try fp.value("s1.fixed_shapes", true, cl.fixed_shapes);
        try fp.words("s1.fixed_host", true, cl.fixed_storage);
        try fp.value("s1.fixed_root", true, cl.fixed_root);
        try fp.value("s1.main_shapes", true, cl.main_shapes);
        try fp.value("s1.beta", true, cl.beta);
        try fp.value("s1.capture_words", true, cl.capture_words);
        try fp.value("s1.binding.row_logs", true, cl.bind_plan.row_logs);
        try fp.value("s1.binding.lane_logs", true, cl.bind_plan.lane_logs);
        try fp.value("s1.binding.offsets", true, cl.bind_plan.offsets);
        try fp.value("s1.binding.output_words", true, cl.bind_plan.output_words);
    }
    fn addStage2(fp: *Fingerprint, cl: *const Class) !void {
        const a = fp.a;
        // ---- Stage 2: framing ----
        try fp.value("s2.geometry", true, [_]u32{ cl.comp_log, cl.split, cl.total, cl.mask_log, cl.claim_count });
        try fp.value("s2.public_input_felts", true, cl.public_values.len / 8);
        try fp.words("s2.request.public_values", false, cl.public_values);
        const none = std.math.maxInt(u32);
        try fp.value("s2.boundary_claims", true, [2]u32{ cl.initial_claim orelse none, cl.terminal_claim orelse none });
        try fp.words("s2.oods_program", true, cl.oods_program);
        {
            var k = FC.Key.init("s2.slots");
            for (cl.slots) |s| {
                k.int(s.log);
                k.int(s.inter_offset);
                k.value(s.binding_index);
                if (s.global) |gl| {
                    k.int(1);
                    k.int(gl.claim_offset);
                    k.int(gl.fixed_first);
                    k.int(gl.main_first);
                } else k.int(0);
            }
            try fp.put("s2.slots", true, &k);
        }
        {
            var k = FC.Key.init("s2.gplans.geometry");
            for (cl.gplans.items) |p| {
                k.bytes(&p.entry.artifact.program.identity);
                k.int(p.log);
                k.int(p.rows);
                k.int(p.fixed_count);
                k.int(p.main_count);
                k.value(p.groups);
                k.int(p.group_count);
                k.int(p.pairs);
                k.int(p.width);
                k.int(p.scan_words);
            }
            try fp.put("s2.gplans.geometry", true, &k);
        }
        // One (class, request) pair per global plan, in slot order.
        for (cl.gplans.items, cl.global_patches) |p, set| {
            const masked = try maskOf(a, set);
            defer a.free(masked);
            try fp.maskedWords("s2.gplan.parameters", "s2.request.gplan.parameters", p.parameters, masked);
        }
        try fp.value("s2.inter_shapes", true, cl.inter_shapes);
        try fp.value("s2.inter_logs", true, cl.inter_logs);
        {
            const cp = &cl.comp_plan.?;
            try fp.value("s2.composition.key", true, cp.key);
            const masked = try maskOf(a, cl.comp_patches);
            defer a.free(masked);
            try fp.maskedWords("s2.composition.table", "s2.request.composition.table", cp.table, masked);
        }
        {
            const px = &cl.pcs.?;
            var k = FC.Key.init("s2.pcs.sections");
            for (px.prepared.section_storage, 0..) |s, i| if (i != 15) k.bytes(std.mem.sliceAsBytes(s));
            try fp.put("s2.pcs.sections", true, &k);
            try fp.words("s2.request.pcs.section15", false, px.prepared.section_storage[15]);
            try fp.value("s2.request.pcs.scope", false, px.prepared.scope);
            var pl = FC.Key.init("s2.pcs.plan");
            pl.bytes(std.mem.asBytes(&px.plan));
            try fp.put("s2.pcs.plan", true, &pl);
            try fp.value("s2.pcs.base_shift", true, [2]u32{ px.base_shift.x.v, px.base_shift.y.v });
            var cols = FC.Key.init("s2.pcs.columns");
            for (cl.pristine_columns) |c| cols.bytes(std.mem.asBytes(&c));
            try fp.put("s2.pcs.columns", true, &cols);
            var sh = FC.Key.init("s2.pcs.shape");
            for (px.prepared.metadata.shape.trees) |t| {
                sh.value(t.coefficient_logs);
                sh.value(t.sorted_to_original);
                sh.value(t.sample_counts);
            }
            try fp.put("s2.pcs.shape", true, &sh);
        }
        try fp.words("s2.program", true, cl.program.?.words);
        try fp.value("s2.program.max_encoded_bytes", true, cl.program.?.max_encoded_bytes);
        try fp.value("s2.fixed_offsets", true, cl.fixed_offsets);
        try fp.value("s2.main_offsets", true, cl.main_offsets);
        try fp.value("s2.main_words", true, cl.main_words);
        {
            var k = FC.Key.init("s2.patches");
            for (cl.global_patches) |p| hashPatchSet(&k, p);
            hashPatchSet(&k, cl.comp_patches);
            k.int(cl.semantic_words);
            try fp.put("s2.patches", true, &k);
        }
    }
    pub fn get(self: *const Fingerprint, name: []const u8, nth: usize) ?Field {
        var seen: usize = 0;
        for (self.fields.items) |f| if (std.mem.eql(u8, f.name, name)) {
            if (seen == nth) return f;
            seen += 1;
        };
        return null;
    }
};

pub fn hashPatchSet(k: *FC.Key, set: S2.PatchSet) void {
    inline for (S2.sources) |source| {
        const p = set.get(source);
        k.value(@as([]const u32, p.dst));
        k.value(@as([]const u32, p.index));
    }
}

/// Every patched dst offset of a patch set (sorted, unique).
pub fn maskOf(a: std.mem.Allocator, set: S2.PatchSet) ![]u32 {
    var out: std.ArrayListUnmanaged(u32) = .empty;
    errdefer out.deinit(a);
    inline for (S2.sources) |source| try out.appendSlice(a, set.get(source).dst);
    std.mem.sort(u32, out.items, {}, std.sort.asc(u32));
    return out.toOwnedSlice(a);
}

pub const Mismatch = struct { name: []const u8, ordinal: usize };

/// Class fields of `x` and `y` in order; the first `out.len` differences.
/// `y` may be a prefix (a Stage-1-only fingerprint): only its fields compare.
pub fn compare(x: *const Fingerprint, y: *const Fingerprint, out: []Mismatch) !usize {
    if (x.fields.items.len < y.fields.items.len) return error.GnShapeFingerprintShape;
    var n: usize = 0;
    for (x.fields.items[0..y.fields.items.len], y.fields.items, 0..) |p, q, i| {
        if (!std.mem.eql(u8, p.name, q.name) or p.class != q.class) return error.GnShapeFingerprintShape;
        if (!p.class or std.mem.eql(u8, &p.digest, &q.digest)) continue;
        if (n < out.len) out[n] = .{ .name = p.name, .ordinal = i };
        n += 1;
    }
    return n;
}

// ---------------------------------------------------------------------------
// From the legacy per-segment inputs (recorder side: the hybrid's sources)
// ---------------------------------------------------------------------------

/// The legacy Stage-1 class of one segment, from exactly the request the
/// hybrid prove() received (retired native hybrid, l.589: NG.Plan.init on the
/// request's scope, instances, native source, FIXED host and MAIN device
/// columns, byte cap; NB.Plan on its instances and traversal layers). Only
/// the Stage-1 fields are set; fingerprint it with `Fingerprint.ofStage1`.
pub fn coefficientWords(values: []const M) []const u32 {
    return @as([*]const u32, @ptrCast(values.ptr))[0..values.len];
}

pub fn stage2Fingerprint(a: std.mem.Allocator, cl: *const Class) !Fingerprint {
    var result = Fingerprint{ .a = a };
    errdefer result.deinit();
    try result.addStage2(cl);
    return result;
}
