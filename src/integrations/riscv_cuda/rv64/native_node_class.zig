//! Request-time node adapter. Only job types/kernels are imported here;
//! authority construction, host graph preparation and leases stay at install.
const std = @import("std");
const OD = @import("jobs/outer_device.zig");
const Job = @import("jobs/outer_job.zig");
const Enc = @import("jobs/outer_encode_job.zig");
const K = @import("jobs/outer_kernels.zig");
const E = @import("jobs/outer_encode.zig");
const Oods = @import("jobs/outer_encode_oods.zig");
pub const Symbols = struct { kernels: *const K.Kernels, whole: Job.Whole, encode: ?E.Symbols, oods: ?Oods.Symbols, compressed: ?@import("jobs/outer_packed_class.zig").Launch = null };
pub const Made = struct { job: Job.OuterNodeJob, enc: Enc.EncodedNode };
pub fn Adapter(comptime Entry: type) type {
    return struct {
        pub fn make(raw: *anyopaque, _: std.mem.Allocator, target: OD.Target) anyerror!OD.Made {
            const a = std.heap.c_allocator;
            const e: *Entry = @ptrCast(@alignCast(raw));
            if (e.program.len == 0) return error.GnNodeClassProgramNotLaidOut;
            const m = try a.create(Made);
            errdefer a.destroy(m);
            const sym = e.runtime_symbols;
            m.job = try Job.OuterNodeJob.initWhole(e.staged, sym.kernels, sym.whole);
            errdefer m.job.deinit();
            try m.job.requireDeviceChecks();
            if (e.compressed) |*compressed| {
                m.job.packed_class = compressed;
                m.job.packed_launch = sym.compressed orelse return error.PackedClassDecoderMissing;
                m.job.packed_verdict = target.class_unpack_status;
                _ = try m.job.layout.add(.opaque_words, @import("jobs/outer_packed_class.zig").field_index, 1);
            }
            m.job.require_warm = e.resources_warmed;
            m.job.defer_decode = true;
            if (target.device < e.graphs.len) m.job.graphs = e.graphs[target.device];
            m.enc = try Enc.EncodedNode.initTarget(a, &m.job, sym.encode orelse return error.GnNodeEncoderUnloaded, e.desc, .{ .region = target.region, .pcs_status = target.pcs_status, .encode_status = target.encode_status, .layout_status_oods = target.oods_status });
            if (sym.oods) |s| try m.enc.withOods(s, e.oods_program);
            m.enc.image_tail = true;
            m.enc.outputs_on_device = true;
            m.enc.device_publish = true;
            return .{ .job = m.enc.job(), .ctx = m, .inputs = inputs, .destroy = destroy };
        }
        fn inputs(raw: *anyopaque) anyerror!OD.Inputs {
            const m: *Made = @ptrCast(@alignCast(raw));
            const st = m.job.staged;
            const b = m.job.bases;
            const out = OD.Inputs{ .seeds = .{ .ptr = @constCast(b.at(st.image.seeds)), .words = st.assignment.seeds.len }, .channel_seed = .{ .ptr = @constCast(b.at(st.image.channel_seed)), .words = 9 }, .outputs = .{ .ptr = @constCast(b.at(st.image.expected)), .words = st.expected.len } };
            m.enc.outputs_device = out.outputs;
            return out;
        }
        fn destroy(raw: *anyopaque) void {
            const m: *Made = @ptrCast(@alignCast(raw));
            m.enc.deinit();
            m.job.deinit();
            std.heap.c_allocator.destroy(m);
        }
    };
}
