//! Native composition roles for the M8 job producer (jobs/native_composition.zig),
//! built from the frontend authorities exactly as resident_composition.zig
//! Context.evaluateAtBlowup binds them (descriptor → case id → artifact,
//! parameter slots from real_composition.metadata, role geometry, hc
//! auxiliary columns). Lives outside rv64/jobs/ because it reads the legacy
//! composition Context's kernel metadata (owner-path imports are forbidden
//! under jobs/ by the sync lint). Pure host; no device access.
//!
//! Custody note (stated, not hidden): the parameters are host values here
//! (lookup challenges, eta, claims from the host items). Only the composition
//! coefficient and its powers are device-resident on this path.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const RC = @import("resident_composition.zig");
const Hybrid = @import("real_composition.zig");
const G = @import("joined_codegen.zig");
const NC = @import("jobs/native_composition.zig");
const Items = CPU.rv64_gkr_cpu_components;

pub const Roles = struct {
    a: std.mem.Allocator,
    specs: []NC.RoleSpec,
    /// Backing storage of every spec's slices.
    words: std.ArrayListUnmanaged([]u32) = .empty,

    pub fn fromItems(a: std.mem.Allocator, context: *const RC.Context, items: []const Items.Item) !Roles {
        if (context.artifact_count != @import("joined_fixture_support.zig").count) return error.CpuCompositionNotInitialized;
        var self = Roles{ .a = a, .specs = try a.alloc(NC.RoleSpec, items.len) };
        errdefer self.deinit();
        for (items, self.specs) |*item, *spec| switch (item.*) {
            inline else => |*c| {
                const T = @TypeOf(c.*);
                const d = Hybrid.descriptor(T, c);
                const id = try Hybrid.caseId(d);
                const artifact = &context.artifacts[id];
                if (artifact.program.roots.len != c.nConstraints()) return error.WrongResidentConstraintCount;
                const metadata = Hybrid.metadata(T, c, d);
                const parameters = try self.own(artifact.parameter_slots.len * 8);
                for (artifact.parameter_slots, 0..) |slot, i| for (metadata[slot].toM31Array(), 0..) |w, j| {
                    parameters[8 * i + j] = w.v;
                };
                const masks = try self.own(artifact.program.inputs.len);
                for (artifact.program.inputs, masks) |input, *m| m.* = input.column;
                const shape = c.mainShape();
                const offsets = c.columnOffsets();
                const trace_log: u32 = @intCast(G.Authority.RoleGeometry.logSize(c));
                spec.* = .{
                    .id = id,
                    .trace_log = trace_log,
                    .eval_log = @intCast(c.maxConstraintLogDegreeBound()),
                    .widths = .{ @intCast(shape.fixed), @intCast(shape.main), @intCast(G.Authority.RoleGeometry.interWidth(c)) },
                    .offsets = .{ @intCast(offsets[0]), @intCast(offsets[1]), @intCast(c.inter_offset) },
                    .parameters = parameters,
                    .mask_columns = masks,
                    .constraints = @intCast(artifact.program.roots.len),
                };
                if (comptime @hasField(T, "data")) {
                    const hc = try self.own(16 * trace_log);
                    for (0..2) |half| for (0..trace_log) |i| for ((if (half == 0) c.data.point.hc0[i] else c.data.point.hc1[i]).toM31Array(), 0..) |w, j| {
                        hc[(half * trace_log + i) * 8 + j] = w.v;
                    };
                    spec.aux = .hc;
                    spec.hc = hc;
                }
            },
        };
        return self;
    }
    fn own(self: *Roles, words: usize) ![]u32 {
        const out = try self.a.alloc(u32, words);
        errdefer self.a.free(out);
        try self.words.append(self.a, out);
        return out;
    }
    pub fn deinit(self: *Roles) void {
        for (self.words.items) |w| self.a.free(w);
        self.words.deinit(self.a);
        self.a.free(self.specs);
        self.* = undefined;
    }
};
