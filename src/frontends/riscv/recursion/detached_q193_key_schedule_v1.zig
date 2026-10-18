//! Proof-free scheduled-verifier plans from an admitted native descriptor roster.
const std = @import("std");
const authority = @import("detached_segment_authority_boundary_v1.zig");
const geometry_mod = @import("detached_native_column_geometry_v1.zig");
const segment = @import("segment_profile.zig");
const schedule = @import("air/verifier_schedule.zig");

pub const Owned = struct {
    shape: schedule.ScheduleShape,
    vm: schedule.Plan,
    recursive: schedule.Plan,

    pub fn init(allocator: std.mem.Allocator, descriptors: authority.DescriptorsV1) !Owned {
        var geometry = try geometry_mod.init(allocator, descriptors, segment.circuitProfile().log_blowup_factor);
        defer geometry.deinit();
        const shape = try geometry.q193ScheduleShape(descriptors);
        var vm = try schedule.Plan.initShape(allocator, try schedule.vmProgramSpec(0, 0), shape);
        errdefer vm.deinit();
        const recursive = try schedule.Plan.initShape(allocator, schedule.RECURSION_PROGRAM_SPEC_V1, shape);
        return .{ .shape = shape, .vm = vm, .recursive = recursive };
    }

    pub fn deinit(self: *Owned) void {
        self.recursive.deinit();
        self.vm.deinit();
        self.* = undefined;
    }
};
