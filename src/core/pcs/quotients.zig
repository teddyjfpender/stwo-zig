const circle = @import("../circle.zig");
const qm31 = @import("../fields/qm31.zig");

pub const PointSample = struct {
    point: circle.CirclePointQM31,
    value: qm31.QM31,
};
