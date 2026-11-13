//! Canonical CPU geometry; independent of transport and execution policy.
const Geo = @import("../../../word16_execution/geometry.zig").Geometry;
const T = @import("../types.zig");
pub const CpuDeclaration = struct { geometry: Geo, bridges: T.Logs };
