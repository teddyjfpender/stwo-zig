//! Bounded RV64 AIR and verifier-owned state relation, separate from execution.
pub const statement = @import("statement.zig");
pub const layout = @import("layout.zig");
pub const rows = @import("rows.zig");
pub const witness = @import("witness.zig");
pub const trace = @import("trace.zig");
pub const evaluation = @import("evaluation.zig");
pub const relations = @import("relations.zig");
pub const component = @import("component.zig");
pub const protocol = @import("protocol.zig");
pub const projection = @import("projection.zig");
pub const operations = @import("operations.zig");
pub const encoding = @import("encoding.zig");
pub const full = struct {
    pub const frame = @import("full/frame.zig");
    pub const component = @import("full/component.zig");
};
pub const program = struct {
    pub const setup = @import("program/setup.zig");
    pub const provider = @import("program/provider.zig");
    pub const component = @import("program/component.zig");
    pub const compact = @import("program/compact.zig");
};
pub const range = struct {
    pub const provider = @import("range/provider.zig");
    pub const cpu = @import("range/cpu.zig");
    pub const table_cpu = @import("range/table_cpu.zig");
};
pub const providers = struct {
    pub const byte = @import("providers/byte.zig");
    pub const tables = @import("providers/tables.zig");
    pub const table_component = @import("providers/table_component.zig");
};
