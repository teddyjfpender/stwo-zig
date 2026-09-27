//! Independent B5CT recursive geometry. Logical counts remain public instance
//! data; neither received proof metadata nor a NativeV3 admission selects it.
const std = @import("std");
const core = @import("stwo_core");
const shape_mod = @import("../air/statement.zig");
const public = @import("block_v5_native_public_admission_v1.zig");
const protocol = @import("block_v5_native_capacity_protocol_v1.zig");
const proof = @import("block_v5_native_capacity_proof_v1.zig");
const catalog_mod = @import("block_v5_native_capacity_catalog_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    shape: *const shape_mod.Blake3ExecutionStatement,
    external_retirements: u32,
    pin: public.Admission,
    template: protocol.Template,
    template_id: protocol.Digest,
    index: u32,
    sealed: seal.Sealed,
    pins: seal.Pins,
    entries: []const seal.Entry,
    catalog: ?catalog_mod.Admission,
    limits: proof.Limits,
    config: core.pcs.PcsConfig,
    logs: [3][]u32,
    reusable_public_inputs: bool = false,
    pub fn init(a: std.mem.Allocator, shape: *const shape_mod.Blake3ExecutionStatement, external: u32, pin: public.Admission, template: protocol.Template, template_id: protocol.Digest, index: u32, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, catalog: ?catalog_mod.Admission, limits: proof.Limits) !Prepared {
        var self = Prepared{ .allocator = a, .shape = shape, .external_retirements = external, .pin = pin, .template = template, .template_id = template_id, .index = index, .sealed = sealed, .pins = pins, .entries = entries, .catalog = catalog, .limits = limits, .config = pins.config, .logs = undefined };
        try self.validateAuthority(template_id);
        self.logs[0] = try protocol.columnLogs(a, shape, external, .fixed);
        errdefer a.free(self.logs[0]);
        self.logs[1] = try protocol.columnLogs(a, shape, external, .main);
        errdefer a.free(self.logs[1]);
        self.logs[2] = try protocol.columnLogs(a, shape, external, .interaction);
        return self;
    }
    pub fn deinit(self: *Prepared) void {
        for (self.logs) |logs| self.allocator.free(logs);
        self.* = undefined;
    }
    pub fn validate(self: *const Prepared, expected: protocol.Digest) !void {
        try self.validateAuthority(expected);
        // These arrays are owned preparation metadata. Reconstruct their
        // geometry from independent shape admission before every capture use;
        // a cached or mutated array cannot select DEEP/PCS masks.
        for (self.logs, [_]@import("block_v5_native_template_protocol_v3.zig").ColumnTree{ .fixed, .main, .interaction }) |logs, tree| {
            protocol.requireColumnLogs(self.shape, self.external_retirements, tree, logs) catch |failure| {
                if (failure == error.UntrustedNativeColumnGeometry) return error.UntrustedNativeCapacityRecursiveGeometry;
                return failure;
            };
        }
    }
    fn validateAuthority(self: *const Prepared, expected: protocol.Digest) !void {
        try self.sealed.require(self.pins, self.entries);
        try self.pin.require(self.pins, &self.shape.public_data);
        const plan = try protocol.Plan.fromShape(self.shape, self.external_retirements);
        try self.limits.require(&plan, self.shape);
        try self.template.admit(self.shape, self.external_retirements, expected);
        if (!std.meta.eql(self.template_id, expected) or !std.meta.eql(self.template.config, self.config) or
            !std.meta.eql(self.config, self.pins.config) or self.pin.context.execution_index != self.index or
            self.index >= self.sealed.execution_instance_count) return error.UntrustedNativeCapacityRecursiveAdmission;
        if (self.catalog) |catalog| {
            try catalog.admit(self.pins, self.sealed, self.index, self.template, expected);
        } else if (!std.meta.eql(self.pins.native_template_id, expected) or
            !std.mem.allEqual(u8, &self.pins.native_template_catalog_digest, 0)) return error.UntrustedNativeCapacityRecursiveAdmission;
    }
};
