//! Borrowed, independently pinned verifier geometry for the native-v5 child
//! recursive circuit. No custody component or proof-carried key is admitted.
const std = @import("std");
const core = @import("stwo_core");
const shape_mod = @import("../air/statement.zig");
const plan_mod = @import("blake3_commitment_plan.zig");
const template_mod = @import("block_v5_native_template_protocol.zig");
const catalog_mod = @import("block_v5_native_template_catalog_v1.zig");
const seal_mod = @import("block_v5_source_seal_v1.zig");

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    shape: *const shape_mod.Blake3ExecutionStatement,
    pin: plan_mod.Admission,
    template: template_mod.Template,
    expected_id: [32]u8,
    index: u32,
    config: core.pcs.PcsConfig,
    sealed: seal_mod.Sealed,
    pins: seal_mod.Pins,
    entries: []const seal_mod.Entry,
    catalog: ?catalog_mod.Admission,
    logs: [3][]u32,
    /// Opt-in v5 public-input circuit; legacy specialized rows remain unchanged.
    reusable_public_inputs: bool = false,

    pub fn init(a: std.mem.Allocator, shape: *const shape_mod.Blake3ExecutionStatement, pin: plan_mod.Admission, template: template_mod.Template, expected_id: [32]u8, index: u32, sealed: seal_mod.Sealed, pins: seal_mod.Pins, entries: []const seal_mod.Entry, catalog: ?catalog_mod.Admission) !Prepared {
        var self = Prepared{ .allocator = a, .shape = shape, .pin = pin, .template = template,
            .expected_id = expected_id, .index = index, .config = pins.config, .sealed = sealed,
            .pins = pins, .entries = entries, .catalog = catalog, .logs = undefined };
        try self.validate(expected_id);
        self.logs[0] = try template_mod.columnLogs(a, shape, template.external_retirements, .fixed);
        errdefer a.free(self.logs[0]);
        self.logs[1] = try template_mod.columnLogs(a, shape, template.external_retirements, .main);
        errdefer a.free(self.logs[1]);
        self.logs[2] = try template_mod.columnLogs(a, shape, template.external_retirements, .interaction);
        return self;
    }

    pub fn deinit(self: *Prepared) void {
        for (self.logs) |logs| self.allocator.free(logs);
        self.* = undefined;
    }

    pub fn admission(self: *const Prepared) plan_mod.Admission {
        return self.pin;
    }

    pub fn validate(self: *const Prepared, expected: [32]u8) !void {
        try self.sealed.require(self.pins, self.entries);
        try self.pin.validatePublic(&self.shape.public_data);
        try self.template.admit(self.shape, expected);
        if (!std.meta.eql(self.expected_id, expected) or !std.meta.eql(self.template.config, self.config) or
            !std.meta.eql(self.config, self.pins.config) or self.index >= self.sealed.execution_instance_count)
            return error.UntrustedNativeV5RecursiveAdmission;
        if (self.catalog) |catalog| {
            try catalog.admit(self.pins, self.sealed, self.index, self.template, expected);
        } else if (!std.meta.eql(self.pins.native_template_id, expected) or
            !std.mem.allEqual(u8, &self.pins.native_template_catalog_digest, 0))
            return error.UntrustedNativeV5RecursiveAdmission;
    }
};
