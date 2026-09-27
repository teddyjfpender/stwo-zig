//! Independently admitted actual nineteen-component caller verifier geometry.
//! Neither a legacy native plan nor received masks select this policy.
const std = @import("std");
const core = @import("stwo_core");
pub const Profile = @import("blake3_ethereum_sha_profile.zig");
pub const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const Family = @import("block_v5_precompile_family_proof_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
pub const VERSION: u32 = 1;
pub const MAX_CLAIM_VALUES: usize = 4096;
pub const Limits = struct { max_capture_bytes: usize = 512 << 20, max_preparation_bytes: usize = 4 << 30, max_columns: usize = 32768, max_samples: usize = 131072 };
pub const Span = struct { offset: usize, column_count: usize };
pub const Component = struct {
    kind: @import("../air/guest_precompile/ethereum_statement.zig").Kind,
    log_size: u32,
    spans: [3]Span,
    direct_constraint_count: u32,
    interaction_batch_count: u32,
};
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    statement: Profile.admission.Statement,
    total_steps: u32,
    binding: Family.CallerBinding,
    roots: [2][32]u8,
    sealed: Seal.Sealed,
    pins: Seal.Pins,
    entries: []const Seal.Entry,
    config: core.pcs.PcsConfig,
    template_id: [32]u8,
    logs: [3][]u32,
    components: [Profile.component_count]Component,
    composition_log: u32,
    composition_split: u32,
    mask_log: u32,
    air_instruction_count: u32,
    detailed_claim_count: u32,
    limits: Limits,
    pub fn init(a: std.mem.Allocator, statement: Profile.admission.Statement, total_steps: u32, binding: Family.CallerBinding, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, limits: Limits) !Prepared {
        try Protocol.validate(&statement, total_steps, pins.config);
        try @import("block_v5_precompile_witness_v1.zig").validateAdmission(a, &statement);
        try Protocol.admit(binding, sealed, pins, entries);
        if (!std.meta.eql(binding.caller_key_id, try Protocol.keyId(&statement, total_steps, pins.config, binding.first_roots[0])) or limits.max_capture_bytes == 0 or limits.max_preparation_bytes == 0 or limits.max_samples == 0) return error.UntrustedCallerRecursiveAdmission;
        var logs: [3][]u32 = undefined;
        var initialized: usize = 0;
        errdefer for (logs[0..initialized]) |log| a.free(log);
        for ([_]Protocol.Tree{ .fixed, .main, .interaction }, 0..) |tree, i| {
            logs[i] = try Protocol.columnLogs(a, &statement, tree);
            initialized += 1;
            if (logs[i].len > limits.max_columns) return error.CallerRecursiveResourceLimit;
        }
        const relations = try Protocol.drawRelations(a, sealed);
        const claims = try Profile.ExtensionClaim.zeroForStatement(&statement);
        const assembly = try Profile.Assembly(.verifier).createBlockV5Standalone(a, &statement, total_steps, &relations, &claims);
        defer assembly.destroy(a);
        const handles = assembly.active();
        if (handles.len != Profile.component_count) return error.UntrustedCallerRecursiveGeometry;
        const all = core.air.components.Components{ .components = handles, .n_preprocessed_columns = logs[0].len };
        const log = all.compositionLogDegreeBound();
        const split = try all.compositionLogSplit();
        const placements = assembly.extensionPlacements();
        const views = claims.componentClaims();
        const descriptors = Profile.descriptors(&statement);
        var components: [Profile.component_count]Component = undefined;
        var constraint_count: u32 = 0;
        var detail_count: u32 = 0;
        var public_count: usize = 0;
        for (&components, placements, views, descriptors, handles, 0..) |*component, placement, view, desc, handle, i| {
            const count = std.math.cast(u32, handle.nConstraints()) orelse return error.CallerRecursiveResourceLimit;
            const batches = std.math.cast(u32, if (i < 14) view.detailed.len else desc.interaction_columns / 4) orelse return error.CallerRecursiveResourceLimit;
            if (count < batches) return error.UntrustedCallerRecursiveGeometry;
            component.* = .{ .kind = statement.ethereum.components[@min(i, 13)].kind, .log_size = desc.log_size, .spans = .{ .{ .offset = placement.preprocessed_offset, .column_count = desc.preprocessed_columns }, .{ .offset = placement.main_offset, .column_count = desc.main_columns }, .{ .offset = placement.interaction_offset, .column_count = desc.interaction_columns } }, .direct_constraint_count = count - batches, .interaction_batch_count = batches };
            constraint_count = try std.math.add(u32, constraint_count, count);
            detail_count = try std.math.add(u32, detail_count, @intCast(view.detailed.len));
            public_count = try std.math.add(usize, public_count, view.detailed.len + @intFromBool(view.has_batch_frame));
            if (public_count > MAX_CLAIM_VALUES) return error.CallerRecursiveResourceLimit;
        }
        var result = Prepared{ .allocator = a, .statement = statement, .total_steps = total_steps, .binding = binding, .roots = binding.first_roots, .sealed = sealed, .pins = pins, .entries = entries, .config = pins.config, .template_id = undefined, .logs = logs, .components = components, .composition_log = log, .composition_split = split, .mask_log = log - split, .air_instruction_count = constraint_count, .detailed_claim_count = detail_count, .limits = limits };
        result.template_id = result.identity();
        return result;
    }
    pub fn deinit(self: *Prepared) void {
        for (self.logs) |logs| self.allocator.free(logs);
        self.* = undefined;
    }
    pub fn identity(self: *const Prepared) [32]u8 {
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ 0x42354147, VERSION, Protocol.TAG, Protocol.VERSION, @intFromEnum(Protocol.circuit_profile), self.total_steps, self.composition_log, self.composition_split, self.air_instruction_count, self.detailed_claim_count }); // B5AG
        channel.mixRoot(self.binding.caller_key_id);
        self.config.mixInto(&channel);
        for (self.components) |component| {
            channel.mixU32s(&.{ @intFromEnum(component.kind), component.log_size, component.direct_constraint_count, component.interaction_batch_count });
            for (component.spans) |span| {
                channel.mixU64(span.offset);
                channel.mixU64(span.column_count);
            }
        }
        for (self.logs) |logs| {
            channel.mixU32s(&.{@intCast(logs.len)});
            channel.mixU32s(logs);
        }
        return channel.digestBytes();
    }
    pub fn validate(self: *const Prepared, expected: [32]u8) !void {
        try Protocol.validate(&self.statement, self.total_steps, self.config);
        try Protocol.admit(self.binding, self.sealed, self.pins, self.entries);
        if (!std.meta.eql(self.config, self.pins.config) or !std.meta.eql(self.roots, self.binding.first_roots) or !std.meta.eql(expected, self.template_id) or !std.meta.eql(expected, self.identity()) or self.mask_log != self.composition_log - self.composition_split) return error.UntrustedCallerRecursiveAdmission;
        // Reconstructing the geometry is mandatory; the identity is not an
        // authority for a host-mutated Prepared object.
        var independently = try Prepared.init(self.allocator, self.statement, self.total_steps, self.binding, self.sealed, self.pins, self.entries, self.limits);
        defer independently.deinit();
        if (!std.meta.eql(independently.template_id, expected)) return error.UntrustedCallerRecursiveGeometry;
    }
    pub fn maskPoints(self: *const Prepared, a: std.mem.Allocator, point: core.circle.CirclePointQM31) !core.air.components.MaskPoints {
        const relations = try Protocol.drawRelations(a, self.sealed);
        const claims = try Profile.ExtensionClaim.zeroForStatement(&self.statement);
        const assembly = try Profile.Assembly(.verifier).createBlockV5Standalone(a, &self.statement, self.total_steps, &relations, &claims);
        defer assembly.destroy(a);
        return (core.air.components.Components{ .components = assembly.active(), .n_preprocessed_columns = self.logs[0].len }).maskPoints(a, point, self.mask_log, false);
    }
};
