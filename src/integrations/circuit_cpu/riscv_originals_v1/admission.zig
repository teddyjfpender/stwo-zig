//! Original-only window admission. No NativeParent proof, rows or key is
//! constructed. Metadata names original statements; external ELF/checkpoints
//! independently determine their authority and initial/terminal policies.
const std = @import("std");
const core = @import("stwo_core");
const Native = @import("../../../frontends/riscv/recursion/block_v8_window_root_receiver_v1.zig");
const Mixed = @import("../../../frontends/riscv/recursion/block_v8_endpoint_mixed_join_receiver_v1.zig");
const Source = @import("../../../frontends/riscv/recursion/block_v8_endpoint_join_source_v1.zig");
const Roster = @import("../../../frontends/riscv/recursion/block_v8_endpoint_join_roster_v1.zig");
const Span = @import("../../../frontends/riscv/recursion/block_v8_window_root_statement_v1.zig").WindowSpan;
const Q = core.fields.qm31.QM31;
pub const production_active = false;
pub const Metadata = union(enum) {
    native: struct { external: Native.External, input: Native.Leaf },
    mixed: struct { external: Native.External, input: Mixed.Input },
};
const Statements = union(enum) {
    native: Native.MetadataOwned,
    mixed: Mixed.MetadataOwned,
    fn deinit(v: *Statements) void {
        switch (v.*) {
            inline else => |*owned| owned.deinit(),
        }
        v.* = undefined;
    }
};
pub const Owned = struct {
    allocator: std.mem.Allocator,
    statements: Statements,
    sources: []Source.Source,
    extra: [264]Q,
    span: Span,
    pub fn derive(a: std.mem.Allocator, metadata: Metadata) !Owned {
        // Original-only transport never carries an intermediate parent proof.
        // The legacy native MAIN-root nomination is deliberately irrelevant:
        // every root used below comes from the actual original STARK inputs.
        switch (metadata) {
            .mixed => |value| if (value.input.root.len != 0) return error.IntermediateParentInOriginalWindowMetadata,
            .native => {},
        }
        var statements: Statements = switch (metadata) {
            .native => |v| .{ .native = try Native.admitLeafMetadata(a, v.external, v.input) },
            .mixed => |v| .{ .mixed = try Mixed.admitMetadata(a, v.external, v.input) },
        };
        errdefer statements.deinit();
        const admissions: []const Source.Admission = switch (statements) {
            .native => |v| v.admissions,
            .mixed => |*v| &v.admissions,
        };
        if (admissions.len < 3 or admissions.len > 64) return error.InvalidOriginalWindowRoster;
        const extra = switch (statements) {
            inline else => |v| v.extra,
        };
        const sources = try a.alloc(Source.Source, admissions.len);
        errdefer a.free(sources);
        var initialized: usize = 0;
        errdefer for (sources[0..initialized]) |source| Source.deinitProfile(source);
        for (sources, admissions) |*destination, input| {
            destination.* = try input.derive(a);
            initialized += 1;
        }
        // This is the original roster's exact preflight, without cold/live
        // NativeParent row materialization or a successful verification receipt.
        try Roster.requireAdmission(sources, &extra);
        const global = sources[sources.len - 1].global;
        const window = global.scope.window;
        const boundary = window.boundary;
        const span = Span{
            .elf_sha256 = window.initial.elf_sha256,
            .config = global.scope.config,
            .first_cycle = try std.math.add(u64, boundary.skip_cycles, 1),
            .cycles = boundary.cycles,
            .incoming_snapshot_id = boundary.incoming_sha256,
            .outgoing_snapshot_id = boundary.outgoing_sha256,
            .initial_cpu = boundary.initial_cpu,
            .final_cpu = boundary.final_cpu,
            .initial_policy_id = if (window.boundary_options.initial) |first| first.policy_id else null,
            .terminal_policy_id = if (window.boundary_options.terminal) |last| last.policy_id else null,
        };
        try span.validate();
        return .{ .allocator = a, .statements = statements, .sources = sources, .extra = extra, .span = span };
    }
    pub fn deinit(v: *Owned) void {
        for (v.sources) |source| Source.deinitProfile(source);
        v.allocator.free(v.sources);
        v.statements.deinit();
        v.* = undefined;
    }
};
