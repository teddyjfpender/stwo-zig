//! Immutable VM composition custody, independent of compiler and request policy.
//! One Source/View type is shared by every compiler specialization. A static
//! compiler operation constructs retained storage inside this boundary; no raw
//! mutable graph or preparation can be adopted as an immutable capability.
const std = @import("std");
const core = @import("stwo_core");
const vm = @import("stwo_riscv_recursion").vm_air_composition_circuit;
const graph_mod = @import("stwo_riscv_rv32").recursion.air.composition_circuit;
const rows = @import("stwo_riscv_rv32").recursion.air.vm_air_composition_input_witness;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const SourceHandle = opaque {};
const SourceStorage = struct { prepared: ?vm.Prepared = null };
fn sourceStorage(handle: *const SourceHandle) *const SourceStorage {
    return @ptrCast(@alignCast(handle));
}

/// Scoped compiler operation, with shared native proof records outside the
/// specialization. The selected compile operation owns its returned program and schedule;
/// Compiler.view exposes only copied metadata and deeply const borrowed slices.
pub fn ForCompiler(comptime Compiler: type) type {
    return struct {
        const CompiledHandle = opaque {
            const owner = Compiler;
        };
        const OwnedHandle = opaque {
            const owner = Compiler;
        };
        const Storage = struct {
            source: SourceStorage = .{},
            allocator: std.mem.Allocator,
            program: Compiler.Program,
            schedule: ?graph_mod.CompiledSchedule,
            fn deinit(self: *Storage) void {
                if (self.source.prepared) |*value| value.deinit();
                if (self.schedule) |*value| value.deinit();
                self.program.deinit();
                self.allocator.destroy(self);
            }
        };
        fn storage(handle: anytype) *Storage {
            return @ptrCast(@alignCast(handle));
        }
        pub const Compiled = struct {
            handle: *CompiledHandle,
            pub fn init(allocator: std.mem.Allocator, input: anytype, comptime compile: anytype) !Compiled {
                var schedule: graph_mod.CompiledSchedule = undefined;
                var compiled_program: Compiler.Program = try compile(allocator, input, &schedule);
                errdefer compiled_program.deinit();
                errdefer schedule.deinit();
                const backing = try allocator.create(Storage);
                backing.* = .{ .allocator = allocator, .program = compiled_program, .schedule = schedule };
                return .{ .handle = @ptrCast(backing) };
            }
            pub fn deinit(self: *Compiled) void {
                storage(self.handle).deinit();
                self.* = undefined;
            }
            pub fn program(self: Compiled) Compiler.View {
                return Compiler.view(&storage(self.handle).program);
            }
            pub fn scheduleRows(self: Compiled) []const graph_mod.Row {
                return storage(self.handle).schedule.?.rows;
            }
            /// Consumes structure on success and failure; every derived graph
            /// value, zero output and schedule is validated before publication.
            pub fn finalize(self: *Compiled, inputs: []const M31, worker_count: usize) !Owned {
                const backing = storage(self.handle);
                const handle = self.handle;
                self.* = undefined;
                errdefer backing.deinit();
                if (worker_count == 0 or worker_count > @import("stwo_riscv_recursion").vm_air_composition_circuit_parallel.MAX_WORKER_COUNT)
                    return error.InvalidWorkerCount;
                var schedule = backing.schedule.?;
                backing.schedule = null;
                backing.source.prepared = try vm.Prepared.initFromAuthenticatedLaneBorrowedParallelV4(
                    backing.allocator,
                    backing.program.lane(),
                    backing.program.air_program_identity,
                    inputs,
                    &schedule,
                    worker_count,
                );
                try backing.source.prepared.?.validate();
                return .{ .handle = @ptrCast(handle) };
            }
        };
        pub const Owned = struct {
            handle: *OwnedHandle,
            pub fn deinit(self: *Owned) void {
                storage(self.handle).deinit();
                self.* = undefined;
            }
            pub fn program(self: Owned) Compiler.View {
                return Compiler.view(&storage(self.handle).program);
            }
            pub fn source(self: Owned) Source {
                return .{ .immutable = @ptrCast(&storage(self.handle).source) };
            }
            pub fn auditAgainst(self: Owned, input: Compiler.AuditInput) !void {
                const backing = storage(self.handle);
                try Compiler.audit(&backing.program, input);
                try backing.source.prepared.?.validate();
            }
        };
    };
}

/// One downstream contract for legacy mutable preparation and immutable
/// ownership. Legacy validation remains mutation-sensitive. Immutable reads
/// are cheap because construction retained no mutable aliases, not because
/// a flag suppresses validation of caller-owned buffers.
pub const Source = union(enum) {
    borrowed: *const vm.Prepared,
    immutable: *const SourceHandle,

    pub fn validate(self: Source) vm.Error!void {
        switch (self) {
            .borrowed => |value| try value.validate(),
            .immutable => |handle| std.debug.assert(sourceStorage(handle).prepared != null),
        }
    }

    pub fn audit(self: Source) vm.Error!void {
        try self.raw().validate();
    }

    pub fn view(self: Source) View {
        const value = self.raw();
        return .{
            .circuit = CircuitView.init(&value.circuit),
            .evaluation = .{ .values = value.evaluation.values, .circuit_identity = value.evaluation.circuit_identity },
            .preprocessing = .{ .rows = value.preprocessing.rows, .log_size = value.preprocessing.log_size, .authority_digest = value.preprocessing.authority_digest },
            .schedule_values = value.schedule_values,
        };
    }

    pub fn generatePreprocessedInto(self: Source, executor: *const rows.Executor, columns: *[rows.PREPROCESSED_COLUMN_COUNT][]M31) !void {
        try self.validate();
        try executor.generatePreprocessedInto(&self.raw().preprocessing, columns);
    }

    pub fn generateMainInto(self: Source, executor: *const rows.Executor, columns: *[rows.MAIN_COLUMN_COUNT][]M31, kind: rows.ProofKind) !void {
        try self.validate();
        const value = self.raw();
        try executor.generateMainInto(&value.preprocessing, columns, value.schedule_values, kind);
    }

    fn raw(self: Source) *const vm.Prepared {
        return switch (self) {
            .borrowed => |value| value,
            .immutable => |handle| &sourceStorage(handle).prepared.?,
        };
    }
};

pub const CircuitView = struct {
    nodes: []const graph_mod.Node,
    outputs: []const u32,
    bindings: []const graph_mod.VmInputBinding,
    input_profile: graph_mod.InputProfile,
    air_profile_digest: [32]u8,
    graph_digest: [32]u8,
    reference_digest: [32]u8,
    schedule_digest: [32]u8,
    identity_digest: [32]u8,

    fn init(value: *const vm.Circuit) CircuitView {
        var result: CircuitView = undefined;
        inline for (std.meta.fields(CircuitView)) |field|
            @field(result, field.name) = @field(value, field.name);
        return result;
    }

    pub fn graph(self: CircuitView) graph_mod.CircuitGraph {
        return .{ .nodes = self.nodes, .outputs = self.outputs, .identity_digest = self.graph_digest };
    }
};

pub const View = struct {
    circuit: CircuitView,
    evaluation: struct { values: []const QM31, circuit_identity: [32]u8 },
    preprocessing: struct { rows: []const graph_mod.Row, log_size: u32, authority_digest: [32]u8 },
    schedule_values: []const M31,
};

test "composition custody gives each compiler distinct owner handles" {
    const First = ForCompiler(struct {
        pub const marker: u8 = 1;
    });
    const Second = ForCompiler(struct {
        pub const marker: u8 = 2;
    });
    try std.testing.expect(@FieldType(First.Compiled, "handle") != @FieldType(Second.Compiled, "handle"));
    try std.testing.expect(@FieldType(First.Owned, "handle") != @FieldType(Second.Owned, "handle"));
    try std.testing.expect(@FieldType(Source, "immutable") != @FieldType(First.Owned, "handle"));
    try std.testing.expect(@typeInfo(@FieldType(Source, "immutable")).pointer.is_const);
}
