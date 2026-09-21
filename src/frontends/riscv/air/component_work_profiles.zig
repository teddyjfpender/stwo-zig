//! Source-derived work accounting for program and memory infrastructure AIR.
const std = @import("std");
const composition_work_support = @import("composition_work_support.zig");
const program_commitment = @import("program/commitment.zig");
const program_interaction = @import("program/interaction.zig");
const memory_interaction = @import("memory_commitment/interaction.zig");

pub fn For(comptime Component: type) type {
    return struct {
        pub fn oodsWorkProfileErased(
            ctx: *const anyopaque,
            allocator: std.mem.Allocator,
            max_log_degree_bound: u32,
            source: *const composition_work_support.ComponentProfile,
        ) anyerror!composition_work_support.OodsComponentProfile {
            _ = allocator;
            const self: *const Component = @ptrCast(@alignCast(ctx));
            const partial_evaluations: usize = switch (self.kind) {
                .program => 2 * program_interaction.N_SUMS,
                .memory => 2 * memory_interaction.N_SUMS,
            };
            return composition_work_support.oodsProfile(
                source,
                self.desc.log_size,
                max_log_degree_bound,
                partial_evaluations,
                true,
            );
        }

        pub fn compositionWorkProfileErased(
            ctx: *const anyopaque,
            allocator: std.mem.Allocator,
        ) anyerror!composition_work_support.ComponentProfile {
            _ = allocator;
            const self: *const Component = @ptrCast(@alignCast(ctx));
            const Scalar = composition_work_support.Scalar;
            const relations = composition_work_support.Relations.init();
            const is_active = composition_work_support.values(1, 100)[0];
            const is_first = composition_work_support.values(1, 101)[0];
            var expression: composition_work_support.FieldOperations = undefined;
            switch (self.kind) {
                .program => {
                    const main = composition_work_support.values(
                        program_commitment.N_MAIN_COLUMNS,
                        0,
                    );
                    const sums = composition_work_support.values(
                        program_interaction.N_SUMS,
                        20,
                    );
                    const previous = composition_work_support.values(
                        program_interaction.N_SUMS,
                        40,
                    );
                    const claims = composition_work_support.values(
                        program_interaction.N_SUMS,
                        60,
                    );
                    try composition_work_support.begin(&expression);
                    defer composition_work_support.end();
                    if (self.fixed_program_columns != null) {
                        _ = program_interaction.evaluateFixedGeneric(Scalar, main, composition_work_support.values(program_interaction.FIXED_COLUMN_COUNT, 120), is_active, is_first, sums, previous, claims, &relations);
                    } else {
                        _ = program_interaction.evaluateGeneric(
                            Scalar,
                            main,
                            is_active,
                            is_first,
                            sums,
                            previous,
                            claims,
                            &relations,
                        );
                    }
                    return composition_work_support.profile(
                        .program,
                        if (self.fixed_program_columns != null) "riscv-program-fixed-elf-evaluate-generic-v1" else "riscv-program-interaction-evaluate-generic-v1",
                        self.maxConstraintLogDegreeBound(),
                        self.nConstraints(),
                        expression,
                        .{},
                        &.{
                            @as(u64, self.desc.log_size),
                            @as(u64, program_commitment.N_MAIN_COLUMNS),
                            @as(u64, program_interaction.N_SUMS),
                        },
                    );
                },
                .memory => {
                    const main = composition_work_support.values(8, 0);
                    const sums = composition_work_support.values(
                        memory_interaction.N_SUMS,
                        20,
                    );
                    const previous = composition_work_support.values(
                        memory_interaction.N_SUMS,
                        40,
                    );
                    const claims = composition_work_support.values(
                        memory_interaction.N_SUMS,
                        60,
                    );
                    try composition_work_support.begin(&expression);
                    defer composition_work_support.end();
                    _ = self.evaluateMemoryConstraintsGeneric(
                        Scalar,
                        main,
                        is_active,
                        is_first,
                        sums,
                        previous,
                        claims,
                        &relations,
                    );
                    return switch (self.memory_boundary_policy) {
                        .legacy_role_filtered_v1 => composition_work_support.profile(
                            .memory,
                            "riscv-memory-interaction-evaluate-generic-v1",
                            self.maxConstraintLogDegreeBound(),
                            self.nConstraints(),
                            expression,
                            .{},
                            &.{
                                @as(u64, self.desc.log_size),
                                8,
                                @as(u64, memory_interaction.N_SUMS),
                            },
                        ),
                        .full_state_split_multiplicity_v3 => composition_work_support.profile(
                            .memory,
                            "riscv-incremental-boundary-interaction-evaluate-generic-v3",
                            self.maxConstraintLogDegreeBound(),
                            self.nConstraints(),
                            expression,
                            .{},
                            &.{
                                @as(u64, self.desc.log_size),
                                8,
                                @as(u64, memory_interaction.N_SUMS),
                                @as(u64, @intFromEnum(self.memory_boundary_policy)),
                            },
                        ),
                    };
                },
            }
        }
    };
}
