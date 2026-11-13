//! Production main-witness work-shape admission against statement-owned row authority.

pub fn For(comptime owner_context: anytype) type {
    const std = owner_context.std;
    const trace_mod = owner_context.trace_mod;
    const main_witness_work = owner_context.main_witness_work;
    const State = owner_context.State;
    const expectedAdd = owner_context.expectedAdd;
    return struct {
        pub fn validateMainWitnessWorkShape(
            self: *const State,
            completed: main_witness_work.Shard,
        ) !void {
            var opcode_rows = [_]u64{0} ** trace_mod.N_FAMILIES;
            var audit_rows = [_]u64{0} ** trace_mod.N_FAMILIES;
            var program_rows: u64 = 0;
            var memory_rows: u64 = 0;
            var merkle_rows: u64 = 0;
            var clock_rows: u64 = 0;

            for (self.statement.component_descs[0..self.statement.n_components]) |desc| {
                const family_index = @intFromEnum(desc.family);
                opcode_rows[family_index] = std.math.add(
                    u64,
                    opcode_rows[family_index],
                    desc.n_rows,
                ) catch return error.MainWitnessWorkOverflow;
                if (self.plan.task_counts.audit_wave != 0) {
                    if (desc.log_size >= @bitSizeOf(u64))
                        return error.InvalidMainWitnessWorkShape;
                    audit_rows[family_index] = std.math.add(
                        u64,
                        audit_rows[family_index],
                        @as(u64, 1) << @intCast(desc.log_size),
                    ) catch return error.MainWitnessWorkOverflow;
                }
            }
            for (self.statement.infra_descs[0..self.statement.n_infra]) |desc| {
                switch (desc.kind) {
                    .program => program_rows = try expectedAdd(program_rows, desc.n_rows),
                    .memory => memory_rows = try expectedAdd(memory_rows, desc.n_rows),
                    .merkle => merkle_rows = try expectedAdd(merkle_rows, desc.n_rows),
                    .clock_update => clock_rows = try expectedAdd(clock_rows, desc.n_rows),
                    else => {},
                }
            }
            const clock_desc = self.statement.infra_descs[
                self.inputs.geometry.clock_infra_index
            ];
            if (clock_desc.log_size >= @bitSizeOf(u64))
                return error.InvalidMainWitnessWorkShape;
            const expected_merges = if (self.plan.opcode_chunk_count == 0)
                0
            else
                self.plan.opcode_chunk_count - 1;
            const expected_guest_lookup_rows: u64 =
                if (self.inputs.poseidon2_caller_lookup) |guest_lookup|
                    guest_lookup.n_rows
                else
                    0;
            if (!std.meta.eql(opcode_rows, completed.opcode_rows) or
                !std.meta.eql(audit_rows, completed.audit_rows) or
                completed.program_rows != program_rows or
                completed.memory_rows != memory_rows or
                completed.merkle_rows != merkle_rows or
                completed.clock_rows != clock_rows or
                completed.program_seed_rows != program_rows or
                completed.memory_seed_rows != memory_rows or
                completed.clock_seed_domain_rows !=
                    (@as(u64, 1) << @intCast(clock_desc.log_size)) or
                completed.clock_seed_active_rows != clock_rows or
                completed.guest_caller_trace_rows != 0 or
                completed.guest_lookup_rows != expected_guest_lookup_rows or
                completed.counter_set_merges != expected_merges)
            {
                return error.InvalidMainWitnessWorkShape;
            }
        }
    };
}
