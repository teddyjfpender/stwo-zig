//! Shared provider-call custody, authenticated completion and output extraction.

pub fn For(comptime owner_context: anytype) type {
    const M31 = owner_context.M31;
    const digest = owner_context.digest;
    const poseidon_air = owner_context.poseidon_air;
    const shared_provider = owner_context.shared_provider;
    const committedRow = owner_context.committedRow;
    const bundleIdentity = owner_context.bundleIdentity;
    const poseidonCallSlicesEqual = owner_context.poseidonCallSlicesEqual;
    const Self = owner_context.Self;
    const SharedLayout = owner_context.SharedLayout;
    const SharedCall = owner_context.SharedCall;
    return struct {
        pub fn providerBatchId(self: *const Self) digest.Digest {
            return if (self.shared_layout) |layout|
                layout.identity
            else
                self.merkle_workspace.authority_digest;
        }

        pub fn providerCallCount(self: *const Self) usize {
            return switch (self.provider_custody) {
                .local_core => self.merkle_workspace.poseidon_calls.len,
                .complete_shared_schedule_v2 => self.shared_calls.len,
                .pending_shared_schedule => self.owned_shared_calls.len,
            };
        }

        pub fn providerCallsPrepared(
            self: *const Self,
        ) ![]const poseidon_air.Call {
            const core_calls = try self.source.merklePoseidonCallsPrepared(
                &self.source_authority,
                &self.fri_workspace,
                &self.merkle_workspace,
            );
            if (self.provider_custody == .local_core) return core_calls;
            if (self.provider_custody == .pending_shared_schedule)
                return error.RowsNotPrepared;
            const layout = self.shared_layout orelse
                return error.ProviderIdentityMismatch;
            layout.validate(self.shared_calls) catch
                return error.ProviderIdentityMismatch;
            const start: usize = layout.verifier_core.start;
            const end: usize = layout.verifier_core.end;
            if (end < start or end > self.shared_calls.len or
                !poseidonCallSlicesEqual(
                    core_calls,
                    self.shared_calls[start..end],
                ))
            {
                return error.ProviderIdentityMismatch;
            }
            return self.shared_calls;
        }

        pub fn providerOutputsPrepared(
            self: *const Self,
        ) ![]const [poseidon_air.WIDTH]u32 {
            if (self.provider_custody == .local_core) {
                return self.source.merklePoseidonOutputsPrepared(
                    &self.source_authority,
                    &self.fri_workspace,
                    &self.merkle_workspace,
                );
            }
            if (!self.shared_outputs_ready or
                self.shared_outputs.len != self.shared_calls.len)
            {
                return error.RowsNotPrepared;
            }
            return self.shared_outputs;
        }

        pub fn captureSharedProviderOutputs(
            self: *Self,
            columns: *const [poseidon_air.N_MAIN_COLUMNS][]M31,
        ) !void {
            if (self.provider_custody != .complete_shared_schedule_v2) return;
            if (self.shared_outputs.len != self.shared_calls.len)
                return error.ProviderIdentityMismatch;

            // Fresh verification rebuilds the authenticated interactions on
            // the same immutable cohort after proving has already prepared
            // them. The second pass must compare the complete provider trace
            // with the first sealed capture; it must never overwrite it.
            if (self.shared_outputs_ready) {
                if (!self.main_prepared)
                    return error.ProviderIdentityMismatch;
                for (self.shared_outputs, 0..) |output, logical_row| {
                    const committed = committedRow(
                        logical_row,
                        self.provider_log_size,
                    );
                    if (!columns.*[0][committed].eql(M31.one()))
                        return error.ProviderIdentityMismatch;
                    for (output, 0..) |word, lane| {
                        if (columns.*[
                            shared_provider.POSEIDON_OUTPUT_COLUMN_START + lane
                        ][committed].toU32() != word)
                            return error.ProviderIdentityMismatch;
                    }
                }
                return;
            }
            if (self.main_prepared) return error.ProviderIdentityMismatch;
            for (self.shared_outputs, 0..) |*output, logical_row| {
                const committed = committedRow(logical_row, self.provider_log_size);
                if (!columns.*[0][committed].eql(M31.one()))
                    return error.ProviderIdentityMismatch;
                for (output, 0..) |*word, lane| word.* = columns.*[
                    shared_provider.POSEIDON_OUTPUT_COLUMN_START + lane
                ][committed].toU32();
            }
            self.shared_outputs_ready = true;
        }

        pub fn finalizePendingSharedSchedule(
            self: *Self,
            core_calls: []const SharedCall,
        ) !void {
            if (self.provider_custody != .pending_shared_schedule) return;
            const boundary = self.shared_layout orelse
                return error.ProviderIdentityMismatch;
            try boundary.validate(self.shared_calls);
            const prefix_count: usize = self.shared_boundary_call_count;
            if (prefix_count != self.shared_calls.len or
                self.owned_shared_calls.len - prefix_count != core_calls.len)
            {
                return error.ProviderIdentityMismatch;
            }
            @memcpy(self.owned_shared_calls[prefix_count..], core_calls);
            const complete = try SharedLayout.initComplete(
                try boundary.transcript.count(),
                try boundary.statement_authority.count(),
                core_calls.len,
                self.owned_shared_calls,
            );
            self.shared_layout = complete;
            self.shared_calls = self.owned_shared_calls;
            self.provider_custody = .complete_shared_schedule_v2;
            self.authority_seal = bundleIdentity(self);
            try self.validate();
        }
    };
}
