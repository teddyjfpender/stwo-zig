//! Retained ArithmeticWorkspace authority storage for the binary FRI source.

pub fn Type(comptime Context: type) type {
    const Self = Context.Source;
    const PreparedAuthority = Context.PreparedAuthorityType;
    const std = Context.std;
    const M31 = Context.M31;
    const air_digest = Context.air_digest;
    const multiply_witness = Context.multiply_witness;
    const inverse_witness = Context.inverse_witness;
    const linear_witness = Context.linear_witness;
    const lowering = Context.lowering;
    const ARITHMETIC_ROW_COUNT = Context.ARITHMETIC_ROW_COUNT;
    const ARITHMETIC_PREPROCESSED_COLUMN_COUNT = Context.ARITHMETIC_PREPROCESSED_COLUMN_COUNT;
    const ARITHMETIC_MAIN_COLUMN_COUNT = Context.ARITHMETIC_MAIN_COLUMN_COUNT;
    const ARITHMETIC_PREPROCESSED_COLUMNS_PER_ROW = Context.ARITHMETIC_PREPROCESSED_COLUMNS_PER_ROW;
    const ARITHMETIC_MAIN_COLUMNS_PER_ROW = Context.ARITHMETIC_MAIN_COLUMNS_PER_ROW;
    const columnStorageCount = Context.columnStorageCount;
    const carveColumnViews = Context.carveColumnViews;
    const validateColumnViews = Context.validateColumnViews;
    const typedSlicesOverlap = Context.typedSlicesOverlap;

    return struct {
        const ArithmeticWorkspace = @This();
        allocator: std.mem.Allocator,
        storage: []M31,
        preprocessed_columns: [ARITHMETIC_PREPROCESSED_COLUMN_COUNT][]M31,
        main_columns: [ARITHMETIC_MAIN_COLUMN_COUNT][]M31,
        multiply_invocations: []multiply_witness.Invocation,
        inverse_invocations: []inverse_witness.Invocation,
        linear_invocations: []linear_witness.Invocation,
        source_authority_digest: air_digest.Digest,
        arithmetic_authority_digest: air_digest.Digest,
        log_sizes: [ARITHMETIC_ROW_COUNT]u32,

        pub fn init(
            allocator: std.mem.Allocator,
            source: *const Self,
        ) !ArithmeticWorkspace {
            try source.requireCompositionAuthorities();
            return initAssumeAuthority(allocator, source);
        }

        pub fn initPrepared(
            allocator: std.mem.Allocator,
            source: *const Self,
            authority: *const PreparedAuthority,
        ) !ArithmeticWorkspace {
            try authority.validateFor(source);
            return initAssumeAuthority(allocator, source);
        }

        fn initAssumeAuthority(
            allocator: std.mem.Allocator,
            source: *const Self,
        ) !ArithmeticWorkspace {
            const rows = source.arithmetic_rows orelse
                return error.MissingCompositionAuthority;
            const counts = rows.plan.counts(.binary_node);
            const multiply_invocations = try allocator.alloc(
                multiply_witness.Invocation,
                counts.multiply,
            );
            errdefer allocator.free(multiply_invocations);
            const inverse_invocations = try allocator.alloc(
                inverse_witness.Invocation,
                counts.inverse,
            );
            errdefer allocator.free(inverse_invocations);
            const linear_invocations = try allocator.alloc(
                linear_witness.Invocation,
                counts.linear,
            );
            errdefer allocator.free(linear_invocations);
            const preprocessed_count = try columnStorageCount(
                rows.log_sizes,
                ARITHMETIC_PREPROCESSED_COLUMNS_PER_ROW,
            );
            const main_count = try columnStorageCount(
                rows.log_sizes,
                ARITHMETIC_MAIN_COLUMNS_PER_ROW,
            );
            const storage = try allocator.alloc(
                M31,
                std.math.add(usize, preprocessed_count, main_count) catch
                    return error.ArithmeticOverflow,
            );
            errdefer allocator.free(storage);

            var result = ArithmeticWorkspace{
                .allocator = allocator,
                .storage = storage,
                .preprocessed_columns = undefined,
                .main_columns = undefined,
                .multiply_invocations = multiply_invocations,
                .inverse_invocations = inverse_invocations,
                .linear_invocations = linear_invocations,
                .source_authority_digest = source.source_authority_digest,
                .arithmetic_authority_digest = rows.authority_digest,
                .log_sizes = rows.log_sizes,
            };
            var storage_at: usize = 0;
            carveColumnViews(
                &result.preprocessed_columns,
                storage,
                &storage_at,
                result.log_sizes,
                ARITHMETIC_PREPROCESSED_COLUMNS_PER_ROW,
            ) catch unreachable;
            carveColumnViews(
                &result.main_columns,
                storage,
                &storage_at,
                result.log_sizes,
                ARITHMETIC_MAIN_COLUMNS_PER_ROW,
            ) catch unreachable;
            std.debug.assert(storage_at == storage.len);
            try result.validateFor(source);
            return result;
        }

        pub fn deinit(self: *ArithmeticWorkspace) void {
            self.allocator.free(self.storage);
            self.allocator.free(self.linear_invocations);
            self.allocator.free(self.inverse_invocations);
            self.allocator.free(self.multiply_invocations);
            self.* = undefined;
        }

        pub fn validateFor(
            self: *const ArithmeticWorkspace,
            source: *const Self,
        ) !void {
            const rows = source.arithmetic_rows orelse
                return error.MissingCompositionAuthority;
            const counts = rows.plan.counts(.binary_node);
            if (!std.mem.eql(
                u8,
                &self.source_authority_digest,
                &source.source_authority_digest,
            ) or !std.mem.eql(
                u8,
                &self.arithmetic_authority_digest,
                &rows.authority_digest,
            ) or !std.meta.eql(self.log_sizes, rows.log_sizes) or
                self.multiply_invocations.len != counts.multiply or
                self.inverse_invocations.len != counts.inverse or
                self.linear_invocations.len != counts.linear or
                self.storage.len != try columnStorageCount(
                    self.log_sizes,
                    ARITHMETIC_PREPROCESSED_COLUMNS_PER_ROW,
                ) + try columnStorageCount(
                    self.log_sizes,
                    ARITHMETIC_MAIN_COLUMNS_PER_ROW,
                ))
            {
                return error.WorkspaceAuthorityMismatch;
            }
            if (typedSlicesOverlap(
                M31,
                self.storage,
                multiply_witness.Invocation,
                self.multiply_invocations,
            ) or typedSlicesOverlap(
                M31,
                self.storage,
                inverse_witness.Invocation,
                self.inverse_invocations,
            ) or typedSlicesOverlap(
                M31,
                self.storage,
                linear_witness.Invocation,
                self.linear_invocations,
            ) or typedSlicesOverlap(
                multiply_witness.Invocation,
                self.multiply_invocations,
                inverse_witness.Invocation,
                self.inverse_invocations,
            ) or typedSlicesOverlap(
                multiply_witness.Invocation,
                self.multiply_invocations,
                linear_witness.Invocation,
                self.linear_invocations,
            ) or typedSlicesOverlap(
                inverse_witness.Invocation,
                self.inverse_invocations,
                linear_witness.Invocation,
                self.linear_invocations,
            )) return error.WorkspaceAuthorityMismatch;
            var storage_at: usize = 0;
            try validateColumnViews(
                &self.preprocessed_columns,
                self.storage,
                &storage_at,
                self.log_sizes,
                ARITHMETIC_PREPROCESSED_COLUMNS_PER_ROW,
            );
            try validateColumnViews(
                &self.main_columns,
                self.storage,
                &storage_at,
                self.log_sizes,
                ARITHMETIC_MAIN_COLUMNS_PER_ROW,
            );
            if (storage_at != self.storage.len)
                return error.WorkspaceAuthorityMismatch;
        }

        pub fn buffers(self: *ArithmeticWorkspace) lowering.InvocationBuffers {
            return .{
                .multiply = self.multiply_invocations,
                .inverse = self.inverse_invocations,
                .linear = self.linear_invocations,
            };
        }
    };
}
