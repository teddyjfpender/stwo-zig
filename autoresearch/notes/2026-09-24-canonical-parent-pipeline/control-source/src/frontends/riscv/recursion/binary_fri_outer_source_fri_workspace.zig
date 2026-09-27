//! Retained Workspace authority storage for the binary FRI source.

pub fn Type(comptime Context: type) type {
    const Self = Context.Source;
    const PreparedAuthority = Context.PreparedAuthorityType;
    const std = Context.std;
    const M31 = Context.M31;
    const air_digest = Context.air_digest;
    const FRI_ROW_COUNT = Context.FRI_ROW_COUNT;
    const PREPROCESSED_COLUMN_COUNT = Context.PREPROCESSED_COLUMN_COUNT;
    const MAIN_COLUMN_COUNT = Context.MAIN_COLUMN_COUNT;
    const PREPROCESSED_COLUMNS_PER_ROW = Context.PREPROCESSED_COLUMNS_PER_ROW;
    const MAIN_COLUMNS_PER_ROW = Context.MAIN_COLUMNS_PER_ROW;
    const friPathLeafDigest = Context.friPathLeafDigest;
    const columnStorageCount = Context.columnStorageCount;
    const carveColumnViews = Context.carveColumnViews;
    const validateColumnViews = Context.validateColumnViews;

    return struct {
        const Workspace = @This();
        allocator: std.mem.Allocator,
        storage: []M31,
        preprocessed_columns: [PREPROCESSED_COLUMN_COUNT][]M31,
        main_columns: [MAIN_COLUMN_COUNT][]M31,
        source_authority_digest: air_digest.Digest,
        log_sizes: [FRI_ROW_COUNT]u32,
        main_ready: bool,
        path_leaf_digest: air_digest.Digest,

        pub fn init(
            allocator: std.mem.Allocator,
            source: *const Self,
        ) !Workspace {
            try source.validate();
            return initAssumeAuthority(allocator, source);
        }

        pub fn initPrepared(
            allocator: std.mem.Allocator,
            source: *const Self,
            authority: *const PreparedAuthority,
        ) !Workspace {
            try authority.validateFor(source);
            return initAssumeAuthority(allocator, source);
        }

        fn initAssumeAuthority(
            allocator: std.mem.Allocator,
            source: *const Self,
        ) !Workspace {
            const preprocessed_count = try columnStorageCount(
                source.fri_rows.log_sizes,
                PREPROCESSED_COLUMNS_PER_ROW,
            );
            const main_count = try columnStorageCount(
                source.fri_rows.log_sizes,
                MAIN_COLUMNS_PER_ROW,
            );
            const total = std.math.add(
                usize,
                preprocessed_count,
                main_count,
            ) catch return error.ArithmeticOverflow;
            const storage = try allocator.alloc(M31, total);
            errdefer allocator.free(storage);
            var result = Workspace{
                .allocator = allocator,
                .storage = storage,
                .preprocessed_columns = undefined,
                .main_columns = undefined,
                .source_authority_digest = source.source_authority_digest,
                .log_sizes = source.fri_rows.log_sizes,
                .main_ready = false,
                .path_leaf_digest = [_]u8{0} ** @sizeOf(air_digest.Digest),
            };
            var storage_at: usize = 0;
            carveColumnViews(
                &result.preprocessed_columns,
                storage,
                &storage_at,
                result.log_sizes,
                PREPROCESSED_COLUMNS_PER_ROW,
            ) catch unreachable;
            carveColumnViews(
                &result.main_columns,
                storage,
                &storage_at,
                result.log_sizes,
                MAIN_COLUMNS_PER_ROW,
            ) catch unreachable;
            std.debug.assert(storage_at == storage.len);
            try result.validateFor(source);
            return result;
        }

        pub fn deinit(self: *Workspace) void {
            self.allocator.free(self.storage);
            self.* = undefined;
        }

        pub fn validateFor(
            self: *const Workspace,
            source: *const Self,
        ) !void {
            if (!std.mem.eql(
                u8,
                &self.source_authority_digest,
                &source.source_authority_digest,
            ) or !std.meta.eql(self.log_sizes, source.fri_rows.log_sizes) or
                self.storage.len != try columnStorageCount(
                    self.log_sizes,
                    PREPROCESSED_COLUMNS_PER_ROW,
                ) + try columnStorageCount(
                    self.log_sizes,
                    MAIN_COLUMNS_PER_ROW,
                ))
            {
                return error.WorkspaceAuthorityMismatch;
            }
            var storage_at: usize = 0;
            try validateColumnViews(
                &self.preprocessed_columns,
                self.storage,
                &storage_at,
                self.log_sizes,
                PREPROCESSED_COLUMNS_PER_ROW,
            );
            try validateColumnViews(
                &self.main_columns,
                self.storage,
                &storage_at,
                self.log_sizes,
                MAIN_COLUMNS_PER_ROW,
            );
            if (storage_at != self.storage.len)
                return error.WorkspaceAuthorityMismatch;
            if (self.main_ready and !std.mem.eql(
                u8,
                &self.path_leaf_digest,
                &friPathLeafDigest(source, &self.main_columns),
            )) return error.WorkspaceAuthorityMismatch;
        }
    };
}
