//! Retained CompositionWorkspace authority storage for the binary FRI source.

pub fn Type(comptime Context: type) type {
    const Self = Context.Source;
    const PreparedAuthority = Context.PreparedAuthorityType;
    const std = Context.std;
    const M31 = Context.M31;
    const air_digest = Context.air_digest;
    const COMPOSITION_ROW_COUNT = Context.COMPOSITION_ROW_COUNT;
    const COMPOSITION_PREPROCESSED_COLUMN_COUNT = Context.COMPOSITION_PREPROCESSED_COLUMN_COUNT;
    const COMPOSITION_MAIN_COLUMN_COUNT = Context.COMPOSITION_MAIN_COLUMN_COUNT;
    const COMPOSITION_PREPROCESSED_COLUMNS_PER_ROW = Context.COMPOSITION_PREPROCESSED_COLUMNS_PER_ROW;
    const COMPOSITION_MAIN_COLUMNS_PER_ROW = Context.COMPOSITION_MAIN_COLUMNS_PER_ROW;
    const columnStorageCount = Context.columnStorageCount;
    const carveColumnViews = Context.carveColumnViews;
    const validateColumnViews = Context.validateColumnViews;

    return struct {
        const CompositionWorkspace = @This();
        allocator: std.mem.Allocator,
        storage: []M31,
        preprocessed_columns: [COMPOSITION_PREPROCESSED_COLUMN_COUNT][]M31,
        main_columns: [COMPOSITION_MAIN_COLUMN_COUNT][]M31,
        source_authority_digest: air_digest.Digest,
        composition_authority_digest: air_digest.Digest,
        log_sizes: [COMPOSITION_ROW_COUNT]u32,

        pub fn init(
            allocator: std.mem.Allocator,
            source: *const Self,
        ) !CompositionWorkspace {
            try source.requireFullBundleAuthority();
            return initAssumeAuthority(allocator, source);
        }

        pub fn initPrepared(
            allocator: std.mem.Allocator,
            source: *const Self,
            authority: *const PreparedAuthority,
        ) !CompositionWorkspace {
            try authority.validateFor(source);
            return initAssumeAuthority(allocator, source);
        }

        fn initAssumeAuthority(
            allocator: std.mem.Allocator,
            source: *const Self,
        ) !CompositionWorkspace {
            const rows = source.composition_rows.?;
            const pp_count = try columnStorageCount(
                rows.log_sizes,
                COMPOSITION_PREPROCESSED_COLUMNS_PER_ROW,
            );
            const main_count = try columnStorageCount(
                rows.log_sizes,
                COMPOSITION_MAIN_COLUMNS_PER_ROW,
            );
            const storage = try allocator.alloc(
                M31,
                std.math.add(usize, pp_count, main_count) catch
                    return error.ArithmeticOverflow,
            );
            errdefer allocator.free(storage);
            var result = CompositionWorkspace{
                .allocator = allocator,
                .storage = storage,
                .preprocessed_columns = undefined,
                .main_columns = undefined,
                .source_authority_digest = source.source_authority_digest,
                .composition_authority_digest = rows.authority_digest,
                .log_sizes = rows.log_sizes,
            };
            var at: usize = 0;
            carveColumnViews(
                &result.preprocessed_columns,
                storage,
                &at,
                result.log_sizes,
                COMPOSITION_PREPROCESSED_COLUMNS_PER_ROW,
            ) catch unreachable;
            carveColumnViews(
                &result.main_columns,
                storage,
                &at,
                result.log_sizes,
                COMPOSITION_MAIN_COLUMNS_PER_ROW,
            ) catch unreachable;
            std.debug.assert(at == storage.len);
            try result.validateFor(source);
            return result;
        }

        pub fn deinit(self: *CompositionWorkspace) void {
            self.allocator.free(self.storage);
            self.* = undefined;
        }

        pub fn validateFor(
            self: *const CompositionWorkspace,
            source: *const Self,
        ) !void {
            const rows = source.composition_rows orelse
                return error.MissingCompositionAuthority;
            if (!std.mem.eql(
                u8,
                &self.source_authority_digest,
                &source.source_authority_digest,
            ) or !std.mem.eql(
                u8,
                &self.composition_authority_digest,
                &rows.authority_digest,
            ) or !std.meta.eql(self.log_sizes, rows.log_sizes)) {
                return error.WorkspaceAuthorityMismatch;
            }
            var at: usize = 0;
            try validateColumnViews(
                &self.preprocessed_columns,
                self.storage,
                &at,
                self.log_sizes,
                COMPOSITION_PREPROCESSED_COLUMNS_PER_ROW,
            );
            try validateColumnViews(
                &self.main_columns,
                self.storage,
                &at,
                self.log_sizes,
                COMPOSITION_MAIN_COLUMNS_PER_ROW,
            );
            if (at != self.storage.len)
                return error.WorkspaceAuthorityMismatch;
        }
    };
}
