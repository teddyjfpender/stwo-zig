//! Backend-neutral ownership and ordering for a complete proving transaction.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const prover_component = @import("stwo_prover_impl").air.component_prover;
const prover_engine = @import("stwo_prover_impl").engine;
const prover_pcs = @import("stwo_prover_impl").pcs;
const stage_profile = @import("stwo_prover_impl").stage_profile;

const ColumnEvaluation = prover_pcs.ColumnEvaluation;
const ColumnSource = prover_pcs.ColumnSource;
const M31 = @import("stwo_core").fields.m31.M31;

pub const Error = error{
    GeometryOverflow,
    InvalidColumnLength,
    InvalidPreparedGeometry,
    PreparedInputConsumed,
};

pub const OwnedColumns = struct {
    columns: ?[]ColumnEvaluation,
    backing_buffers: ?[][]M31 = null,
    source: ColumnSource = .materialized,

    pub const Taken = struct {
        columns: []ColumnEvaluation,
        backing_buffers: ?[][]M31,
        source: ColumnSource,
    };

    pub fn init(columns: []ColumnEvaluation) OwnedColumns {
        return .{ .columns = columns };
    }

    pub fn initWithBacking(
        columns: []ColumnEvaluation,
        backing_buffers: [][]M31,
    ) OwnedColumns {
        return .{ .columns = columns, .backing_buffers = backing_buffers };
    }

    pub fn initWithBackingAndSource(
        columns: []ColumnEvaluation,
        backing_buffers: [][]M31,
        source: ColumnSource,
    ) OwnedColumns {
        return .{
            .columns = columns,
            .backing_buffers = backing_buffers,
            .source = source,
        };
    }

    /// Transfers the allocation. The caller must consume or release it.
    pub fn take(self: *OwnedColumns) []ColumnEvaluation {
        std.debug.assert(self.backing_buffers == null);
        const columns = self.columns orelse unreachable;
        self.columns = null;
        std.debug.assert(self.source.isMaterialized());
        return columns;
    }

    /// Transfers the column descriptors and any shared backing allocations.
    pub fn takeWithBacking(self: *OwnedColumns) Taken {
        const columns = self.columns orelse unreachable;
        const backing_buffers = self.backing_buffers;
        const source = self.source;
        self.columns = null;
        self.backing_buffers = null;
        self.source = .materialized;
        return .{
            .columns = columns,
            .backing_buffers = backing_buffers,
            .source = source,
        };
    }

    pub fn deinit(self: *OwnedColumns, allocator: std.mem.Allocator) void {
        const columns = self.columns orelse return;
        self.columns = null;
        if (self.backing_buffers) |buffers| {
            self.backing_buffers = null;
            allocator.free(columns);
            for (buffers) |buffer| allocator.free(buffer);
            allocator.free(buffers);
        } else {
            for (columns) |column| allocator.free(column.values);
            allocator.free(columns);
        }
    }
};

pub const PreparedTrace = struct {
    preprocessed: OwnedColumns,
    main: OwnedColumns,
    max_column_log: u32,
    committed_columns: u64,
    committed_cells: u64,

    /// Consumes both trees on success and failure.
    pub fn initOwned(
        allocator: std.mem.Allocator,
        preprocessed: []ColumnEvaluation,
        main: []ColumnEvaluation,
    ) Error!PreparedTrace {
        var trace = PreparedTrace{
            .preprocessed = OwnedColumns.init(preprocessed),
            .main = OwnedColumns.init(main),
            .max_column_log = 0,
            .committed_columns = 0,
            .committed_cells = 0,
        };
        errdefer trace.deinit(allocator);

        const geometry = try measure(&trace);
        trace.max_column_log = geometry.max_column_log;
        trace.committed_columns = geometry.committed_columns;
        trace.committed_cells = geometry.committed_cells;
        return trace;
    }

    /// Consumes column descriptors whose values may borrow shared arenas.
    pub fn initOwnedWithBacking(
        allocator: std.mem.Allocator,
        preprocessed: OwnedColumns,
        main: OwnedColumns,
    ) Error!PreparedTrace {
        var trace = PreparedTrace{
            .preprocessed = preprocessed,
            .main = main,
            .max_column_log = 0,
            .committed_columns = 0,
            .committed_cells = 0,
        };
        errdefer trace.deinit(allocator);

        const geometry = try measure(&trace);
        trace.max_column_log = geometry.max_column_log;
        trace.committed_columns = geometry.committed_columns;
        trace.committed_cells = geometry.committed_cells;
        return trace;
    }

    pub fn validate(self: *const PreparedTrace) Error!void {
        if (self.preprocessed.columns == null or self.main.columns == null)
            return error.PreparedInputConsumed;
        const geometry = try measure(self);
        if (geometry.max_column_log != self.max_column_log or
            geometry.committed_columns != self.committed_columns or
            geometry.committed_cells != self.committed_cells)
        {
            return error.InvalidPreparedGeometry;
        }
    }

    pub fn deinit(self: *PreparedTrace, allocator: std.mem.Allocator) void {
        self.preprocessed.deinit(allocator);
        self.main.deinit(allocator);
    }

    const Geometry = struct {
        max_column_log: u32 = 0,
        committed_columns: u64 = 0,
        committed_cells: u64 = 0,
    };

    fn measure(self: *const PreparedTrace) Error!Geometry {
        var geometry = Geometry{};
        try measureTree(self.preprocessed.columns orelse return error.PreparedInputConsumed, &geometry);
        try measureTree(self.main.columns orelse return error.PreparedInputConsumed, &geometry);
        return geometry;
    }

    fn measureTree(columns: []const ColumnEvaluation, geometry: *Geometry) Error!void {
        const column_count = std.math.cast(u64, columns.len) orelse
            return error.GeometryOverflow;
        geometry.committed_columns = std.math.add(
            u64,
            geometry.committed_columns,
            column_count,
        ) catch return error.GeometryOverflow;

        for (columns) |column| {
            if (column.log_size >= @bitSizeOf(usize)) return error.InvalidColumnLength;
            const expected_len = @as(usize, 1) << @intCast(column.log_size);
            if (column.values.len != expected_len) return error.InvalidColumnLength;
            geometry.max_column_log = @max(geometry.max_column_log, column.log_size);
            const cells = std.math.cast(u64, column.values.len) orelse
                return error.GeometryOverflow;
            geometry.committed_cells = std.math.add(
                u64,
                geometry.committed_cells,
                cells,
            ) catch return error.GeometryOverflow;
        }
    }
};

pub fn PreparedInput(comptime Request: type) type {
    return struct {
        request: Request,
        trace: PreparedTrace,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.trace.deinit(allocator);
            self.* = undefined;
        }
    };
}

pub fn Output(comptime Statement: type, comptime ExtendedProof: type) type {
    return struct {
        statement: Statement,
        proof: ExtendedProof,
    };
}

/// Consumes `prepared_input` on every success or error path.
pub fn provePreparedEx(
    comptime Engine: type,
    comptime Spec: type,
    comptime use_session: bool,
    session: if (use_session) *const Engine.Session else void,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    prepared_input: Spec.PreparedInput,
    options: prover_engine.ProveOptions,
) anyerror!Output(Spec.Statement, Engine.ExtendedProof) {
    comptime assertContract(Engine, Spec, use_session);
    const has_interaction = comptime @hasDecl(Spec, "PreparedInteraction");

    var prepared = prepared_input;
    defer prepared.deinit(allocator);
    try Spec.validateRequest(prepared.request);
    try prepared.trace.validate();
    try Spec.validatePrepared(&prepared);

    const composition_log = try Spec.compositionLog(prepared.request);
    const commitment_log = std.math.add(
        u32,
        prepared.trace.max_column_log,
        pcs_config.fri_config.log_blowup_factor,
    ) catch return error.GeometryOverflow;
    const required_circle_log = @max(
        @max(composition_log, commitment_log),
        pcs_config.lifting_log_size orelse 0,
    );

    const Initialized = struct {
        channel: Engine.Channel,
        scheme: Engine.Scheme,
    };
    const initialized = blk: {
        var stage = try stage_profile.StageScope.begin(
            options.recorder,
            "channel_and_scheme_init",
            "Channel and scheme init",
        );
        defer stage.end();

        var channel = Engine.Channel{};
        pcs_config.mixInto(&channel);
        break :blk Initialized{
            .channel = channel,
            .scheme = if (comptime use_session)
                try Engine.initWithSession(session, pcs_config, required_circle_log)
            else
                try Engine.init(allocator, pcs_config),
        };
    };
    var channel = initialized.channel;
    var scheme = initialized.scheme;
    var scheme_owned = true;
    errdefer if (scheme_owned) Engine.deinit(&scheme, allocator);

    {
        var stage = try stage_profile.StageScope.begin(
            options.recorder,
            "preprocessed_commit",
            "Preprocessed commit",
        );
        defer stage.end();
        const owned = prepared.trace.preprocessed.takeWithBacking();
        try Engine.commitPreparedWithBacking(
            &scheme,
            allocator,
            owned.columns,
            owned.backing_buffers,
            owned.source,
            options.recorder,
            &channel,
        );
    }
    {
        var stage = try stage_profile.StageScope.begin(
            options.recorder,
            "main_trace_commit",
            "Main trace commit",
        );
        defer stage.end();
        const owned = prepared.trace.main.takeWithBacking();
        try Engine.commitPreparedWithBacking(
            &scheme,
            allocator,
            owned.columns,
            owned.backing_buffers,
            owned.source,
            options.recorder,
            &channel,
        );
    }

    var prepared_interaction: if (has_interaction) Spec.PreparedInteraction else void =
        if (has_interaction) undefined else {};
    defer if (comptime has_interaction)
        Spec.deinitPreparedInteraction(&prepared_interaction, allocator);
    if (comptime has_interaction) {
        {
            var stage = try stage_profile.StageScope.begin(
                options.recorder,
                "interaction_trace_generation",
                "Interaction trace generation",
            );
            defer stage.end();
            prepared_interaction = try Spec.prepareInteraction(
                allocator,
                &channel,
                &prepared,
            );
        }
        {
            var stage = try stage_profile.StageScope.begin(
                options.recorder,
                "interaction_trace_commit",
                "Interaction trace commit",
            );
            defer stage.end();
            const owned = prepared_interaction.columns.takeWithBacking();
            try Engine.commitPreparedWithBacking(
                &scheme,
                allocator,
                owned.columns,
                owned.backing_buffers,
                owned.source,
                options.recorder,
                &channel,
            );
        }
    }

    var context: Spec.ProverContext = undefined;
    {
        var stage = try stage_profile.StageScope.begin(
            options.recorder,
            "statement_mix",
            "Statement mix",
        );
        defer stage.end();
        if (comptime has_interaction) {
            try Spec.initProverContext(
                &context,
                &channel,
                prepared.request,
                &prepared_interaction,
            );
        } else {
            try Spec.initProverContext(&context, &channel, prepared.request);
        }
    }

    var component_storage: [Spec.max_components]prover_component.ComponentProver = undefined;
    const components = try Spec.proverComponents(&context, component_storage[0..]);
    const statement = Spec.statement(&context);
    const extended_proof = blk: {
        var stage = try stage_profile.StageScope.begin(
            options.recorder,
            "core_prove",
            "Core prove",
        );
        defer stage.end();
        scheme_owned = false;
        break :blk try Engine.prove(allocator, components, &channel, scheme, options);
    };
    return .{ .statement = statement, .proof = extended_proof };
}

fn assertContract(comptime Engine: type, comptime Spec: type, comptime use_session: bool) void {
    prover_engine.assertProverEngine(Engine);
    inline for (&.{ "Channel", "ExtendedProof" }) |name| {
        if (!@hasDecl(Engine, name)) @compileError("transaction engine requires " ++ name);
    }
    if (use_session) {
        if (!@hasDecl(Engine, "Session")) @compileError("session engine requires Session");
        if (!@hasDecl(Engine, "initWithSession"))
            @compileError("session engine requires initWithSession");
    }
    inline for (&.{
        "Statement",
        "PreparedInput",
        "ProverContext",
        "max_components",
        "validateRequest",
        "validatePrepared",
        "compositionLog",
        "initProverContext",
        "statement",
        "proverComponents",
    }) |name| {
        if (!@hasDecl(Spec, name)) @compileError("prover spec requires " ++ name);
    }
    if (@hasDecl(Spec, "PreparedInteraction")) {
        inline for (&.{ "prepareInteraction", "deinitPreparedInteraction" }) |name| {
            if (!@hasDecl(Spec, name))
                @compileError("interaction prover spec requires " ++ name);
        }
    }
}
