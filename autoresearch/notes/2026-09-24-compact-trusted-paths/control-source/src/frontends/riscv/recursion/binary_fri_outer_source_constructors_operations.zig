//! Constructor operations for the authenticated binary FRI source.

pub fn Operations(comptime Context: type) type {
    const Self = Context.Source;

    const dimensions = Context.dimensions_value;
    const Boundary = Context.BoundaryType;
    const PairPrepared = Context.PairPreparedType;
    const RootPin = Context.RootPinType;
    const Child = Context.ChildType;
    const std = Context.std;
    const M31 = Context.M31;
    const fixed_wire = Context.fixed_wire;
    const protocol = Context.protocol;
    const schedule = Context.schedule;
    const CHILD_COUNT = Context.CHILD_COUNT;
    const LEFT_CHILD = Context.LEFT_CHILD;
    const RIGHT_CHILD = Context.RIGHT_CHILD;
    const SharedArithmeticInput = Context.SharedArithmeticInput;
    const CompositionRowsAuthority = Context.CompositionRowsAuthority;
    const FriRowsAuthority = Context.FriRowsAuthority;
    const ArithmeticRowsAuthority = Context.ArithmeticRowsAuthority;
    const MerkleRowsAuthority = Context.MerkleRowsAuthority;
    const validatePairBoundary = Context.validatePairBoundary;
    const validateChildProfiles = Context.validateChildProfiles;
    const validateCapturedAgainstWire = Context.validateCapturedAgainstWire;
    const validateExecutionAgainstCapture = Context.validateExecutionAgainstCapture;

    return struct {
        pub fn initAuthenticated(
            allocator: std.mem.Allocator,
            pair: *const PairPrepared,
            root_pin: RootPin,
            vm_plan: *const schedule.Plan,
            recursion_plans: [2]*const schedule.Plan,
            children: [2]Child,
            shared_arithmetic: ?SharedArithmeticInput,
        ) !Self {
            if (comptime Boundary.IS_LEGACY)
                @compileError("use Source.init for the frozen V1 boundary");
            try Boundary.validateInputs(
                dimensions,
                pair,
                root_pin,
                vm_plan,
                recursion_plans,
                children,
                shared_arithmetic,
            );
            if (shared_arithmetic) |input| try input.validate();

            const query_word_storage = try allocator.alloc(
                M31,
                CHILD_COUNT * dimensions.query_count,
            );
            errdefer allocator.free(query_word_storage);
            try Boundary.fillQueryWords(
                dimensions,
                pair,
                children,
                query_word_storage,
            );
            const query_words = [2][]const M31{
                query_word_storage[0..dimensions.query_count],
                query_word_storage[dimensions.query_count..][0..dimensions.query_count],
            };

            var composition_rows = try Boundary.initCompositionRows(
                allocator,
                pair,
                vm_plan,
                recursion_plans[0],
                children,
            );
            errdefer composition_rows.deinit();
            var fri_rows = if (comptime @hasDecl(Boundary, "initFriRows"))
                try Boundary.initFriRows(
                    allocator,
                    pair,
                    vm_plan,
                    recursion_plans[0],
                    children,
                )
            else
                try FriRowsAuthority.init(
                    allocator,
                    vm_plan,
                    recursion_plans[0],
                    children,
                );
            errdefer fri_rows.deinit();
            var arithmetic_rows = if (comptime @hasDecl(
                Boundary,
                "initArithmeticRows",
            ))
                try Boundary.initArithmeticRows(
                    allocator,
                    pair,
                    children,
                    shared_arithmetic,
                )
            else
                try ArithmeticRowsAuthority.init(
                    allocator,
                    children,
                    shared_arithmetic,
                );
            errdefer arithmetic_rows.deinit();
            var merkle_rows = try MerkleRowsAuthority.init(allocator);
            errdefer merkle_rows.deinit();

            var result = Self{
                .allocator = allocator,
                .pair = pair,
                .root_pin = root_pin,
                .vm_plan = vm_plan,
                .recursion_plans = recursion_plans,
                .children = children,
                .query_word_storage = query_word_storage,
                .query_words = query_words,
                .shared_arithmetic = shared_arithmetic,
                .composition_rows = composition_rows,
                .fri_rows = fri_rows,
                .arithmetic_rows = arithmetic_rows,
                .merkle_rows = merkle_rows,
                .source_authority_digest = undefined,
            };
            result.source_authority_digest = result.computeSourceAuthorityDigest();
            try result.validate();
            return result;
        }

        pub fn init(
            allocator: std.mem.Allocator,
            pair: *const PairPrepared,
            root_pin: RootPin,
            vm_plan: *const schedule.Plan,
            recursion_plans: [2]*const schedule.Plan,
            children: [2]Child,
        ) !Self {
            return initInternal(
                allocator,
                pair,
                root_pin,
                vm_plan,
                recursion_plans,
                children,
                null,
            );
        }

        pub fn initWithSharedArithmetic(
            allocator: std.mem.Allocator,
            pair: *const PairPrepared,
            root_pin: RootPin,
            vm_plan: *const schedule.Plan,
            recursion_plans: [2]*const schedule.Plan,
            children: [2]Child,
            shared_arithmetic: SharedArithmeticInput,
        ) !Self {
            try shared_arithmetic.validate();
            return initInternal(
                allocator,
                pair,
                root_pin,
                vm_plan,
                recursion_plans,
                children,
                shared_arithmetic,
            );
        }

        fn initInternal(
            allocator: std.mem.Allocator,
            pair: *const PairPrepared,
            root_pin: RootPin,
            vm_plan: *const schedule.Plan,
            recursion_plans: [2]*const schedule.Plan,
            children: [2]Child,
            shared_arithmetic: ?SharedArithmeticInput,
        ) !Self {
            try validatePairBoundary(pair, root_pin, vm_plan, recursion_plans);
            try validateChildProfiles(children);
            if (shared_arithmetic) |input| try input.validate();

            const proof_bytes = try allocator.alloc(
                u8,
                fixed_wire.serializedByteCount(dimensions),
            );
            defer allocator.free(proof_bytes);
            const query_word_storage = try allocator.alloc(
                M31,
                CHILD_COUNT * dimensions.query_count,
            );
            errdefer allocator.free(query_word_storage);
            const query_words = [2][]const M31{
                query_word_storage[0..dimensions.query_count],
                query_word_storage[dimensions.query_count..][0..dimensions.query_count],
            };

            for (children, &pair.authority.children, &pair.executions, 0..) |
                child,
                *verified_child,
                *execution,
                child_index,
            | {
                try child.shape.validate();
                try child.wire.validateAgainstShape(child.shape);
                try child.wire.encodeInto(proof_bytes, child.shape);
                if (!std.meta.eql(
                    protocol.proofId(proof_bytes),
                    verified_child.proof_id,
                )) return error.PairAuthorityMismatch;
                try validateCapturedAgainstWire(
                    dimensions,
                    child.capture,
                    child.shape,
                    child.wire,
                );
                try validateExecutionAgainstCapture(
                    execution,
                    child.capture,
                    @constCast(query_words[child_index]),
                );
                if (child.composition) |composition_authority| {
                    const trusted = child.trusted_composition_profile orelse
                        return error.MissingCompositionAuthority;
                    try composition_authority.validateAgainst(
                        trusted,
                        verified_child.*,
                        child.shape,
                    );
                    if (composition_authority.child_index != child_index)
                        return error.ChildOrderMismatch;
                } else if (child.trusted_composition_profile != null) {
                    return error.MissingCompositionAuthority;
                }
            }
            if (std.meta.eql(
                pair.authority.children[0].proof_id,
                pair.authority.children[1].proof_id,
            )) return error.DuplicateChildProof;

            var fri_rows = try FriRowsAuthority.init(
                allocator,
                vm_plan,
                recursion_plans[0],
                children,
            );
            errdefer fri_rows.deinit();
            var arithmetic_rows: ?ArithmeticRowsAuthority = if (children[LEFT_CHILD].composition != null) try ArithmeticRowsAuthority.init(
                allocator,
                children,
                shared_arithmetic,
            ) else null;
            errdefer if (arithmetic_rows) |*rows| rows.deinit();
            const left_trusted = children[LEFT_CHILD].trusted_composition_profile;
            const right_trusted = children[RIGHT_CHILD].trusted_composition_profile;
            const has_row18_authority = left_trusted != null and
                right_trusted != null and
                left_trusted.?.row18_input_authority and
                right_trusted.?.row18_input_authority;
            if ((left_trusted != null and left_trusted.?.row18_input_authority) !=
                (right_trusted != null and right_trusted.?.row18_input_authority))
            {
                return error.ProfileMismatch;
            }
            var composition_rows: ?CompositionRowsAuthority = if (has_row18_authority) try CompositionRowsAuthority.init(
                allocator,
                pair,
                vm_plan,
                recursion_plans[0],
                children,
            ) else null;
            errdefer if (composition_rows) |*rows| rows.deinit();
            var merkle_rows = try MerkleRowsAuthority.init(allocator);
            errdefer merkle_rows.deinit();

            var result = Self{
                .allocator = allocator,
                .pair = pair,
                .root_pin = root_pin,
                .vm_plan = vm_plan,
                .recursion_plans = recursion_plans,
                .children = children,
                .query_word_storage = query_word_storage,
                .query_words = query_words,
                .shared_arithmetic = shared_arithmetic,
                .composition_rows = composition_rows,
                .fri_rows = fri_rows,
                .arithmetic_rows = arithmetic_rows,
                .merkle_rows = merkle_rows,
                .source_authority_digest = undefined,
            };
            result.source_authority_digest = result.computeSourceAuthorityDigest();
            try result.validate();
            return result;
        }
    };
}
