//! Boundary-selectable Merkle custody for authenticated binary FRI sources.

pub fn Operations(comptime Context: type) type {
    const Self = Context.Source;
    const Boundary = Context.BoundaryType;
    const dimensions = Context.dimensions_value;
    const fallback = Context.fallback;

    return struct {
        pub fn merkleLeafCount(source: *const Self) !usize {
            if (comptime !Boundary.IS_LEGACY and
                @hasDecl(Boundary, "merkleLeafCount"))
            {
                return Boundary.merkleLeafCount(dimensions, source);
            }
            return fallback.merkleLeafCount(source);
        }

        pub fn merkleInvocationCount(source: *const Self) !usize {
            if (comptime !Boundary.IS_LEGACY and
                @hasDecl(Boundary, "merkleInvocationCount"))
            {
                return Boundary.merkleInvocationCount(dimensions, source);
            }
            return fallback.merkleInvocationCount(source);
        }

        pub fn sharedPoseidonCallCount(source: *const Self) !usize {
            if (comptime !Boundary.IS_LEGACY and
                @hasDecl(Boundary, "sharedPoseidonCallCount"))
            {
                return Boundary.sharedPoseidonCallCount(dimensions, source);
            }
            return fallback.sharedPoseidonCallCount(source);
        }

        pub fn materializeMerkleWorkspace(
            source: *const Self,
            fri_workspace: anytype,
            merkle_workspace: anytype,
        ) !void {
            if (comptime !Boundary.IS_LEGACY and
                @hasDecl(Boundary, "materializeMerkleWorkspace"))
            {
                return Boundary.materializeMerkleWorkspace(
                    dimensions,
                    source,
                    fri_workspace,
                    merkle_workspace,
                );
            }
            return fallback.materializeMerkleWorkspace(
                source,
                fri_workspace,
                merkle_workspace,
            );
        }
    };
}
