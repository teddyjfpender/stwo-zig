//! Focused conformance and mutation tests for the Poseidon2 AIR.

pub fn Tests(comptime context: anytype) type {
    return struct {
        const std = context.std;
        const M31 = context.M31;
        const QM31 = context.QM31;
        const logup = context.logup;
        const relations_mod = context.relations_mod;
        const permutation = context.permutation;
        const WIDTH = context.WIDTH;
        const N_MAIN_COLUMNS = context.N_MAIN_COLUMNS;
        const N_CONSTRAINTS = context.N_CONSTRAINTS;
        const INPUT_START = context.INPUT_START;
        const TEMP_START = context.TEMP_START;
        const WIDE_COLUMN = context.WIDE_COLUMN;
        const IO_COLUMN = context.IO_COLUMN;
        const OUTPUT_START = context.OUTPUT_START;
        const Call = context.Call;
        const Claims = context.Claims;
        const fill = context.fill;
        const output = context.output;
        const evaluate = context.evaluate;
        const generateInteraction = context.generateInteraction;
        const generateIoInteractionFromOutputs = context.generateIoInteractionFromOutputs;
        const claimsFromIoOutputs = context.claimsFromIoOutputs;
        const claimsFromIoOutputsInto = context.claimsFromIoOutputsInto;
        const rowPairsFromCall = context.rowPairsFromCall;
        const rowPairs = context.rowPairs;
        const secureRow = context.secureRow;
        const expectAllZero = context.expectAllZero;

        test "poseidon2 AIR: exact narrow pair matches the pinned permutation" {
            const row = fill(Call.narrow(1, 2));
            try std.testing.expectEqual(@as(u32, 1975699496), output(row)[0].toU32());
            try std.testing.expectEqual(permutation.hashPair(1, 2), output(row)[0].toU32());
            try expectAllZero(&evaluate(secureRow(row)));
        }

        test "poseidon2 AIR: generated column schedule matches pinned Rust" {
            const row = fill(Call.narrow(1, 2));
            const expected = [_]struct { column: usize, value: u32 }{
                .{ .column = 0, .value = 1 },
                .{ .column = 16, .value = 0 },
                .{ .column = 17, .value = 888382669 },
                .{ .column = 48, .value = 1245644797 },
                .{ .column = 49, .value = 1900086922 },
                .{ .column = 80, .value = 2142961709 },
                .{ .column = 128, .value = 125143133 },
                .{ .column = 176, .value = 1759109891 },
                .{ .column = 218, .value = 572377586 },
                .{ .column = 266, .value = 1621981814 },
                .{ .column = 314, .value = 1610989476 },
                .{ .column = 362, .value = 738050654 },
                .{ .column = 409, .value = 260539998 },
                .{ .column = 410, .value = 59563392 },
                .{ .column = 425, .value = 1888574172 },
                .{ .column = 426, .value = 1886810401 },
                .{ .column = 441, .value = 23371529 },
                .{ .column = 442, .value = 369091567 },
                .{ .column = 443, .value = 0 },
                .{ .column = 444, .value = 0 },
            };
            for (expected) |item| {
                try std.testing.expectEqual(item.value, row[item.column].toU32());
            }
        }

        test "poseidon2 AIR: arbitrary canonical narrow pairs satisfy every constraint" {
            var prng = std.Random.DefaultPrng.init(0x506f736569646f6e);
            const random = prng.random();
            for (0..64) |_| {
                const lhs = random.int(u32) % @import("stwo_core").fields.m31.Modulus;
                const rhs = random.int(u32) % @import("stwo_core").fields.m31.Modulus;
                try expectAllZero(&evaluate(secureRow(fill(Call.narrow(lhs, rhs)))));
            }
        }

        test "poseidon2 AIR: input, intermediate, output, and conflicting flags fail" {
            const honest = fill(Call.narrow(11, 22));
            inline for (.{ INPUT_START, TEMP_START, OUTPUT_START }) |column| {
                var mutated = honest;
                mutated[column] = mutated[column].add(M31.one());
                const constraints = evaluate(secureRow(mutated));
                var nonzero = false;
                for (constraints) |value| nonzero = nonzero or !value.isZero();
                try std.testing.expect(nonzero);
            }
            var conflicting_flags = honest;
            conflicting_flags[WIDE_COLUMN] = M31.one();
            conflicting_flags[IO_COLUMN] = M31.one();
            const flag_constraints = evaluate(secureRow(conflicting_flags));
            try std.testing.expect(!flag_constraints[N_CONSTRAINTS - 1].isZero());
        }

        test "poseidon2 AIR: padding is zero and the enabler is boolean" {
            const padding = [_]QM31{QM31.zero()} ** N_MAIN_COLUMNS;
            try expectAllZero(&evaluate(padding));
            var non_boolean = padding;
            non_boolean[0] = QM31.fromBase(M31.fromU64(2));
            const constraints = evaluate(non_boolean);
            try std.testing.expect(!constraints[0].isZero());
        }

        test "poseidon2 AIR: Merkle input and narrow output cancel exactly" {
            const relations = relations_mod.Relations.dummy();
            const call = Call.narrow(31, 41);
            const row = secureRow(fill(call));
            const poseidon_pairs = rowPairs(row, &relations);
            var merkle_input = [_]QM31{QM31.zero()} ** WIDTH;
            merkle_input[0] = QM31.fromBase(M31.fromU64(31));
            merkle_input[1] = QM31.fromBase(M31.fromU64(41));
            var merkle_output = [_]QM31{QM31.zero()} ** WIDTH;
            merkle_output[0] = row[OUTPUT_START];
            const merkle_sum = (try relations.poseidon2.combineSecure(merkle_input).inv())
                .sub(try relations.poseidon2.combineSecure(merkle_output).inv());
            const poseidon_sum = try pairSum(poseidon_pairs[0]);
            try std.testing.expect(merkle_sum.add(poseidon_sum).isZero());
        }

        test "poseidon2 AIR: carried narrow output preserves active interaction terms" {
            const relations = relations_mod.Relations.dummy();
            const plain = Call.narrow(31, 41);
            const output_value = output(fill(plain))[0].v;
            const carried = Call.narrowWithOutput(31, 41, output_value);
            const expected = rowPairsFromCall(plain, &relations);
            const actual = rowPairsFromCall(carried, &relations);
            try std.testing.expectEqualDeep(expected[0], actual[0]);
            try std.testing.expect(actual[1].n1.isZero());
            try std.testing.expect(actual[1].n2.isZero());
            try std.testing.expect((try pairSum(expected[1])).isZero());
            try std.testing.expect((try pairSum(actual[1])).isZero());

            // A carried value is a narrow-only optimization. Other protocol modes
            // deliberately fall back to the full row so ReleaseFast cannot silently
            // reinterpret a malformed Call when debug assertions are disabled.
            var wide = carried;
            wide.wide = true;
            var plain_wide = plain;
            plain_wide.wide = true;
            try std.testing.expectEqualDeep(
                rowPairsFromCall(plain_wide, &relations),
                rowPairsFromCall(wide, &relations),
            );
        }

        test "poseidon2 AIR: retained IO outputs remove permutation replay exactly" {
            const allocator = std.testing.allocator;
            const relations = relations_mod.Relations.dummy();
            var calls: [3]Call = undefined;
            var outputs: [3][WIDTH]u32 = undefined;
            for (&calls, &outputs, 0..) |*call, *output_value, row| {
                var input: [WIDTH]u32 = undefined;
                for (&input, 0..) |*word, lane|
                    word.* = @intCast(17 * row + 13 * lane + 1);
                call.* = .{ .input = input, .io = true };
                const result = output(fill(call.*));
                for (output_value, result) |*word, value| word.* = value.toU32();
            }

            var replayed = try generateInteraction(allocator, &calls, 2, &relations);
            defer replayed.deinit(allocator);
            var retained = try generateIoInteractionFromOutputs(
                allocator,
                &calls,
                &outputs,
                2,
                &relations,
            );
            defer retained.deinit(allocator);
            try std.testing.expectEqualDeep(replayed.claims, retained.claims);
            for (replayed.columns, retained.columns) |expected, actual|
                try std.testing.expectEqualSlices(M31, expected, actual);

            calls[0].wide = true;
            try std.testing.expectError(
                error.InvalidTraceShape,
                generateIoInteractionFromOutputs(
                    allocator,
                    &calls,
                    &outputs,
                    2,
                    &relations,
                ),
            );
        }

        test "poseidon2 AIR: retained IO claims-only audit matches active and padded domains" {
            const allocator = std.testing.allocator;
            const relations = relations_mod.Relations.dummy();
            var calls: [4]Call = undefined;
            var outputs: [4][WIDTH]u32 = undefined;
            for (&calls, &outputs, 0..) |*call, *output_value, row| {
                var input: [WIDTH]u32 = undefined;
                for (&input, 0..) |*word, lane|
                    word.* = @intCast(29 * row + 7 * lane + 3);
                call.* = .{ .input = input, .io = true };
                const result = output(fill(call.*));
                for (output_value, result) |*word, value| word.* = value.toU32();
            }

            // Four active rows exercise the exact domain boundary at log-size two;
            // log-size three proves that omitted padding has precisely zero effect.
            for ([_]u32{ 2, 3 }) |log_size| {
                var full = try generateIoInteractionFromOutputs(
                    allocator,
                    &calls,
                    &outputs,
                    log_size,
                    &relations,
                );
                defer full.deinit(allocator);
                const claims = try claimsFromIoOutputs(
                    &calls,
                    &outputs,
                    log_size,
                    &relations,
                );
                try std.testing.expectEqualDeep(full.claims, claims);
            }

            const original_claims = try claimsFromIoOutputs(
                &calls,
                &outputs,
                2,
                &relations,
            );
            outputs[1][3] = if (outputs[1][3] == 0) 1 else outputs[1][3] - 1;
            for ([_]u32{ 2, 3 }) |log_size| {
                var full = try generateIoInteractionFromOutputs(
                    allocator,
                    &calls,
                    &outputs,
                    log_size,
                    &relations,
                );
                defer full.deinit(allocator);
                const claims = try claimsFromIoOutputs(
                    &calls,
                    &outputs,
                    log_size,
                    &relations,
                );
                try std.testing.expectEqualDeep(full.claims, claims);
            }
            const mutated_claims = try claimsFromIoOutputs(
                &calls,
                &outputs,
                2,
                &relations,
            );
            try std.testing.expect(
                !original_claims.sums[0].eql(mutated_claims.sums[0]) or
                    !original_claims.sums[1].eql(mutated_claims.sums[1]),
            );

            const sentinel = Claims{
                .sums = .{
                    QM31.fromU32Unchecked(11, 13, 17, 19),
                    QM31.fromU32Unchecked(23, 29, 31, 37),
                },
            };
            var destination = sentinel;
            var malformed_calls = calls;
            malformed_calls[0].wide = true;
            try std.testing.expectError(
                error.InvalidTraceShape,
                claimsFromIoOutputsInto(
                    &destination,
                    &malformed_calls,
                    &outputs,
                    2,
                    &relations,
                ),
            );
            try std.testing.expectEqualDeep(sentinel, destination);
        }

        fn pairSum(pair: logup.RowPair) !QM31 {
            return pair.n1.mul(try pair.d1.inv()).add(pair.n2.mul(try pair.d2.inv()));
        }
    };
}
