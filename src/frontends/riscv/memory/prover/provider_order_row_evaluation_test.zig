//! Physical field-identical row and call-value qualification.

pub fn For(comptime owner_context: anytype) type {
    const std = owner_context.std;
    const M31 = owner_context.M31;
    const QM31 = owner_context.QM31;
    const selected_main_count = owner_context.selected_main_count;
    const evaluateSelectedRowPrepared = owner_context.evaluateSelectedRowPrepared;
    const evaluateSelectedGeneric = owner_context.evaluateSelectedGeneric;
    const CallValuePowersV1 = owner_context.CallValuePowersV1;
    const callValue = owner_context.callValue;
    const ChallengesV1 = owner_context.ChallengesV1;
    const ClaimV1 = owner_context.ClaimV1;
    const format_version = owner_context.format_version;
    const ProviderOrderComponent = owner_context.ProviderOrderComponent;
    const legacySelectedMainColumns = owner_context.legacySelectedMainColumns;
    const poseidon2_air = owner_context.poseidon2_air;
    return struct {
        test "provider order prepared row evaluator is field-identical to the generic evaluator" {
            var prng = std.Random.DefaultPrng.init(0x0de5_0001);
            const random = prng.random();
            const randomM31 = struct {
                fn call(r: std.Random) M31 {
                    return M31.fromCanonical(r.uintLessThan(u32, @import("stwo_core").fields.m31.Modulus));
                }
            }.call;
            const randomQM31 = struct {
                fn call(r: std.Random) QM31 {
                    return QM31.fromM31(
                        M31.fromCanonical(r.uintLessThan(u32, @import("stwo_core").fields.m31.Modulus)),
                        M31.fromCanonical(r.uintLessThan(u32, @import("stwo_core").fields.m31.Modulus)),
                        M31.fromCanonical(r.uintLessThan(u32, @import("stwo_core").fields.m31.Modulus)),
                        M31.fromCanonical(r.uintLessThan(u32, @import("stwo_core").fields.m31.Modulus)),
                    );
                }
            }.call;
            for (0..64) |_| {
                const challenges = ChallengesV1{
                    .row_power = randomQM31(random),
                    .accumulator_power = randomQM31(random),
                };
                const claim = ClaimV1{
                    .format = format_version,
                    .first_call = random.int(u64) >> 2,
                    .call_count = random.int(u32) >> 1,
                    .terminal = randomQM31(random),
                };
                const component = ProviderOrderComponent{
                    .log_size = 18,
                    .n_rows = 1,
                    .is_first_col_idx = 0,
                    .is_active_col_idx = 1,
                    .main_col_offset = 0,
                    .main_column_count = 239,
                    .selected_main_columns = legacySelectedMainColumns(),
                    .composition_log_split = 2,
                    .interaction_col_offset = 0,
                    .challenges = challenges,
                    .claim = claim,
                };
                const constants = component.rowConstants();
                for (0..32) |_| {
                    var selected: [selected_main_count]M31 = undefined;
                    var selected_secure: [selected_main_count]QM31 = undefined;
                    for (&selected, &selected_secure) |*felt, *secure| {
                        felt.* = randomM31(random);
                        secure.* = QM31.fromBase(felt.*);
                    }
                    const current = randomQM31(random);
                    const previous = randomQM31(random);
                    const is_first = randomM31(random);
                    const is_active = randomM31(random);
                    const expected = evaluateSelectedGeneric(
                        QM31,
                        selected_secure,
                        current,
                        previous,
                        QM31.fromBase(is_first),
                        QM31.fromBase(is_active),
                        component.challenges.row_power,
                        component.challenges.accumulator_power,
                        claim.first_call,
                        claim.call_count,
                        claim.terminal,
                    );
                    const actual = evaluateSelectedRowPrepared(
                        constants,
                        selected,
                        current,
                        previous,
                        is_first,
                        is_active,
                    );
                    for (expected, actual) |lhs, rhs| try std.testing.expect(lhs.eql(rhs));
                }
            }
        }

        test "provider order base-field call value is field-identical to the Horner call value" {
            var prng = std.Random.DefaultPrng.init(0xca11_0001);
            const random = prng.random();
            for (0..256) |_| {
                const power = QM31.fromM31(
                    M31.fromCanonical(random.uintLessThan(u32, @import("stwo_core").fields.m31.Modulus)),
                    M31.fromCanonical(random.uintLessThan(u32, @import("stwo_core").fields.m31.Modulus)),
                    M31.fromCanonical(random.uintLessThan(u32, @import("stwo_core").fields.m31.Modulus)),
                    M31.fromCanonical(random.uintLessThan(u32, @import("stwo_core").fields.m31.Modulus)),
                );
                var call = poseidon2_air.Call{ .input = undefined, .narrow_output = 0 };
                for (&call.input) |*word| word.* = random.uintLessThan(u32, @import("stwo_core").fields.m31.Modulus);
                call.narrow_output = random.uintLessThan(u32, @import("stwo_core").fields.m31.Modulus);
                const powers = CallValuePowersV1.init(power);
                try std.testing.expect(callValue(call, power).eql(powers.callValue(call)));
            }
        }
    };
}
