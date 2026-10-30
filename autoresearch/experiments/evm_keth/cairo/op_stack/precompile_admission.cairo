// Jovian bounds cause an exceptional precompile halt, consuming all call gas.
from starkware.cairo.common.math_cmp import is_le_felt

func exceeds_limit{range_check_ptr}(address: felt, input_length: felt) -> felt {
    if (address == 8 * 2 ** 152) {
        return is_le_felt(81985, input_length);
    }
    if (address == 12 * 2 ** 152) {
        return is_le_felt(288961, input_length);
    }
    if (address == 14 * 2 ** 152) {
        return is_le_felt(278785, input_length);
    }
    if (address == 15 * 2 ** 152) {
        return is_le_felt(156673, input_length);
    }
    return 0;
}
