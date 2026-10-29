// Exact FlzCompressLen used by pinned op-geth for Fjord L1 data fees.
// The table is constrained by dictionary squashing; no compression-result hint.
from starkware.cairo.common.default_dict import default_dict_new
from starkware.cairo.common.dict_access import DictAccess
from starkware.cairo.common.math import assert_nn_le
from starkware.cairo.common.math_cmp import is_le_felt
from legacy.utils.dict import dict_read, dict_write, default_dict_finalize
from ethereum_types.bytes import Bytes
from ethereum.utils.numeric import divmod

func flz_length{range_check_ptr}(data: Bytes) -> felt {
    alloc_locals;
    assert_nn_le(data.value.len, 0xffffffff);
    assert_bytes(data.value.data, data.value.len);
    let comparison_1 = is_le_felt(13, data.value.len);
    if (comparison_1 == 0) {
        let n = literals(data.value.len);
        return n;
    }
    let (table) = default_dict_new(0);
    local start: DictAccess* = cast(table, DictAccess*);
    let dict_ptr = start;
    with dict_ptr {
        let n = outer(data, data.value.len - 13, 2, 0, 0);
        // op-geth accumulates into uint32. Folding once is equivalent to
        // wrapping after each addition, including near-4-GiB raw inputs.
        let (_, n) = divmod(n, 2 ** 32);
        default_dict_finalize(start, dict_ptr, 0);
        return n;
    }
}

func assert_bytes{range_check_ptr}(data: felt*, n: felt) {
    if (n == 0) {
        return ();
    }
    assert_nn_le(data[0], 255);
    return assert_bytes(data + 1, n - 1);
}

func u24(data: Bytes, ip: felt) -> felt {
    return data.value.data[ip] + 256 * data.value.data[ip + 1] + 65536 * data.value.data[ip + 2];
}

func hash24{range_check_ptr}(value: felt) -> felt {
    let (shifted, _) = divmod(2654435769 * value, 524288);
    let (_, index) = divmod(shifted, 8192);
    return index;
}

func literals{range_check_ptr}(n: felt) -> felt {
    let (q, r) = divmod(n, 32);
    if (r == 0) {
        return 33 * q;
    }
    return 33 * q + r + 1;
}

func match_size{range_check_ptr}(n: felt) -> felt {
    let (q, r) = divmod(n - 1, 262);
    let comparison_2 = is_le_felt(6, r);
    if (comparison_2 != 0) {
        return 3 * q + 3;
    }
    return 3 * q + 2;
}

func seek{range_check_ptr, dict_ptr: DictAccess*}(data: Bytes, ip: felt, limit: felt) -> (felt, felt) {
    alloc_locals;
    let comparison_3 = is_le_felt(limit, ip);
    if (comparison_3 != 0) {
        return (ip, 0);
    }
    let s = u24(data, ip);
    let h = hash24(s);
    let (r) = dict_read(h);
    dict_write(h, ip);
    let comparison_4 = is_le_felt(ip - r, 8191);
    if (comparison_4 != 0) {
        let previous = u24(data, r);
        if (s == previous) {
            return (ip + 1, r);
        }
    }
    return seek(data, ip + 1, limit);
}

func compare(data: Bytes, p: felt, q: felt, end: felt, n: felt) -> felt {
    if (q + n == end) {
        return n;
    }
    if (data.value.data[p + n] != data.value.data[q + n]) {
        return n + 1;
    }
    return compare(data, p, q, end, n + 1);
}

func set_next{range_check_ptr, dict_ptr: DictAccess*}(data: Bytes, ip: felt) -> felt {
    let s = u24(data, ip);
    let h = hash24(s);
    dict_write(h, ip);
    return ip + 1;
}

func outer{range_check_ptr, dict_ptr: DictAccess*}(
    data: Bytes, limit: felt, ip: felt, anchor: felt, size: felt
) -> felt {
    alloc_locals;
    let comparison_5 = is_le_felt(limit, ip);
    if (comparison_5 != 0) {
        let tail = literals(data.value.len - anchor);
        return size + tail;
    }
    let (next_ip, r) = seek(data, ip, limit);
    let comparison_6 = is_le_felt(limit, next_ip);
    if (comparison_6 != 0) {
        let tail = literals(data.value.len - anchor);
        return size + tail;
    }
    let ip = next_ip - 1;
    let literal_size = literals(ip - anchor);
    let length = compare(data, r + 3, ip + 3, limit + 9, 0);
    let encoded_size = match_size(length);
    let ip = set_next(data, ip + length);
    let ip = set_next(data, ip);
    return outer(data, limit, ip, ip, size + literal_size + encoded_size);
}
