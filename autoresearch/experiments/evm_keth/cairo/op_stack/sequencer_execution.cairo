// Post-Jovian OP fee accounting around Keth's Prague transaction execution.
// The caller binds canonical bytes, block context, state views and receipts.
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, PoseidonBuiltin, ModBuiltin
from starkware.cairo.common.math import assert_nn_le
from ethereum_types.numeric import U256, U256Struct, Uint
from ethereum_types.bytes import Bytes, Bytes32, Bytes32Struct
from ethereum.prague.blocks import UnionBytesLegacyTransaction
from ethereum.prague.fork_types import Address
from ethereum.prague.state import State, get_account, get_storage, set_account_balance, account_exists_and_is_empty, destroy_account
from ethereum.prague.vm import BlockOutput
from ethereum.prague.vm.env_impl import BlockEnvironment, BlockEnvImpl
from ethereum.prague.transactions import decode_transaction, recover_sender, get_transaction_hash
from ethereum.prague.transactions_types import get_gas, get_nonce, get_transaction_type
from ethereum_rlp.rlp import encode_transaction
from ethereum.crypto.hash import Hash32, keccak256
from ethereum.prague.fork import process_transaction
from ethereum.utils.numeric import U256_add, U256_add_with_carry, U256_sub, U256_mul, divmod
from op_stack.fastlz import flz_length
from op_stack.fees import fjord_fee, operator_fee, estimated_size_scaled
from op_stack.deposit_execution import finish_deposit_state

const L1_BLOCK = 119888806187300630008896021433757591456150716482;
const BASE_FEE_VAULT = 142724769270595988105828596944949513638274662466;
const L1_FEE_VAULT = 148433760041419827630061740822747494183805648962;
const OPERATOR_FEE_VAULT = 154142750812243667154294884700545474729336635458;

struct FeeContext {
    l1_fee: U256,
    operator_scalar: felt,
    operator_constant: felt,
    da_scalar: felt,
}

func fee_context{range_check_ptr, state: State}(size: felt) -> FeeContext* {
    alloc_locals;
    tempvar base_key = Bytes32(new Bytes32Struct(0, 2 ** 120));
    tempvar scalars_key = Bytes32(new Bytes32Struct(0, 3 * 2 ** 120));
    tempvar blob_key = Bytes32(new Bytes32Struct(0, 7 * 2 ** 120));
    tempvar operator_key = Bytes32(new Bytes32Struct(0, 8 * 2 ** 120));
    let base = get_storage(Address(L1_BLOCK), base_key);
    let packed = get_storage(Address(L1_BLOCK), scalars_key);
    let blob = get_storage(Address(L1_BLOCK), blob_key);
    let operator = get_storage(Address(L1_BLOCK), operator_key);
    local state: State = state;
    assert_nn_le(packed.value.low, 2 ** 128 - 1);
    assert_nn_le(operator.value.low, 2 ** 128 - 1);
    let (base_scalar, _) = divmod(packed.value.low, 2 ** 96);
    let (upper, _) = divmod(packed.value.low, 2 ** 64);
    let (_, blob_scalar) = divmod(upper, 2 ** 32);
    let (upper, constant) = divmod(operator.value.low, 2 ** 64);
    let (_, scalar) = divmod(upper, 2 ** 32);
    let (upper_da, _) = divmod(operator.value.low, 2 ** 96);
    let (_, da_scalar) = divmod(upper_da, 2 ** 16);
    let da_scalar = effective_da_scalar(da_scalar);
    let l1 = fjord_fee(size, base, blob, base_scalar, blob_scalar);
    tempvar result = new FeeContext(l1, scalar, constant, da_scalar);
    return result;
}

func credit{range_check_ptr, state: State}(address: Address, amount: U256) {
    alloc_locals;
    if (amount.value.low == 0 and amount.value.high == 0) {
        let empty = account_exists_and_is_empty(address);
        if (empty.value != 0) {
            destroy_account(address);
            return ();
        }
        return ();
    }
    let account = get_account(address);
    local state: State = state;
    let (balance, _) = U256_add_with_carry(account.value.balance, amount);
    set_account_balance(address, balance);
    return ();
}

func execute_sequencer_detailed{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*, poseidon_ptr: PoseidonBuiltin*,
    range_check96_ptr: felt*, add_mod_ptr: ModBuiltin*, mul_mod_ptr: ModBuiltin*,
    block_env: BlockEnvironment, block_output: BlockOutput,
}(raw: Bytes, encoded: UnionBytesLegacyTransaction, index: Uint) -> (Hash32, felt, felt) {
    alloc_locals;
    // This first integration qualifies OP Mainnet's post-Karst fork context.
    assert block_env.value.chain_id.value = 10;
    assert block_env.value.time.value.high = 0;
    assert_nn_le(1783526401, block_env.value.time.value.low);
    let tx = decode_transaction(encoded);
    let kind = get_transaction_type(tx);
    // OP admits legacy, access-list, dynamic-fee and set-code transactions.
    // Blob transactions are excluded from the execution-layer body.
    assert kind * (kind - 1) * (kind - 2) * (kind - 4) = 0;
    let canonical = encode_transaction(tx);
    let canonical_hash = get_transaction_hash(canonical);
    let raw_hash = keccak256(raw);
    assert [canonical_hash.value] = [raw_hash.value];
    let sender = recover_sender(block_env.value.chain_id, tx);
    let nonce = get_nonce(tx);
    assert nonce.value.high = 0;
    assert_nn_le(nonce.value.low, 2 ** 64 - 2);
    let gas = get_gas(tx);
    assert_nn_le(gas.value, 2 ** 64 - 1);
    let size = flz_length(raw);
    let state = block_env.value.state;
    let fees = fee_context{state=state}(size);
    let scaled = estimated_size_scaled(size);
    let (da_size, _) = divmod(scaled, 1000000);
    local footprint = da_size * fees.da_scalar;
    let reservation = operator_fee(gas.value, fees.operator_scalar, fees.operator_constant, 1);
    tempvar reservation_u256 = U256(new U256Struct(reservation, 0));
    let upfront = U256_add(fees.l1_fee, reservation_u256);
    let account = get_account{state=state}(sender);
    let balance = U256_sub(account.value.balance, upfront);
    set_account_balance{state=state}(sender, balance);
    BlockEnvImpl.set_state(state);
    // Keth checks the remaining balance against max gas fee plus tx value,
    // so reserving OP fees first also enforces op-geth's upfront balance rule.
    local before_gas = block_output.value.block_gas_used.value;
    process_transaction(encoded, index);
    let used = block_output.value.block_gas_used.value - before_gas;
    assert_nn_le(used, gas.value);
    let charged = operator_fee(used, fees.operator_scalar, fees.operator_constant, 1);
    assert_nn_le(charged, reservation);
    tempvar refund = U256(new U256Struct(reservation - charged, 0));
    let state = block_env.value.state;
    credit{state=state}(sender, refund);
    credit{state=state}(Address(L1_FEE_VAULT), fees.l1_fee);
    tempvar actual_operator = U256(new U256Struct(charged, 0));
    credit{state=state}(Address(OPERATOR_FEE_VAULT), actual_operator);
    tempvar gas_u256 = U256(new U256Struct(used, 0));
    tempvar base_u256 = U256(new U256Struct(block_env.value.base_fee_per_gas.value, 0));
    let base_charge = U256_mul(gas_u256, base_u256);
    credit{state=state}(Address(BASE_FEE_VAULT), base_charge);
    BlockEnvImpl.set_state(state);
    finish_deposit_state(sender);
    return (raw_hash, used, footprint);
}

func effective_da_scalar(scalar: felt) -> felt {
    if (scalar == 0) {
        return 400;
    }
    return scalar;
}

func execute_sequencer{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*, poseidon_ptr: PoseidonBuiltin*,
    range_check96_ptr: felt*, add_mod_ptr: ModBuiltin*, mul_mod_ptr: ModBuiltin*,
    block_env: BlockEnvironment, block_output: BlockOutput,
}(raw: Bytes, encoded: UnionBytesLegacyTransaction, index: Uint) -> (Hash32, felt) {
    let (hash, used, footprint) = execute_sequencer_detailed(raw, encoded, index);
    return (hash, used);
}
