// Post-Regolith/Prague deposit execution using Keth's EVM. No L1 authorization
// or OP precompile compatibility claim is made by this execution kernel.
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, PoseidonBuiltin, ModBuiltin
from starkware.cairo.common.default_dict import default_dict_new
from starkware.cairo.common.dict_access import DictAccess
from starkware.cairo.common.math import assert_nn_le
from starkware.cairo.common.math_cmp import is_le_felt
from ethereum_types.numeric import U256, U256Struct, Uint, OptionalUint
from ethereum_types.bytes import OptionalHash32
from ethereum.prague.fork_types import (
    Address, AccountStruct, OptionalAccount, TupleVersionedHash, TupleVersionedHashStruct,
    TupleAuthorization, TupleAuthorizationStruct, Authorization, SetAddress, SetAddressStruct,
    SetAddressDictAccess, SetTupleAddressBytes32, SetTupleAddressBytes32Struct,
    SetTupleAddressBytes32DictAccess
)
from ethereum.prague.state import (
    get_account, set_account, set_account_balance, empty_transient_storage, State, StateImpl,
    account_exists_and_is_empty, destroy_account
)
from ethereum.prague.trie import TrieTupleAddressBytes32U256, TrieTupleAddressBytes32U256Struct
from ethereum.prague.vm.env_impl import BlockEnvironment, BlockEnvImpl, TransactionEnvironment, TransactionEnvironmentStruct
from ethereum.prague.transactions_types import (
    Transaction, TransactionStruct, LegacyTransaction, LegacyTransactionStruct,
    AccessListTransaction, AccessListTransactionStruct, FeeMarketTransaction, FeeMarketTransactionStruct,
    BlobTransaction, BlobTransactionStruct, SetCodeTransaction, SetCodeTransactionStruct
)
from ethereum.prague.transactions import calculate_intrinsic_cost
from ethereum.prague.utils.message import prepare_message
from ethereum.prague.vm.interpreter import process_message_call
from ethereum.prague.fork import process_storage_deletions, process_account_deletions
from ethereum.crypto.hash import Hash32
from ethereum.utils.numeric import U256_add_with_carry, U256_le, divmod, min, max
from legacy.utils.dict import hashdict_write, default_dict_finalize, dict_squash
from op_stack.deposit_types import Deposit

func finish_deposit_state{range_check_ptr, block_env: BlockEnvironment}(sender: Address) {
    let state = block_env.value.state;
    remove_empty_sender{state=state}(sender);
    close_original_storage{state=state}();
    BlockEnvImpl.set_state(state);
    return ();
}

func remove_empty_sender{range_check_ptr, state: State}(sender: Address) {
    let empty = account_exists_and_is_empty{state=state}(sender);
    if (empty.value == 0) {
        return ();
    }
    destroy_account{state=state}(sender);
    return ();
}

func close_original_storage{range_check_ptr, state: State}() {
    let original = state.value.original_storage_tries;
    if (cast(original.value, felt) == 0) {
        return ();
    }
    // Keth's error return retains the pre-finalization environment. Close
    // this transaction's original-storage view on that path as well.
    dict_squash(cast(original.value._data.value.dict_ptr_start, DictAccess*),
                cast(original.value._data.value.dict_ptr, DictAccess*));
    StateImpl.set_original_storage_tries{state=state}(
        TrieTupleAddressBytes32U256(cast(0, TrieTupleAddressBytes32U256Struct*)));
    return ();
}

func increment_deposit_nonce{range_check_ptr, block_env: BlockEnvironment}(sender: Address) -> Uint {
    alloc_locals;
    let state = block_env.value.state;
    let account = get_account{state=state}(sender);
    assert_nn_le(account.value.nonce.value, 2 ** 64 - 1);
    let (_, next) = divmod(account.value.nonce.value + 1, 2 ** 64);
    tempvar updated = OptionalAccount(new AccountStruct(
        nonce=Uint(next), balance=account.value.balance, code_hash=account.value.code_hash,
        storage_root=account.value.storage_root, code=account.value.code
    ));
    set_account{state=state}(sender, updated);
    BlockEnvImpl.set_state(state);
    return account.value.nonce;
}

func execute_deposit{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*, poseidon_ptr: PoseidonBuiltin*,
    range_check96_ptr: felt*, add_mod_ptr: ModBuiltin*, mul_mod_ptr: ModBuiltin*,
    block_env: BlockEnvironment,
}(deposit: Deposit*, tx_hash: Hash32) -> (gas_used: felt, success: felt, nonce: Uint) {
    alloc_locals;
    // Creation support needs the uint64-wrapping sender nonce propagated into
    // prepare_message's CREATE address calculation. Refuse it until implemented.
    assert cast(deposit.to.value.bytes0, felt) = 0;
    assert_nn_le(block_env.value.block_gas_limit.value, 2 ** 64 - 1);
    assert_nn_le(deposit.gas.value, block_env.value.block_gas_limit.value);
    let state = block_env.value.state;
    let sender = get_account{state=state}(deposit.sender);
    // op-geth's uint256 balance addition wraps, including deposit minting.
    let (balance, _) = U256_add_with_carry(sender.value.balance, deposit.mint);
    set_account_balance{state=state}(deposit.sender, balance);
    BlockEnvImpl.set_state(state);
    let nonce = increment_deposit_nonce(deposit.sender);
    tempvar zero = U256(new U256Struct(0, 0));
    tempvar legacy = LegacyTransaction(new LegacyTransactionStruct(
        nonce=zero, gas_price=Uint(0), gas=deposit.gas, to=deposit.to,
        value=deposit.value, data=deposit.data, v=zero, r=zero, s=zero
    ));
    tempvar tx = Transaction(new TransactionStruct(legacy,
        AccessListTransaction(cast(0, AccessListTransactionStruct*)),
        FeeMarketTransaction(cast(0, FeeMarketTransactionStruct*)),
        BlobTransaction(cast(0, BlobTransactionStruct*)),
        SetCodeTransaction(cast(0, SetCodeTransactionStruct*))));
    let (intrinsic, floor) = calculate_intrinsic_cost(tx);
    let intrinsic_ok = is_le_felt(intrinsic.value, deposit.gas.value);
    let floor_ok = is_le_felt(floor.value, deposit.gas.value);
    let value_ok = U256_le(deposit.value, balance);
    if (intrinsic_ok * floor_ok * value_ok.value == 0) {
        // Consensus-invalid deposits retain mint and nonce, consume all gas.
        finish_deposit_state(deposit.sender);
        return (deposit.gas.value, 0, nonce);
    }
    let (addresses) = default_dict_new(0);
    local address_start: DictAccess* = addresses;
    hashdict_write{dict_ptr=addresses}(1, &block_env.value.coinbase.value, 1);
    tempvar warm_addresses = SetAddress(new SetAddressStruct(
        cast(address_start, SetAddressDictAccess*), cast(addresses, SetAddressDictAccess*)
    ));
    let (keys) = default_dict_new(0);
    tempvar warm_keys = SetTupleAddressBytes32(new SetTupleAddressBytes32Struct(
        cast(keys, SetTupleAddressBytes32DictAccess*), cast(keys, SetTupleAddressBytes32DictAccess*)
    ));
    default_dict_finalize(address_start, addresses, 0);
    default_dict_finalize(keys, keys, 0);
    let transient = empty_transient_storage();
    tempvar tx_env = TransactionEnvironment(new TransactionEnvironmentStruct(
        origin=deposit.sender, gas_price=Uint(0), gas=Uint(deposit.gas.value - intrinsic.value),
        access_list_addresses=warm_addresses, access_list_storage_keys=warm_keys,
        transient_storage=transient,
        blob_versioned_hashes=TupleVersionedHash(new TupleVersionedHashStruct(cast(0, Hash32*), 0)),
        authorizations=TupleAuthorization(new TupleAuthorizationStruct(cast(0, Authorization*), 0)),
        index_in_block=OptionalUint(cast(0, Uint*)), tx_hash=OptionalHash32(tx_hash.value)
    ));
    let message = prepare_message{tx_env=tx_env}(tx);
    let (result, block_env) = process_message_call(message);
    assert result.value.refund_counter.value.high = 0;
    assert_nn_le(result.value.gas_left.value, deposit.gas.value - intrinsic.value);
    let spent = deposit.gas.value - result.value.gas_left.value;
    let (cap, _) = divmod(spent, 5);
    let refund = min(cap, result.value.refund_counter.value.low);
    let used = max(spent - refund, floor.value);
    let state = block_env.value.state;
    process_storage_deletions{state=state}(result.value.accessed_storage_keys, result.value.accounts_to_delete);
    process_account_deletions{state=state}(result.value.accounts_to_delete);
    BlockEnvImpl.set_state(state);
    finish_deposit_state(deposit.sender);
    if (cast(result.value.error, felt) == 0) {
        return (used, 1, nonce);
    }
    return (used, 0, nonce);
}
