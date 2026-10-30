// Differential deposit execution against the unmodified pinned op-geth core.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"runtime/debug"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/superchain"
	"github.com/holiman/uint256"
)

type account struct {
	Nonce    hexutil.Uint64              `json:"nonce"`
	Balance  *hexutil.Big                `json:"balance"`
	CodeHash common.Hash                 `json:"codeHash"`
	Storage  map[common.Hash]common.Hash `json:"storage"`
}

type input struct {
	Pre         map[common.Address]*account   `json:"pre_state"`
	Codes       map[common.Hash]hexutil.Bytes `json:"codes"`
	Transaction hexutil.Bytes                 `json:"transaction"`
	PreviousGas uint64                        `json:"previous_gas"`
	Environment struct {
		ChainID   uint64         `json:"chain_id"`
		Number    uint64         `json:"number"`
		GasLimit  uint64         `json:"gas_limit"`
		Timestamp uint64         `json:"timestamp"`
		BaseFee   *big.Int       `json:"base_fee"`
		Coinbase  common.Address `json:"coinbase"`
		Randao    common.Hash    `json:"prev_randao"`
		Hashes    []common.Hash  `json:"block_hashes"`
	} `json:"environment"`
}

func run(value *input) (map[string]any, error) {
	chain, err := superchain.GetChain(value.Environment.ChainID)
	if err != nil {
		return nil, err
	}
	registry, err := chain.Config()
	if err != nil {
		return nil, err
	}
	config, err := params.LoadOPStackChainConfig(registry)
	if err != nil {
		return nil, err
	}
	db, err := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	if err != nil {
		return nil, err
	}
	for address, a := range value.Pre {
		if a == nil {
			continue
		}
		code, ok := value.Codes[a.CodeHash]
		if !ok || crypto.Keccak256Hash(code) != a.CodeHash {
			return nil, errors.New("missing or wrong account code")
		}
		balance, overflow := uint256.FromBig((*big.Int)(a.Balance))
		if overflow {
			return nil, errors.New("balance exceeds uint256")
		}
		db.SetBalance(address, balance, tracing.BalanceChangeUnspecified)
		db.SetNonce(address, uint64(a.Nonce), tracing.NonceChangeUnspecified)
		db.SetCode(address, code, tracing.CodeChangeUnspecified)
		for key, slot := range a.Storage {
			db.SetState(address, key, slot)
		}
	}
	// Establish the initial storage as committed state, so SSTORE refunds use
	// original values, then execute one canonical binary deposit transaction.
	root, err := db.Commit(0, true, false)
	if err != nil {
		return nil, err
	}
	db, err = state.New(root, db.Database())
	if err != nil {
		return nil, err
	}
	var tx types.Transaction
	if err := tx.UnmarshalBinary(value.Transaction); err != nil {
		return nil, err
	}
	if !tx.IsDepositTx() && tx.Type() > types.DynamicFeeTxType && tx.Type() != types.SetCodeTxType {
		return nil, errors.New("expected deposit, legacy, access-list, dynamic-fee or set-code transaction")
	}
	e := value.Environment
	context := vm.BlockContext{CanTransfer: core.CanTransfer, Transfer: core.Transfer,
		L1CostFunc: types.NewL1CostFunc(config, db), OperatorCostFunc: types.NewOperatorCostFunc(config, db),
		GetHash: func(n uint64) common.Hash {
			if n >= e.Number || e.Number-n > uint64(len(e.Hashes)) {
				return common.Hash{}
			}
			return e.Hashes[uint64(len(e.Hashes))-(e.Number-n)]
		}, Coinbase: e.Coinbase, GasLimit: e.GasLimit, BlockNumber: new(big.Int).SetUint64(e.Number),
		Time: e.Timestamp, BaseFee: e.BaseFee, BlobBaseFee: big.NewInt(1), Random: &e.Randao}
	msg, err := core.TransactionToMessage(&tx, types.MakeSigner(config, context.BlockNumber, e.Timestamp), e.BaseFee)
	if err != nil {
		return nil, err
	}
	depositNonce := db.GetNonce(msg.From)
	evm := vm.NewEVM(context, db, config, vm.Config{})
	db.SetTxContext(tx.Hash(), 0)
	result, err := core.ApplyMessage(evm, msg, core.NewGasPool(e.GasLimit))
	if err != nil {
		return nil, err
	}
	db.Finalise(true)
	if err := db.Error(); err != nil {
		return nil, err
	}
	var encodedReceipt hexutil.Bytes
	if !tx.IsDepositTx() {
		receipt := &types.Receipt{Type: tx.Type(), CumulativeGasUsed: value.PreviousGas + result.UsedGas,
			Status: types.ReceiptStatusSuccessful, Logs: db.GetLogs(tx.Hash(), e.Number, common.Hash{}, e.Timestamp)}
		if result.Failed() {
			receipt.Status = types.ReceiptStatusFailed
		}
		receipt.Bloom = types.CreateBloom(receipt)
		encodedReceipt, err = receipt.MarshalBinary()
		if err != nil {
			return nil, err
		}
	}
	post := make(map[common.Address]any)
	for address, original := range value.Pre {
		if !db.Exist(address) {
			post[address] = nil
			continue
		}
		storage := make(map[common.Hash]common.Hash)
		if original != nil {
			for key := range original.Storage {
				storage[key] = db.GetState(address, key)
			}
		}
		post[address] = map[string]any{"nonce": hexutil.Uint64(db.GetNonce(address)),
			"balance": (*hexutil.Big)(db.GetBalance(address).ToBig()), "codeHash": db.GetCodeHash(address), "storage": storage}
	}
	var module any
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dependency := range info.Deps {
			if dependency.Path == "github.com/ethereum/go-ethereum" {
				module = dependency
			}
		}
	}
	return map[string]any{"schema": "keth-op-deposit-oracle-v1", "transaction_hash": tx.Hash(),
		"gas_used": result.UsedGas, "success": !result.Failed(), "nonce": depositNonce,
		"encoded_receipt": encodedReceipt,
		"post_state":      post, "geth_module": module, "execution_error": fmt.Sprint(result.Err)}, nil
}

func main() {
	source := flag.String("input", "", "execution input JSON")
	out := flag.String("output", "", "new result JSON")
	flag.Parse()
	raw, err := os.ReadFile(*source)
	if err != nil {
		panic(err)
	}
	var value input
	if err := json.Unmarshal(raw, &value); err != nil {
		panic(err)
	}
	result, err := run(&value)
	if err != nil {
		panic(err)
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		panic(err)
	}
	file, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		panic(err)
	}
}
