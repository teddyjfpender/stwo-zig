package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/params"
)

type access struct {
	Address common.Address `json:"address"`
	Keys    []common.Hash  `json:"storageKeys"`
}

type captureWriter struct {
	path        string
	accesses    []access
	checkpoints []map[string]any
	index       int
	err         error
	proofs      bool
}

func newCapture(path, accessPath string) (*captureWriter, error) {
	if path == "" || accessPath == "" {
		return nil, errors.New("checkpoints and access-list must be supplied together")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		return nil, errors.New("checkpoint destination already exists or is inaccessible")
	}
	raw, err := os.ReadFile(accessPath)
	if err != nil {
		return nil, err
	}
	capture := &captureWriter{path: path}
	if err := json.Unmarshal(raw, &capture.accesses); err != nil {
		return nil, err
	}
	seen := make(map[common.Address]bool)
	for _, entry := range capture.accesses {
		if seen[entry.Address] {
			return nil, errors.New("duplicate capture account")
		}
		seen[entry.Address] = true
		keys := make(map[common.Hash]bool)
		for _, key := range entry.Keys {
			if keys[key] {
				return nil, errors.New("duplicate capture storage key")
			}
			keys[key] = true
		}
	}
	return capture, nil
}

func (c *captureWriter) take(db *state.StateDB, phase string, txHash common.Hash, receipt *types.Receipt) {
	if c.err != nil {
		return
	}
	// Merkleize a copy: checkpoint construction must not clear the live EVM
	// journal or alter rollback/transaction semantics.
	view := db.Copy()
	root := view.IntermediateRoot(true)
	accounts := make(map[common.Address]any)
	for _, entry := range c.accesses {
		address := entry.Address
		if !view.Exist(address) {
			accounts[address] = nil
			continue
		}
		storage := make(map[common.Hash]common.Hash)
		for _, key := range entry.Keys {
			storage[key] = view.GetState(address, key)
		}
		accounts[address] = map[string]any{
			"nonce":    hexutil.Uint64(view.GetNonce(address)),
			"balance":  (*hexutil.Big)(view.GetBalance(address).ToBig()),
			"codeHash": view.GetCodeHash(address), "storageHash": view.GetStorageRoot(address),
			"storage": storage,
		}
	}
	if err := view.Error(); err != nil {
		c.err = fmt.Errorf("checkpoint %d %s: %w", c.index, phase, err)
		return
	}
	entry := map[string]any{"transaction_index": c.index, "transaction_hash": txHash,
		"phase": phase, "root": root, "state": accounts, "receipt": receipt}
	if c.proofs {
		nodes, err := c.proofNodes(view, root)
		if err != nil {
			c.err = fmt.Errorf("checkpoint proof %d %s: %w", c.index, phase, err)
			return
		}
		entry["proof_nodes"] = nodes
	}
	c.checkpoints = append(c.checkpoints, entry)
}

// Commit only the detached copy, then reopen it to export membership paths.
// The live processor's journal and transaction boundaries remain untouched.
func (c *captureWriter) proofNodes(view *state.StateDB, expected common.Hash) ([]hexutil.Bytes, error) {
	database := view.Database()
	root, err := view.Commit(0, true, false)
	if err != nil {
		return nil, err
	}
	if root != expected {
		return nil, errors.New("checkpoint commit changed intermediate root")
	}
	if err := database.TrieDB().Commit(root, false); err != nil {
		return nil, err
	}
	view, err = state.New(root, database)
	if err != nil {
		return nil, err
	}
	proof := memorydb.New()
	defer proof.Close()
	accounts, err := database.OpenTrie(root)
	if err != nil {
		return nil, err
	}
	for _, entry := range c.accesses {
		if err := accounts.Prove(crypto.Keccak256(entry.Address.Bytes()), proof); err != nil {
			return nil, err
		}
		if !view.Exist(entry.Address) || len(entry.Keys) == 0 {
			continue
		}
		storage, err := database.OpenStorageTrie(root, entry.Address, view.GetStorageRoot(entry.Address), accounts)
		if err != nil {
			return nil, err
		}
		for _, key := range entry.Keys {
			if err := storage.Prove(crypto.Keccak256(key.Bytes()), proof); err != nil {
				return nil, err
			}
		}
	}
	iterator := proof.NewIterator(nil, nil)
	defer iterator.Release()
	nodes := []hexutil.Bytes{}
	for iterator.Next() {
		nodes = append(nodes, common.CopyBytes(iterator.Value()))
	}
	return nodes, iterator.Error()
}

func (c *captureWriter) hooks(db *state.StateDB, config *params.ChainConfig, timestamp uint64) *tracing.Hooks {
	if c == nil {
		return nil
	}
	var hash common.Hash
	var current *types.Transaction
	l1Cost := types.NewL1CostFunc(config, db)
	operatorCost := types.NewOperatorCostFunc(config, db)
	var accesses *logger.AccessListTracer
	var entered types.AccessList
	return &tracing.Hooks{
		OnTxStart: func(context *tracing.VMContext, tx *types.Transaction, sender common.Address) {
			current = tx
			hash = tx.Hash()
			c.take(db, "pre", hash, nil)
			seed := append(types.AccessList{}, tx.AccessList()...)
			seed = append(seed, types.AccessTuple{Address: sender}, types.AccessTuple{Address: context.Coinbase})
			if tx.To() != nil {
				seed = append(seed, types.AccessTuple{Address: *tx.To()})
			}
			for _, authorization := range tx.SetCodeAuthorizations() {
				seed = append(seed, types.AccessTuple{Address: authorization.Address})
				if authority, err := authorization.Authority(); err == nil {
					seed = append(seed, types.AccessTuple{Address: authority})
				}
			}
			if !tx.IsDepositTx() {
				seed = append(seed, types.AccessTuple{Address: params.OptimismBaseFeeRecipient},
					types.AccessTuple{Address: params.OptimismL1FeeRecipient},
					types.AccessTuple{Address: params.OptimismOperatorFeeRecipient},
					types.AccessTuple{Address: common.HexToAddress("0x4200000000000000000000000000000000000015"),
						StorageKeys: []common.Hash{common.BigToHash(big.NewInt(1)), common.BigToHash(big.NewInt(3)),
							common.BigToHash(big.NewInt(7)), common.BigToHash(big.NewInt(8))}})
			}
			accesses = logger.NewAccessListTracer(seed, nil)
			entered = nil
			if c.err == nil {
				raw, err := tx.MarshalBinary()
				if err != nil {
					c.err = err
					return
				}
				entry := c.checkpoints[len(c.checkpoints)-1]
				entry["fastlz_size"] = types.FlzCompressLen(raw)
				if !tx.IsDepositTx() && l1Cost != nil && operatorCost != nil {
					entry["l1_fee"] = (*hexutil.Big)(l1Cost(tx.RollupCostData(), timestamp))
					entry["operator_fee_reserve"] = (*hexutil.Big)(operatorCost(tx.Gas(), timestamp).ToBig())
				}
			}
		},
		OnEnter: func(_ int, _ byte, from common.Address, to common.Address, _ []byte, _ uint64, _ *big.Int) {
			if accesses == nil {
				return
			}
			for _, address := range []common.Address{from, to} {
				entered = append(entered, types.AccessTuple{Address: address})
				code := db.GetCode(address)
				if len(code) == 23 && code[0] == 0xef && code[1] == 1 && code[2] == 0 {
					entered = append(entered, types.AccessTuple{Address: common.BytesToAddress(code[3:])})
				}
			}
		},
		OnOpcode: func(pc uint64, opcode byte, gas, cost uint64, scope tracing.OpContext, data []byte, depth int, err error) {
			if accesses != nil {
				accesses.OnOpcode(pc, opcode, gas, cost, scope, data, depth, err)
			}
		},
		OnTxEnd: func(receipt *types.Receipt, err error) {
			if err != nil && c.err == nil {
				c.err = err
			}
			c.take(db, "post", hash, receipt)
			if c.err == nil && accesses != nil {
				merged := logger.NewAccessListTracer(append(accesses.AccessList(), entered...), nil).AccessList()
				c.checkpoints[len(c.checkpoints)-1]["transaction_access_list"] = merged
			}
			accesses = nil
			if c.err == nil && receipt != nil && !current.IsDepositTx() && operatorCost != nil {
				c.checkpoints[len(c.checkpoints)-1]["operator_fee"] = (*hexutil.Big)(operatorCost(receipt.GasUsed, timestamp).ToBig())
			}
			c.index++
		},
	}
}

func (c *captureWriter) finish(verified bool) error {
	file, err := os.OpenFile(c.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	result := map[string]any{"schema": "keth-op-reference-checkpoints-v1", "complete_reference_execution": verified && c.err == nil,
		"checkpoints": c.checkpoints, "cairo_execution_proved": false}
	if c.err != nil {
		result["error"] = c.err.Error()
	}
	encoder := json.NewEncoder(file)
	err = encoder.Encode(result)
	return errors.Join(err, file.Close(), c.err)
}
