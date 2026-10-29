package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
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
	c.checkpoints = append(c.checkpoints, map[string]any{"transaction_index": c.index, "transaction_hash": txHash,
		"phase": phase, "root": root, "state": accounts, "receipt": receipt})
}

func (c *captureWriter) hooks(db *state.StateDB, config *params.ChainConfig, timestamp uint64) *tracing.Hooks {
	if c == nil {
		return nil
	}
	var hash common.Hash
	var current *types.Transaction
	l1Cost := types.NewL1CostFunc(config, db)
	operatorCost := types.NewOperatorCostFunc(config, db)
	return &tracing.Hooks{
		OnTxStart: func(_ *tracing.VMContext, tx *types.Transaction, _ common.Address) {
			current = tx
			hash = tx.Hash()
			c.take(db, "pre", hash, nil)
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
		OnTxEnd: func(receipt *types.Receipt, err error) {
			if err != nil && c.err == nil {
				c.err = err
			}
			c.take(db, "post", hash, receipt)
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
