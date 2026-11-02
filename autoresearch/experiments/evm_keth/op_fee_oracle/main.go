// Differential fee oracle using the unmodified pinned op-geth functions.
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"runtime/debug"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

type input struct {
	Transactions     []hexutil.Bytes `json:"transactions"`
	GasLimits        []uint64        `json:"gas_limits"`
	GasUsed          []uint64        `json:"gas_used"`
	BaseFee          *big.Int        `json:"base_fee"`
	BlobFee          *big.Int        `json:"blob_fee"`
	BaseScalar       uint32          `json:"base_scalar"`
	BlobScalar       uint32          `json:"blob_scalar"`
	OperatorScalar   uint32          `json:"operator_scalar"`
	OperatorConstant uint64          `json:"operator_constant"`
	Jovian           uint64          `json:"jovian"`
	DAScalar         uint16          `json:"da_scalar"`
}

type feeState struct{ value common.Hash }

func (f feeState) GetState(address common.Address, slot common.Hash) common.Hash {
	if address == types.L1BlockAddr && slot == types.OperatorFeeParamsSlot {
		return f.value
	}
	return common.Hash{}
}

func run(in input) (map[string]any, error) {
	if len(in.Transactions) != len(in.GasLimits) || len(in.Transactions) != len(in.GasUsed) || in.Jovian > 1 {
		return nil, fmt.Errorf("invalid batch lengths/fork flag")
	}
	if in.BaseFee == nil || in.BlobFee == nil || in.BaseFee.Sign() < 0 || in.BlobFee.Sign() < 0 || in.BaseFee.BitLen() > 256 || in.BlobFee.BitLen() > 256 {
		return nil, fmt.Errorf("base fees must be uint256")
	}
	zero := uint64(0)
	config := &params.ChainConfig{Optimism: &params.OptimismConfig{}, IsthmusTime: &zero}
	if in.Jovian != 0 {
		config.JovianTime = &zero
	}
	var packed common.Hash
	binary.BigEndian.PutUint32(packed[20:24], in.OperatorScalar)
	binary.BigEndian.PutUint64(packed[24:32], in.OperatorConstant)
	operator := types.NewOperatorCostFunc(config, feeState{packed})
	l1 := types.NewL1CostFuncFjord(in.BaseFee, in.BlobFee, new(big.Int).SetUint64(uint64(in.BaseScalar)), new(big.Int).SetUint64(uint64(in.BlobScalar)))
	rows := make([]map[string]any, 0, len(in.Transactions))
	for index, raw := range in.Transactions {
		if in.GasUsed[index] > in.GasLimits[index] {
			return nil, fmt.Errorf("gas used exceeds gas limit")
		}
		cost := types.NewRollupCostData(raw)
		fee, _ := l1(cost)
		daSize := cost.EstimatedDASize().Uint64()
		rows = append(rows, map[string]any{"hash": crypto.Keccak256Hash(raw), "bytes": len(raw),
			"fastlz_size": types.FlzCompressLen(raw), "l1_fee": (*hexutil.Big)(fee), "l1_fee_overflow": fee.BitLen() > 256,
			"operator_reserve":  (*hexutil.Big)(operator(in.GasLimits[index], 1).ToBig()),
			"operator_fee":      (*hexutil.Big)(operator(in.GasUsed[index], 1).ToBig()),
			"estimated_da_size": daSize, "da_footprint": daSize * uint64(in.DAScalar)})
	}
	result := map[string]any{"schema": "keth-op-fee-reference-v1", "rows": rows}
	if build, ok := debug.ReadBuildInfo(); ok {
		for _, dependency := range build.Deps {
			if dependency.Path == "github.com/ethereum/go-ethereum" {
				result["geth_module"] = dependency
			}
		}
	}
	return result, nil
}

func main() {
	source := flag.String("input", "", "JSON fee batch")
	target := flag.String("output", "", "new JSON reference result")
	flag.Parse()
	raw, err := os.ReadFile(*source)
	var in input
	if err == nil {
		err = json.Unmarshal(raw, &in)
	}
	var result map[string]any
	if err == nil {
		result, err = run(in)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	file, err := os.OpenFile(*target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	if err := json.NewEncoder(file).Encode(result); err != nil {
		panic(err)
	}
}
