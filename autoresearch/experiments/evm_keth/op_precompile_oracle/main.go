// Differential Jovian precompile vectors against the pinned op-geth contracts.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/vm"
)

type vector struct {
	Address common.Address `json:"address"`
	Input   hexutil.Bytes  `json:"input"`
	Gas     uint64         `json:"gas"`
}

func main() {
	input := flag.String("input", "", "vector JSON")
	output := flag.String("output", "", "new result JSON")
	flag.Parse()
	raw, err := os.ReadFile(*input)
	if err != nil {
		panic(err)
	}
	var vectors []vector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		panic(err)
	}
	results := []map[string]any{}
	for _, v := range vectors {
		contract, ok := vm.PrecompiledContractsJovian[v.Address]
		if !ok || len(v.Input) > 1024*1024 {
			panic("unsupported or oversized vector")
		}
		result, left, err := vm.RunPrecompiledContract(nil, contract, v.Address, v.Input, v.Gas, nil)
		failure := ""
		if err != nil {
			failure = err.Error()
		}
		results = append(results, map[string]any{"address": v.Address, "output": hexutil.Bytes(result),
			"gas_left": left, "required_gas": contract.RequiredGas(v.Input), "error": failure})
	}
	encoded, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		panic(err)
	}
	file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	if _, err := fmt.Fprintln(file, string(encoded)); err != nil {
		panic(err)
	}
}
