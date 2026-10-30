// Find a storage key in a short public trie-path prefix so eth_getProof can
// expose an otherwise unaccessed sibling required for intermediate deletion.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	prefix := flag.String("prefix", "", "1-7 public secure-trie nibbles")
	workers := flag.Uint64("workers", 4, "parallel hash searches")
	limit := flag.Uint64("attempts", 1<<28, "bounded total candidate range")
	out := flag.String("output", "", "new JSON result path")
	flag.Parse()
	if len(*prefix) < 1 || len(*prefix) > 7 || *workers < 1 || *workers > 16 || *out == "" {
		fmt.Fprintln(os.Stderr, "require a 1-7 nibble prefix, 1-16 workers and an output")
		os.Exit(2)
	}
	padding := *prefix
	if len(padding)%2 != 0 {
		padding += "0"
	}
	wanted, err := hex.DecodeString(padding)
	if err != nil {
		panic(err)
	}
	var found atomic.Bool
	var hashes atomic.Uint64
	var group sync.WaitGroup
	var result map[string]any
	started := time.Now()
	for worker := uint64(0); worker < *workers; worker++ {
		group.Go(func() {
			var raw [32]byte
			for candidate := worker; candidate < *limit && !found.Load(); candidate += *workers {
				binary.BigEndian.PutUint64(raw[24:], candidate)
				hash := crypto.Keccak256Hash(raw[:])
				matches := true
				for index, expected := range wanted {
					mask := byte(255)
					if index == len(wanted)-1 && len(*prefix)%2 != 0 {
						mask = 240
					}
					if hash[index]&mask != expected {
						matches = false
						break
					}
				}
				hashes.Add(1)
				if matches && found.CompareAndSwap(false, true) {
					result = map[string]any{"storage_key": "0x" + hex.EncodeToString(raw[:]), "secure_path": hash.Hex()}
				}
			}
		})
	}
	group.Wait()
	if result == nil {
		result = make(map[string]any)
	}
	result["prefix"], result["found"], result["hashes"] = strings.ToLower(*prefix), found.Load(), hashes.Load()
	result["elapsed_seconds"] = time.Since(started).Seconds()
	file, err := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	if err := json.NewEncoder(file).Encode(result); err != nil {
		panic(err)
	}
	if !found.Load() {
		os.Exit(1)
	}
}
