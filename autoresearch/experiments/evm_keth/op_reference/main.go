// Run retained witnesses through pinned, unmodified op-geth execution.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
)

func main() {
	inputPath := flag.String("input", "", "retained JSON block and witness")
	outputPath := flag.String("output", "", "new JSON result path")
	checkpointPath := flag.String("checkpoints", "", "new optional execution checkpoint JSON")
	accessesPath := flag.String("access-list", "", "candidate account/storage preimages for checkpoints")
	checkpointProofs := flag.Bool("checkpoint-proofs", false, "export account/storage membership paths for every checkpoint")
	flag.Parse()
	if *inputPath == "" || *outputPath == "" {
		fmt.Fprintln(os.Stderr, "--input and --output are required")
		os.Exit(2)
	}
	result := map[string]any{"schema": "keth-op-reference-execution-v1", "offline_execution_checked": false,
		"cairo_execution_proved": false, "derivation_proved": false, "consensus_authenticated": false}
	result["go_version"] = runtime.Version()
	if build, ok := debug.ReadBuildInfo(); ok {
		for _, dependency := range build.Deps {
			if dependency.Path == "github.com/ethereum/go-ethereum" {
				result["geth_module"] = dependency
			}
		}
	}
	raw, err := os.ReadFile(*inputPath)
	var in input
	if err == nil {
		err = json.Unmarshal(raw, &in)
	}
	var capture *captureWriter
	if err == nil && (*checkpointPath != "" || *accessesPath != "") {
		capture, err = newCapture(*checkpointPath, *accessesPath)
	}
	if err == nil && *checkpointProofs {
		if capture == nil {
			err = errors.New("--checkpoint-proofs requires --checkpoints and --access-list")
		} else {
			capture.proofs = true
		}
	}
	if err == nil {
		err = execute(&in, result, capture)
	}
	if capture != nil {
		if captureErr := capture.finish(err == nil); captureErr != nil {
			err = errors.Join(err, captureErr)
			result["offline_execution_checked"] = false
		}
	}
	if err != nil {
		result["error"] = err.Error()
	}
	output, openErr := os.OpenFile(*outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if openErr != nil {
		fmt.Fprintln(os.Stderr, openErr)
		os.Exit(1)
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	writeErr := encoder.Encode(result)
	closeErr := output.Close()
	if err != nil || writeErr != nil || closeErr != nil {
		fmt.Fprintln(os.Stderr, errors.Join(err, writeErr, closeErr))
		os.Exit(1)
	}
}
