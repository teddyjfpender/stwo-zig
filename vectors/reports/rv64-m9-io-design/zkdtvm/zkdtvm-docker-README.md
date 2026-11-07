# zkDTVM

zkDTVM is a RISC-V based zero-knowledge virtual machine engineered, from the ground up, to extract maximum throughput from modern GPUs. While most zkVMs treat GPU acceleration as an afterthought — a back-end that swaps out a few hot kernels in an otherwise CPU-shaped pipeline — zkDTVM treats the GPU as a first-class design constraint that propagates all the way up to the proving system, the arithmetization, and the execution model.

This repository provides the binary release of zkDTVM and the tool for proving Ethereum block, designed to enable developers to prove Ethereum block using zkDTVM.

## Docker-Based Installation

We provide a Docker container with zkDTVM for proving Ethereum block.

## Dependencies

Servers with x86-64 CPUs, NVIDIA RTX 5090 GPUs and cuda 12.8 are required.


## Usage

### Pull the docker image

```bash
# Download the container
docker pull ghcr.io/doubizhizun/zkdtvm_eth_proofs:0.6.1
```

### Run with a single GPU

```bash
# Start the single prover
./prove_single.sh <http_rpc_url> <ws_rpc_url> <api_token>
```

### Run with 8 GPUs

```bash
# Firstly, start the coordinator and 8 provers
./prove_network_coordinator.sh
# Then, start the network
./prove_network.sh <http_rpc_url> <ws_rpc_url> <api_token>
```

### Run with 16 GPUs (2 servers)

```bash
# Firstly, start the coordinator and 8 provers on the superior server
./prove_network_coordinator.sh
# Then, start 8 provers on the subordinate server
./prove_network_prover.sh http://<superior_server_ip>:8000
# Finally, start the network on the superior server
./prove_network.sh <http_rpc_url> <ws_rpc_url> <api_token>
```

## Acknowledgements

During the development of zkdtvm, we relied heavily on and learned from several outstanding open-source projects in the ZK ecosystem. We would like to express our gratitude:

- [Plonky3](https://github.com/Plonky3/Plonky3): Our STARK proving and verification stack is built on top of the Plonky3 library. We forked and extended several of its core crates — including field arithmetic, matrix operations, FRI, and Merkle tree primitives — to support the specific needs of our proof system. We are grateful for its clean, modular architecture at the polynomial IOP level.

- [SP1](https://github.com/succinctlabs/sp1): The overall zkVM architecture of this project draws significant inspiration from SP1. Many of our design choices around the STARK machine structure, recursion framework, AIR chip layout, and proof composition pipeline were informed by studying SP1's implementation. We appreciate the Succinct team for open-sourcing their work and advancing the state of zkVM engineering.

## License

This project is licensed under the [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).
