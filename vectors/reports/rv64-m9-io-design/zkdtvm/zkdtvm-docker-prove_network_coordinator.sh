#!/bin/bash

if [ $# -eq 0 ]; then
    coordinator_port=8000
    prover_port=9000
elif [ $# -eq 1 ]; then
    coordinator_port=$1
    prover_port=9000
elif [ $# -eq 2 ]; then
    coordinator_port=$1
    prover_port=$2
else
    echo "invalid parameters, usage: ./prove_network_coordinator.sh [<coordinator_port>] [<prover_port>]"
    exit 1
fi

docker run -it -d \
    --restart unless-stopped \
    --network host \
    --name zkdtvm_eth_proofs_coordinator \
    -e MODE=coordinator \
    -e PORT=$coordinator_port \
    -e RUST_LOG=info \
    ghcr.io/doubizhizun/zkdtvm_eth_proofs:0.6.1

# PROVER_PORTS=(9000 9001 9002 9003 9004 9005 9006 9007)
CUDA_DEVS=(0 1 2 3 4 5 6 7)
CPU_RANGES=("0-15" "16-31" "32-47" "48-61" "62-77" "78-93" "94-109" "110-123")
NUMAS=(0 0 0 0 1 1 1 1)
PID=()
for i in "${!CUDA_DEVS[@]}"; do
    PORT=$(($prover_port + $i))
    CUDA=${CUDA_DEVS[$i]}
    CPUS=${CPU_RANGES[$i]}
    NUMA=${NUMAS[$i]}

    docker run -it -d \
        --cpuset-cpus="$CPUS" \
        --cpuset-mems="$NUMA" \
        --gpus "device=$CUDA" \
        --restart unless-stopped \
        --network host \
        --name zkdtvm_eth_proofs_prover_$i \
        -e MODE=prover \
        -e PORT=$PORT \
        -e COORDINATOR=http://localhost:$coordinator_port \
        -e RUST_LOG=info \
        ghcr.io/doubizhizun/zkdtvm_eth_proofs:0.6.1 &
    PID+=($!)
done

for pid in "${PID[@]}"; do
    wait $pid
done

echo "✅ Coordinator and Provers are Running!"