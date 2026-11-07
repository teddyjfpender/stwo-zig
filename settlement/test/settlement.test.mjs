import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { after, test } from "node:test";

import { JsonRpcProvider, ContractFactory, id, keccak256 } from "ethers";
import solc from "solc";

const sources = {};
for (const directory of ["src", "test"]) {
  for (const name of readdirSync(new URL(`../${directory}/`, import.meta.url))) {
    if (!name.endsWith(".sol")) continue;
    const path = `${directory}/${name}`;
    sources[path] = { content: readFileSync(new URL(`../${path}`, import.meta.url), "utf8") };
  }
}

const input = JSON.stringify({
  language: "Solidity",
  sources,
  settings: {
    evmVersion: "shanghai",
    viaIR: true,
    optimizer: { enabled: true, runs: 100_000 },
    outputSelection: { "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] } },
  },
});

const compiler = process.env.SOLAR;
const started = performance.now();
let compiled;
if (compiler) {
  const result = spawnSync(compiler, ["--standard-json"], {
    input,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) throw result.error ?? new Error(result.stderr);
  compiled = JSON.parse(result.stdout);
} else {
  compiled = JSON.parse(solc.compile(input));
}
const fatalDiagnostics = (compiled.errors ?? []).filter(
  ({ severity, errorCode }) => severity === "error" || errorCode === "2519",
);
assert.deepEqual(fatalDiagnostics, []);
console.log(JSON.stringify({ compiler: compiler || solc.version(), compileMs: Math.round(performance.now() - started) }));

const chain = spawn(process.env.ANVIL ?? "anvil", [
  "--port", "0", "--hardfork", process.env.ANVIL_HARDFORK ?? "shanghai", "--gas-limit", "100000000",
]);
after(() => chain.kill());
const rpc = await new Promise((resolve, reject) => {
  const deadline = setTimeout(() => reject(new Error("Anvil did not start")), 10_000);
  chain.once("error", reject);
  chain.once("exit", (code) => reject(new Error(`Anvil exited with ${code}`)));
  chain.stderr.resume();
  let output = "";
  chain.stdout.on("data", (chunk) => {
    output += chunk;
    const match = output.match(/Listening on (127\.0\.0\.1:\d+)/);
    if (match) {
      clearTimeout(deadline);
      resolve(`http://${match[1]}`);
    }
    output = output.slice(-512);
  });
});
const provider = new JsonRpcProvider(rpc, undefined, { cacheTimeout: -1 });
after(() => provider.destroy());
const signer = await provider.getSigner();

async function deploy(path, name, ...args) {
  const artifact = compiled.contracts[path][name];
  assert.ok(artifact.evm.deployedBytecode.object.length / 2 <= 24_576);
  const factory = new ContractFactory(artifact.abi, artifact.evm.bytecode.object, signer);
  const contract = await factory.deploy(...args);
  await contract.waitForDeployment();
  return contract;
}

const verifier = await deploy("src/LiftedOpeningVerifier.sol", "LiftedOpeningVerifier");
const harness = await deploy("test/Harness.sol", "Harness");

function hash(tag, ...payload) {
  const prefix = Buffer.alloc(64);
  prefix.write(tag);
  return "0x" + createHash("blake2s256").update(prefix).update(Buffer.concat(payload)).digest("hex");
}

function binary(hex) {
  return Buffer.from(hex.slice(2), "hex");
}

test("matches the independent BLAKE2s implementation across block boundaries", async () => {
  for (const size of [4, 16, 28, 32, 36, 60, 64, 68, 96, 128, 132, 260]) {
    const row = Buffer.from(Array.from({ length: size }, (_, i) => (37 * i + size) % 256));
    assert.equal(await harness.leaf(row), hash("leaf", row));
  }
  for (const size of [0, 37, 40, 52, 64]) {
    const block = Buffer.alloc(64);
    for (let i = 0; i < size; i++) block[i] = (37 * i + size) % 256;
    const expected = createHash("blake2s256").update(block.subarray(0, size)).digest("hex");
    assert.equal(await harness.shortDigest(block.subarray(0, 32), block.subarray(32), size), "0x" + expected);
  }
  const left = binary(id("left"));
  const right = binary(id("right"));
  assert.equal(await harness.node(left, right), hash("node", left, right));
  assert.equal(await harness.node(right, left), hash("node", right, left));
  const receipt = await (await harness.node.send(left, right)).wait();
  console.log(JSON.stringify({ nodeHashGas: Number(receipt.gasUsed) }));
});

test("strict compressed opening with shared siblings and a depth-zero tree", async () => {
  const data = Buffer.from("01000000020000000300000004000000", "hex");
  const leaves = Array.from({ length: 4 }, (_, i) => hash("leaf", data.subarray(i * 4, (i + 1) * 4)));
  const right = hash("node", binary(leaves[2]), binary(leaves[3]));
  const root = hash("node", binary(hash("node", binary(leaves[0]), binary(leaves[1]))), binary(right));
  const rows = data.subarray(0, 8);
  assert.equal(await verifier.verifyOpening(root, 2, [0, 1], rows, 4, [right]), true);
  assert.equal(await verifier.verifyOpening(id("wrong"), 2, [0, 1], rows, 4, [right]), false);
  assert.equal(await verifier.verifyOpening(leaves[0], 0, [0], rows.subarray(0, 4), 4, []), true);
  for (const args of [
    [2, [0, 1], rows, 4, []],
    [2, [0, 1], rows, 4, [right, right]],
    [2, [0, 0], rows, 4, [right]],
    [2, [1, 0], rows, 4, [right]],
    [2, [0, 4], rows, 4, [right]],
    [2, [0, 1], rows.subarray(1), 4, [right]],
    [31, [0, 1], rows, 4, [right]],
  ]) {
    await assert.rejects(verifier.verifyOpening(root, ...args), { name: "Error", code: "CALL_EXCEPTION" });
  }
});

test("checkpoint binds state, instance, output and L1 origin before persisting", async () => {
  const backend = await deploy("test/Harness.sol", "MockTransitionVerifier");
  const address = await backend.getAddress();
  const codeHash = keccak256(await provider.getCode(address));
  const initial = id("genesis");
  const next = id("next");
  const origin = id("l1");
  const config = id("OP Mainnet config");
  const path = "src/KonaCheckpoint.sol";
  const params = [10, config, 121057302, initial, address, codeHash];
  await assert.rejects(deploy(path, "KonaCheckpoint", ...params.slice(0, -1), id("wrong code")));
  const checkpoint = await deploy(path, "KonaCheckpoint", ...params);
  const other = await deploy(path, "KonaCheckpoint", ...params);
  const proof = await checkpoint.transitionDigest(121057303, next, origin);

  for (const [target, number, output, l1] of [
    [checkpoint, 121057304, next, origin],
    [checkpoint, 121057303, id("other root"), origin],
    [checkpoint, 121057303, next, id("other origin")],
    [other, 121057303, next, origin],
  ]) {
    await assert.rejects(target.advance.staticCall(number, output, l1, proof));
  }
  assert.equal(await checkpoint.outputRoot(), initial);
  assert.equal(await checkpoint.blockNumber(), 121057302n);
  const receipt = await (await checkpoint.advance(121057303, next, origin, proof)).wait();
  assert.equal(receipt.status, 1);
  assert.equal(await checkpoint.outputRoot(), next);
  assert.equal(await checkpoint.blockNumber(), 121057303n);
  await assert.rejects(checkpoint.advance.staticCall(121057303, next, origin, proof));
  await assert.rejects(checkpoint.advance.staticCall(121057304, next, origin, proof));
  console.log(JSON.stringify({ checkpointMockGas: Number(receipt.gasUsed) }));
});

function reconstructLayers({ depth, positions, rows, rowBytes, witness, root }) {
  let nodes = new Map(positions.map((index, i) => [
    index,
    hash("leaf", rows.subarray(i * rowBytes, (i + 1) * rowBytes)),
  ]));
  const layers = [];
  let cursor = 0;
  for (let level = 0; level < depth; level++) {
    layers.push(nodes);
    const parents = new Map();
    for (const index of [...nodes.keys()]) {
      if (parents.has(index >> 1)) continue;
      const left = index & ~1;
      if (!nodes.has(index ^ 1)) nodes.set(index ^ 1, witness[cursor++]);
      parents.set(index >> 1, hash("node", binary(nodes.get(left)), binary(nodes.get(left + 1))));
    }
    nodes = parents;
  }
  assert.equal(cursor, witness.length);
  assert.deepEqual([...nodes], [[0, root]]);
  return layers;
}

function reconstructPaths(fixture) {
  const layers = reconstructLayers(fixture);
  return fixture.positions.map((position) => layers.map((layer, i) => layer.get((position >> i) ^ 1)));
}

function loadOpening(worker) {
  const opening = JSON.parse(readFileSync(new URL(`../fixtures/op-mainnet-121057303-${worker}.json`, import.meta.url)));
  return { ...opening, rows: binary(opening.rows) };
}

function mergeOpenings(openings) {
  const [{ root, depth, rowBytes }] = openings;
  const knownNodes = Array.from({ length: depth }, () => new Map());
  const knownRows = new Map();
  for (const opening of openings) {
    assert.equal(opening.root, root);
    assert.equal(opening.depth, depth);
    assert.equal(opening.rowBytes, rowBytes);
    for (const [level, nodes] of reconstructLayers(opening).entries()) {
      for (const [index, hash] of nodes) {
        const previous = knownNodes[level].get(index);
        if (previous !== undefined) assert.equal(hash, previous);
        knownNodes[level].set(index, hash);
      }
    }
    opening.positions.forEach((index, i) => {
      const row = opening.rows.subarray(i * rowBytes, (i + 1) * rowBytes);
      if (knownRows.has(index)) assert.deepEqual(row, knownRows.get(index));
      knownRows.set(index, row);
    });
  }

  const positions = [...knownRows.keys()].sort((a, b) => a - b);
  let active = positions;
  const witness = [];
  for (const level of knownNodes) {
    const activeSet = new Set(active);
    for (const index of active) {
      if (activeSet.has(index ^ 1)) continue;
      const sibling = level.get(index ^ 1);
      assert.ok(sibling);
      witness.push(sibling);
    }
    active = [...new Set(active.map((index) => index >> 1))];
  }
  return { root, depth, rowBytes, positions, rows: Buffer.concat(positions.map((i) => knownRows.get(i))), witness };
}

for (const worker of ["truth-3", "truth-4"]) {
  test(`checks the native Kona Mainnet opening from ${worker}`, async () => {
    const fixture = loadOpening(worker);
    const { root, depth, positions, rowBytes, witness, rows } = fixture;
    const paths = reconstructPaths({ ...fixture, rows });
    const args = [root, depth, positions, rows, rowBytes];
    assert.equal(await verifier.verifyOpening(...args, witness), true);
    assert.equal(await harness.checkSeparately(await verifier.getAddress(), ...args, paths), true);
    const mutated = Buffer.from(rows);
    mutated[0] ^= 1;
    assert.equal(await verifier.verifyOpening(root, depth, positions, mutated, rowBytes, witness), false);
    const changedWitness = [...witness];
    changedWitness[0] = id("bad sibling");
    assert.equal(await verifier.verifyOpening(...args, changedWitness), false);

    const limit = { gasLimit: 50_000_000 };
    const batch = await (await verifier.verifyOpening.send(...args, witness, limit)).wait();
    const separate = await (await harness.checkSeparately.send(await verifier.getAddress(), ...args, paths, limit)).wait();
    const one = await (await verifier.verifyOpening.send(
      root, depth, positions.slice(0, 1), rows.subarray(0, rowBytes), rowBytes, paths[0], limit,
    )).wait();
    assert.ok(batch.gasUsed < separate.gasUsed);
    console.log(JSON.stringify({
      block: fixture.blockNumber,
      worker,
      depth,
      queries: positions.length,
      witnessHashes: witness.length,
      separateWitnessHashes: positions.length * depth,
      packedGas: Number(batch.gasUsed),
      separateGas: Number(separate.gasUsed),
      singleGas: Number(one.gasUsed),
      runtimeBytes: (await provider.getCode(await verifier.getAddress())).slice(2).length / 2,
    }));
  });
}


test("binds both native Mainnet openings to PoW and the exact union of sampled queries", async () => {
  const contract = await deploy("src/NativeQueryOpening.sol", "NativeQueryOpening");
  // A commitment checker provides no transition verifier entry point.
  const address = await contract.getAddress();
  const codeHash = keccak256(await provider.getCode(address));
  const initialRoot = id("trusted initial output");
  const checkpoint = await deploy(
    "src/KonaCheckpoint.sol", "KonaCheckpoint", 10, id("rollup"), 121057302, initialRoot, address, codeHash,
  );
  await assert.rejects(checkpoint.advance.staticCall(121057303, id("next"), id("l1 origin"), "0x"));
  assert.equal(await checkpoint.outputRoot(), initialRoot);

  const contexts = JSON.parse(readFileSync(new URL("../fixtures/native-queries-121057303.json", import.meta.url)));
  const workers = ["truth-3", "truth-4"].map(loadOpening);
  const input = workers.map((worker) => {
    const { workerSha256, ...context } = contexts[worker.worker];
    assert.equal(workerSha256, worker.workerSha256);
    return context;
  });
  const call = (opening, trusted) => [
    opening.root, opening.depth, trusted, opening.positions, opening.rows, opening.rowBytes, opening.witness,
  ];
  const send = async (opening, trusted) => {
    const args = call(opening, trusted);
    assert.equal(await contract.verifyQueriedOpening(...args), true);
    // Keep the solc deployment candidate inside the Ethereum transaction cap.
    // The Solar run measures the same call even if its bytecode costs more.
    const gasLimit = compiler ? 50_000_000 : 16_777_216;
    return (await (await contract.verifyQueriedOpening.send(...args, { gasLimit })).wait()).gasUsed;
  };

  const separate = (await send(workers[0], input.slice(0, 1))) + (await send(workers[1], input.slice(1)));
  const union = mergeOpenings(workers);
  const combined = await send(union, input);
  assert.ok(combined < separate);

  // Both full openings are valid under the same root, but each worker has
  // its own Fiat–Shamir queries. Neither can stand in for the other.
  assert.equal(await contract.verifyQueriedOpening(...call(workers[0], input.slice(1))), false);
  assert.equal(await contract.verifyQueriedOpening(...call(workers[0], input)), false);
  assert.equal(await contract.verifyQueriedOpening(...call(union, input.slice(0, 1))), false);
  const changedNonce = { ...input[0], nonce: BigInt(input[0].nonce) + 1n };
  assert.equal(await contract.verifyQueriedOpening(...call(union, [changedNonce, input[1]])), false);
  const changedDigest = { ...input[0], prePowDigest: id("wrong pre-PoW digest") };
  assert.equal(await contract.verifyQueriedOpening(...call(union, [changedDigest, input[1]])), false);
  const wrongDomain = { ...input[0], domainLog: input[0].domainLog + 1 };
  assert.equal(await contract.verifyQueriedOpening(...call(union, [wrongDomain, input[1]])), false);
  const rows = Buffer.from(union.rows);
  rows[0] ^= 1;
  assert.equal(await contract.verifyQueriedOpening(...call({ ...union, rows }, input)), false);
  await assert.rejects(contract.verifyQueriedOpening(...call(union, [])));
  console.log(JSON.stringify({
    sharedRootQueries: union.positions.length,
    sharedRootSiblingHashes: union.witness.length,
    separateSiblingHashes: workers.reduce((sum, item) => sum + item.witness.length, 0),
    sharedRootGas: Number(combined),
    separateRootGas: Number(separate),
    runtimeBytes: (await provider.getCode(await contract.getAddress())).slice(2).length / 2,
  }));
});

test("projects native queries into larger and depth-zero trees", async () => {
  const contract = await deploy("src/NativeQueryOpening.sol", "NativeQueryOpening");
  const context = {
    prePowDigest: "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    nonce: 3304224,
    domainLog: 2,
  };
  const leaves = Array.from({ length: 8 }, (_, i) => {
    const row = Buffer.alloc(4);
    row.writeUInt32LE(i + 1);
    return { row, digest: hash("leaf", row) };
  });
  const join = (left, right) => hash("node", binary(left), binary(right));
  const [a, b, c, d] = Array.from({ length: 4 }, (_, i) => join(leaves[2 * i].digest, leaves[2 * i + 1].digest));
  const root = join(join(a, b), join(c, d));
  const positions = [0, 1, 4, 5];
  const rows = Buffer.concat(positions.map((i) => leaves[i].row));
  assert.equal(await contract.verifyOpening(root, 3, positions, rows, 4, [b, d]), true);
  assert.equal(await contract.verifyQueriedOpening(leaves[0].digest, 0, [context], [0], leaves[0].row, 4, []), true);
  assert.equal(await contract.verifyQueriedOpening(root, 3, [context], positions, rows, 4, [b, d]), true);
});
