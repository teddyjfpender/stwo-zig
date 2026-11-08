import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { after, test } from "node:test";

import { AbiCoder, JsonRpcProvider, ContractFactory, id, keccak256 } from "ethers";
import solc from "solc";
import { registerFriTests } from "./fri-cases.mjs";

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
registerFriTests(deploy);

function hash(tag, ...payload) {
  const prefix = Buffer.alloc(64);
  prefix.write(tag);
  return "0x" + createHash("blake2s256").update(prefix).update(Buffer.concat(payload)).digest("hex");
}

function binary(hex) {
  return Buffer.from(hex.slice(2), "hex");
}

test("computes native OM31 DEEP answers from exact projected trace openings", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../fixtures/native-deep-vector.json", import.meta.url)));
  const deep = await deploy("test/DeepHarness.sol", "DeepHarness");
  function words(values) {
    const bytes = Buffer.alloc(values.length * 4);
    values.forEach((value, i) => bytes.writeUInt32LE(value, i * 4));
    return bytes;
  }
  const prefix = Buffer.from(fixture.prefixBytes);
  const samples = words(fixture.samples.flat());
  const digest = createHash("blake2s256").update(prefix).update(samples).digest();
  const challenge = createHash("blake2s256").update(digest).update(Buffer.alloc(5)).digest();
  assert.deepEqual(fixture.alpha, Array.from({ length: 8 }, (_, i) => challenge.readUInt32LE(i * 4) % 0x7fffffff));

  function opening(i, { extra = false, invalidResidue = false } = {}) {
    const logSize = fixture.treeLogs[i];
    const columnCount = fixture.treeWidths[i];
    const allRows = words(fixture.rows[i]);
    const positions = [...new Set(fixture.queries.map((q) =>
      ((q >> (1 + fixture.domainLog - logSize)) << 1) | (q & 1)
    ))].sort((a, b) => a - b);
    if (extra) {
      const missing = Array.from({ length: 1 << logSize }, (_, j) => j).find((j) => !positions.includes(j));
      positions.push(missing);
      positions.sort((a, b) => a - b);
    }
    if (invalidResidue) allRows.writeUInt32LE(0x7fffffff, positions[0] * columnCount * 4);
    const row = (j) => allRows.subarray(j * columnCount * 4, (j + 1) * columnCount * 4);
    let level = Array.from({ length: 1 << logSize }, (_, j) => hash("leaf", row(j)));
    let active = positions;
    const witness = [];
    while (level.length > 1) {
      const siblings = new Set(active);
      for (const j of active) if (!siblings.has(j ^ 1)) witness.push(level[j ^ 1]);
      active = [...new Set(active.map((j) => j >> 1))];
      level = Array.from({ length: level.length >> 1 }, (_, j) =>
        hash("node", binary(level[2 * j]), binary(level[2 * j + 1]))
      );
    }
    return [{ root: level[0], logSize, columnCount }, { positions, rows: Buffer.concat(positions.map(row)), witness }];
  }
  const cases = fixture.treeLogs.map((_, i) => opening(i));
  const args = [
    fixture.domainLog, fixture.columns, fixture.points, prefix, samples,
    cases.map(([tree]) => tree), cases.map(([, proof]) => proof), fixture.queries,
  ];
  const got = await deep.deep(...args);
  const normalized = (values) => values.map((value) => value.map(Number));
  assert.deepEqual(normalized(got), fixture.answers);

  const wrongOpening = (tree, proof) => [
    ...args.slice(0, 5), [tree, ...args[5].slice(1)], [proof, ...args[6].slice(1)], args[7],
  ];
  const badRow = Buffer.from(cases[0][1].rows);
  badRow[0] ^= 1;
  await assert.rejects(deep.deep(...wrongOpening(cases[0][0], { ...cases[0][1], rows: badRow })));
  await assert.rejects(deep.deep(...wrongOpening(...opening(0, { extra: true }))));
  await assert.rejects(deep.deep(...wrongOpening(...opening(0, { invalidResidue: true }))));
  const otherQueries = [...fixture.queries.slice(0, -1), 30];
  await assert.rejects(deep.deep(...args.slice(0, -1), otherQueries));

  const modifiedSample = Buffer.from(samples);
  modifiedSample[0] ^= 1;
  const changed = normalized(await deep.deep(...args.slice(0, 4), modifiedSample, ...args.slice(5)));
  assert.notDeepEqual(changed, fixture.answers);
  modifiedSample.writeUInt32LE(0x7fffffff, 28);
  await assert.rejects(deep.deep(...args.slice(0, 4), modifiedSample, ...args.slice(5)));
  await assert.rejects(deep.deep(...args.slice(0, 4), samples.subarray(0, -32), ...args.slice(5)));
  const fixedPoint = { x: [1, 0, 0, 0, 0, 0, 0, 0], y: Array(8).fill(0) };
  await assert.rejects(deep.deep(...args.slice(0, 2), [fixedPoint, fixture.points[1]], ...args.slice(3)));

  const receipt = await (await deep.deep.send(...args)).wait();
  console.log(JSON.stringify({ deepOpenedRows: got.length, deepOpenedRowsGas: Number(receipt.gasUsed) }));
});

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
  const anchorBlock = await provider.getBlock("latest");
  const anchor = [anchorBlock.number, anchorBlock.hash];
  await provider.send("evm_mine", []);
  const proof = await checkpoint.transitionDigest(121057303, next, origin, anchor);
  // A proof matching the statement is insufficient if the anchor is fabricated.
  for (const invalid of [
    [anchorBlock.number, id("fake anchor")],
    [anchorBlock.number, "0x" + "00".repeat(32)],
    [anchorBlock.number + 1, anchorBlock.hash],
  ]) {
    const matchingProof = await checkpoint.transitionDigest(121057303, next, origin, invalid);
    await assert.rejects(
      checkpoint.advance.staticCall(121057303, next, origin, invalid, matchingProof),
      (error) => error.revert?.name === "InvalidL1Anchor",
    );
  }
  const earlier = await provider.getBlock(anchorBlock.number - 1);
  await assert.rejects(
    checkpoint.advance.staticCall(121057303, next, origin, [earlier.number, earlier.hash], proof),
    (error) => error.revert?.name === "InvalidProof",
  );

  for (const [target, number, output, l1] of [
    [checkpoint, 121057304, next, origin],
    [checkpoint, 121057303, id("other root"), origin],
    [checkpoint, 121057303, next, id("other origin")],
    [other, 121057303, next, origin],
  ]) {
    await assert.rejects(target.advance.staticCall(number, output, l1, anchor, proof));
  }
  assert.equal(await checkpoint.outputRoot(), initial);
  assert.equal(await checkpoint.blockNumber(), 121057302n);
  const receipt = await (await checkpoint.advance(121057303, next, origin, anchor, proof)).wait();
  assert.equal(receipt.status, 1);
  assert.equal(await checkpoint.outputRoot(), next);
  assert.equal(await checkpoint.blockNumber(), 121057303n);
  await assert.rejects(checkpoint.advance.staticCall(121057303, next, origin, anchor, proof));
  await assert.rejects(checkpoint.advance.staticCall(121057304, next, origin, anchor, proof));
  await provider.send("anvil_mine", ["0x101"]);
  const expiredProof = await checkpoint.transitionDigest(121057304, next, origin, anchor);
  await assert.rejects(
    checkpoint.advance.staticCall(121057304, next, origin, anchor, expiredProof),
    (error) => error.revert?.name === "InvalidL1Anchor",
  );
  assert.equal(await checkpoint.blockNumber(), 121057303n);
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
  const block = await provider.getBlock("latest");
  await provider.send("evm_mine", []);
  await assert.rejects(
    checkpoint.advance.staticCall(121057303, id("next"), id("l1 origin"), [block.number, block.hash], "0x"),
  );
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

test("reconstructs the native DEEP and FRI commitment transcript", async () => {
  const rawHash = (...pieces) => createHash("blake2s256").update(Buffer.concat(pieces)).digest();
  const draw = (digest) => {
    const block = rawHash(digest, Buffer.alloc(5));
    return Array.from({ length: 8 }, (_, i) => BigInt(block.readUInt32LE(4 * i) % 0x7fffffff));
  };
  const prefix = id("verified OODS prefix");
  const roots = [id("circle layer"), id("line layer one"), id("line layer two")];
  const last = Buffer.alloc(32, 11);
  for (const count of [0, 1, 2, 3, 4, 5, 8]) {
    const samples = Buffer.alloc(count * 32, 7);
    let digest = rawHash(binary(prefix), samples);
    const deep = draw(digest);
    const folding = roots.map((root) => {
      digest = rawHash(digest, binary(root));
      return draw(digest);
    });
    const result = await harness.derivePcs(prefix, 11, count, samples, roots, last);
    assert.deepEqual(Array.from(result.deep), deep);
    assert.deepEqual(result.folding.map((alpha) => Array.from(alpha)), folding);
    assert.equal(result.prePowDigest, "0x" + rawHash(digest, last).toString("hex"));
  }
  const boundary = Buffer.alloc(32);
  for (let lane = 0; lane < 8; ++lane) boundary.writeUInt32LE(0x7ffffffe, 4 * lane);
  await harness.derivePcs(prefix, 11, 1, boundary, roots, boundary);
  for (let lane = 0; lane < 8; ++lane) {
    for (const residue of [0x7fffffff, 0x80000000]) {
      const malformed = Buffer.from(boundary);
      malformed.writeUInt32LE(residue, 4 * lane);
      await assert.rejects(harness.derivePcs(prefix, 11, 2, Buffer.concat([boundary, malformed]), roots, last));
      await assert.rejects(harness.derivePcs(prefix, 11, 0, "0x", roots, malformed));
    }
  }
  await assert.rejects(harness.derivePcs(prefix, 11, 2, Buffer.alloc(32), roots, last));
  await assert.rejects(harness.derivePcs(prefix, 11, 0, "0x", roots.slice(1), last));
  await assert.rejects(harness.derivePcs(prefix, 11, 0, "0x", roots, Buffer.alloc(64)));
  await assert.rejects(harness.derivePcs(prefix, 11, 0, "0x", roots, "0x"));
});

test("folds native OM31 FRI subgroups in bit-reversed pair order", async () => {
  const p = 0x7fffffffn;
  const mod = (x) => ((x % p) + p) % p;
  const add = (a, b) => a.map((x, i) => mod(x + b[i]));
  const subtract = (a, b) => a.map((x, i) => mod(x - b[i]));
  const complexMul = ([ar, ai], [br, bi]) => [mod(ar * br - ai * bi), mod(ar * bi + ai * br)];
  const towerMul = (innerMul, nonresidue) => (a, b) => {
    const n = a.length / 2;
    const [a0, a1, b0, b1] = [a.slice(0, n), a.slice(n), b.slice(0, n), b.slice(n)];
    return add(innerMul(a0, b0), innerMul(nonresidue, innerMul(a1, b1)))
      .concat(add(innerMul(a0, b1), innerMul(a1, b0)));
  };
  const quarticMul = towerMul(complexMul, [2n, 1n]);
  const octicMul = towerMul(quarticMul, [0n, 0n, 1n, 0n]);
  const alpha = [p - 1n, 3n, 123n, 7n, 11n, p - 9n, 17n, 19n];
  for (const size of [2, 4, 8, 16]) {
    const values = Array.from({ length: size }, (_, i) =>
      Array.from({ length: 8 }, (_, j) => mod(p - BigInt(i * 11 + 1) ** BigInt(j + 1))));
    const inverses = Array.from({ length: size - 1 }, (_, i) => BigInt(i + 3));
    let current = values;
    let challenge = alpha;
    let at = 0;
    while (current.length > 1) {
      current = Array.from({ length: current.length / 2 }, (_, i) => {
        const left = current[2 * i];
        const right = current[2 * i + 1];
        const inverse = inverses[at++];
        return add(add(left, right), octicMul(challenge, subtract(left, right).map((x) => mod(x * inverse))));
      });
      challenge = octicMul(challenge, challenge);
    }
    assert.deepEqual(Array.from(await harness.foldFri(values, alpha, inverses)), current[0]);
    const receipt = await (await harness.foldFri.send(values, alpha, inverses)).wait();
    console.log(JSON.stringify({ friFoldWidth: size, gas: Number(receipt.gasUsed) }));
  }
  const zero = Array(8).fill(0n);
  const max = Array(8).fill(p - 1n);
  const vector = (label) => {
    const digest = createHash("sha256").update(label).digest();
    return Array.from({ length: 8 }, (_, i) => BigInt(digest.readUInt32LE(i * 4)) % p);
  };
  const products = [[zero, max], [max, max], ...Array.from(
    { length: 16 }, (_, i) => [vector(`left-${i}`), vector(`right-${i}`)],
  )];
  for (const [left, challenge] of products) {
    const expected = add(left, octicMul(challenge, left));
    assert.deepEqual(Array.from(await harness.foldFri([left, zero], challenge, [1])), expected);
  }
  await assert.rejects(harness.foldFri([[p, ...zero.slice(1)], zero], alpha, [1]));
  await assert.rejects(harness.foldFri([zero, zero], alpha, [p]));
  await assert.rejects(harness.foldFri([zero, zero], alpha, [0]));
  await assert.rejects(harness.foldFri([zero, zero], alpha, []));
  await assert.rejects(harness.foldFri([zero, zero, zero], alpha, [1, 1]));
  await assert.rejects(harness.foldFri([zero, zero], [p, ...alpha.slice(1)], [1]));
});

test("binds FRI inverse coordinates to the canonical circle and line subgroups", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../fixtures/native-pcs-121057303-truth-4.json", import.meta.url)));
  const { folding } = await harness.derivePcs(
    fixture.prefix, fixture.domainLog, fixture.sampleCount, fixture.samples, fixture.friRoots, fixture.lastCoefficient,
  );
  const p = 0x7fffffffn;
  const mod = (value) => (value % p + p) % p;
  const product = ([x, y], [u, v]) => [mod(x * u - y * v), mod(x * v + y * u)];
  const double = (point) => product(point, point);
  function inverse(value) {
    let result = 1n;
    for (let exponent = p - 2n; exponent !== 0n; exponent >>= 1n) {
      if (exponent & 1n) result = mod(result * value);
      value = mod(value * value);
    }
    return result;
  }
  function coset(log, circle) {
    let first = [2n, 1_268_011_823n];
    for (let i = log; i < (circle ? 30 : 29); i++) first = double(first);
    const step = double(double(first));
    const points = [first];
    for (let i = 1; i < (1 << (log - Number(circle))); i++) points.push(product(points[i - 1], step));
    return points;
  }
  function subgroupInverses(log, query, length, circle) {
    const result = [];
    let base = query - (query % length);
    while (length > 1) {
      const points = coset(log, circle);
      length /= 2;
      for (let i = 0; i < length; i++) {
        const index = Number.parseInt((base + 2 * i).toString(2).padStart(log, "0").split("").reverse().join(""), 2);
        result.push(inverse(points[index][Number(circle)]));
      }
      circle = false;
      base >>= 1;
      log--;
    }
    return result;
  }
  for (const [log, query, count, circle, challenge] of [
    [fixture.domainLog, 117, 16, true, Array.from(folding[0])],
    [fixture.domainLog - 4, 17, 16, false, Array.from(folding[1])],
    [1, 1, 2, false, Array.from(folding[2])],
  ]) {
    const values = Array.from({ length: count }, (_, i) => Array.from({ length: 8 }, (_, j) => i * 17 + j));
    const inverses = subgroupInverses(log, query, count, circle);
    const expected = await harness.foldFri(values, challenge, inverses);
    const actual = await harness.foldCanonicalFri(values, challenge, inverses, log, query, circle);
    assert.deepEqual(Array.from(actual), Array.from(expected));
    const receipt = await (await harness.foldCanonicalFri.send(values, challenge, inverses, log, query, circle)).wait();
    console.log(JSON.stringify({ canonicalFriWidth: count, domainLog: log, circle, gas: Number(receipt.gasUsed) }));
    const modified = [mod(inverses[0] + 1n), ...inverses.slice(1)];
    await assert.rejects(harness.foldCanonicalFri(values, challenge, modified, log, query, circle));
    await assert.rejects(harness.foldCanonicalFri(values, challenge, inverses, log, 1 << log, circle));
    await assert.rejects(harness.foldCanonicalFri(values, challenge, inverses, log, query, !circle));
  }
});

test("replays the DEEP/FRI commitment suffix from a native OP Mainnet proof", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../fixtures/native-pcs-121057303-truth-4.json", import.meta.url)));
  const native = JSON.parse(readFileSync(new URL("../fixtures/native-queries-121057303.json", import.meta.url)))[fixture.worker];
  assert.equal(native.workerSha256, fixture.workerSha256);
  assert.equal(native.domainLog, fixture.domainLog);
  const args = [
    fixture.prefix, fixture.domainLog, fixture.sampleCount, fixture.samples,
    fixture.friRoots, fixture.lastCoefficient,
  ];
  const limits = { gasLimit: 100_000_000 };
  const result = await harness.derivePcs(...args, limits);
  assert.equal(result.prePowDigest, native.prePowDigest);
  const receipt = await (await harness.derivePcs.send(...args, limits)).wait();
  console.log(JSON.stringify({ nativePcsSuffixGas: Number(receipt.gasUsed) }));
  const opening = loadOpening("truth-4");
  const queryVerifier = await deploy("src/NativeQueryOpening.sol", "NativeQueryOpening");
  assert.equal(await queryVerifier.verifyQueriedOpening(
    opening.root, opening.depth,
    [{ prePowDigest: result.prePowDigest, nonce: native.nonce, domainLog: native.domainLog }],
    opening.positions, opening.rows, opening.rowBytes, opening.witness,
  ), true);
});

test("checks transcript-derived OODS against a verifier-owned split composition evaluator", async () => {
  const contract = await deploy("test/OodsHarness.sol", "OodsHarness");
  const p = 0x7fffffffn;
  const mod = (x) => (x % p + p) % p;
  const add = (a, b) => a.map((x, i) => mod(x + b[i]));
  const sub = (a, b) => a.map((x, i) => mod(x - b[i]));
  const basis = (i) => Array.from({ length: 8 }, (_, j) => BigInt(i === j));
  const one = basis(0);
  const zero = Array(8).fill(0n);
  const complex = ([ar, ai], [br, bi]) => [mod(ar * br - ai * bi), mod(ar * bi + ai * br)];
  const tower = (multiply, nonresidue) => (a, b) => {
    const n = a.length / 2;
    const [a0, a1, b0, b1] = [a.slice(0, n), a.slice(n), b.slice(0, n), b.slice(n)];
    return add(multiply(a0, b0), multiply(nonresidue, multiply(a1, b1)))
      .concat(add(multiply(a0, b1), multiply(a1, b0)));
  };
  const mul = tower(tower(complex, [2n, 1n]), [0n, 0n, 1n, 0n]);
  const pow = (base, exponent) => {
    let result = one;
    while (exponent > 0n) {
      if (exponent & 1n) result = mul(result, base);
      base = mul(base, base);
      exponent >>= 1n;
    }
    return result;
  };
  const rawHash = (...parts) => createHash("blake2s256").update(Buffer.concat(parts)).digest();
  const toField = (bytes) => Array.from({ length: 8 }, (_, i) => BigInt(bytes.readUInt32LE(4 * i)) % p);
  const draw = (digest) => toField(rawHash(digest, Buffer.alloc(5)));
  const encode = (field) => {
    const bytes = Buffer.alloc(32);
    field.forEach((x, i) => bytes.writeUInt32LE(Number(x), 4 * i));
    return bytes;
  };
  const getPoint = (prefix) => {
    const t = draw(prefix);
    const t2 = mul(t, t);
    const inverse = pow(add(one, t2), p ** 8n - 2n);
    return { x: mul(sub(one, t2), inverse), y: mul(add(t, t), inverse), inverse };
  };
  const pre = id("authority through interaction commitment");
  const root = id("composition commitment");
  const prefix = rawHash(binary(pre), binary(root));
  const alpha = draw(binary(pre));
  const { x, y, inverse } = getPoint(prefix);
  const trace = toField(rawHash(Buffer.from("trace sample")));
  const expected = add(mul(alpha, trace), mul(x, y));
  const partials = Array.from({ length: 32 }, (_, i) =>
    i === 0 ? zero : toField(rawHash(Buffer.from(`partial-${i}`))));
  const chunks = Array.from({ length: 4 }, (_, i) => partials.slice(i * 8, (i + 1) * 8)
    .reduce((sum, sample, lane) => add(sum, mul(basis(lane), sample)), zero));
  const doubleX = (v) => sub(mul([2n, ...zero.slice(1)], mul(v, v)), one);
  let factor = x;
  for (let i = 0; i < 8; ++i) factor = doubleX(factor);
  const even = add(chunks[0], mul(factor, chunks[1]));
  const odd = add(chunks[2], mul(factor, chunks[3]));
  partials[0] = sub(expected, add(even, mul(doubleX(factor), odd)));
  const samples = Buffer.concat([trace, ...partials].map(encode));
  assert.equal(await contract.check(pre, root, samples, encode(inverse)), "0x" + prefix.toString("hex"));

  const mainnet = JSON.parse(readFileSync(new URL("../fixtures/native-pcs-121057303-truth-4.json", import.meta.url)));
  const mainnetPoint = getPoint(binary(mainnet.prefix));
  const nativePoint = await contract.point(mainnet.prefix, encode(mainnetPoint.inverse));
  assert.deepEqual(Array.from(nativePoint.x), mainnetPoint.x);
  assert.deepEqual(Array.from(nativePoint.y), mainnetPoint.y);

  const differentRoot = id("different composition commitment");
  const differentPoint = getPoint(rawHash(binary(pre), binary(differentRoot)));
  await assert.rejects(contract.check(pre, differentRoot, samples, encode(differentPoint.inverse)), /CompositionMismatch/);
  await assert.rejects(contract.check(pre, root, samples, encode(zero)), /InvalidPointInverse/);
  await assert.rejects(contract.check(pre, root, samples.subarray(32), encode(inverse)), /InvalidSampleShape/);
  for (const index of [0, 32, samples.length - 1]) {
    const mutated = Buffer.from(samples);
    mutated[index] ^= 1;
    await assert.rejects(contract.check(pre, root, mutated, encode(inverse)), /CompositionMismatch/);
  }
  const noncanonical = Buffer.from(samples);
  noncanonical.writeUInt32LE(Number(p), 0);
  await assert.rejects(contract.check(pre, root, noncanonical, encode(inverse)), /NonCanonicalField/);
});

test("evaluates the receiver-pinned native RV64 initial AIR at OODS", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../fixtures/native-air-initial.json", import.meta.url)));
  const wire = binary(fixture.wire);
  const code = wire.subarray(0, fixture.codeBytes);
  const inputEnd = fixture.codeBytes + 32 * code.readUInt32LE(16);
  const parameterEnd = inputEnd + 32 * code.readUInt32LE(20);
  const inputs = wire.subarray(fixture.codeBytes, inputEnd);
  const parameters = wire.subarray(inputEnd, parameterEnd);
  const decode = (field) => Array.from({ length: 8 }, (_, i) => BigInt(field.readUInt32LE(4 * i)));
  const field = (i) => wire.subarray(parameterEnd + i * 32, parameterEnd + (i + 1) * 32);
  const alpha = decode(field(0));
  const point = [decode(field(1)), decode(field(2))];
  const inverse = field(3);
  const expected = decode(field(4));
  const authority = "0x9ee12bcc9933ee1e098f64c5dff9d066c9189d7656b82a25fa9e6846bce806a7";
  assert.equal(keccak256(code), authority);
  const contract = await deploy("test/AirProgramHarness.sol", "AirProgramHarness", authority, fixture.maskLog);
  assert.deepEqual(Array.from(await contract.quotient(code, inputs, parameters, point, alpha, inverse)), expected);

  const mutated = Buffer.from(code);
  mutated[mutated.length - 1] ^= 1;
  await assert.rejects(contract.quotient(mutated, inputs, parameters, point, alpha, inverse), /ProgramIdentityMismatch/);
  await assert.rejects(contract.quotient(code, inputs.subarray(32), parameters, point, alpha, inverse), /InvalidProgram/);
  await assert.rejects(contract.quotient(code, inputs, parameters, point, alpha, Buffer.alloc(32)), /InvalidVanishingInverse/);
  const receipt = await (await contract.quotient.send(code, inputs, parameters, point, alpha, inverse)).wait();
  console.log(JSON.stringify({ nativeInitialAirGas: Number(receipt.gasUsed), nodes: code.readUInt32LE(4), residuals: code.readUInt32LE(8) }));
});

test("reconstructs the V3 truth worker prefix from the pinned native profile and authority", async () => {
  const contract = await deploy("test/TruthV3TranscriptHarness.sol", "TruthV3TranscriptHarness");
  const hash = (...pieces) => createHash("blake2s256").update(Buffer.concat(pieces)).digest();
  const words = (...fields) => {
    const encoded = Buffer.alloc(4 * fields.length);
    fields.forEach((word, index) => encoded.writeUInt32LE(word, index * 4));
    return encoded;
  };
  const sha = (...pieces) => createHash("sha256").update(Buffer.concat(pieces)).digest();
  const tag = words(0x5354574f, 0x524d3331, 1, 0x7fffffff, 32, 8, 8, 1);
  const channelIdentity = sha(Buffer.from("stwo-native-raw-u32-mod-m31/v1\0"), tag);
  const caps = [8, 108, 1, 4, 20, 0, 128, 256, 22, 23, 16384, 65536, 8, 5, 128, 128, 9, 3, 30, 1 << 20, 128];
  const capBytes = Buffer.alloc(caps.length * 8);
  caps.forEach((word, i) => capBytes.writeBigUInt64LE(BigInt(word), i * 8));
  const profile = sha(Buffer.from("rv64-om31-rawblake-native-localgkr-128-CONJECTURED-ethstark/v2\0"),
    Buffer.from("conjectured128_b2_q108_p20_fold4"), channelIdentity, capBytes);
  const authority = {
    ordinal: 0xfedcba98,
    statement: id("worker statement"),
    fixedIdentity: id("fixed identity"),
    fixedRoot: id("fixed root"),
    mainRoot: id("MAIN root"),
    manifest: id("manifest"),
  };
  const interaction = id("interaction root");
  const roots = [authority.fixedRoot, authority.mainRoot, interaction];
  const claim = words(1, 2, 3, 4, 5, 6, 7, 8);
  let digest = hash(hash(Buffer.alloc(32), tag), words(20, 1, 108, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0));
  const early = [words(0x57474b4f, 1, 8, 4, authority.ordinal),
    hash(Buffer.from("RV64-SERVICES-CPU-GKR-TRUTH-CLASSIC-OM31-V1")), binary(authority.statement),
    hash(Buffer.from("rv64-OM-localGKR-classicTruth-beta2-engineering/v1\0")), binary(authority.fixedIdentity),
    binary(authority.fixedRoot), profile, binary(authority.fixedRoot), binary(authority.mainRoot),
    words(0x56334259, 1, 8)];
  for (const part of early) digest = hash(digest, part);
  const byteDraw = hash(digest, Buffer.alloc(5));
  const byteChallenge = Array.from({ length: 8 }, (_, i) => BigInt(byteDraw.readUInt32LE(i * 4) % 0x7fffffff));
  for (const part of [words(0x57474b32, 1, 1), binary(authority.manifest), claim, binary(interaction)]) {
    digest = hash(digest, part);
  }
  const [preComposition, challenge] = await contract.derive(authority, roots, claim);
  assert.equal(preComposition, "0x" + digest.toString("hex"));
  assert.deepEqual(Array.from(challenge), byteChallenge);
  await assert.rejects(contract.derive(authority, [roots[1], roots[0], roots[2]], claim), /WorkerRootMismatch/);
  const noncanonical = Buffer.from(claim);
  noncanonical.writeUInt32LE(0x7fffffff, 8);
  await assert.rejects(contract.derive(authority, roots, noncanonical), /NonCanonicalField/);
  const [other] = await contract.derive({ ...authority, manifest: id("another manifest") }, roots, claim);
  assert.notEqual(other, preComposition);
});

function checkpointDigest(scope, checkpoint) {
  const typeHash = id("KonaTransition(uint256 settlementChainId,address checkpoint,uint256 rollupChainId,bytes32 rollupConfig,uint64 previousNumber,bytes32 previousRoot,uint64 nextNumber,bytes32 nextRoot,bytes32 l1Origin,uint64 l1AnchorNumber,bytes32 l1AnchorHash)");
  const types = ["bytes32", "uint256", "address", "uint256", "bytes32", "uint64", "bytes32", "uint64", "bytes32", "bytes32", "uint64", "bytes32"];
  return keccak256(AbiCoder.defaultAbiCoder().encode(types, [typeHash, ...scope, ...checkpoint]));
}

test("binds the checkpoint digest to the exact Rust and Python Kona guest outputs", async () => {
  const contract = await deploy("test/KonaStatementHarness.sol", "KonaStatementHarness");
  const scope = [1, await contract.getAddress(), 10, id("OP Mainnet config")];
  const checkpoint = [200, "0x" + "b2".repeat(32), 201, "0x" + "c3".repeat(32),
    "0x" + "d4".repeat(32), 100, "0x" + "a1".repeat(32)];
  const payload = "0x" + "e5".repeat(32);
  const blockHash = "0x" + "f6".repeat(32);
  const statement = [checkpoint, 99, payload, blockHash];
  const digest = checkpointDigest(scope, checkpoint);
  const [derivation, execution] = await contract.outputs(digest, scope, statement);
  assert.equal(derivation, "0x79dc71b2ef04d3b09ab72857909758cc2d94b77d82907b8568d187e7b529ba72010a000000000000004f44");
  assert.equal(execution, "0xa1070315845855c79cb5c43f2782fa954672205424a5b42a47d1962a0ca2a9ca010a000000000000004f50");
  await assert.rejects(contract.outputs(digest, [1, await signer.getAddress(), ...scope.slice(2)], statement), /InvalidStatement/);
  await assert.rejects(contract.outputs(digest, scope, [checkpoint, 101, payload, blockHash]), /InvalidStatement/);
  const otherCheckpoint = [...checkpoint];
  otherCheckpoint[3] = id("wrong output root");
  await assert.rejects(contract.outputs(digest, scope, [otherCheckpoint, ...statement.slice(1)]), /InvalidStatement/);
  const other = await contract.outputs(digest, scope, [checkpoint, 99, id("wrong payload"), blockHash]);
  assert.notEqual(other[0], derivation);
  assert.notEqual(other[1], execution);
});

test("opens the actual OP Mainnet 159257842 checkpoint into the accepted RV64 statement", async () => {
  const contract = await deploy("test/KonaStatementHarness.sol", "KonaStatementHarness");
  const fixture = JSON.parse(readFileSync(new URL("../fixtures/kona-transition-159257842.json", import.meta.url)));
  const s = fixture.statement;
  const hex = (value) => "0x" + value;
  const scope = [s.l1_chain_id, await contract.getAddress(), s.chain_id, id("OP Mainnet config")];
  const checkpoint = [s.previous_number, hex(s.previous_root), s.next_number, hex(s.next_root),
    hex(s.next_origin_hash), s.anchor_number, hex(s.anchor_hash)];
  const opened = [checkpoint, s.next_origin_number, hex(s.payload_commitment), hex(s.block_hash)];
  const [od, op] = await contract.outputs(checkpointDigest(scope, checkpoint), scope, opened);
  assert.equal(od, hex(fixture.native_and_rv64_output));
  assert.equal(op, hex(fixture.execution_transport));
});
