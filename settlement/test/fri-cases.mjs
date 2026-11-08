import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";

const P = 2n ** 31n - 1n;
const M = x => (x % P + P) % P;
const ZERO = [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n];
const hash = (...parts) => createHash("blake2s256").update(Buffer.concat(parts)).digest();
const tagged = (tag, ...parts) => {
  const prefix = Buffer.alloc(64);
  prefix.write(tag);
  return hash(prefix, ...parts);
};
const word = (value, size = 4) => {
  const out = Buffer.alloc(size);
  if (size === 4) out.writeUInt32LE(Number(value));
  else out.writeBigUInt64LE(BigInt(value));
  return out;
};
const pack = x => Buffer.concat(x.map(v => word(v)));
const hex = bytes => "0x" + bytes.toString("hex");
const fromHex = value => Buffer.from(value.slice(2), "hex");
const vector = bytes => ZERO.map((_, i) => BigInt(bytes.readUInt32LE(i * 4)) % P);
const sortedUnique = values => [...new Set(values)].sort((a, b) => a - b);
const add = (a, b) => a.map((x, i) => M(x + b[i]));
const scale = (a, x) => a.map(y => M(x * y));

// Independent coefficient multiplication by reducing the formal monomials
// i^2=-1, u^2=2+i, and v^2=u, without Karatsuba or the Solidity layout.
function multiply(a, b) {
  const out = [...ZERO];
  function term(i, u, v, x) {
    if (v >= 2) term(i, u + 1, v - 2, x);
    else if (u >= 2) {
      term(i, u - 2, v, 2n * x);
      term(i + 1, u - 2, v, x);
    } else if (i >= 2) term(i - 2, u, v, -x);
    else out[i + 2 * u + 4 * v] += x;
  }
  for (let i = 0; i < 8; ++i) {
    for (let j = 0; j < 8; ++j) {
      term((i & 1) + (j & 1), ((i >> 1) & 1) + ((j >> 1) & 1), (i >> 2) + (j >> 2), a[i] * b[j]);
    }
  }
  return out.map(M);
}

function power(value, exponent, identity, product) {
  let result = identity;
  for (let n = exponent; n !== 0n; n >>= 1n) {
    if (n & 1n) result = product(result, value);
    value = product(value, value);
  }
  return result;
}

function reverse(position, log) {
  let out = 0;
  for (let i = 0; i < log; ++i) out = (out << 1) | ((position >> i) & 1);
  return out;
}

function point(position, log, circle) {
  const index = reverse(position, log);
  const half = 2 ** (log - 1);
  const conjugate = circle && index >= half;
  const exponent = BigInt(1 + 4 * (conjugate ? index - half : index)) << BigInt((circle ? 30 : 29) - log);
  const [x, y] = power([2n, 1268011823n], exponent, [1n, 0n], ([a, b], [c, d]) =>
    [M(a * c - b * d), M(a * d + b * c)]);
  return [x, conjugate ? M(-y) : y];
}

function inverse(position, log, circle) {
  const coordinate = point(position, log, circle)[circle ? 1 : 0];
  return Number(power(coordinate, P - 2n, 1n, (a, b) => M(a * b)));
}

function groupInverses(group, log, step, circle) {
  const inverses = [];
  for (let round = 0; round < step; ++round) {
    const width = 2 ** (step - round);
    for (let offset = 0; offset < width; offset += 2) {
      inverses.push(inverse(group * width + offset, log - round, circle && round === 0));
    }
  }
  return inverses;
}

function fold(values, alpha, log, step, circle) {
  for (let round = 0; round < step; ++round) {
    const next = [];
    for (let i = 0; i < values.length; i += 2) {
      const sum = add(values[i], values[i + 1]);
      const difference = add(values[i], scale(values[i + 1], -1n));
      const odd = scale(difference, BigInt(inverse(i, log - round, circle && round === 0)));
      next.push(add(sum, multiply(alpha, odd)));
    }
    values = next;
    alpha = multiply(alpha, alpha);
  }
  return values;
}

function tree(values, leafWidth, encode = pack) {
  const rows = [];
  for (let i = 0; i < values.length; i += leafWidth) {
    rows.push(Buffer.concat(values.slice(i, i + leafWidth).map(encode)));
  }
  const levels = [rows.map(row => tagged("leaf", row))];
  while (levels.at(-1).length !== 1) {
    const previous = levels.at(-1);
    levels.push(previous.filter((_, i) => i % 2 === 0).map((left, i) => tagged("node", left, previous[2 * i + 1])));
  }
  return { rows, levels, root: levels.at(-1)[0] };
}

function openTree(tree, positions) {
  const siblings = [];
  for (const level of tree.levels.slice(0, -1)) {
    const present = new Set(positions);
    for (const position of positions) {
      if (!present.has(position ^ 1)) siblings.push(hex(level[position ^ 1]));
    }
    positions = sortedUnique(positions.map(position => position >> 1));
  }
  return siblings;
}

const draw = (digest, counter) => hash(digest, word(counter), Buffer.alloc(1));

function queryPositions(prePow, nonce, log) {
  const mixed = hash(prePow, word(nonce, 8));
  const raw = [];
  for (let counter = 0; raw.length < 108; ++counter) {
    const block = draw(mixed, counter);
    for (let i = 0; i < 8 && raw.length < 108; ++i) raw.push(block.readUInt32LE(4 * i) & (2 ** log - 1));
  }
  return sortedUnique(raw);
}

function validNonce(prePow, nonce) {
  const prefix = hash(word(0x12345678), Buffer.alloc(12), prePow, word(20));
  return (hash(prefix, word(nonce, 8)).readUInt32LE() & ((1 << 20) - 1)) === 0;
}

// Pinned PoW nonces for the independently committed test vectors.
const nonces = {
  "10-false-false": 544017,
  "10-true-false": 193894,
  "10-false-true": 2745198,
  "native-deep": 120618,
};

function makeProof({ domainLog = 10, badLayer = false, badLast = false, nativeDeep } = {}) {
  const prefix = nativeDeep ? Buffer.from(nativeDeep.prefixBytes) : hash(Buffer.from("Independent native FRI chain fixture v1"));
  const samples = nativeDeep ? Buffer.concat(nativeDeep.samples.map(pack)) : pack([5n, 7n, 13n, 17n, 23n, 29n, 31n, 37n]);
  let digest = hash(prefix, samples);
  // A nonconstant low-degree circle polynomial, with nonzero odd and even
  // terms in the extension basis. FRI folds it into a constant.
  const initial = nativeDeep?.allAnswers.map(value => value.map(BigInt)) ?? Array.from({ length: 2 ** domainLog }, (_, position) => {
    const [x, y] = point(position, domainLog, true);
    return add(add(vector(samples), scale([3n, 0n, 5n, 0n, 0n, 7n, 0n, 0n], x ** 3n)),
      scale([0n, 11n, 0n, 13n, 0n, 0n, 17n, 19n], y * (1n + x ** 5n)));
  });
  let values = initial;
  const stages = [];
  for (let log = domainLog; log > 1;) {
    const step = Math.min(log - 1, 4);
    const leafWidth = step > 1 ? 4 : 1;
    const circle = log === domainLog;
    if (badLayer && log === domainLog - 4) values = values.map(value => add(value, [1n, ...ZERO.slice(1)]));
    const committed = tree(values, leafWidth);
    digest = hash(digest, committed.root);
    const alpha = vector(draw(digest, 0));
    stages.push({ log, step, leafWidth, committed, circle });
    values = fold(values, alpha, log, step, circle);
    log -= step;
  }
  assert.deepEqual(values[0], values[1], "final polynomial must be constant");
  const last = pack(badLast ? add(values[0], [1n, ...ZERO.slice(1)]) : values[0]);
  const prePow = hash(digest, last);
  const key = nativeDeep ? "native-deep" : `${domainLog}-${badLayer}-${badLast}`;
  const nonce = nonces[key];
  assert.notEqual(nonce, undefined);
  assert.ok(validNonce(prePow, nonce), `invalid nonce for ${hex(prePow)}`);
  const queries = queryPositions(prePow, nonce, domainLog);
  const deepValues = queries.map(position => hex(pack(initial[position])));
  let positions = queries;
  const layers = stages.map(({ log, step, leafWidth, committed, circle }) => {
    const width = 2 ** step;
    const groups = sortedUnique(positions.map(position => position >> step));
    const leaves = groups.flatMap(group => Array.from({ length: width / leafWidth }, (_, i) => group * width / leafWidth + i));
    positions = groups;
    return {
      rows: hex(Buffer.concat(leaves.map(leaf => committed.rows[leaf]))),
      siblings: openTree(committed, leaves),
      inverses: groups.flatMap(group => groupInverses(group, log, step, circle)),
    };
  });
  return {
    input: { prefix: hex(prefix), domainLog, sampleCount: samples.length / 32, samples: hex(samples),
      roots: stages.map(stage => hex(stage.committed.root)), lastCoefficient: hex(last), nonce },
    queries, deepValues, layers,
  };
}

const fixture = name => new URL(`../fixtures/${name}`, import.meta.url);
const readFixture = name => JSON.parse(readFileSync(fixture(name)));

export function registerFriTests(deploy) {
  test("authenticates all native FRI layers and rejects disconnected commitments", async () => {
    const fri = await deploy("test/NativeFriHarness.sol", "NativeFriHarness");
    const { input, queries, deepValues, layers } = makeProof();
    const gas = { gasLimit: 60_000_000 };
    assert.deepEqual((await fri.positions(input)).map(Number), queries);
    assert.equal(await fri.check(input, deepValues, layers, gas), true);
    const receipt = await (await fri.check.send(input, deepValues, layers, gas)).wait();
    console.log(JSON.stringify({ nativeFriChainGas: Number(receipt.gasUsed), domainLog: input.domainLog,
      queries: queries.length, layerRows: layers.map(layer => (layer.rows.length - 2) / 2) }));

    const badDeep = deepValues.slice();
    badDeep[0] = deepValues[1];
    assert.notEqual(badDeep[0], deepValues[0]);
    assert.equal(await fri.check(input, badDeep, layers, gas), false);
    assert.equal(await fri.check({ ...input, nonce: input.nonce + 1 }, deepValues, layers, gas), false);
    await assert.rejects(fri.check(input, deepValues, layers.slice(0, -1), gas), { code: "CALL_EXCEPTION" });

    const tampered = structuredClone(layers);
    const row = fromHex(tampered[0].rows);
    row[0] ^= 1;
    tampered[0].rows = hex(row);
    assert.equal(await fri.check(input, deepValues, tampered, gas), false);
    const inverse = structuredClone(layers);
    inverse[0].inverses[0] ^= 1;
    await assert.rejects(fri.check(input, deepValues, inverse, gas), { code: "CALL_EXCEPTION" });

    for (const options of [{ badLayer: true }, { badLast: true }]) {
      // New commitments, transcript, valid nonce, and valid paths. A return
      // value of false therefore tests the link itself, not a stale PoW.
      const bad = makeProof(options);
      assert.deepEqual((await fri.positions(bad.input)).map(Number), bad.queries);
      assert.equal(await fri.check(bad.input, bad.deepValues, bad.layers, gas), false);
    }
  });

  test("feeds native DEEP quotients into the transcript-bound FRI chain", async () => {
    const nativeDeep = readFixture("native-deep-vector.json");
    const { domainLog, columns, points } = nativeDeep;
    const { input, queries, layers } = makeProof({ domainLog, nativeDeep });
    const { prefix, samples, roots: friRoots, lastCoefficient, nonce, sampleCount } = input;
    const pcs = await deploy("test/DeepFriHarness.sol", "DeepFriHarness");
    function tracesAt(changeRow = false) {
      return nativeDeep.treeWidths.map((columnCount, i) => {
        const logSize = nativeDeep.treeLogs[i];
        const positions = sortedUnique(queries.map(q => ((q >> (1 + domainLog - logSize)) << 1) | (q & 1)));
        const rowValues = [...nativeDeep.rows[i]];
        if (changeRow && i === 0) rowValues[positions[0] * columnCount] ^= 1;
        const committed = tree(rowValues, columnCount, value => word(value));
        return [
          { root: hex(committed.root), logSize, columnCount },
          { positions, rows: hex(Buffer.concat(positions.map(pos => committed.rows[pos]))), witness: openTree(committed, positions) },
        ];
      });
    }
    const gas = { gasLimit: 16_777_216 };
    const check = (opened, send) => {
      const layout = { domainLog, sampleCount, columns, points, trees: opened.map(([tree]) => tree) };
      const proof = { friRoots, lastCoefficient, nonce, traces: opened.map(([, trace]) => trace), layers };
      return (send ? pcs.check.send : pcs.check)(prefix, samples, layout, proof, gas);
    };
    assert.equal(await check(tracesAt()), true);
    // Even a valid Merkle opening under a recomputed trace root is rejected
    // when its recomputed DEEP quotient does not match the committed FRI row.
    assert.equal(await check(tracesAt(true)), false);
    const receipt = await (await check(tracesAt(), true)).wait();
    console.log(JSON.stringify({ nativeDeepFriGas: Number(receipt.gasUsed), queries: queries.length }));
  });

  const pcs = readFixture("native-pcs-121057303-truth-4.json");
  const query = readFixture("native-queries-121057303.json")["truth-4.bin"];
  const input = { ...pcs, roots: pcs.friRoots, nonce: query.nonce };
  test("FRI derives the real mainnet transcript queries", async () => {
    const fri = await deploy("test/NativeFriHarness.sol", "NativeFriHarness");
    const opening = readFixture("op-mainnet-121057303-truth-4.json");
    assert.equal(opening.workerSha256, pcs.workerSha256);
    assert.equal(opening.depth, pcs.domainLog);
    assert.deepEqual(queryPositions(fromHex(pcs.prePowDigest), query.nonce, opening.depth), opening.positions);
    assert.deepEqual((await fri.positions(input, { gasLimit: 60_000_000 })).map(Number), opening.positions);
  });

  const filename = "native-fri-121057303-truth-4.json";
  test("replays exported mainnet FRI openings", { skip: !existsSync(fixture(filename)) }, async () => {
    const fri = await deploy("test/NativeFriHarness.sol", "NativeFriHarness");
    const exported = readFixture(filename);
    assert.equal(exported.workerSha256, pcs.workerSha256);
    assert.equal(await fri.check(input, exported.deepValues, exported.layers, { gasLimit: 95_000_000 }), true);
  });
}
