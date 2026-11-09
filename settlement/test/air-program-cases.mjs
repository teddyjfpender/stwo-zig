import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { keccak256 } from "ethers";
import { product } from "./packed-om31-cases.mjs";
const P = (1n << 31n) - 1n;
const mod = (x) => ((x % P) + P) % P;
const field = (a) => {
  const b = Buffer.alloc(32);
  a.forEach((v, i) => b.writeUInt32LE(Number(v), 4 * i));
  return b;
};
function program(count) {
  const draw = (label) => {
    const b = createHash("sha256").update(label).digest();
    return Array.from(
      { length: 8 },
      (_, i) => BigInt(b.readUInt32LE(4 * i)) % P,
    );
  };
  const constant = draw("air-constant"),
    input = draw("air-input"),
    parameter = draw("air-parameter"),
    alpha = draw("air-alpha");
  const values = [constant, input, parameter],
    nodes = [];
  for (let i = 0; i < count; ++i) {
    const op = i < 3 ? i : 3 + (i % 4),
      lhs = i < 3 ? 0 : i - 1,
      rhs = i < 3 ? 0 : (i * 7) % i;
    const node = Buffer.alloc(13);
    node[0] = op;
    node.writeUInt32LE(lhs, 1);
    node.writeUInt32LE(rhs, 5);
    nodes.push(node);
    if (i >= 3) {
      const a = values[lhs],
        b = values[rhs];
      values.push(
        op === 3
          ? a.map((v, j) => mod(v + b[j]))
          : op === 4
            ? a.map((v, j) => mod(v - b[j]))
            : op === 5
              ? product(a, b)
              : a.map((v) => mod(-v)),
      );
    }
  }
  const roots = [count - 1, count - 2, Math.floor(count / 2), 3];
  let expected = Array(8).fill(0n);
  for (const r of roots)
    expected = product(expected, alpha).map((v, j) => mod(v + values[r][j]));
  const header = Buffer.alloc(24);
  header.write("AIR1");
  header.writeUInt32LE(count, 4);
  header.writeUInt32LE(roots.length, 8);
  header.writeUInt32LE(1, 12);
  header.writeUInt32LE(1, 16);
  header.writeUInt32LE(1, 20);
  const tail = Buffer.alloc(roots.length * 4);
  roots.forEach((r, i) => tail.writeUInt32LE(r, 4 * i));
  const code = Buffer.concat([header, ...nodes, field(constant), tail]);
  return {
    code,
    inputs: field(input),
    parameters: field(parameter),
    alpha,
    expected,
  };
}
export function registerAirProgramTests(deploy) {
  test("packed AIR evaluates mixed operation DAGs at bounded memory cost", async () => {
    const c = await deploy(
      "test/AirProgramDynamicHarness.sol",
      "AirProgramDynamicHarness",
    );
    for (const count of [17, 257, 2048]) {
      const p = program(count),
        args = [keccak256(p.code), p.code, p.inputs, p.parameters, p.alpha];
      assert.deepEqual(Array.from(await c.evaluate(...args)), p.expected);
      const receipt = await (await c.evaluate.send(...args)).wait();
      console.log(
        JSON.stringify({
          nativeMixedAirGas: Number(receipt.gasUsed),
          nodes: count,
          residuals: 4,
        }),
      );
    }
  });
  test("packed AIR preserves canonical and topological admission", async () => {
    const c = await deploy(
        "test/AirProgramDynamicHarness.sol",
        "AirProgramDynamicHarness",
      ),
      p = program(17);
    const check = (
      code = p.code,
      inputs = p.inputs,
      parameters = p.parameters,
      alpha = p.alpha,
    ) => c.evaluate(keccak256(code), code, inputs, parameters, alpha);
    for (const change of [
      (b) => {
        b[24 + 3 * 13] = 7;
      },
      (b) => b.writeUInt32LE(3, 24 + 3 * 13 + 1),
      (b) => b.writeUInt32LE(6, 24 + 6 * 13 + 5),
      (b) => b.writeUInt32LE(1, 24 + 9),
      (b) => b.writeUInt32LE(17, b.length - 4),
    ]) {
      const bad = Buffer.from(p.code);
      change(bad);
      await assert.rejects(check(bad), /InvalidProgram/);
    }
    for (const index of [0, 7]) {
      const badInput = Buffer.from(p.inputs);
      badInput.writeUInt32LE(Number(P), index * 4);
      await assert.rejects(check(p.code, badInput), /NonCanonicalField/);
      const badParameter = Buffer.from(p.parameters);
      badParameter.writeUInt32LE(Number(P), index * 4);
      await assert.rejects(
        check(p.code, p.inputs, badParameter),
        /NonCanonicalField/,
      );
      const badConstant = Buffer.from(p.code);
      badConstant.writeUInt32LE(Number(P), 24 + 17 * 13 + index * 4);
      await assert.rejects(check(badConstant), /NonCanonicalField/);
      const badAlpha = [...p.alpha];
      badAlpha[index] = P;
      await assert.rejects(
        check(p.code, p.inputs, p.parameters, badAlpha),
        /NonCanonicalField/,
      );
    }
    await assert.rejects(
      check(p.code.subarray(0, p.code.length - 1)),
      /InvalidProgram/,
    );
  });
}
