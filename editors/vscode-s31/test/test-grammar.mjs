import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

import textmate from 'vscode-textmate';
import oniguruma from 'vscode-oniguruma';

const { Registry, parseRawGrammar } = textmate;
const { createOnigScanner, createOnigString, loadWASM } = oniguruma;

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const extension = path.resolve(here, '..');
const repository = path.resolve(extension, '../..');
const grammarPath = path.join(extension, 'syntaxes/s31.tmLanguage.json');
const wasm = fs.readFileSync(require.resolve('vscode-oniguruma/release/onig.wasm'));
await loadWASM(wasm.buffer.slice(wasm.byteOffset, wasm.byteOffset + wasm.byteLength));

const registry = new Registry({
  onigLib: Promise.resolve({ createOnigScanner, createOnigString }),
  loadGrammar: async (scopeName) => scopeName === 'source.s31'
    ? parseRawGrammar(fs.readFileSync(grammarPath, 'utf8'), grammarPath)
    : null,
});
const grammar = await registry.loadGrammar('source.s31');
assert.ok(grammar, 'S31 grammar must load');

function scopesForLine(line, stack = null) {
  const result = grammar.tokenizeLine(line, stack);
  return {
    stack: result.ruleStack,
    tokens: result.tokens.map((token) => ({
      text: line.slice(token.startIndex, token.endIndex),
      scopes: token.scopes,
    })),
  };
}

function expectScope(line, text, scope) {
  const tokens = scopesForLine(line).tokens;
  assert.ok(tokens.some((token) => token.text === text && token.scopes.includes(scope)),
    `expected ${JSON.stringify(text)} to have ${scope}: ${JSON.stringify(tokens)}`);
}

expectScope('circuit wide_order(', 'circuit', 'keyword.declaration.function.s31');
expectScope('circuit wide_order(', 'wide_order', 'entity.name.function.s31');
expectScope('    private digest_bytes: Bytes32,', 'private', 'storage.modifier.visibility.s31');
expectScope('    private digest_bytes: Bytes32,', 'digest_bytes', 'variable.parameter.s31');
expectScope('    private digest_bytes: Bytes32,', 'Bytes32', 'support.type.primitive.s31');
expectScope('let x = std::math::add_u256(a, b);', 'std', 'support.module.std.s31');
expectScope('let x = std::math::add_u256(a, b);', 'math', 'support.namespace.s31');
expectScope('let x = std::math::add_u256(a, b);', 'add_u256', 'support.function.builtin.s31');
for (const type of ['u8', 'u16', 'u32', 'u64', 'u128', 'i8', 'i16', 'i32', 'i64', 'i128']) {
  expectScope(`private value: ${type},`, type, 'support.type.primitive.s31');
}
for (const builtin of [
  'add_checked', 'add_wrapping', 'sub_checked', 'sub_wrapping',
  'le', 'lt', 'ge', 'gt', 'eq', 'ne', 'limbs',
  'from_limbs_u8', 'from_limbs_i128', 'reinterpret_u32', 'reinterpret_i64',
]) {
  const line = `let value = std::int::${builtin}(a, b);`;
  expectScope(line, 'std', 'support.module.std.s31');
  expectScope(line, 'int', 'support.namespace.s31');
  expectScope(line, builtin, 'support.function.builtin.s31');
}
expectScope('let x = splat<4>(7_m31);', '7_m31', 'constant.numeric.field.m31.s31');
expectScope('v .* v + splat<4>(7_m31)', '.*', 'keyword.operator.arithmetic.s31');
expectScope('a - -b', '-', 'keyword.operator.arithmetic.s31');
expectScope('fn step(v: [m31; 4]) -> [m31; 4] {', '->', 'keyword.operator.return.s31');
expectScope('assert_eq(a, b);', 'assert_eq', 'keyword.other.assertion.s31');
expectScope('// private is only a comment', '// private is only a comment', 'comment.line.double-slash.s31');

const examples = path.join(repository, 'src/frontends/s31/examples');
function* sourceFiles(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const file = path.join(directory, entry.name);
    if (entry.isDirectory()) yield* sourceFiles(file);
    else if (entry.isFile() && entry.name.endsWith('.s31')) yield file;
  }
}

let count = 0;
let nested = false;
for (const file of sourceFiles(examples)) {
  const name = path.relative(examples, file);
  nested ||= name.includes(path.sep);
  let stack = null;
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    const result = scopesForLine(line, stack);
    stack = result.stack;
    assert.ok(result.tokens.length > 0, `${name}: expected tokens for every line`);
  }
  count += 1;
}
assert.ok(count > 0, 'expected at least one shipped S31 example');
assert.ok(nested, 'expected to tokenize examples in nested directories');
console.log(`S31 TextMate grammar: representative scopes and ${count} examples passed`);
