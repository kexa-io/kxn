// Functional smoke test for the kxn-wasm Node.js package.
// Run from the repo root after `wasm-pack build crates/kxn-wasm --target nodejs --out-dir pkg-node`.
// Exercises a real scan: the shipped AWS CIS rule set evaluated against a
// crafted inventory with a known violation (root account with an access key).
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const kxn = require('../crates/kxn-wasm/pkg-node/kxn_wasm.js');

const fail = (msg) => {
  console.error(`FAIL: ${msg}`);
  process.exit(1);
};

const version = kxn.version();
if (!/^\d+\.\d+\.\d+/.test(version)) fail(`unexpected engine version: ${version}`);
console.log(`engine version: ${version}`);

const rulesToml = readFileSync(new URL('../rules/aws-cis.toml', import.meta.url), 'utf8');
const parsed = JSON.parse(kxn.validate_rules(rulesToml));
if (!parsed.rules?.length) fail('aws-cis.toml parsed to zero rules');
console.log(`validate_rules: ${parsed.rules.length} rules parsed`);

const inventory = {
  iam_user: [
    { name: 'root', has_access_key: true, mfa_enabled: false },
    { name: 'alice', has_access_key: true, mfa_enabled: true },
  ],
};
const summary = JSON.parse(kxn.evaluate(rulesToml, JSON.stringify(inventory)));
if (summary.total_rules !== parsed.rules.length) fail('total_rules mismatch');
if (!summary.results.some((r) => r.rule_name === 'aws-cis-1.4-no-root-access-keys')) {
  fail('known violation aws-cis-1.4-no-root-access-keys was not detected');
}
console.log(`evaluate: ${summary.total_rules} rules, ${summary.passed} passed, ${summary.failed} failed — CIS 1.4 violation detected`);

try {
  kxn.validate_rules('not [ valid');
  fail('malformed TOML did not throw');
} catch {
  console.log('malformed TOML correctly rejected');
}

console.log('wasm smoke test passed');
